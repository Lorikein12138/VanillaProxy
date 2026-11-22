package service

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

const bandwidthTestVLESS = `{"decryption":"none","clients":[{"id":"00000000-0000-4000-8000-000000000001","email":"Shared@Example.com"}]}`
const bandwidthTestREALITY = `"realitySettings":{"target":"cover.test:443","serverNames":["cover.test"],"privateKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortIds":["01020304"]}`

func TestAutomaticBandwidthXrayPolicyChangesBindingsAndDeniesMissingAccounts(t *testing.T) {
	const email = "Shared@Example.com"
	const uuid = "00000000-0000-4000-8000-000000000001"
	const rotatedUUID = "00000000-0000-4000-8000-000000000002"
	const sharedPSK = "BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const rotatedPSK = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const masterKey = "AQEBAQEBAQEBAQEBAQEBAQ=="
	const userKey = "AgICAgICAgICAgICAgICAg=="
	const rotatedKey = "AwMDAwMDAwMDAwMDAwMDAw=="
	const newPassword = "new-password"
	repeat := strings.Repeat
	for _, test := range []struct {
		name, protocol, settings, stream string
		wireProtocol, credential         string
		rotateFrom, rotateTo             string
		omitWhenDenied                   bool
	}{
		{"VLESS", "vless", bandwidthTestVLESS, "", "vless", uuid, uuid, rotatedUUID, false},
		{"Hysteria", "hysteria", `{"version":2,"users":[{"email":"ignored","auth":"unused"}],"clients":[{"email":"` + email + `","auth":"secret"}]}`,
			`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2}}`, "hysteria", "secret", "secret", newPassword, false},
		{"VMess", "vmess", `{"clients":[{"email":"` + email + `","id":"` + uuid + `"}]}`, "", "vmess", uuid, uuid, rotatedUUID, false},
		{"Trojan", "trojan", `{"clients":[{"email":"` + email + `","password":"secret"}]}`, "", "trojan", "secret", "secret", newPassword, false},
		{"Shadowsocks", "shadowsocks", `{"method":"aes-128-gcm","clients":[{"email":"` + email + `","method":"aead_aes_128_gcm","password":"secret"}]}`,
			"", "shadowsocks", bandwidthexchange.CredentialParts("aes-128-gcm", "secret"), "secret", newPassword, false},
		{"SS2022", "shadowsocks", `{"method":"2022-blake3-aes-128-gcm","email":"` + email + `","password":"` + masterKey + `","clients":[{"email":"` + email + `","password":"` + userKey + `"}]}`,
			"", "shadowsocks-2022", bandwidthexchange.CredentialParts("2022-blake3-aes-128-gcm", repeat("\x01", 16), repeat("\x02", 16)), userKey, rotatedKey, true},
		{"MASQUE", "masque", `{"address":["10.0.0.1/24"],"clients":[{"email":"` + email + `","pass":"secret"}]}`,
			`{"network":"masque","security":"tls"}`, "masque", "secret", "secret", newPassword, false},
		{"WireGuard", "wireguard", `{"secretKey":"` + repeat("ab", 32) + `","peers":[{"email":"` + email + `","publicKey":"` + repeat("BC", 32) + `","preSharedKey":"` + sharedPSK + `","allowedIPs":["10.0.0.2/32"]}]}`,
			"", "wireguard", bandwidthexchange.CredentialParts(repeat("bc", 32), "07"+repeat("00", 31)), sharedPSK, rotatedPSK, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := xray.InboundConfig{PanelGenerated: true, Tag: "data", Port: 12345, Protocol: test.protocol,
				Settings: json_util.RawMessage(test.settings), StreamSettings: json_util.RawMessage(test.stream)}
			config := &xray.Config{InboundConfigs: []xray.InboundConfig{inbound}}
			legacy := func(string) (string, bool) { return "static-id", true }
			fingerprint := bandwidthexchange.CredentialFingerprint(test.wireProtocol, test.credential)
			prepare := func(accounts map[string]string) (*xray.Config, map[string]map[string]string) {
				t.Helper()
				prepared, bindings, err := prepareBandwidthXrayConfigWithPolicy(true, config, legacy, func(protocol, email, credential string) (string, bool) {
					id, exists := accounts[email]
					return id, exists && bandwidthexchange.CredentialFingerprint(protocol, credential) == fingerprint
				})
				if err != nil {
					t.Fatal(err)
				}
				return prepared, bindings
			}
			limited, limitedBindings := prepare(map[string]string{email: "auto-id"})
			unrestricted, unrestrictedBindings := prepare(map[string]string{email: ""})
			if !limited.Equals(unrestricted) || equalBandwidthXrayBindings(limitedBindings, unrestrictedBindings) ||
				limitedBindings[inbound.Tag][email] != "auto-id" || unrestrictedBindings[inbound.Tag][email] != launch.UnmeteredXrayAccountID {
				t.Fatal("an unchanged native config must still detect a metering binding change")
			}
			live, err := liveBandwidthXrayPolicyAccounts(unrestricted, unrestrictedBindings)
			if _, ok := live[email][bandwidthexchange.PolicyBinding{Protocol: test.wireProtocol, Fingerprint: fingerprint}]; err != nil || !ok || len(live[email]) != 1 {
				t.Fatalf("authorized generated account not represented in live readiness: %v", live)
			}
			assertDenied := func(filtered *xray.Config, bindings map[string]map[string]string) {
				t.Helper()
				if test.omitWhenDenied {
					if len(filtered.InboundConfigs) != 0 || len(bindings) != 0 {
						t.Fatal("denied multi-user SS2022 would expose the server key as a single-user password")
					}
					return
				}
				if nativeEmails, err := bandwidthXrayClients(filtered.InboundConfigs[0]); err != nil || len(nativeEmails) != 0 || len(bindings[inbound.Tag]) != 0 {
					t.Fatalf("denied account returned native users %q, bindings %v, error %v", nativeEmails, bindings, err)
				}
			}
			filtered, deniedBindings := prepare(map[string]string{strings.ToLower(email): "other"})
			assertDenied(filtered, deniedBindings)
			config.InboundConfigs[0].Settings = json_util.RawMessage(strings.Replace(string(inbound.Settings), test.rotateFrom, test.rotateTo, 1))
			filtered, deniedBindings = prepare(map[string]string{email: ""})
			assertDenied(filtered, deniedBindings)
			config.InboundConfigs[0].PanelGenerated = false
			_, templateBindings := prepare(map[string]string{email: "auto-id"})
			if templateBindings[inbound.Tag][email] != "static-id" {
				t.Fatal("template inbound consumed generated-account policy")
			}
		})
	}
}

func TestPrepareBandwidthXrayConfigNativeAccounts(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol model.Protocol
		settings string
		stream   string
		identity string
	}{
		{"Trojan clients override", model.Trojan, `{"users":[null],"clients":[{"password":"secret","email":"shared"}]}`, "", "shared"},
		{"classic Shadowsocks user", model.Shadowsocks, `{"method":"aes-128-gcm","clients":[{"password":"secret","email":"shared"}]}`, "", "shared"},
		{"classic Shadowsocks single", model.Shadowsocks, `{"method":"aes-128-gcm","password":"secret","email":"shared"}`, "", "shared"},
		{"SS2022 single TCP and UDP", model.Shadowsocks, `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","email":"shared","network":"tcp,udp"}`, "", "shared"},
		{"SS2022 multi TCP", model.Shadowsocks, `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","network":"tcp","clients":[{"password":"AgICAgICAgICAgICAgICAg==","email":"shared"}]}`, "", "shared"},
		{"SS2022 multi TCP and UDP", model.Shadowsocks, `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","network":"tcp,udp","clients":[{"password":"AgICAgICAgICAgICAgICAg==","email":"shared"}]}`, "", "shared"},
		{"SS2022 multi default network", model.Shadowsocks, `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","clients":[{"password":"AgICAgICAgICAgICAgICAg==","email":"shared"}]}`, "", "shared"},
		{"HTTP accounts override", model.HTTP, `{"users":[null],"accounts":[{"user":"user-one","pass":"secret"}]}`, "", "user-one"},
		{"HTTP origin-form requests", model.HTTP, `{"allowTransparent":true,"accounts":[{"user":"user-one","pass":"secret"}]}`, "", "user-one"},
		{"Mixed password", model.Mixed, `{"auth":"password","accounts":[{"user":"user-one","pass":"secret"}]}`, "", "user-one"},
		{"Mixed password UDP", model.Mixed, `{"auth":"password","udp":true,"accounts":[{"user":"user-one","pass":"secret"}]}`, "", "user-one"},
		{"MASQUE panel password", model.MASQUE, `{"address":["10.0.0.1/24"],"clients":[{"password":"secret","email":"shared"}]}`, `{"network":"masque","security":"tls"}`, "shared"},
		{"WireGuard panel peer", model.WireGuard, `{"secretKey":"` + strings.Repeat("ab", 32) + `","clients":[{"enable":true,"email":"shared","publicKey":"` + strings.Repeat("bc", 32) + `","allowedIPs":["10.0.0.2/32"]}]}`, "", "shared"},
		{"Vision per-user", model.VLESS, `{"decryption":"none","clients":[{"id":"5ed47836-4826-4a65-998d-fe57bb6d539e","email":"shared","flow":"xtls-rprx-vision"}]}`, `{"network":"raw","security":"tls"}`, "shared"},
		{"Vision inherited", model.VLESS, `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"5ed47836-4826-4a65-998d-fe57bb6d539e","email":"shared"}]}`, `{"method":"raw","network":"ws","security":"tls","rawSettings":{"header":{"type":"none"}}}`, "shared"},
		{"REALITY", model.VLESS, bandwidthTestVLESS, `{"network":"tcp","security":"reality",` + bandwidthTestREALITY + `}`, "Shared@Example.com"},
		{"REALITY Vision", model.VLESS, `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"5ed47836-4826-4a65-998d-fe57bb6d539e","email":"shared"}]}`, `{"network":"raw","security":"reality",` + bandwidthTestREALITY + `}`, "shared"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := &model.Inbound{Tag: "data", Port: 20101, Protocol: test.protocol, Settings: test.settings, StreamSettings: test.stream}
			config := bandwidthTestDefaultConfig(t)
			config.InboundConfigs = append(config.InboundConfigs, *inbound.GenXrayInboundConfig())
			prepared, bindings, err := prepareBandwidthXrayConfig(false, config, func(identity string) (string, bool) {
				return "account-42", identity == test.identity
			})
			want := map[string]map[string]string{"data": {test.identity: "account-42"}}
			if err != nil || prepared == nil || !reflect.DeepEqual(bindings, want) {
				t.Fatalf("native settings = %s, bindings = %v, want %v, error = %v", config.InboundConfigs[1].Settings, bindings, want, err)
			}
		})
	}
}

func TestBandwidthMarkedProxyAccountsRequireAutomaticOwnership(t *testing.T) {
	config := &xray.Config{InboundConfigs: []xray.InboundConfig{
		{PanelGenerated: true, Tag: "http", Protocol: "http", Port: 20101,
			Settings: json_util.RawMessage(`{"allowTransparent":true,"accounts":[{"user":"mapped","pass":"secret","bandwidthClientId":1}]}`)},
		{PanelGenerated: true, Tag: "mixed", Protocol: "mixed", Port: 20102,
			Settings: json_util.RawMessage(`{"auth":"password","accounts":[{"user":"mapped","pass":"secret","bandwidthClientId":2},{"user":"legacy","pass":"password"}]}`)},
	}}
	prepared, bindings, err := prepareBandwidthXrayConfig(true, config, func(user string) (string, bool) {
		if user == "mapped" {
			t.Fatal("an explicitly marked account consumed native username policy")
		}
		return "legacy-account", true
	})
	if err != nil || len(prepared.InboundConfigs) != 1 || prepared.InboundConfigs[0].Tag != "mixed" ||
		!reflect.DeepEqual(bindings, map[string]map[string]string{"mixed": {"legacy": "legacy-account"}}) {
		t.Fatalf("legacy node admitted an explicitly marked proxy account: %v (%v)", bindings, err)
	}
}

func TestPrepareBandwidthXrayConfigRejectsUnprovenNativeVariants(t *testing.T) {
	for _, test := range []struct {
		name, protocol, settings, stream, want string
	}{
		{"fallback Trojan", "trojan", `{"fallbacks":[{"dest":8080}]}`, "", "fallback"},
		{"missing Trojan credential", "trojan", `{"clients":[null]}`, "", "password credentials"},
		{"duplicate Trojan passwords", "trojan", `{"clients":[{"email":"one","password":"shared"},{"email":"two","password":"shared"}]}`, "", "unique passwords"},
		{"anonymous HTTP override", "http", `{"users":[{"user":"who","pass":"secret"}],"accounts":[]}`, "", "authentication"},
		{"transparent anonymous HTTP", "http", `{"allowTransparent":true,"accounts":[]}`, "", "username/password"},
		{"transparent socket HTTP", "http", `{"accounts":[{"user":"name","pass":"secret"}]}`, `{"sockopt":{"tproxy":"tproxy"}}`, "transparent reception"},
		{"marked HTTP colon username", "http", `{"accounts":[{"user":"who:else","pass":"secret","bandwidthClientId":1}]}`, "", "invalid authenticated proxy credentials"},
		{"marked Mixed oversized password", "mixed", `{"auth":"password","accounts":[{"user":"who","pass":"` + strings.Repeat("é", 128) + `","bandwidthClientId":1}]}`, "", "invalid authenticated proxy credentials"},
		{"anonymous Mixed", "mixed", `{"auth":"noauth","accounts":[{"user":"who","pass":"secret"}]}`, "", "password authentication"},
		{"anonymous UDP Mixed", "mixed", `{"auth":"noauth","udp":true,"accounts":[{"user":"who","pass":"secret"}]}`, "", "password authentication"},
		{"unnamed Shadowsocks", "shadowsocks", `{"method":"aes-128-gcm","password":"secret"}`, "", "unique non-empty emails"},
		{"nil Shadowsocks client", "shadowsocks", `{"clients":[null]}`, "", "password credentials"},
		{"SS2022 relay", "shadowsocks", `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","clients":[{"password":"AgICAgICAgICAgICAgICAg==","email":"shared","address":"127.0.0.1","port":8000}]}`, "", "relay"},
		{"SS2022 multi unknown network", "shadowsocks", `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","network":"tcp,unknown","clients":[{"password":"AgICAgICAgICAgICAgICAg==","email":"shared"}]}`, "", "TCP or UDP network"},
		{"global MASQUE auth", "masque", `{"clients":[{"pass":"secret","email":"shared"}]}`, `{"network":"masque","security":"tls","masqueSettings":{"user":"global","pass":"secret"}}`, "per-user auth"},
		{"missing MASQUE credential", "masque", `{"clients":[null]}`, `{"network":"masque","security":"tls"}`, "per-user credentials"},
		{"nil WireGuard peer", "wireguard", `{"peers":[null]}`, "", "public key"},
		{"Vision non-raw", "vless", `{"decryption":"none","flow":"xtls-rprx-vision"}`, `{"network":"raw","method":"ws","security":"tls"}`, "raw TCP"},
		{"Vision HTTP header", "vless", `{"decryption":"none","flow":"xtls-rprx-vision"}`, `{"network":"raw","security":"tls","rawSettings":{"header":{"type":"http"}}}`, "raw TCP"},
		{"REALITY non-raw", "vless", bandwidthTestVLESS, `{"network":"grpc","security":"reality",` + bandwidthTestREALITY + `}`, "raw TCP"},
		{"REALITY HTTP header", "vless", bandwidthTestVLESS, `{"network":"raw","security":"reality","rawSettings":{"header":{"type":"http"}},` + bandwidthTestREALITY + `}`, "raw TCP"},
		{"REALITY non-VLESS", "vmess", `{"clients":[]}`, `{"network":"raw","security":"reality",` + bandwidthTestREALITY + `}`, "requires VLESS"},
		{"REALITY invalid destination", "vless", bandwidthTestVLESS, `{"security":"reality",` + strings.Replace(bandwidthTestREALITY, "cover.test:443", "cover.test:0", 1) + `}`, "invalid managed Xray REALITY server settings"},
		{"REALITY unknown nested field", "vless", bandwidthTestVLESS, `{"security":"reality",` + strings.Replace(bandwidthTestREALITY, `"shortIds"`, `"unknownField":42,"shortIds"`, 1) + `}`, "invalid managed Xray REALITY server settings"},
		{"REALITY misspelled nested field", "vless", bandwidthTestVLESS, `{"security":"reality",` + strings.Replace(bandwidthTestREALITY, `"shortIds"`, `"short_ids"`, 1) + `}`, "invalid managed Xray REALITY server settings"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := bandwidthTestDefaultConfig(t)
			config.InboundConfigs = append(config.InboundConfigs, xray.InboundConfig{
				Tag: "data", Port: 20101, Protocol: test.protocol,
				Settings: json_util.RawMessage(test.settings), StreamSettings: json_util.RawMessage(test.stream),
			})
			prepared, bindings, err := prepareBandwidthXrayConfig(false, config, func(string) (string, bool) {
				return "account-42", true
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || prepared != nil || bindings != nil {
				t.Fatalf("preparation = (%v, %v, %v), want nil results and error containing %q", prepared, bindings, err, test.want)
			}
		})
	}
}

func TestPrepareBandwidthEncryptedREALITYVisionAccounts(t *testing.T) {
	const client = `{"email":"peer","id":"00000000-0000-4000-8000-000000000001"}`
	const rawREALITY = `{"network":"raw","security":"reality",` + bandwidthTestREALITY + `}`
	for _, tc := range []struct {
		name, decryption, settings, stream, wantError string
	}{
		{"inherited Vision", goldenVlessDecryption, `"flow":"xtls-rprx-vision","clients":[` + client + `]`, rawREALITY, ""},
		{"explicit Vision", goldenVlessDecryption, `"users":[` + strings.TrimSuffix(client, "}") + `,"flow":"xtls-rprx-vision"}]`, rawREALITY, ""},
		{"plain flow", goldenVlessDecryption, `"clients":[` + client + `]`, rawREALITY, "Vision flow for each account"},
		{"TLS", goldenVlessDecryption, `"flow":"xtls-rprx-vision","clients":[` + client + `]`, `{"network":"raw","security":"tls"}`, "REALITY over raw TCP"},
		{"fallback", goldenVlessDecryption, `"fallbacks":[{"dest":8080}],"clients":[` + client + `]`, rawREALITY, "unsupported VLESS inbound settings"},
		{"reverse", goldenVlessDecryption, `"clients":[` + strings.TrimSuffix(client, "}") + `,"reverse":{"tag":"r"}}]`, rawREALITY, "unsupported or invalid managed Xray account"},
		{"bad prefix", "unknown.native.600s.invalid-private-value", `"clients":[` + client + `]`, rawREALITY, "invalid managed VLESS encryption"},
		{"bad mode", strings.Replace(goldenVlessDecryption, ".native.", ".xorpub.", 1), `"clients":[` + client + `]`, rawREALITY, "invalid managed VLESS encryption"},
		{"bad key", "mlkem768x25519plus.native.600s.invalid-private-value", `"clients":[` + client + `]`, rawREALITY, "invalid managed VLESS encryption"},
		{"bad duration", strings.Replace(goldenVlessDecryption, ".600s.", ".invalid-private-value.", 1), `"clients":[` + client + `]`, rawREALITY, "invalid managed VLESS encryption"},
		{"unsupported duration", strings.Replace(goldenVlessDecryption, ".600s.", ".300s.", 1), `"clients":[` + client + `]`, rawREALITY, "invalid managed VLESS encryption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := xray.InboundConfig{
				Tag: "encrypted", Port: 20101, Protocol: "vless", StreamSettings: json_util.RawMessage(tc.stream),
				Settings: json_util.RawMessage(`{"decryption":"` + tc.decryption + `",` + tc.settings + `}`),
			}
			config := &xray.Config{InboundConfigs: []xray.InboundConfig{inbound}}
			_, bindings, err := prepareBandwidthXrayConfig(false, config, func(email string) (string, bool) {
				return "canonical-peer", email == "peer"
			})
			if tc.wantError == "" {
				if err != nil || bindings["encrypted"]["peer"] != "canonical-peer" {
					t.Fatalf("prepare encrypted inbound: bindings=%v, error=%v", bindings, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) || strings.Contains(err.Error(), tc.decryption) {
				t.Fatalf("prepare encrypted inbound error = %v, want redacted error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestSaveBandwidthXrayREALITYPanelSettings(t *testing.T) {
	setupEnablePortTest(t)
	panel := setupBandwidthSaveNode(t)
	inbound := &model.Inbound{
		Tag: "panel-reality", Protocol: model.VLESS, Listen: "127.0.0.1", Enable: true, Port: 40493,
		Settings: `{"decryption":"none","encryption":"none","fallbacks":[],"clients":[{"id":"00000000-0000-4000-8000-000000000001","email":"peer","enable":true,"flow":"xtls-rprx-vision"}]}`,
		StreamSettings: `{"network":"tcp","tcpSettings":{"header":{"type":"none"}},"security":"reality",
			"realitySettings":{"show":false,"xver":0,"target":"cover.test:443","serverNames":["cover.test"],
			"privateKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","minClientVer":"","maxClientVer":"",
			"maxTimediff":5000,"shortIds":["a3f1","b8c2"],"mldsa65Seed":"",
			"limitFallbackUpload":{"afterBytes":10,"bytesPerSec":20,"burstBytesPerSec":30},
			"limitFallbackDownload":{"afterBytes":40,"bytesPerSec":50,"burstBytesPerSec":60},
			"settings":{"publicKey":"client-metadata","fingerprint":"chrome","serverName":"","spiderX":"/","mldsa65Verify":""}}}`,
	}
	service := &InboundService{}
	if _, _, err := service.AddInbound(inbound); err != nil {
		t.Fatalf("save REALITY from panel: %v", err)
	}
	generated, err := service.buildGeneratedXrayInbound(nil, inbound, true)
	if err != nil {
		t.Fatal(err)
	}
	var stream struct {
		REALITY map[string]json.RawMessage `json:"realitySettings"`
	}
	if err := json.Unmarshal(generated.StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	if _, exists := stream.REALITY["settings"]; exists {
		t.Fatal("generated REALITY settings include client metadata")
	}
	_, bindings, err := prepareBandwidthXrayConfig(false, &xray.Config{InboundConfigs: []xray.InboundConfig{*generated}}, panel.AccountID)
	if err != nil || bindings[inbound.Tag]["peer"] != "shared-account" {
		t.Fatalf("generated REALITY admission => %v, %v", bindings, err)
	}
}

func bandwidthTestDefaultConfig(t *testing.T) *xray.Config {
	t.Helper()
	var config xray.Config
	if err := json.Unmarshal([]byte(xrayTemplateConfig), &config); err != nil {
		t.Fatal(err)
	}
	return &config
}

func TestPrepareBandwidthXrayConfigManagementOnly(t *testing.T) {
	config := bandwidthTestDefaultConfig(t)
	prepared, bindings, err := prepareBandwidthXrayConfig(false, config, func(email string) (string, bool) {
		t.Fatalf("management tunnel passed to account resolver: %q", email)
		return "", false
	})
	if err != nil || prepared == nil || len(bindings) != 0 {
		t.Fatalf("preparation rejected the management-only template: bindings = %v, error = %v", bindings, err)
	}
}

func TestPrepareBandwidthXrayConfigDefaultTemplateAndSharedAccount(t *testing.T) {
	config := bandwidthTestDefaultConfig(t)
	config.API = json_util.RawMessage(`{"tag":"api","services":["HandlerService","statsService","RoutingService","LoggerService","hAnDlErSeRvIcE","rOuTiNgSeRvIcE"]}`)
	config.InboundConfigs = append(config.InboundConfigs,
		xray.InboundConfig{Tag: "vless-1", Port: 20101, Protocol: "vless", Settings: json_util.RawMessage(bandwidthTestVLESS)},
		xray.InboundConfig{Tag: "vmess-1", Port: 20102, Protocol: "vmess", Settings: json_util.RawMessage(`{"users":[{"id":"temporary-id","level":0,"email":"Shared@Example.com","security":"auto"}]}`)},
		xray.InboundConfig{
			Tag: "hy2-1", Port: 20103, Protocol: "hysteria",
			Settings:       json_util.RawMessage(`{"version":2,"clients":[{"auth":"secret","email":"Shared@Example.com"}]}`),
			StreamSettings: json_util.RawMessage(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"","udpIdleTimeout":60}}`),
		},
	)
	original, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	prepared, bindings, err := prepareBandwidthXrayConfig(false, config, func(email string) (string, bool) {
		calls++
		return "account-42", email == "Shared@Example.com"
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"vless-1": {"Shared@Example.com": "account-42"},
		"vmess-1": {"Shared@Example.com": "account-42"},
		"hy2-1":   {"Shared@Example.com": "account-42"},
	}
	if !reflect.DeepEqual(bindings, want) || calls != 1 {
		t.Fatalf("bindings = %v, resolver called %d times", bindings, calls)
	}
	var api struct {
		Services []string `json:"services"`
	}
	if err := json.Unmarshal(prepared.API, &api); err != nil {
		t.Fatal(err)
	}
	if want := []string{"statsService", "LoggerService"}; !reflect.DeepEqual(api.Services, want) {
		t.Errorf("API services = %v, want %v", api.Services, want)
	}
	if !reflect.DeepEqual(prepared.InboundConfigs, config.InboundConfigs) || !reflect.DeepEqual(prepared.RouterConfig, config.RouterConfig) {
		t.Fatal("preparation changed the generated inbounds or routing rules")
	}
	prepared.InboundConfigs[1].Settings[0] = '['
	prepared.RouterConfig[0] = '['
	after, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != string(after) {
		t.Fatal("preparation mutated or shared writable state with the original config")
	}
}

func TestPrepareBandwidthXrayConfigRejectsUnprovenIngress(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*xray.Config, *xray.InboundConfig)
		found bool
		want  string
	}{
		{"missing account", func(*xray.Config, *xray.InboundConfig) {}, false, "canonical account binding"},
		{"anonymous socks", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Protocol = "socks"
			inbound.Listen = json_util.RawMessage(`"127.0.0.1"`)
			inbound.Settings = json_util.RawMessage(`{"auth":"noauth"}`)
		}, true, "unsupported traffic ingress"},
		{"nonloopback API", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.InboundConfigs[0].Listen = json_util.RawMessage(`"0.0.0.0"`)
		}, true, "loopback API tunnel"},
		{"shadowed API route", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.RouterConfig = json_util.RawMessage(`{"rules":[{"type":"field","network":"tcp","outboundTag":"direct"},{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}`)
		}, true, "first routing rule"},
		{"conditional API route", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.RouterConfig = json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api","network":"udp"}]}`)
		}, true, "first routing rule"},
		{"case-aliased routing rules", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.RouterConfig = json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}],"RULES":[{"type":"field","network":"tcp","outboundTag":"direct"}]}`)
		}, true, "first routing rule"},
		{"unrecognized routing rules", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.RouterConfig = json_util.RawMessage(`{"r-u-l-e-s":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}`)
		}, true, "first routing rule"},
		{"direct API listen", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.API = json_util.RawMessage(`{"tag":"api","listen":"0.0.0.0:12345","services":["StatsService"]}`)
		}, true, "default routed API endpoint"},
		{"duplicate tag", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Tag = "api"
		}, true, "unique non-empty inbound tags"},
		{"reverse app", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.Reverse = json_util.RawMessage(`{"bridges":[{"tag":"bridge","domain":"example.org"}]}`)
		}, true, "reverse"},
		{"vless outbound reverse", func(cfg *xray.Config, _ *xray.InboundConfig) {
			cfg.OutboundConfigs = json_util.RawMessage(`[{"tag":"reverse","protocol":"VLESS","settings":{"REVERSE":{"tag":"reverse"}}}]`)
		}, true, "VLESS outbound reverse"},
		{"vless fallback", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Settings = json_util.RawMessage(`{"decryption":"none","fallbacks":[{"dest":8080}]}`)
		}, true, "unsupported VLESS inbound settings"},
		{"vless vision", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Settings = json_util.RawMessage(`{"decryption":"none","clients":[{"id":"a","email":"a","flow":"xtls-rprx-vision"}]}`)
		}, true, "invalid managed Xray account"},
		{"duplicate native email", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Settings = json_util.RawMessage(`{"decryption":"none","clients":[{"id":"a","email":"Shared"},{"id":"b","email":"Shared"}]}`)
		}, true, "unique non-empty emails"},
		{"null Hysteria user", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Protocol = "hysteria"
			inbound.Settings = json_util.RawMessage(`{"version":2,"clients":[null]}`)
			inbound.StreamSettings = json_util.RawMessage(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2}}`)
		}, true, "invalid managed Xray account"},
		{"Hysteria global auth", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Protocol = "hysteria"
			inbound.Settings = json_util.RawMessage(`{"version":2,"clients":[{"auth":"per-user","email":"one"}]}`)
			inbound.StreamSettings = json_util.RawMessage(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"global"}}`)
		}, true, "per-user auth"},
		{"Hysteria proxy masquerade", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.Protocol = "hysteria"
			inbound.Settings = json_util.RawMessage(`{"version":2,"clients":[{"auth":"per-user","email":"one"}]}`)
			inbound.StreamSettings = json_util.RawMessage(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"masquerade":{"type":"proxy","url":"https://example.org"}}}`)
		}, true, "no masquerade"},
		{"REALITY missing server settings", func(_ *xray.Config, inbound *xray.InboundConfig) {
			inbound.StreamSettings = json_util.RawMessage(`{"network":"tcp","security":"reality"}`)
		}, true, "REALITY requires VLESS over raw TCP with server settings"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := bandwidthTestDefaultConfig(t)
			config.InboundConfigs = append(config.InboundConfigs, xray.InboundConfig{
				Tag: "data", Port: 20101, Protocol: "vless", Settings: json_util.RawMessage(bandwidthTestVLESS),
			})
			test.edit(config, &config.InboundConfigs[1])
			prepared, bindings, err := prepareBandwidthXrayConfig(false, config, func(string) (string, bool) {
				return "account-42", test.found
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || prepared != nil || bindings != nil {
				t.Errorf("preparation = (%v, %v, %v), want both results nil and error containing %q", prepared, bindings, err, test.want)
			}
		})
	}
}

func TestPrepareBandwidthXrayConfigUsesEffectiveClientsList(t *testing.T) {
	config := bandwidthTestDefaultConfig(t)
	config.InboundConfigs = append(config.InboundConfigs, xray.InboundConfig{
		Tag: "disabled-users", Port: 20101, Protocol: "vless",
		Settings: json_util.RawMessage(`{"decryption":"none","users":[{"id":"inactive-user","email":"inactive"}],"clients":[]}`),
	})
	_, bindings, err := prepareBandwidthXrayConfig(false, config, func(email string) (string, bool) {
		t.Fatalf("inactive email passed to resolver: %q", email)
		return "", false
	})
	if err != nil || len(bindings) != 1 || bindings["disabled-users"] == nil || len(bindings["disabled-users"]) != 0 {
		t.Fatalf("preparation = (%v, %v), want a managed tag with no accounts", bindings, err)
	}
}
