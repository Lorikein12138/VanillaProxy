package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

func TestSaveBandwidthXrayTemplatePreservesPreviousSettings(t *testing.T) {
	setupConflictDB(t)
	assets := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", assets)
	raw, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{
		Code: "PRIVATE",
		Cidr: []*geodata.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "geoip.dat"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &XraySettingService{}
	previous := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(previous) })
	if err := svc.SaveXraySetting(xrayTemplateConfig); err != nil {
		t.Fatalf("default template cannot be saved on a managed node: %v", err)
	}
	saved, err := svc.GetXrayConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, template, want string
	}{
		{"anonymous", `{"inbounds":[{"port":44531,"tag":"custom-http","protocol":"http","settings":{}}]}`, "username/password authentication"},
		{"unbound user", `{"inbounds":[{"port":44531,"tag":"custom-http","protocol":"http","settings":{"accounts":[{"user":"missing","pass":"secret"}]}}]}`, "canonical account binding"},
		{"reverse", `{"reverse":{"bridges":[{"tag":"b","domain":"test.invalid"}]}}`, "reverse"},
		{"global transport", `{"transport":{"tcpSettings":{}}}`, "global transport"},
		{"routing script", `{"routing":{"script":"function Route() end"}}`, "script"},
		{"outbound reverse", `{"outbounds":[{"tag":"reverse","protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"6e45abb0-c265-4add-97d9-2e6b9588a2a0","encryption":"none","reverse":{"tag":"r"}}}]}`, "VLESS outbound reverse"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := svc.SaveXraySetting(test.template); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("save error = %v, want %q", err, test.want)
			}
			after, err := svc.GetXrayConfigTemplate()
			if err != nil || after != saved {
				t.Fatalf("rejected template changed stored settings: %v", err)
			}
		})
	}
}

func TestSaveBandwidthXrayTemplateAllowsStockAnonymousInbound(t *testing.T) {
	setupConflictDB(t)
	svc := &XraySettingService{}
	const template = `{"inbounds":[{"port":44531,"tag":"custom-http","protocol":"http","settings":{}}]}`
	if err := svc.SaveXraySetting(template); err != nil {
		t.Fatalf("default mode rejected a supported custom template: %v", err)
	}
	saved, err := svc.GetXrayConfigTemplate()
	if err != nil || !strings.Contains(saved, "custom-http") {
		t.Fatalf("custom template not saved: %v", err)
	}
}

func TestSaveBandwidthXrayInboundChecksActiveNativeAccounts(t *testing.T) {
	setupEnablePortTest(t)
	setupBandwidthSaveNode(t)
	svc := &InboundService{}
	const exact = `{"accounts":[{"user":"peer","pass":"secret"}]}`
	const wrongCase = `{"accounts":[{"user":"Peer","pass":"secret"}]}`
	candidate := &model.Inbound{Tag: "canonical-http", Protocol: model.HTTP, Enable: true, Port: 40491, Settings: wrongCase}
	if _, _, err := svc.AddInbound(candidate); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
		t.Fatalf("add with unbound username returned %v", err)
	}
	var count int64
	if err := database.GetDB().Model(&model.Inbound{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rejected add left %d rows: %v", count, err)
	}
	candidate.Enable = false
	if _, _, err := svc.AddInbound(candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetInboundEnable(candidate.Id, true); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
		t.Fatalf("enable with unbound username returned %v", err)
	}
	saved, err := svc.GetInbound(candidate.Id)
	if err != nil || saved.Enable {
		t.Fatalf("rejected enable modified the inbound: %v", err)
	}
	saved.Settings = exact
	if _, _, err := svc.UpdateInbound(saved); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetInboundEnable(saved.Id, true); err != nil {
		t.Fatalf("enable with an exact account failed: %v", err)
	}
	saved, err = svc.GetInbound(saved.Id)
	if err != nil {
		t.Fatal(err)
	}
	edited := *saved
	edited.Enable = false // The live flag comes from the serialized DB snapshot.
	edited.Settings = wrongCase
	if _, _, err := svc.UpdateInbound(&edited); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
		t.Fatalf("edit with unbound username returned %v", err)
	}
	after, err := svc.GetInbound(saved.Id)
	if err != nil || !after.Enable || after.Settings != saved.Settings {
		t.Fatalf("rejected edit modified or disabled the inbound: %v", err)
	}
}

func TestSaveBandwidthXrayInboundOmitsDisabledAndDepletedClients(t *testing.T) {
	setupEnablePortTest(t)
	setupBandwidthSaveNode(t)
	const clientID = "6e45abb0-c265-4add-97d9-2e6b9588a2a0"
	inbound := &model.Inbound{
		Tag: "non-serving-clients", Protocol: model.VLESS, Enable: true, Port: 40492,
		Settings: fmt.Sprintf(`{"decryption":"none","clients":[
			{"id":"6e45abb0-c265-4add-97d9-2e6b9588a2a1","email":"manually-disabled","enable":false},
			{"id":%q,"email":"depleted","enable":true,"expiryTime":%d}
		]}`, clientID, time.Now().Add(-time.Hour).UnixMilli()),
	}
	svc := &InboundService{}
	if _, _, err := svc.AddInbound(inbound); err != nil {
		t.Fatalf("add attempted to bind inactive clients: %v", err)
	}
	// Updating parent metadata rebuilds the real runtime clients and traffic
	// flags. An expired account stays omitted even before the next traffic tick.
	inbound.Remark = "updated"
	if _, _, err := svc.UpdateInbound(inbound); err != nil {
		t.Fatalf("edit attempted to bind inactive clients: %v", err)
	}
	aliasOnly := &model.Inbound{
		Tag: "stale-native-alias", Protocol: model.Trojan, Enable: true, Port: 40498,
		Settings: `{"users":[{"email":"stale-user","password":"stale-password"}]}`,
	}
	if _, _, err := svc.AddInbound(aliasOnly); err != nil {
		t.Fatalf("generated inbound reused an unmanaged native users alias: %v", err)
	}
}

func TestSaveBandwidthGeneratedPanelFieldsReachPrivateChild(t *testing.T) {
	setupEnablePortTest(t)
	panel := setupBandwidthSaveNode(t)
	release, reserveTCP, reserveUDP := reserveBandwidthChildTestPorts(t)
	config := bandwidthChildTestConfig(t)
	config.InboundConfigs[0].Port = reserveTCP()
	template := mustJSON(t, config)
	if err := (&XraySettingService{}).SaveXraySetting(string(template)); err != nil {
		t.Fatal(err)
	}

	svc := &InboundService{}
	for _, inbound := range []*model.Inbound{
		{Tag: "panel-ss", Protocol: model.Shadowsocks, Listen: "127.0.0.1", Enable: true, Port: reserveTCP(),
			Settings: `{"method":"aes-128-gcm","ivCheck":false,"network":"tcp","clients":[{"email":"peer","enable":true,"password":"secret"}]}`},
		{Tag: "panel-wg", Protocol: model.WireGuard, Listen: "127.0.0.1", Enable: true, Port: reserveUDP(),
			Settings: `{"secretKey":"` + strings.Repeat("ab", 32) + `","address":["10.60.0.1/24"],"subnetIp":"10.60.0.0","subnetCidr":24,"dns":"10.60.0.1","noKernelTun":true,"peers":[],"clients":[{"email":"wg-peer","enable":true,"publicKey":"` + strings.Repeat("cd", 32) + `","allowedIPs":["10.60.0.2/32"]}]}`},
	} {
		if _, _, err := svc.AddInbound(inbound); err != nil {
			t.Fatalf("normal %s panel save failed: %v", inbound.Protocol, err)
		}
	}
	generated, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	prepared, bindings, err := prepareBandwidthXrayConfig(false, generated, panel.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	for tag, account := range map[string]string{"panel-ss": "peer", "panel-wg": "wg-peer"} {
		if id := bindings[tag][account]; id != "shared-account" {
			t.Fatalf("%s canonical ID = %q", tag, id)
		}
	}
	resolved := map[string]bool{}
	for _, inbound := range generated.InboundConfigs {
		if inbound.Protocol == "shadowsocks" || inbound.Protocol == "wireguard" {
			settings := string(inbound.Settings)
			for _, panelField := range []string{`"ivCheck"`, `"subnetIp"`, `"subnetCidr"`, `"dns"`} {
				if strings.Contains(settings, panelField) {
					t.Fatalf("generated %s settings retained panel-only field %s", inbound.Protocol, panelField)
				}
			}
			resolved[inbound.Tag] = true
		}
	}
	if !resolved["panel-ss"] || !resolved["panel-wg"] {
		t.Fatalf("generated config omitted expected listeners: %v", resolved)
	}
	_, wireGuardPatched := any((*wireguard.Server)(nil)).(interface{ VanillaProxyWireGuardPacketGateV1() })
	release()
	if !wireGuardPatched {
		runGeneratedBandwidthChild(t, prepared, bindings, "requires the patched native WireGuard packet gate", func(context.Context, string, int) error { return nil })
		inbounds := prepared.InboundConfigs[:0]
		for _, inbound := range prepared.InboundConfigs {
			if inbound.Protocol != "wireguard" {
				inbounds = append(inbounds, inbound)
			}
		}
		prepared.InboundConfigs = inbounds
		delete(bindings, "panel-wg")
	}
	runGeneratedBandwidthChild(t, prepared, bindings, "", func(context.Context, string, int) error { return nil })
}

func TestSavedGeneratedInboundsAllowExplicitUnmeteredXrayAccounts(t *testing.T) {
	const limitedEmail = "peer"
	const exemptEmail = "ordinary"
	for _, mode := range []struct {
		name  string
		allow bool
	}{{"default strict", false}, {"opt in", true}} {
		t.Run(mode.name, func(t *testing.T) {
			setupEnablePortTest(t)
			panel := setupBandwidthSaveNodeWithUnmeteredAccounts(t, mode.allow)
			if panel.AllowsUnmeteredXrayAccounts() != mode.allow {
				t.Fatal("unexpected runtime option")
			}
			if _, exists := panel.AccountID(exemptEmail); exists {
				t.Fatal("the sidecar account resolver accepted a missing canonical account")
			}
			release, reserveTCP, reserveUDP := reserveBandwidthChildTestPorts(t)
			template := bandwidthChildTestConfig(t)
			template.InboundConfigs[0].Port = reserveTCP()
			httpPort := reserveTCP()
			tlsStream := strings.TrimSuffix(bandwidthChildTestTLSStream(t, "hysteria"), "}") +
				`,"hysteriaSettings":{"version":2}}`
			inbounds := []*model.Inbound{
				{Tag: "opt-vless", Protocol: model.VLESS, Listen: "127.0.0.1", Enable: true, Port: reserveTCP(),
					Settings: `{"decryption":"none","clients":[
						{"id":"00000000-0000-4000-8000-000000000001","email":"peer","enable":true},
						{"id":"00000000-0000-4000-8000-000000000002","email":"ordinary","enable":true}
					]}`},
				{Tag: "opt-hysteria", Protocol: model.Hysteria, Listen: "127.0.0.1", Enable: true, Port: reserveUDP(),
					StreamSettings: tlsStream, Settings: `{"version":2,"clients":[
						{"auth":"limited-auth","email":"wg-peer","enable":true},
						{"auth":"ordinary-auth","email":"ordinary-hy","enable":true}
					]}`},
			}
			release()
			if err := (&XraySettingService{}).SaveXraySetting(string(mustJSON(t, template))); err != nil {
				t.Fatal(err)
			}
			service := &InboundService{}
			for _, inbound := range inbounds {
				// Template inbounds must still have canonical bindings.
				templateRow := *inbound
				templateRow.Settings = strings.ReplaceAll(templateRow.Settings, `,"enable":true`, "")
				template.InboundConfigs = append(template.InboundConfigs[:1], *templateRow.GenXrayInboundConfig())
				if err := (&XraySettingService{}).SaveXraySetting(string(mustJSON(t, template))); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
					t.Fatalf("template %s validation got %v", inbound.Protocol, err)
				}
				_, _, err := service.AddInbound(inbound)
				if !mode.allow {
					if err == nil || !strings.Contains(err.Error(), "canonical account binding") {
						t.Errorf("default %s save got %v", inbound.Protocol, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("opt-in %s save: %v", inbound.Protocol, err)
				}
				inbound.Remark = "updated"
				if _, _, err := service.UpdateInbound(inbound); err != nil {
					t.Fatalf("opt-in %s update: %v", inbound.Protocol, err)
				}
			}
			if !mode.allow {
				return
			}
			other := &model.Inbound{
				Protocol: model.HTTP, Listen: "127.0.0.1", Enable: true, Port: httpPort,
				Settings: `{"accounts":[{"user":"ordinary","pass":"test-password"}]}`,
			}
			if _, _, err := service.AddInbound(other); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
				t.Fatalf("opt-in HTTP save got %v", err)
			}
			generated, err := (&XrayService{}).GetXrayConfig()
			if err != nil {
				t.Fatal(err)
			}
			prepared, bindings, err := prepareBandwidthXrayConfig(panel.AllowsUnmeteredXrayAccounts(), generated, panel.AccountID)
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []struct{ tag, limited, exempt string }{
				{inbounds[0].Tag, limitedEmail, exemptEmail},
				{inbounds[1].Tag, "wg-peer", "ordinary-hy"},
			} {
				users := bindings[expected.tag]
				if len(users) != 2 || users[expected.limited] != "shared-account" || users[expected.exempt] != launch.UnmeteredXrayAccountID {
					t.Fatalf("generated %s bindings = %q", expected.tag, users)
				}
			}
			if _, err := panel.Node().NewManagedXrayWithRelays(prepared, bindings, nil); err != nil {
				t.Fatalf("cannot construct managed process with unmetered Xray accounts: %v", err)
			}
			relays := map[string]launch.SidecarRelay{"relay": {Accounts: map[string]string{exemptEmail: launch.UnmeteredXrayAccountID}}}
			if _, err := panel.Node().NewManagedXrayWithRelays(prepared, bindings, relays); err == nil {
				t.Fatal("unmetered account was accepted on a sidecar relay")
			}
			runGeneratedBandwidthChild(t, prepared, bindings, "", func(context.Context, string, int) error { return nil })
		})
	}
}

func setupBandwidthSaveNode(t *testing.T) *bandwidthruntime.PanelRuntime {
	t.Helper()
	return setupBandwidthSaveNodeWithUnmeteredAccounts(t, false)
}

func setupBandwidthSaveNodeWithUnmeteredAccounts(t *testing.T, allowUnmetered bool) *bandwidthruntime.PanelRuntime {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		owner, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("icacls.exe", token, "/inheritance:r", "/grant:r", "*"+owner.Uid+":F").CombinedOutput(); err != nil {
			t.Fatalf("restrict test token permissions: %v (%s)", err, out)
		}
	}
	path := filepath.Join(dir, "node.json")
	content := `{"node":{"id":"node","generation":"gen","authorityID":"root","tokenFile":"token","accounts":{
		"peer":{"id":"shared-account","requestedBitsPerSecond":1000000},
		"wg-peer":{"id":"shared-account","requestedBitsPerSecond":1000000}
	}}}`
	if allowUnmetered {
		content = strings.Replace(content, `"accounts":`, `"allowUnmeteredXrayAccounts":true,"accounts":`, 1)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := bandwidthruntime.LoadPanelConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	panel, err := bandwidthruntime.StartPanelRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	previous := activeBandwidthNode.Swap(&managedBandwidthNode{panel: panel})
	t.Cleanup(func() {
		activeBandwidthNode.Store(previous)
		_ = panel.Close()
	})
	return panel
}
