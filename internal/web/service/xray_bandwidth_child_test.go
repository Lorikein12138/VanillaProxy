package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func TestGeneratedBandwidthConfigStartsPrivateChild(t *testing.T) {
	tlsStream := bandwidthChildTestTLSStream(t, "raw")
	config := bandwidthChildTestConfig(t)
	ports := make(map[string]int)
	models := []model.Inbound{
		{Tag: "vmess", Protocol: model.VMESS, Settings: `{"clients":[{"email":"peer","id":"5ed47836-4826-4a65-998d-fe57bb6d539e"}]}`},
		{Tag: "trojan", Protocol: model.Trojan, Settings: `{"clients":[{"email":"peer","password":"secret"}]}`, StreamSettings: tlsStream},
		{Tag: "ss-classic", Protocol: model.Shadowsocks, Settings: `{"method":"aes-128-gcm","clients":[{"email":"peer","password":"secret"}]}`},
		{Tag: "ss2022-datagram", Protocol: model.Shadowsocks, Settings: `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","email":"peer","network":"tcp,udp"}`},
		{Tag: "ss2022-multi", Protocol: model.Shadowsocks, Settings: `{"method":"2022-blake3-aes-128-gcm","password":"AQEBAQEBAQEBAQEBAQEBAQ==","network":"tcp","clients":[{"email":"peer","password":"AgICAgICAgICAgICAgICAg=="}]}`},
		{Tag: "http", Protocol: model.HTTP, Settings: `{"allowTransparent":true,"users":[{"user":"peer","pass":"secret","bandwidthClientId":1}]}`},
		{Tag: "mixed", Protocol: model.Mixed, Settings: `{"auth":"password","udp":true,"accounts":[{"user":"peer","pass":"secret","bandwidthClientId":1},{"user":"uncapped","pass":"secret","bandwidthClientId":2}]}`},
		{Tag: "vision", Protocol: model.VLESS, Settings: `{"decryption":"none","clients":[{"id":"5ed47836-4826-4a65-998d-fe57bb6d539e","email":"peer","flow":"xtls-rprx-vision"}]}`, StreamSettings: tlsStream},
	}
	finishPorts, reserveTCP, reserveUDP := reserveBandwidthChildTestPorts(t)
	apiPort := reserveTCP()
	config.InboundConfigs[0].Port = apiPort
	for _, inbound := range models {
		inbound.Listen = "127.0.0.1"
		if inbound.Tag == "ss2022-datagram" {
			inbound.Port = reserveUDP()
		} else {
			inbound.Port = reserveTCP()
		}
		ports[inbound.Tag] = inbound.Port
		generated := inbound.GenXrayInboundConfig()
		generated.PanelGenerated = true
		if inbound.Protocol == model.HTTP || inbound.Protocol == model.Mixed {
			generated.BandwidthProxyOwners = map[string]string{"peer": "proxy-owner", "uncapped": "uncapped-owner"}
		}
		config.InboundConfigs = append(config.InboundConfigs, *generated)
	}
	prepared, bindings, err := prepareBandwidthXrayConfigWithPolicy(false, config, func(identity string) (string, bool) {
		return "shared-account", identity == "peer"
	}, func(protocol, email, credential string) (string, bool) {
		if protocol == "http" || protocol == "mixed" {
			if email == "uncapped-owner" && protocol == "mixed" {
				return "", true
			}
			return "proxy-account", email == "proxy-owner" && credential != ""
		}
		if protocol == "trojan" || protocol == "shadowsocks-2022" {
			return "", email == "peer" && credential != ""
		}
		return "shared-account", email == "peer" && credential != ""
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, inbound := range models {
		want := "shared-account"
		if inbound.Protocol == model.HTTP || inbound.Protocol == model.Mixed {
			want = "proxy-account"
		}
		if inbound.Tag == "trojan" || inbound.Tag == "ss2022-multi" {
			want = launch.UnmeteredXrayAccountID
		}
		wantedBindings := map[string]string{"peer": want}
		if inbound.Protocol == model.Mixed {
			wantedBindings["uncapped"] = launch.UnmeteredXrayAccountID
		}
		if !reflect.DeepEqual(bindings[inbound.Tag], wantedBindings) {
			t.Fatalf("%s bindings = %v", inbound.Tag, bindings[inbound.Tag])
		}
	}
	var charged sync.Map
	finishPorts()
	runGeneratedBandwidthChild(t, prepared, bindings, "", func(_ context.Context, account string, size int) error {
		if account != "proxy-account" {
			return fmt.Errorf("unexpected account %q", account)
		}
		charged.Store(account, size)
		return nil
	})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "metered response")
	}))
	defer origin.Close()
	for _, tag := range []string{"http", "mixed"} {
		t.Run(tag+" charges canonical account", func(t *testing.T) {
			proxy := &url.URL{
				Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", ports[tag]),
				User: url.UserPassword("peer", "secret"),
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			charged.Delete("proxy-account")
			response, err := httpClient.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "metered response" {
				t.Fatalf("unexpected response: %s %q (%v)", response.Status, body, err)
			}
			if size, ok := charged.Load("proxy-account"); !ok || size.(int) <= 0 {
				t.Fatal("authenticated traffic reached the origin without a bandwidth charge")
			}
		})
	}
	t.Run("HTTP origin-form request requires authentication and charges the owner", func(t *testing.T) {
		transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", ports["http"]))
		}}
		defer transport.CloseIdleConnections()
		httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		for _, spec := range []struct {
			password string
			status   int
		}{
			{"", http.StatusProxyAuthRequired},
			{"wrong", http.StatusProxyAuthRequired},
			{"secret", http.StatusOK},
		} {
			charged.Delete("proxy-account")
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if spec.password != "" {
				request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("peer:"+spec.password)))
			}
			response, err := httpClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != spec.status {
				t.Fatalf("origin-form status = %d, want %d (%v)", response.StatusCode, spec.status, err)
			}
			if size, ok := charged.Load("proxy-account"); spec.status == http.StatusOK {
				if !ok || size.(int) <= 0 || string(body) != "metered response" {
					t.Fatal("authenticated origin-form request did not reach and meter the origin")
				}
			} else if ok {
				t.Fatal("rejected origin-form request consumed an authenticated account's bandwidth")
			}
		}
	})
}

func TestGeneratedBandwidthPacketGates(t *testing.T) {
	_, masquePatched := any((*masque.Server)(nil)).(interface{ VanillaProxyPacketGateV1() })
	_, wireGuardPatched := any((*wireguard.Server)(nil)).(interface{ VanillaProxyWireGuardPacketGateV1() })
	for _, spec := range []struct {
		inbound model.Inbound
		patched bool
		gate    string
	}{
		{
			model.Inbound{Tag: "masque", Protocol: model.MASQUE, StreamSettings: bandwidthChildTestTLSStream(t, "masque"),
				Settings: `{"address":["10.19.10.1/24"],"clients":[{"email":"peer","password":"secret"}]}`},
			masquePatched, "MASQUE",
		},
		{
			model.Inbound{Tag: "wireguard", Protocol: model.WireGuard,
				Settings: `{"address":["10.19.11.1/24"],"secretKey":"` + strings.Repeat("ab", 32) +
					`","clients":[{"enable":true,"email":"peer","publicKey":"` + strings.Repeat("cd", 32) + `","allowedIPs":["10.19.11.2/32"]}]}`},
			wireGuardPatched, "WireGuard",
		},
	} {
		t.Run(spec.inbound.Tag, func(t *testing.T) {
			releasePorts, reserveTCP, reserveUDP := reserveBandwidthChildTestPorts(t)
			inbound := spec.inbound
			inbound.Listen = "127.0.0.1"
			inbound.Port = reserveUDP()
			config := bandwidthChildTestConfig(t)
			config.InboundConfigs[0].Port = reserveTCP()
			generated := inbound.GenXrayInboundConfig()
			generated.PanelGenerated = true
			config.InboundConfigs = append(config.InboundConfigs, *generated)
			prepared, bindings, err := prepareBandwidthXrayConfigWithPolicy(false, config, func(string) (string, bool) {
				return "", false
			}, func(_, email, credential string) (string, bool) {
				return "", email == "peer" && credential != ""
			})
			if err != nil {
				t.Fatal(err)
			}
			releasePorts()
			wantError := ""
			if !spec.patched {
				wantError = "requires the patched native " + spec.gate + " packet gate"
			}
			runGeneratedBandwidthChild(t, prepared, bindings, wantError, func(context.Context, string, int) error { return nil })
		})
	}
}

func runGeneratedBandwidthChild(t *testing.T, config *xray.Config, bindings map[string]map[string]string, wantError string, gate bandwidthipc.Gate) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "managed-xray.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(platform.NewEnvFlag(platform.AssetLocation).AltName, filepath.Dir(path))
	permits, err := bandwidthipc.Listen(gate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = permits.Close() })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	nonce := make([]byte, launch.ReadyNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	generated := make(map[string]bool)
	for _, inbound := range config.InboundConfigs {
		if inbound.PanelGenerated && inbound.BandwidthAutomatic {
			generated[inbound.Tag] = true
		}
	}
	digest := sha256.Sum256(raw)
	handshake, err := json.Marshal(launch.Handshake{
		IPC: permits.Info(), Clients: bindings, Generated: generated, ConfigSHA256: digest[:],
		Ready: &launch.Ready{Address: listener.Addr().String(), Nonce: nonce},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	child := make(chan error, 1)
	go func() { child <- xraybandwidthchild.Run(ctx, []string{path}, io.NopCloser(bytes.NewReader(handshake))) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-child:
			if err != nil && wantError == "" {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("private child did not shut down")
		}
	})
	ready := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		got, err := io.ReadAll(io.LimitReader(conn, launch.ReadyNonceSize+1))
		ready <- err == nil && bytes.Equal(got, nonce)
	}()
	select {
	case err := <-child:
		child <- nil
		if wantError == "" || err == nil || !strings.Contains(err.Error(), wantError) {
			t.Fatalf("child exited with %v, expected error containing %q", err, wantError)
		}
	case ok := <-ready:
		if !ok || wantError != "" {
			t.Fatalf("child sent readiness %v, expected error containing %q", ok, wantError)
		}
	case <-ctx.Done():
		t.Fatal("private child startup timed out")
	}
}

func reserveBandwidthChildTestPorts(t *testing.T) (release func(), reserveTCP func() int, reserveUDP func() int) {
	t.Helper()
	var sockets []io.Closer
	release = func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
		sockets = nil
	}
	t.Cleanup(release)
	reserveTCP = func() int {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, listener)
		return listener.Addr().(*net.TCPAddr).Port
	}
	reserveUDP = func() int {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, listener)
		return listener.LocalAddr().(*net.UDPAddr).Port
	}
	return release, reserveTCP, reserveUDP
}

func bandwidthChildTestTLSStream(t *testing.T, network string) string {
	t.Helper()
	cert, key := writeTestCertificate(t)
	return fmt.Sprintf(`{"network":%q,"security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]}}`, network, cert, key)
}

func bandwidthChildTestConfig(t *testing.T) *xray.Config {
	t.Helper()
	config := bandwidthTestDefaultConfig(t)
	// The default metrics listener has a fixed port outside the test fixture.
	config.Metrics = nil
	// Keep the routed management tunnel. Fixtures use only loopback addresses,
	// so the production geodata rules would require unrelated data files.
	config.RouterConfig = json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}`)
	config.OutboundConfigs = json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"ip":["127.0.0.1/32"],"action":"allow"}]}}]`)
	return config
}
