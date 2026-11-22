package bandwidthruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testPanelToken = "0123456789abcdef0123456789ABCDEFfedcba9876543210FEDCBA9876543210"
	testPanelNode  = `{"id":"node-a","generation":"generation-a","authorityID":"authority-a","tokenFile":"secrets/token","accounts":{"Local.User":{"id":"canonical-a","requestedBitsPerSecond":5000}}}`
)

func testPanelPeer(id, url string, total int64) string {
	return fmt.Sprintf(`{"id":%q,"generation":"generation-a","url":%q,"tokenFile":"secrets/token","clients":{"canonical-a":{"totalBitsPerSecond":%d,"nodeBitsPerSecond":2500}}}`, id, url, total)
}

func testPanelAuthority(peers ...string) string {
	return `"authority":{"nodes":[` + strings.Join(peers, ",") + `]}`
}

func writePanelTestConfig(t *testing.T, spec, content string) (path, tokenPath string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "bandwidth.json")
	tokenPath = filepath.Join(dir, "secrets", "token")
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	protectTestPanelToken(t, tokenPath)
	return path, tokenPath
}

func TestPanelConfigDisabled(t *testing.T) {
	cfg, err := LoadPanelConfig("")
	if err != nil || cfg != nil {
		t.Fatalf("disabled configuration = %v, %v", cfg, err)
	}
	panel, err := StartPanelRuntime(cfg)
	if err != nil || panel != nil || panel.Node() != nil || panel.ExchangeHandler() != nil {
		t.Fatalf("disabled runtime = %v, %v", panel, err)
	}
	if _, ok := panel.AccountID("Local.User"); ok || panel.Close() != nil {
		t.Fatal("disabled runtime unexpectedly has an account or failed closing")
	}
}

func TestPanelConfigStrictValidation(t *testing.T) {
	node := `"node":` + testPanelNode
	peer := testPanelPeer("node-a", "https://example.test/exchange", 8000)
	for _, tt := range []struct {
		name string
		body string
	}{
		{"no role", `{}`},
		{"unknown member", `{` + node + `,"` + testPanelToken + `":true}`},
		{"case mismatched member", `{"Node":` + testPanelNode + `}`},
		{"duplicate role", `{` + node + `,` + node + `}`},
		{"duplicate field", `{` + strings.Replace(node, `"generation":`, `"id":"node-b","generation":`, 1) + `}`},
		{"duplicate email", `{` + strings.Replace(node, `"Local.User":`, `"Local.User":{},"Local\u002eUser":`, 1) + `}`},
		{"trailing value", `{` + node + `}{}`},
		{"invalid email", `{` + strings.Replace(node, `Local.User`, `Local User`, 1) + `}`},
		{"invalid identity", `{` + strings.Replace(node, `canonical-a`, `canonical-a `, 1) + `}`},
		{"nonpositive request", `{` + strings.Replace(node, `:5000`, `:0`, 1) + `}`},
		{"overflowing request", `{` + strings.Replace(node, `:5000`, `:9223372036854775808`, 1) + `}`},
		{"inconsistent aliases", `{` + strings.Replace(node, `"Local.User":`, `"Alias":{"id":"canonical-a","requestedBitsPerSecond":2000},"Local.User":`, 1) + `}`},
		{"absolute token path", `{` + strings.Replace(node, `secrets/token`, `/absolute/`+testPanelToken, 1) + `}`},
		{"parent token path", `{` + strings.Replace(node, `secrets/token`, `../`+testPanelToken, 1) + `}`},
		{"missing token file", `{` + strings.Replace(node, `secrets/token`, `secrets/`+testPanelToken, 1) + `}`},
		{"empty authority", `{` + testPanelAuthority() + `}`},
		{"duplicate node", `{` + testPanelAuthority(peer, peer) + `}`},
		{"inconsistent total", `{` + testPanelAuthority(peer, testPanelPeer("node-b", "https://example.test/exchange", 9000)) + `}`},
		{"unsecured endpoint", `{` + testPanelAuthority(testPanelPeer("node-a", "http://example.test/exchange", 8000)) + `}`},
		{"query endpoint", `{` + testPanelAuthority(testPanelPeer("node-a", "https://example.test/exchange?token="+testPanelToken, 8000)) + `}`},
		{"userinfo endpoint", `{` + testPanelAuthority(testPanelPeer("node-a", "https://"+testPanelToken+"@example.test/exchange", 8000)) + `}`},
		{"invalid local limit", `{` + testPanelAuthority(strings.Replace(peer, `:2500`, `:-2500`, 1)) + `}`},
		{"invalid total limit", `{` + testPanelAuthority(testPanelPeer("node-a", "https://example.test/exchange", 0)) + `}`},
		{"valid node with invalid authority", `{` + node + `,` + testPanelAuthority(peer, peer) + `}`},
		{"oversized configuration", `{` + node + `}` + strings.Repeat(" ", maxPanelConfigBytes)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, _ := writePanelTestConfig(t, tt.body, testPanelToken)
			cfg, err := LoadPanelConfig(path)
			if err == nil || cfg != nil {
				t.Fatalf("accepted invalid configuration: %v, %v", cfg, err)
			}
			if strings.Contains(err.Error(), testPanelToken) || strings.Contains(err.Error(), path) {
				t.Fatal("invalid configuration error disclosed sensitive input")
			}
		})
	}
}

func TestPanelTokenFileValidation(t *testing.T) {
	spec := `{"node":` + testPanelNode + `}`
	for _, token := range []string{"", testPanelToken[:63], "z" + testPanelToken[1:], " " + testPanelToken[1:], testPanelToken + "\n\n", testPanelToken + "\r\n\r\n"} {
		path, _ := writePanelTestConfig(t, spec, token)
		if cfg, err := LoadPanelConfig(path); err == nil || cfg != nil || strings.Contains(err.Error(), testPanelToken) {
			t.Fatal("accepted invalid token or disclosed it")
		}
	}
	if runtime.GOOS != "windows" {
		path, tokenPath := writePanelTestConfig(t, spec, testPanelToken)
		if err := os.Chmod(tokenPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if cfg, err := LoadPanelConfig(path); err == nil || cfg != nil {
			t.Fatal("accepted a publicly readable token file")
		}
	}
}

func panelTestExchange(t *testing.T, handler http.Handler, scheme string, headers []string, status int) {
	t.Helper()
	const requestBody = `{"node_id":"node-a","generation":"generation-a","grants":[]}`
	req := httptest.NewRequest(http.MethodPost, scheme+"://example.test/exchange", strings.NewReader(requestBody))
	for _, header := range headers {
		req.Header.Add("Authorization", header)
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != status || strings.Contains(resp.Body.String(), testPanelToken) {
		t.Fatalf("unexpected exchange result, status %d, want %d", resp.Code, status)
	}
}

func TestPanelRuntimeNode(t *testing.T) {
	spec := `{"node":` + testPanelNode + `}`
	path, _ := writePanelTestConfig(t, spec, testPanelToken+"\r\n")
	cfg, err := LoadPanelConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	panel, err := StartPanelRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = panel.Close() })
	if panel.Node() == nil || panel.ExchangeHandler() == nil || panel.done != nil {
		t.Fatal("node role did not start independently")
	}
	if id, ok := panel.AccountID("Local.User"); !ok || id != "canonical-a" {
		t.Fatalf("account = %q, %t", id, ok)
	}
	for _, email := range []string{"local.user", " Local.User", "Local.User ", "canonical-a"} {
		if _, ok := panel.AccountID(email); ok {
			t.Fatalf("unexpected account match for %q", email)
		}
	}
	valid := bearerPrefix + testPanelToken
	for _, invalid := range [][]string{nil, {bearerPrefix + "a" + testPanelToken[1:]}, {"Basic " + testPanelToken}, {valid, valid}} {
		panelTestExchange(t, panel.ExchangeHandler(), "https", invalid, http.StatusForbidden)
	}
	panelTestExchange(t, panel.ExchangeHandler(), "http", []string{valid}, http.StatusForbidden)
	panelTestExchange(t, panel.ExchangeHandler(), "https", []string{valid}, http.StatusOK)
}

func TestPanelRuntimeAuthorityAndBoth(t *testing.T) {
	for _, withNode := range []bool{false, true} {
		t.Run(fmt.Sprintf("node=%t", withNode), func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			peer := testPanelPeer("node-a", "https://"+listener.Addr().String()+"/exchange", 8000)
			spec := "{" + testPanelAuthority(peer)
			if withNode {
				spec += `,"node":` + testPanelNode
			}
			path, _ := writePanelTestConfig(t, spec+"}", testPanelToken+"\n")
			cfg, err := LoadPanelConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", cfg, *cfg), testPanelToken) {
				t.Fatal("formatting configuration disclosed bearer credential")
			}
			if cfg.targets[0].Authorization != bearerPrefix+testPanelToken {
				t.Fatal("authority did not configure its credential")
			}
			limits, ok := cfg.resolveLimits(context.Background(), "node-a", "generation-a", "canonical-a", nil)
			if !ok || limits.TotalBitsPerSecond != 8000 || limits.NodeBitsPerSecond != 2500 {
				t.Fatalf("authority limits = %v, %t", limits, ok)
			}
			if _, ok := cfg.resolveLimits(context.Background(), "node-a", "wrong", "canonical-a", nil); ok {
				t.Fatal("authority accepted a different generation")
			}
			panel, err := StartPanelRuntime(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer panel.Close()
			if (panel.Node() != nil) != withNode || (panel.ExchangeHandler() != nil) != withNode || panel.done == nil {
				t.Fatal("unexpected runtime roles")
			}
			if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var closes sync.WaitGroup
			for range 8 {
				closes.Go(func() {
					if err := panel.Close(); err != nil {
						t.Errorf("closing panel runtime: %v", err)
					}
				})
			}
			closes.Wait()
			select {
			case <-panel.done:
			default:
				t.Fatal("authority poller remained running after Close")
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			beforeTLS, err := io.ReadAll(conn)
			if err != nil || strings.Contains(string(beforeTLS), testPanelToken) {
				t.Fatal("unfinished TLS connection stayed open or received the bearer credential")
			}
			if withNode {
				panelTestExchange(t, panel.ExchangeHandler(), "https", []string{bearerPrefix + testPanelToken}, http.StatusServiceUnavailable)
			}
		})
	}
}
