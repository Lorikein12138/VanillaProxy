package xray

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/core"
)

func init() {
	if len(os.Args) < 2 || os.Args[1] != launch.Command {
		return
	}
	switch os.Getenv("XUI_TEST_BANDWIDTH_CHILD") {
	case "exit":
		os.Exit(0)
	case "stall":
		_, _ = io.Copy(io.Discard, os.Stdin)
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestBandwidthProcessCommand(t *testing.T) {
	const token = "private-test-token"
	const clientID = "original-client"
	wantHandshake := launch.Handshake{
		IPC:       bandwidthipc.Info{Address: "127.0.0.1:12345", Token: token},
		Clients:   map[string]map[string]string{"inbound": {"client@example.test": clientID}},
		Generated: map[string]bool{"inbound": true},
	}
	bindings := map[string]map[string]string{"inbound": {"client@example.test": clientID}}
	cfg := &Config{InboundConfigs: []InboundConfig{{Tag: "inbound", PanelGenerated: true, BandwidthAutomatic: true}}}
	p, err := NewProcessWithBandwidth(cfg, launch.Handshake{IPC: wantHandshake.IPC, Clients: bindings, Generated: map[string]bool{"forged": true}})
	if err != nil {
		t.Fatalf("create metered Xray process: %v", err)
	}
	if version := p.GetXrayVersion(); version != core.Version() {
		t.Fatalf("embedded Xray version = %q, want %q", version, core.Version())
	}

	// Mutating the original bindings cannot alter the launch snapshot.
	bindings["inbound"]["client@example.test"] = "changed-client"
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	configPath := GetConfigPath()
	if err := p.PersistConfig(); err != nil {
		t.Fatalf("persist test config: %v", err)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read test config: %v", err)
	}
	if strings.Contains(string(configData), token) || strings.Contains(string(configData), clientID) {
		t.Fatal("private handshake parameters are present in the generated config")
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	var previousNonce []byte
	for range 2 {
		listener, ready, err := newBandwidthReadiness()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		if !ready.Valid() || bytes.Equal(previousNonce, ready.Nonce) {
			t.Fatal("each launch must receive a fresh loopback readiness challenge")
		}
		previousNonce = ready.Nonce
		if bytes.Contains(configData, []byte(base64.StdEncoding.EncodeToString(ready.Nonce))) {
			t.Fatal("readiness nonce is present in the generated config")
		}
		cmd, err := p.command(configPath, ready, configData)
		if err != nil {
			t.Fatalf("construct metered Xray command: %v", err)
		}
		if want := []string{executable, launch.Command, configPath}; cmd.Path != executable || !slices.Equal(cmd.Args, want) {
			t.Fatal("metered Xray command must launch the panel with only the child command and config path")
		}
		if cmd.Env != nil {
			t.Fatal("metered Xray command must inherit an unmodified environment")
		}
		payload, err := io.ReadAll(cmd.Stdin)
		if err != nil {
			t.Fatalf("read child stdin: %v", err)
		}
		var got launch.Handshake
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatal("child stdin is not a single JSON handshake")
		}
		want := wantHandshake
		want.Ready = ready
		digest := sha256.Sum256(configData)
		want.ConfigSHA256 = digest[:]
		if !reflect.DeepEqual(got, want) {
			t.Fatal("child stdin does not match the original handshake")
		}
	}
	var snapshot launch.Handshake
	if err := json.Unmarshal(p.bandwidthHandshake, &snapshot); err != nil || !reflect.DeepEqual(snapshot, wantHandshake) {
		t.Fatal("the constructor snapshot changed across startup attempts")
	}
}

func TestBandwidthProcessRejectsOversizedHandshake(t *testing.T) {
	handshake := launch.Handshake{IPC: bandwidthipc.Info{Token: strings.Repeat("x", launch.MaxHandshakeSize)}}
	if p, err := NewProcessWithBandwidth(&Config{}, handshake); p != nil || err == nil {
		t.Fatal("accepted a handshake above the child size limit")
	}
}

func TestStockProcessCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	configPath := filepath.Join(dir, "config.json")
	p := NewProcess(&Config{})
	cmd, err := p.command(configPath, nil, nil)
	if err != nil {
		t.Fatalf("construct stock Xray command: %v", err)
	}
	if want := []string{GetBinaryPath(), "-c", configPath}; cmd.Path != GetBinaryPath() || !slices.Equal(cmd.Args, want) {
		t.Fatal("stock launch must invoke the external Xray binary with -c and the generated config path")
	}
	if cmd.Stdin != nil || cmd.Env != nil {
		t.Fatal("stock Xray command must preserve implicit stdin and environment")
	}
}

func TestBandwidthProcessRequiresReady(t *testing.T) {
	for _, tc := range []struct {
		mode, want string
		timeout    time.Duration
	}{
		{mode: "exit", want: "exited before reporting readiness", timeout: 3 * time.Second},
		{mode: "stall", want: "timed out waiting for metered Xray readiness", timeout: 250 * time.Millisecond},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XUI_BIN_FOLDER", dir)
			t.Setenv("XUI_LOG_FOLDER", dir)
			t.Setenv("XUI_TEST_BANDWIDTH_CHILD", tc.mode)
			t.Setenv("GORACE", "atexit_sleep_ms=0")
			previousTimeout := xrayBandwidthReadyTimeout
			xrayBandwidthReadyTimeout = tc.timeout
			t.Cleanup(func() { xrayBandwidthReadyTimeout = previousTimeout })
			handshake := launch.Handshake{
				IPC:     bandwidthipc.Info{Address: "127.0.0.1:12345", Token: "test-token"},
				Clients: map[string]map[string]string{"inbound": {"client@example.test": "test-client"}},
			}
			p, err := NewProcessWithBandwidth(&Config{}, handshake)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if p.IsRunning() {
					_ = p.Stop()
				}
			})
			if err := p.Start(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("start = %v, want %q", err, tc.want)
			}
			if p.IsRunning() || p.GetErr() == nil {
				t.Fatal("an unready managed process was not stopped or its startup error was lost")
			}
		})
	}
}

func TestBandwidthReadyRejectsInvalidFrames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		frame    func([]byte) []byte
		holdOpen bool
	}{
		{name: "wrong nonce", frame: func(nonce []byte) []byte {
			wrong := bytes.Clone(nonce)
			wrong[0] ^= 0xff
			return wrong
		}},
		{name: "trailing data", frame: func(nonce []byte) []byte { return append(bytes.Clone(nonce), 1) }},
		{name: "missing EOF", frame: bytes.Clone, holdOpen: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, ready, err := newBandwidthReadiness()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			conn, err := net.DialTimeout("tcp4", ready.Address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write(tc.frame(ready.Nonce)); err != nil {
				t.Fatal(err)
			}
			if !tc.holdOpen {
				_ = conn.Close()
			}
			if err := waitBandwidthReady(listener, ready.Nonce, nil, 40*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("readiness = %v, want timeout", err)
			}
			if conn, err := net.DialTimeout("tcp4", ready.Address, 100*time.Millisecond); err == nil {
				_ = conn.Close()
				t.Fatal("readiness listener survived a timeout")
			}
		})
	}
}
