package mtproto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

func testBandwidthOptions() *BandwidthOptions {
	return &BandwidthOptions{
		IPC: bandwidthipc.Info{
			Address: "127.0.0.1:32123",
			Token:   base64.RawURLEncoding.EncodeToString([]byte("test capability for mtg sidecar!")),
		},
		ClientIDs: map[string]string{"alice": "canonical-client"},
	}
}

func testFakeTLSSecret(key byte) string {
	return fmt.Sprintf("ee%032x%x", key, "example.org")
}

func TestBandwidthLaunchCommand(t *testing.T) {
	bobSecret, _ := hex.DecodeString(testFakeTLSSecret(2))
	inst := mtgInst(1,
		SecretEntry{Name: "alice", Secret: testFakeTLSSecret(1)},
		SecretEntry{Name: "bob", Secret: base64.RawURLEncoding.EncodeToString(bobSecret)},
	)
	proc := newProcess("path with space.toml", "test")
	cmd, err := proc.startCommand(launch.Ready{})
	if err != nil || cmd.Stdin != nil || !slices.Equal(cmd.Args[1:], []string{"run", proc.configPath}) {
		t.Fatal("stock invocation must keep its original arguments and default stdin")
	}

	inst.Bandwidth = testBandwidthOptions()
	inst.Bandwidth.ClientIDs["bob"] = "canonical-client"
	wantIPC, wantIDs := inst.Bandwidth.IPC, maps.Clone(inst.Bandwidth.ClientIDs)
	payload, err := inst.bandwidthHandshake()
	if err != nil {
		t.Fatal(err)
	}
	inst.Bandwidth.IPC.Token = ""
	inst.Bandwidth.ClientIDs["alice"] = "different"
	proc.bandwidthHandshake = payload
	listener, ready, err := newBandwidthReadiness()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd, err = proc.startCommand(ready)
	if err != nil || !slices.Equal(cmd.Args[1:], []string{"run", "--vanilla-bandwidth", proc.configPath}) {
		t.Fatal("metered launch argv must contain only the opt-in flag and config path")
	}
	decoder := json.NewDecoder(cmd.Stdin)
	var handshake bandwidthBootstrap
	if err := decoder.Decode(&handshake); err != nil || handshake.IPC != wantIPC || !maps.Equal(handshake.ClientIDs, wantIDs) ||
		handshake.Ready.Address != ready.Address || !slices.Equal(handshake.Ready.Nonce, ready.Nonce) {
		t.Fatal("stdin must carry the original capability and client bindings and a readiness challenge")
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatal("stdin must end after one JSON document")
	}
	if config := renderConfig(inst, 1234, "api-token"); strings.Contains(config, wantIPC.Address) ||
		strings.Contains(config, wantIPC.Token) || strings.Contains(config, wantIDs["alice"]) {
		t.Fatal("IPC credentials and bindings must stay out of persistent TOML")
	}
}

func TestBandwidthHandshakeRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Instance)
	}{
		{"missing name", func(inst *Instance) { delete(inst.Bandwidth.ClientIDs, "alice") }},
		{"extra name", func(inst *Instance) { inst.Bandwidth.ClientIDs["bob"] = "canonical-client" }},
		{"unknown name", func(inst *Instance) { inst.Bandwidth.ClientIDs = map[string]string{"bob": "canonical-client"} }},
		{"duplicate name", func(inst *Instance) {
			inst.Secrets = append(inst.Secrets, inst.Secrets[0])
			inst.Bandwidth.ClientIDs["bob"] = "canonical-client"
		}},
		{"empty ID", func(inst *Instance) { inst.Bandwidth.ClientIDs["alice"] = "" }},
		{"malformed ID", func(inst *Instance) { inst.Bandwidth.ClientIDs["alice"] = "alice\x00bob" }},
		{"long ID", func(inst *Instance) { inst.Bandwidth.ClientIDs["alice"] = strings.Repeat("a", 257) }},
		{"remote endpoint", func(inst *Instance) { inst.Bandwidth.IPC.Address = "192.0.2.1:12345" }},
		{"invalid token", func(inst *Instance) { inst.Bandwidth.IPC.Token = "private-invalid-token" }},
		{"malformed secret", func(inst *Instance) { inst.Secrets[0].Secret = "ee01" }},
		{"same signing key with different hostname and encoding", func(inst *Instance) {
			secret, _ := hex.DecodeString(inst.Secrets[0].Secret)
			secret = append(secret[:1+fakeTLSKeyBytes], "other.example"...)
			inst.Secrets = append(inst.Secrets, SecretEntry{Name: "bob", Secret: base64.RawURLEncoding.EncodeToString(secret)})
			inst.Bandwidth.ClientIDs["bob"] = "another-client"
		}},
		{"oversized handshake", func(inst *Instance) {
			name := strings.Repeat("a", maxBandwidthHandshakeSize)
			inst.Secrets[0].Name = name
			inst.Bandwidth.ClientIDs = map[string]string{name: "canonical-client"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := mtgInst(1, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(1)})
			inst.Bandwidth = testBandwidthOptions()
			tc.mutate(&inst)
			if payload, err := inst.bandwidthHandshake(); err == nil || payload != nil {
				t.Fatal("invalid bandwidth configuration was accepted")
			} else if strings.Contains(err.Error(), inst.Bandwidth.IPC.Token) {
				t.Fatal("validation error leaked an IPC token")
			}
		})
	}
}

func TestEnsureBandwidthChangesRestart(t *testing.T) {
	pidFile := installFakeMtg(t)
	mgr := &Manager{procs: map[int]*managed{}, swept: true}
	t.Cleanup(mgr.StopAll)
	inst := mtgInst(1, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(1)})

	ensure := func(wantProcCount int) {
		t.Helper()
		if err := mgr.Ensure(inst); err != nil {
			t.Fatal(err)
		}
		waitSpawnCount(t, pidFile, wantProcCount)
	}
	ensure(1)
	inst.Bandwidth = testBandwidthOptions()
	ensure(2)
	cur := mgr.procs[inst.Id]
	if strings.Contains(cur.structuralFP, inst.Bandwidth.IPC.Token) {
		t.Fatal("structural fingerprint retained the raw capability")
	}

	reloaded := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/secrets" {
			select {
			case reloaded <- struct{}{}:
			default:
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	cur.apiPort = serverPort(t, srv)
	inst.Secrets[0].Secret = testFakeTLSSecret(3)
	ensure(3)
	select {
	case <-reloaded:
		t.Fatal("a metered rekey must not call the hot reload endpoint")
	default:
	}
	if mgr.procs[inst.Id] == cur || cur.proc.IsRunning() {
		t.Fatal("the previous child must stop even when the rekey preserves the same client binding")
	}

	inst.Secrets[0].QuotaBytes = 100
	ensure(4)
	inst.Secrets = append(inst.Secrets, SecretEntry{Name: "bob", Secret: testFakeTLSSecret(2)})
	inst.Bandwidth.ClientIDs["bob"] = "canonical-client"
	ensure(5)
	slices.Reverse(inst.Secrets)
	ensure(5)
	inst.Bandwidth.ClientIDs["bob"] = "second-client"
	ensure(6)
	inst.Bandwidth.IPC.Address = "127.0.0.1:32124"
	ensure(7)
	inst.Bandwidth.IPC.Token = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	ensure(8)
	inst.Secrets = inst.Secrets[1:]
	delete(inst.Bandwidth.ClientIDs, "bob")
	ensure(9)

	delete(inst.Bandwidth.ClientIDs, "alice")
	if err := mgr.Ensure(inst); err == nil || mgr.HasRunning() {
		t.Fatal("invalid desired bindings must stop the previous process")
	}
	if _, err := os.Stat(configPathForID(inst.Id)); !os.IsNotExist(err) {
		t.Fatalf("the stopped child's generated config should be removed, stat error: %v", err)
	}
}

func TestEnsureBandwidthDoesNotRetryStockInvocation(t *testing.T) {
	pidFile := installFakeMtg(t)
	t.Setenv("MTG_FAKE_STOCK", "1")
	mgr := &Manager{procs: map[int]*managed{}, swept: true}
	t.Cleanup(mgr.StopAll)
	inst := mtgInst(1, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(1)})
	inst.Bandwidth = testBandwidthOptions()
	if err := mgr.Ensure(inst); err == nil || !strings.Contains(err.Error(), "exited before reporting readiness") {
		t.Fatalf("stock binary must fail managed startup, got %v", err)
	}
	waitSpawnCount(t, pidFile, 1)
	if mgr.HasRunning() || mgr.procs[inst.Id] != nil {
		t.Fatal("a stock binary must exit without an unmetered launch")
	}
}

func TestManagedStartupRequiresReadinessProof(t *testing.T) {
	oldTimeout := bandwidthReadyTimeout
	bandwidthReadyTimeout = 500 * time.Millisecond
	t.Cleanup(func() { bandwidthReadyTimeout = oldTimeout })
	for _, mode := range []string{"silent", "wrong"} {
		t.Run(mode, func(t *testing.T) {
			pidFile := installFakeMtg(t)
			t.Setenv("MTG_FAKE_READY", mode)
			mgr := &Manager{swept: true}
			t.Cleanup(mgr.StopAll)
			inst := mtgInst(9, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(9)})
			inst.Bandwidth = testBandwidthOptions()
			if err := mgr.Ensure(inst); err == nil || !strings.Contains(err.Error(), "timed out waiting for child readiness") {
				t.Fatalf("startup must require the readiness proof, got %v", err)
			}
			waitSpawnCount(t, pidFile, 1)
			if mgr.HasRunning() || mgr.procs[inst.Id] != nil {
				t.Fatal("unready child must be stopped and unpublished")
			}
			if _, err := os.Stat(configPathForID(inst.Id)); !os.IsNotExist(err) {
				t.Fatalf("unready child's config should be removed, stat error: %v", err)
			}
		})
	}
}

func TestStopDuringManagedStartup(t *testing.T) {
	pidFile := installFakeMtg(t)
	t.Setenv("MTG_FAKE_READY", "silent")
	inst := mtgInst(10, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(10)})
	inst.Bandwidth = testBandwidthOptions()
	proc := newProcess("unused.toml", "test")
	var err error
	proc.bandwidthHandshake, err = inst.bandwidthHandshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Stop() })
	startResult := make(chan error, 1)
	go func() {
		startResult <- proc.Start()
	}()
	waitSpawnCount(t, pidFile, 1)
	if err := proc.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-startResult:
		if err == nil || !strings.Contains(err.Error(), "exited before reporting readiness") {
			t.Fatalf("stopping must interrupt startup, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not observe the child exit")
	}
}

func TestReadinessRejectsExtraBytesAndMissingEOF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trailer []byte
		eof     bool
	}{
		{name: "trailing byte", trailer: []byte{1}, eof: true},
		{name: "open connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, ready, err := newBandwidthReadiness()
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialTimeout("tcp4", ready.Address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write(append(ready.Nonce, tc.trailer...)); err != nil {
				t.Fatal(err)
			}
			if tc.eof {
				_ = conn.Close()
			}
			if err := waitBandwidthReady(listener, ready, make(chan struct{}), 100*time.Millisecond); err == nil {
				t.Fatal("only a complete nonce immediately followed by EOF is valid")
			}
		})
	}
}

func TestNativeManagedReadiness(t *testing.T) {
	source := os.Getenv("VANILLAPROXY_MTG_TEST_BINARY")
	if source == "" {
		t.Skip("set VANILLAPROXY_MTG_TEST_BINARY to a locally patched mtg-multi binary")
	}
	binDir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", binDir)
	executable, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(GetBinaryPath(), executable, 0o755); err != nil {
		t.Fatal(err)
	}
	server, err := bandwidthipc.Listen(func(context.Context, string, int) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	publicPort, err := FreeLocalPort()
	if err != nil {
		t.Fatal(err)
	}
	apiPort, err := FreeLocalPort()
	if err != nil {
		t.Fatal(err)
	}
	inst := mtgInst(11, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(11)})
	inst.Port = publicPort
	inst.Bandwidth = testBandwidthOptions()
	inst.Bandwidth.IPC = server.Info()
	config := renderConfig(inst, apiPort, "test-api-token")
	config = strings.Replace(config, fmt.Sprintf("bind-to = %q", inst.bindTo()),
		fmt.Sprintf("bind-to = [%q, %q]", inst.bindTo(), occupied.Addr().String()), 1)
	configPath := filepath.Join(binDir, "readiness.toml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	proc := newProcess(configPath, "native readiness test")
	proc.bandwidthHandshake, err = inst.bandwidthHandshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Stop() })
	if err := proc.Start(); err == nil || !strings.Contains(proc.GetResult(), "cannot start proxy on") {
		t.Fatalf("one available listener and a live API must not admit an occupied second listener: %v, %s", err, proc.GetResult())
	}
	if proc.IsRunning() {
		t.Fatal("mtg kept running after reporting a bind failure")
	}
	wasOccupied := occupied.Addr().String()
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(); err != nil {
		t.Fatalf("patched mtg failed to become ready: %v, %s", err, proc.GetResult())
	}
	for _, address := range []string{inst.bindTo(), wasOccupied} {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err != nil {
			t.Fatalf("confirmed listener %s is unavailable: %v", address, err)
		}
		_ = conn.Close()
	}
	if err := proc.Stop(); err != nil || proc.IsRunning() {
		t.Fatalf("failed to stop ready mtg child: %v", err)
	}
}

func TestConfiguredBandwidthAppliesToEnsureAndReconcile(t *testing.T) {
	pidFile := installFakeMtg(t)
	mgr := &Manager{swept: true}
	t.Cleanup(mgr.StopAll)
	inst := mtgInst(4, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(4)})
	inst.Bandwidth = testBandwidthOptions()
	inst.Bandwidth.ClientIDs["alice"] = "manual-client"

	denied := errors.New("inbound not authorized")
	var prepareErr error
	var emptyPolicy bool
	var calls int
	prepare := func(desired Instance) (*BandwidthOptions, error) {
		calls++
		if desired.Id != inst.Id || len(desired.Secrets) != 1 || desired.Secrets[0].Name != "alice" || desired.Bandwidth != nil {
			t.Fatal("prepare must receive the active instance without a manual bandwidth override")
		}
		if emptyPolicy {
			return nil, nil
		}
		// An options result cannot override a preparation error.
		return testBandwidthOptions(), prepareErr
	}
	if err := mgr.ConfigureBandwidth(prepare); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ConfigureBandwidth(prepare); err == nil {
		t.Fatal("cannot replace the bandwidth policy after configuring it")
	}
	if err := mgr.Ensure(inst); err != nil {
		t.Fatal(err)
	}
	waitSpawnCount(t, pidFile, 1)
	cur := mgr.procs[inst.Id]
	var policy BandwidthOptions
	if err := json.Unmarshal(cur.proc.bandwidthHandshake, &policy); err != nil ||
		policy.ClientIDs["alice"] != "canonical-client" {
		t.Fatal("child must use the prepared policy rather than the caller's override")
	}
	mgr.Reconcile([]Instance{inst})
	if mgr.procs[inst.Id] != cur || calls != 2 {
		t.Fatal("reconcile must prepare policy and keep the unchanged sidecar")
	}

	assertRemoved := func() {
		t.Helper()
		if cur.proc.IsRunning() || mgr.procs[inst.Id] != nil {
			t.Fatal("rejected or empty policy left the previous process running")
		}
		if _, err := os.Stat(configPathForID(inst.Id)); !os.IsNotExist(err) {
			t.Fatalf("the stopped child's generated config should be removed, stat error: %v", err)
		}
	}
	prepareErr = denied
	if err := mgr.Ensure(inst); !errors.Is(err, denied) || calls != 3 {
		t.Fatalf("Ensure must return the preparation error, got %v", err)
	}
	assertRemoved()
	waitSpawnCount(t, pidFile, 1)

	prepareErr = nil
	mgr.Reconcile([]Instance{inst})
	waitSpawnCount(t, pidFile, 2)
	cur = mgr.procs[inst.Id]
	emptyPolicy = true
	mgr.Reconcile([]Instance{inst})
	assertRemoved()
	if calls != 5 {
		t.Fatal("reconcile must reject nil options after preparing policy")
	}
	waitSpawnCount(t, pidFile, 2)

	emptyPolicy = false
	if err := mgr.Ensure(inst); err != nil {
		t.Fatal(err)
	}
	waitSpawnCount(t, pidFile, 3)
	cur = mgr.procs[inst.Id]
	empty := inst
	empty.Secrets = nil
	if err := mgr.Ensure(empty); err != nil {
		t.Fatal(err)
	}
	assertRemoved()
	mgr.Reconcile([]Instance{empty})
	if calls != 6 {
		t.Fatal("an empty instance must be removed without preparing client bindings")
	}
	waitSpawnCount(t, pidFile, 3)
}

func TestAutomaticBandwidthExactLifecycle(t *testing.T) {
	pidFile := installFakeMtg(t)
	mgr := &Manager{swept: true}
	t.Cleanup(mgr.StopAll)
	alice := SecretEntry{Name: "alice", Secret: testFakeTLSSecret(10)}
	exempt := SecretEntry{Name: "exempt", Secret: testFakeTLSSecret(11)}
	missing := SecretEntry{Name: "missing", Secret: testFakeTLSSecret(12)}
	inst := mtgInst(7, alice, exempt, missing)
	fingerprint := func(secret SecretEntry) string {
		return bandwidthexchange.CredentialFingerprint("mtproto", BandwidthCredential(secret.Secret))
	}

	ids := map[string]string{"alice": "canonical-client", "exempt": ""}
	pins := map[string]string{"alice": fingerprint(alice), "exempt": fingerprint(exempt)}
	if err := mgr.ConfigureBandwidth(func(Instance) (*BandwidthOptions, error) {
		options := testBandwidthOptions()
		options.ClientIDs = ids
		options.PolicyBindings = pins
		return options, nil
	}); err != nil {
		t.Fatal(err)
	}
	apply := func() {
		t.Helper()
		if err := mgr.Reconcile([]Instance{inst}); err != nil {
			t.Fatal(err)
		}
	}
	checkReady := func(want map[string]string) {
		t.Helper()
		ready := mgr.ReadyBandwidthBindings()
		if len(ready) != len(want) {
			t.Fatalf("ready accounts = %v; want %v", ready, want)
		}
		for name, pin := range want {
			if !slices.Equal(ready[name], []bandwidthexchange.PolicyBinding{{Protocol: "mtproto", Fingerprint: pin}}) {
				t.Fatalf("ready binding for %q = %v; want %q", name, ready[name], pin)
			}
		}
	}
	checkReady(nil)
	apply()
	waitSpawnCount(t, pidFile, 1)
	first := mgr.procs[inst.Id]
	var startup BandwidthOptions
	if err := json.Unmarshal(first.proc.bandwidthHandshake, &startup); err != nil ||
		!maps.Equal(startup.ClientIDs, ids) || !maps.Equal(startup.PolicyBindings, pins) {
		t.Fatal("child bootstrap must include the metered and explicitly unmetered bindings")
	}
	config, err := os.ReadFile(configPathForID(inst.Id))
	if err != nil || strings.Contains(string(config), missing.Secret) || strings.Contains(string(config), pins["exempt"]) ||
		!strings.Contains(string(config), exempt.Secret) {
		t.Fatalf("automatic config included an unauthorized key or private pin, or omitted its exempt key: %v", err)
	}
	checkReady(pins)
	apply()
	if first != mgr.procs[inst.Id] {
		t.Fatal("identical policy restarted the ready sidecar")
	}

	// Replacement bypassing the normal policy lookup must still be rejected by
	// the manager's key validation. A stale exempt binding never transfers.
	inst.Secrets[1].Secret = testFakeTLSSecret(13)
	if err := mgr.Reconcile([]Instance{inst}); err == nil || !strings.Contains(err.Error(), "authentication key") {
		t.Fatalf("stale credential returned %v", err)
	}
	checkReady(nil)
	if first.proc.IsRunning() {
		t.Fatal("the previous sidecar survived a stale policy")
	}

	delete(ids, "exempt")
	delete(pins, "exempt")
	apply()
	waitSpawnCount(t, pidFile, 2)
	checkReady(pins)
	delete(ids, "alice")
	delete(pins, "alice")
	apply()
	checkReady(nil)
	if mgr.procs[inst.Id] != nil {
		t.Fatal("an empty automatic snapshot must stop the sidecar")
	}
}

func TestConfigureBandwidthMustPrecedeFirstLaunch(t *testing.T) {
	pidFile := installFakeMtg(t)
	mgr := &Manager{swept: true}
	t.Cleanup(mgr.StopAll)
	inst := mtgInst(5, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(5)})
	prepare := func(Instance) (*BandwidthOptions, error) { return testBandwidthOptions(), nil }
	if err := mgr.ConfigureBandwidth(nil); err == nil {
		t.Fatal("nil preparation must be rejected")
	}
	inst.RouteThroughXray = true
	inst.XrayRoutePort = 19081
	if err := mgr.Ensure(inst); err != nil {
		t.Fatalf("stock sidecar must retain Xray routing: %v", err)
	}
	waitSpawnCount(t, pidFile, 1)
	if err := mgr.ConfigureBandwidth(prepare); err == nil {
		t.Fatal("cannot configure bandwidth after starting stock sidecars")
	}
	mgr.Remove(inst.Id)
	if err := mgr.ConfigureBandwidth(prepare); err == nil {
		t.Fatal("removing existing sidecars must not re-open configuration")
	}
}

func TestManagedBandwidthRejectsXrayEgress(t *testing.T) {
	pidFile := installFakeMtg(t)
	for _, managerPolicy := range []bool{false, true} {
		mgr := &Manager{swept: true}
		t.Cleanup(mgr.StopAll)
		inst := mtgInst(6, SecretEntry{Name: "alice", Secret: testFakeTLSSecret(6)})
		if managerPolicy {
			if err := mgr.ConfigureBandwidth(func(Instance) (*BandwidthOptions, error) {
				t.Fatal("Xray egress must be rejected before preparing the policy")
				return nil, nil
			}); err != nil {
				t.Fatal(err)
			}
		} else {
			inst.Bandwidth = testBandwidthOptions()
		}
		inst.RouteThroughXray = true
		inst.XrayRoutePort = 19081
		if err := mgr.Ensure(inst); err == nil || !strings.Contains(err.Error(), "requires direct egress") {
			t.Fatalf("managed Xray egress must be rejected, got %v", err)
		}
		if _, err := os.Stat(configPathForID(inst.Id)); !os.IsNotExist(err) {
			t.Fatalf("rejected Xray egress must not leave a generated config, stat error: %v", err)
		}
	}
	waitSpawnCount(t, pidFile, 0)
}
