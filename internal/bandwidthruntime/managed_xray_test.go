package bandwidthruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestMain(m *testing.M) {
	// Exercise the production supervisor's self-exec and stdin path through
	// the same child entry point, with no panel services or database started.
	if len(os.Args) > 1 && os.Args[1] == xraybandwidthchild.Command {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := xraybandwidthchild.Run(ctx, os.Args[2:], os.Stdin)
		stop()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestManagedXrayProcessUsesNodeGrant(t *testing.T) {
	const nodeID, generation, id = "test-node", "test-generation", "test-client"
	const tag, email, credential = "managed-vless", "client@example.test", "6e45abb0-c265-4add-97d9-2e6b9588a2a0"
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	t.Setenv("XRAY_LOCATION_ASSET", dir)

	node, err := StartNode(NodeConfig{
		NodeID: nodeID, Generation: generation, ClientRates: map[string]int64{id: 100_000}, Authorize: authorizeTestRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if process, err := node.NewManagedXrayProcess(&xray.Config{}, map[string]map[string]string{tag: {email: "unknown"}}); err == nil || process != nil {
		t.Fatal("accepted an unconfigured canonical client ID")
	}
	server := httptest.NewTLSServer(node.Handler())
	t.Cleanup(server.Close)
	var offset time.Duration
	authority := bandwidthlease.NewAuthority(func() time.Time { return time.Now().Add(offset) })
	offset = bandwidthlease.Retention
	poller, err := NewPoller(authority, []RootTarget{{
		Client: server.Client(), Target: bandwidthexchange.Target{
			URL: server.URL, NodeID: nodeID, Generation: generation, Authorization: "Bearer test-root",
			ClientIDs: map[string]struct{}{id: {}},
		},
	}}, func(_ context.Context, node, gen, client string) (bandwidthlease.Limits, bool) {
		return bandwidthlease.Limits{TotalBitsPerSecond: 80_000}, node == nodeID && gen == generation && client == id
	})
	if err != nil {
		t.Fatal(err)
	}

	backend := listenLoopback(t)
	reservation := listenLoopback(t)
	addr := reservation.Addr().(*net.TCPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	configJSON := fmt.Sprintf(`{
		"log":{"loglevel":"none"},
		"inbounds":[{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"vless",
			"settings":{"decryption":"none","clients":[{"id":%q,"email":%q}]}}],
		"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"ip":["127.0.0.1/32"],"action":"allow"}]}}]
	}`, tag, addr.Port, credential, email)
	var config xray.Config
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatal(err)
	}
	process, err := node.NewManagedXrayProcess(&config, map[string]map[string]string{tag: {email: id}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.IsRunning() {
			_ = process.Stop()
		}
	})
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var conn net.Conn
	dialer := net.Dialer{Timeout: 50 * time.Millisecond}
	for {
		if conn, err = dialer.DialContext(ctx, "tcp4", addr.String()); err == nil {
			break
		}
		if !process.IsRunning() {
			t.Fatalf("managed child exited: %v (%s)", process.GetErr(), process.GetResult())
		}
		select {
		case <-ctx.Done():
			t.Fatal("managed child did not listen in time")
		case <-ticker.C:
		}
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	account, err := (&vless.Account{Id: credential}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Command: protocol.RequestCommandTCP, User: &protocol.MemoryUser{Account: account},
		Address: xnet.LocalHostIP, Port: xnet.Port(backend.Addr().(*net.TCPAddr).Port),
	}
	if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	upstream, err := backend.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	const payload = "metered payload"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	for len(poller.peers[nodeID].grants) == 0 {
		if err := poller.Poll(ctx, nodeID); err != nil {
			t.Fatalf("poll for managed demand: %v", err)
		}
		if len(poller.peers[nodeID].grants) == 0 {
			select {
			case <-ctx.Done():
				t.Fatal("managed child never requested a grant")
			case <-ticker.C:
			}
		}
	}
	if err := upstream.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	var netErr net.Error
	if n, err := upstream.Read(buf); n != 0 || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("backend read before grant: %d bytes, %v", n, err)
	}

	if err := poller.Poll(ctx, nodeID); err != nil {
		t.Fatalf("deliver root grant: %v", err)
	}
	if err := upstream.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(upstream, buf); err != nil || string(buf) != payload {
		t.Fatalf("backend read after grant = %q, %v", buf, err)
	}
	if err := process.Stop(); err != nil || process.IsRunning() {
		t.Fatalf("managed child did not stop: %v", err)
	}
	if conn, err := dialer.DialContext(ctx, "tcp4", addr.String()); err == nil {
		_ = conn.Close()
		t.Fatal("managed child listener survived Stop")
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := node.NewManagedXrayProcess(&config, map[string]map[string]string{tag: {email: id}}); !errors.Is(err, errNodeClosed) {
		t.Fatalf("closed node accepted a managed process: %v", err)
	}
}

func listenLoopback(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
