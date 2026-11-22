package bandwidthruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

func authorizeTestRoot(r *http.Request) (string, bool) {
	return "root", r.Header.Get("Authorization") == "Bearer test-root"
}

func TestManagedTrafficStopsAfterControllerIsUnreachable(t *testing.T) {
	t.Parallel()
	rates := map[string]int64{"managed": 40_000}
	node, err := StartNode(NodeConfig{
		NodeID: "node-1", Generation: "gen-1", ClientRates: rates, Authorize: authorizeTestRoot,
		DemandIdle: 12 * time.Second, ActivationWait: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	rates["unknown"] = 40_000

	child, err := bandwidthipc.Dial(node.IPCInfo())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })
	server := httptest.NewTLSServer(node.Handler())
	t.Cleanup(server.Close)

	var clockOffset time.Duration
	authority := bandwidthlease.NewAuthority(func() time.Time { return time.Now().Add(clockOffset) })
	clockOffset = bandwidthlease.Retention
	const capRate = 20_000
	limits := func(_ context.Context, nodeID, generation, clientID string) (bandwidthlease.Limits, bool) {
		return bandwidthlease.Limits{TotalBitsPerSecond: capRate}, nodeID == "node-1" && generation == "gen-1" && clientID == "managed"
	}
	poller, err := NewPoller(authority, []RootTarget{{
		Client: server.Client(),
		Target: bandwidthexchange.Target{
			URL: server.URL, NodeID: "node-1", Generation: "gen-1", Authorization: "Bearer test-root",
			ClientIDs: map[string]struct{}{"managed": {}},
		},
	}}, limits)
	if err != nil {
		t.Fatal(err)
	}

	if err := child.Acquire(t.Context(), "unknown", 1); err == nil {
		t.Fatal("unknown client received a permit")
	}
	if err := poller.Poll(t.Context(), "node-1"); err != nil || len(poller.peers["node-1"].grants) != 0 {
		t.Fatalf("poll with nobody eligible prepared a grant: %v", err)
	}

	runContext, stop := context.WithCancel(t.Context())
	defer stop()
	completed := make(chan error, 1)
	failed := make(chan error, 1)
	go func() {
		completed <- poller.Run(runContext, 100*time.Millisecond, func(_ string, err error) {
			select {
			case failed <- err:
			default:
			}
		})
	}()
	if err := child.Acquire(t.Context(), "managed", 1); err != nil {
		t.Fatalf("managed request could not obtain a grant after two HTTPS polls: %v", err)
	}
	if grant, ok := node.leases.Current("managed"); !ok || grant.BitsPerSecond != capRate {
		t.Fatalf("lease = %+v, %v; want root cap %d", grant, ok, capRate)
	}

	server.Close()
	select {
	case <-failed:
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not detect the unreachable node")
	}
	stop()
	select {
	case err := <-completed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("controller cancellation = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop")
	}
	if err := child.Acquire(t.Context(), "managed", 1); err != nil {
		t.Fatalf("unreachable controller prematurely revoked delivered lease: %v", err)
	}

	// Exercise the real node timer while leaving the local child connection up.
	wait, cancel := context.WithTimeout(t.Context(), bandwidthlease.Lifetime+3*time.Second)
	defer cancel()
	ticks := time.NewTicker(500 * time.Millisecond)
	defer ticks.Stop()
	for {
		select {
		case <-wait.Done():
			t.Fatal("local IPC still had a live lease beyond its challenge deadline")
		case <-ticks.C:
			if _, active := node.leases.Current("managed"); active {
				continue
			}
			if err := child.Acquire(wait, "managed", 1); err == nil {
				t.Fatal("IPC permitted traffic after lease expiry")
			}
			return
		}
	}
}

func TestCloseDisablesAlreadyMountedEndpoint(t *testing.T) {
	node, err := StartNode(NodeConfig{
		NodeID: "node-1", Generation: "gen-1", ClientRates: map[string]int64{"managed": 10_000},
		Authorize: authorizeTestRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	server := httptest.NewTLSServer(node.Handler())
	t.Cleanup(server.Close)
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	target := bandwidthexchange.Target{
		URL: server.URL, NodeID: "node-1", Generation: "gen-1", Authorization: "Bearer test-root",
	}
	if _, err := bandwidthexchange.Exchange(t.Context(), server.Client(), target, nil); err == nil {
		t.Fatal("closed runtime still exchanged leases")
	}
}
