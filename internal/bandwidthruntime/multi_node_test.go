package bandwidthruntime

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

const (
	sharedClient   = "shared-client"
	otherClient    = "other-client"
	nodeA          = "node-a"
	nodeB          = "node-b"
	testGeneration = "test-generation"
	mbps           = 1_000_000
)

type testBandwidthPeer struct {
	id   string
	node *Node
	ipc  *bandwidthipc.Client
}

func startTestBandwidthPeers(t *testing.T, rates map[string]int64, limits LimitsResolver) ([]testBandwidthPeer, *Poller) {
	t.Helper()
	clientIDs := make(map[string]struct{}, len(rates))
	for id := range rates {
		clientIDs[id] = struct{}{}
	}
	var nodes []testBandwidthPeer
	var targets []RootTarget
	for _, nodeID := range []string{nodeA, nodeB} {
		node, err := StartNode(NodeConfig{
			NodeID: nodeID, Generation: testGeneration, Authorize: authorizeTestRoot,
			ClientRates: rates,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = node.Close() })
		ipc, err := bandwidthipc.Dial(node.IPCInfo())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ipc.Close() })
		server := httptest.NewTLSServer(node.Handler())
		t.Cleanup(server.Close)
		nodes = append(nodes, testBandwidthPeer{id: nodeID, node: node, ipc: ipc})
		targets = append(targets, RootTarget{
			Client: server.Client(),
			Target: bandwidthexchange.Target{
				URL: server.URL, NodeID: nodeID, Generation: testGeneration, Authorization: "Bearer test-root",
				ClientIDs: clientIDs,
			},
		})
	}
	var offset time.Duration
	authority := bandwidthlease.NewAuthority(func() time.Time { return time.Now().Add(offset) })
	offset = bandwidthlease.Retention
	poller, err := NewPoller(authority, targets, limits)
	if err != nil {
		t.Fatal(err)
	}
	return nodes, poller
}

func (peer testBandwidthPeer) startPermit(t *testing.T, ctx context.Context, clientID string) <-chan error {
	t.Helper()
	completed := make(chan error, 1)
	go func() { completed <- peer.ipc.Acquire(ctx, clientID, 1) }()
	ticks := time.NewTicker(time.Millisecond)
	defer ticks.Stop()
	for {
		peer.node.mu.Lock()
		ready := !peer.node.demand[clientID].IsZero()
		peer.node.mu.Unlock()
		if ready {
			return completed
		}
		select {
		case err := <-completed:
			t.Fatalf("IPC permit finished before registering demand on %s for %s: %v", peer.id, clientID, err)
		case <-ctx.Done():
			t.Fatalf("IPC request did not register demand on %s for %s", peer.id, clientID)
		case <-ticks.C:
		}
	}
}

func waitTestPermit(t *testing.T, ctx context.Context, completed <-chan error) {
	t.Helper()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("IPC permit failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("IPC permit did not complete in time")
	}
}

func (peer testBandwidthPeer) currentRate(clientID string) int64 {
	grant, _ := peer.node.leases.Current(clientID)
	return grant.BitsPerSecond
}

func pollTestBandwidthPeer(t *testing.T, ctx context.Context, poller *Poller, nodeID string, peers []testBandwidthPeer, caps map[string]int64) {
	t.Helper()
	if err := poller.Poll(ctx, nodeID); err != nil {
		t.Fatalf("node %s poll: %v", nodeID, err)
	}
	for clientID, cap := range caps {
		var total int64
		for _, peer := range peers {
			total += peer.currentRate(clientID)
		}
		if total > cap {
			t.Fatalf("after polling %s, client %s has %d bps across nodes, cap %d", nodeID, clientID, total, cap)
		}
	}
}

func TestTwoNodesShareClientCapOverTLS(t *testing.T) {
	caps := map[string]int64{sharedClient: 100 * mbps, otherClient: 75 * mbps}
	nodes, poller := startTestBandwidthPeers(t, caps, func(_ context.Context, nodeID, gen, clientID string) (bandwidthlease.Limits, bool) {
		if gen != testGeneration {
			return bandwidthlease.Limits{}, false
		}
		var limits bandwidthlease.Limits
		switch clientID {
		case sharedClient:
			limits.TotalBitsPerSecond = 100 * mbps
			if nodeID == nodeA {
				limits.NodeBitsPerSecond = 60 * mbps
			}
		case otherClient:
			limits.TotalBitsPerSecond = 75 * mbps
			if nodeID == nodeA {
				limits.NodeBitsPerSecond = 20 * mbps
			}
		default:
			return bandwidthlease.Limits{}, false
		}
		return limits, true
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var completed []<-chan error
	for _, peer := range nodes {
		for clientID := range caps {
			completed = append(completed, peer.startPermit(t, ctx, clientID))
		}
	}
	for range 4 {
		for _, peer := range nodes {
			pollTestBandwidthPeer(t, ctx, poller, peer.id, nodes, caps)
		}
	}
	want := []map[string]int64{
		{sharedClient: 50 * mbps, otherClient: 20 * mbps},
		{sharedClient: 50 * mbps, otherClient: 55 * mbps},
	}
	for i, peer := range nodes {
		for clientID, rate := range want[i] {
			if got := peer.currentRate(clientID); got != rate {
				t.Errorf("node %s, client %s grant = %d bps, want %d bps", peer.id, clientID, got, rate)
			}
		}
	}
	for _, permit := range completed {
		waitTestPermit(t, ctx, permit)
	}
}

func TestTwoUncappedNodesRebalanceOverTLS(t *testing.T) {
	const total = 100 * mbps
	caps := map[string]int64{sharedClient: total}
	nodes, poller := startTestBandwidthPeers(t, caps, func(_ context.Context, _, gen, clientID string) (bandwidthlease.Limits, bool) {
		return bandwidthlease.Limits{TotalBitsPerSecond: total}, gen == testGeneration && clientID == sharedClient
	})
	a, b := nodes[0], nodes[1]
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	poll := func(peer testBandwidthPeer) { pollTestBandwidthPeer(t, ctx, poller, peer.id, nodes, caps) }
	assertRates := func(wantA, wantB int64) {
		t.Helper()
		if aRate, bRate := a.currentRate(sharedClient), b.currentRate(sharedClient); aRate != wantA || bRate != wantB {
			t.Fatalf("node A/B rates = %d/%d bps, want %d/%d bps", aRate, bRate, wantA, wantB)
		}
	}
	aPermit := a.startPermit(t, ctx, sharedClient)
	poll(a)
	poll(a)
	assertRates(total, 0)
	waitTestPermit(t, ctx, aPermit)

	bPermit := b.startPermit(t, ctx, sharedClient)
	poll(b)
	assertRates(total, 0)
	for range 4 {
		poll(a)
		poll(b)
	}
	assertRates(total/2, total/2)
	waitTestPermit(t, ctx, bPermit)

	// Advance B's demand deadline while leaving its live lease unchanged.
	b.node.mu.Lock()
	b.node.demand[sharedClient] = time.Now().Add(-time.Second)
	b.node.mu.Unlock()
	poll(b)
	poll(a)
	assertRates(total/2, total/2)

	// The TLS node applies the zero grant, but the authority loses its receipt.
	peer := poller.peers[nodeB]
	client := peer.config.Client
	peer.config.Client = &http.Client{Transport: discardExchangeResponse{client.Transport}}
	if err := poller.Poll(ctx, nodeB); !errors.Is(err, errDiscardedExchangeResponse) {
		t.Fatalf("poll with discarded response = %v", err)
	}
	peer.config.Client = client
	assertRates(total/2, 0)
	poll(a)
	assertRates(total/2, 0)

	// Retrying the same grant can recover the receipt after demand disappears.
	for range 3 {
		poll(b)
		poll(a)
	}
	assertRates(total, 0)
}

var errDiscardedExchangeResponse = errors.New("test discarded exchange response")

type discardExchangeResponse struct{ http.RoundTripper }

func (transport discardExchangeResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := transport.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	return nil, errDiscardedExchangeResponse
}

func TestFairShareSplitsRemainderAfterCappedDemand(t *testing.T) {
	contenders := []nodeDemand{{"node-d", 20}, {"node-c", 7}, {nodeB, 90}, {nodeA, 90}}
	for id, want := range map[string]int64{nodeA: 32, nodeB: 31, "node-c": 7, "node-d": 20} {
		if got := fairShare(id, 90, contenders); got != want {
			t.Errorf("share of %s = %d, want %d", id, got, want)
		}
	}
}

func TestPollerReplacesCompleteDemandAndDropsStalePeers(t *testing.T) {
	poller := Poller{demands: map[string]demandSnapshot{
		nodeA: {deadline: time.Now().Add(-time.Second), rates: map[string]int64{sharedClient: 1}},
		nodeB: {deadline: time.Now().Add(time.Second), rates: map[string]int64{sharedClient: 2, otherClient: 2}},
	}}
	demands := []bandwidthexchange.Demand{{
		Challenge: bandwidthlease.Challenge{ClientID: sharedClient}, RequestedBitsPerSecond: 3,
	}}
	snapshots := poller.recordDemands(nodeB, demands)
	if _, present := snapshots[nodeA]; present {
		t.Fatal("stale peer still counts towards demand")
	}
	if got := snapshots[nodeB].rates; !maps.Equal(got, map[string]int64{sharedClient: 3}) {
		t.Fatalf("latest complete demand = %v, want only %s", got, sharedClient)
	}
	demands[0].RequestedBitsPerSecond = 0
	if got := poller.recordDemands(nodeB, demands); len(got) != 0 {
		t.Fatalf("zero demand still counts towards demand: %v", got)
	}
}
