package bandwidthruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

type testPolicyReader func(context.Context, int) (ClientBandwidthPolicy, error)

func (read testPolicyReader) ReadClientBandwidth(ctx context.Context, recordID int) (ClientBandwidthPolicy, error) {
	return read(ctx, recordID)
}

func TestPanelBandwidthPolicyControlsSharedLeaseAuthority(t *testing.T) {
	const staticTotal = 100 * mbps
	const dynamicTotal = 60 * mbps
	const storedID = 17
	const firstNodeKey = "guid:physical-a"
	cfg := &PanelConfig{
		panelClients:      map[string]int{sharedClient: storedID},
		panelCanonicalIDs: map[int]string{storedID: sharedClient},
		panelPeers:        map[string]string{firstNodeKey: nodeA},
		limits: map[string]panelPeerLimits{
			nodeA: {generation: testGeneration, panelNodeKey: firstNodeKey, clients: map[string]bandwidthlease.Limits{
				sharedClient: {TotalBitsPerSecond: staticTotal, NodeBitsPerSecond: 10 * mbps},
			}},
			nodeB: {generation: testGeneration, clients: map[string]bandwidthlease.Limits{
				sharedClient: {TotalBitsPerSecond: staticTotal},
				otherClient:  {TotalBitsPerSecond: 20 * mbps},
			}},
		},
	}
	panel := &PanelRuntime{policyConfig: cfg}
	if !panel.ClientBandwidthAvailable(storedID, "testing", map[string]struct{}{firstNodeKey: {}}) ||
		panel.ClientBandwidthAvailable(storedID, "testing", map[string]struct{}{firstNodeKey: {}, "guid:unmapped": {}}) {
		t.Fatal("available must require every physical node to be bound")
	}
	policy := ClientBandwidthPolicy{TotalBitsPerSecond: dynamicTotal, NodeBitsPerSecond: map[string]int64{firstNodeKey: 0}}
	readErr := errors.New("policy unreadable")
	reader := testPolicyReader(func(_ context.Context, id int) (ClientBandwidthPolicy, error) {
		if id != storedID {
			t.Fatalf("policy reader got client ID %d, want %d", id, storedID)
		}
		return policy, readErr
	})
	resolve := func(ctx context.Context, nodeID, generation, clientID string) (bandwidthlease.Limits, bool) {
		return cfg.resolveLimits(ctx, nodeID, generation, clientID, reader)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if limits, ok := resolve(ctx, nodeB, testGeneration, otherClient); !ok || limits.TotalBitsPerSecond != 20*mbps {
		t.Fatalf("unbound client must retain static limits: %v, %t", limits, ok)
	}
	nodes, poller := startTestBandwidthPeers(t, map[string]int64{sharedClient: staticTotal}, resolve)
	first := nodes[0].startPermit(t, ctx, sharedClient)
	for range 2 {
		pollTestBandwidthPeer(t, ctx, poller, nodeA, nodes, map[string]int64{sharedClient: 0})
	}
	if got := len(poller.peers[nodeA].grants); got != 0 {
		t.Fatalf("an unreadable policy produced %d grants", got)
	}
	readErr = nil
	caps := map[string]int64{sharedClient: dynamicTotal}
	pollTestBandwidthPeer(t, ctx, poller, nodeA, nodes, caps)
	pollTestBandwidthPeer(t, ctx, poller, nodeA, nodes, caps)
	if got := nodes[0].currentRate(sharedClient); got != dynamicTotal {
		t.Fatalf("node A grant = %d, want %d with explicit zero node override", got, dynamicTotal)
	}
	second := nodes[1].startPermit(t, ctx, sharedClient)
	for range 4 {
		for _, peer := range nodes {
			pollTestBandwidthPeer(t, ctx, poller, peer.id, nodes, caps)
		}
	}
	for _, peer := range nodes {
		if got := peer.currentRate(sharedClient); got != dynamicTotal/2 {
			t.Fatalf("node %s grant = %d, want %d from shared cap", peer.id, got, dynamicTotal/2)
		}
	}
	waitTestPermit(t, ctx, first)
	waitTestPermit(t, ctx, second)
}

func TestPanelBandwidthPolicyBindings(t *testing.T) {
	peer := testPanelPeer("node-a", "https://example.test/exchange", 8000)
	withKey := func(peer, key string) string {
		return strings.Replace(peer, `"clients":`, `"panelNodeKey":"`+key+`","clients":`, 1)
	}
	valid := `"panelClients":{"canonical-a":17}`
	for _, tc := range []struct {
		name     string
		binding  string
		nodes    []string
		local    bool
		accepted bool
	}{
		{"remote key", valid, []string{withKey(peer, "guid:physical")}, false, true},
		{"scoped synthetic descendant", valid, []string{withKey(peer, "via:7:3")}, false, true},
		{"invalid descendant id", valid, []string{withKey(peer, "via:7:003")}, false, false},
		{"local matches role", valid, []string{withKey(peer, "local")}, true, true},
		{"local requires role", valid, []string{withKey(peer, "local")}, false, false},
		{"local requires matching generation", valid, []string{withKey(strings.Replace(peer, "generation-a", "generation-b", 1), "local")}, true, false},
		{"invalid node id", valid, []string{withKey(peer, "node:001")}, false, false},
		{"duplicate key", valid, []string{withKey(peer, "node:7"), withKey(testPanelPeer("node-b", "https://example.test/exchange", 8000), "node:7")}, false, false},
		{"unknown canonical", `"panelClients":{"canonical-b":17}`, []string{peer}, false, false},
		{"zero client id", `"panelClients":{"canonical-a":0}`, []string{peer}, false, false},
		{"duplicate client id", `"panelClients":{"canonical-a":17,"canonical-b":17}`, []string{peer, strings.Replace(testPanelPeer("node-b", "https://example.test/exchange", 8000), "canonical-a", "canonical-b", 1)}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := `"authority":{` + tc.binding + `,"nodes":[` + strings.Join(tc.nodes, ",") + `]}`
			if tc.local {
				spec += `,"node":` + testPanelNode
			}
			path, _ := writePanelTestConfig(t, `{`+spec+`}`, testPanelToken)
			cfg, err := LoadPanelConfig(path)
			if (err == nil && cfg != nil) != tc.accepted {
				t.Fatalf("LoadPanelConfig = %v, %v, want accepted %t", cfg, err, tc.accepted)
			}
		})
	}
}

func TestAutomaticBandwidthPolicyPhysicalGUIDBinding(t *testing.T) {
	const physicalKey = "guid:physical-a"
	peer := strings.Replace(
		testPanelPeer("node-a", "https://example.test/exchange", 8000),
		`"clients":`,
		`"panelNodeKey":"`+physicalKey+`","automaticPolicy":true,"clients":`,
		1,
	)
	path, _ := writePanelTestConfig(t,
		`{"authority":{"panelClients":{"canonical-a":17},"nodes":[`+peer+`]}}`,
		testPanelToken,
	)
	cfg, err := LoadPanelConfig(path)
	if err != nil {
		t.Fatalf("LoadPanelConfig rejected explicit physical GUID automatic policy: %v", err)
	}
	if got := cfg.panelPeers[physicalKey]; got != "node-a" {
		t.Fatalf("physical GUID binding points to %q, want node-a", got)
	}
	reader := testPolicyReader(func(_ context.Context, recordID int) (ClientBandwidthPolicy, error) {
		if recordID != 17 {
			t.Fatalf("policy reader got record ID %d, want 17", recordID)
		}
		return ClientBandwidthPolicy{
			TotalBitsPerSecond: 6000,
			NodeBitsPerSecond:  map[string]int64{physicalKey: 1500},
		}, nil
	})
	limits, ok := cfg.resolveLimits(t.Context(), "node-a", "generation-a", "canonical-a", reader)
	if !ok || limits.TotalBitsPerSecond != 6000 || limits.NodeBitsPerSecond != 1500 {
		t.Fatalf("automatic policy limits = %v, %t; want total 6000 and physical GUID cap 1500", limits, ok)
	}
	if _, ok := cfg.resolveLimits(t.Context(), "node-a", "other-generation", "canonical-a", reader); ok {
		t.Fatal("automatic policy accepted a different peer generation")
	}
}

func TestAutomaticBandwidthPolicyRejectsInvalidOrSyntheticBindings(t *testing.T) {
	peer := func(id, key string) string {
		return strings.Replace(
			testPanelPeer(id, "https://example.test/exchange", 8000),
			`"clients":`,
			`"panelNodeKey":"`+key+`","automaticPolicy":true,"clients":`,
			1,
		)
	}
	for _, tc := range []struct {
		name  string
		peers []string
	}{
		{name: "invalid GUID", peers: []string{peer("node-a", "guid:")}},
		{name: "duplicate GUID", peers: []string{peer("node-a", "guid:physical-a"), peer("node-b", "guid:physical-a")}},
		{name: "synthetic descendant", peers: []string{peer("node-a", "via:7:3")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := `{"authority":{"panelClients":{"canonical-a":17},"nodes":[` + strings.Join(tc.peers, ",") + `]}}`
			path, _ := writePanelTestConfig(t, spec, testPanelToken)
			if cfg, err := LoadPanelConfig(path); err == nil || cfg != nil {
				t.Fatalf("accepted invalid automatic policy binding: %v, %v", cfg, err)
			}
		})
	}
}
