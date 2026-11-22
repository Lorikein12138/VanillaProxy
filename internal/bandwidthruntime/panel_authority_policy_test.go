package bandwidthruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

const (
	firstBandwidthKey  = "node:1"
	secondBandwidthKey = "node:2"
)

type testBandwidthInventory struct {
	rows []BandwidthAccount
	err  error
}

func (reader *testBandwidthInventory) ReadBandwidthInventory(context.Context) ([]BandwidthAccount, error) {
	return reader.rows, reader.err
}

func (reader *testBandwidthInventory) ReadClientBandwidth(context.Context, int) (ClientBandwidthPolicy, error) {
	return ClientBandwidthPolicy{}, errors.New("automatic authority should use the inventory")
}

func automaticTestPanel(url string) *PanelConfig {
	return &PanelConfig{
		panelPeers: map[string]string{firstBandwidthKey: nodeA, secondBandwidthKey: nodeB},
		limits: map[string]panelPeerLimits{
			nodeA: {generation: testGeneration, panelNodeKey: firstBandwidthKey, automaticPolicy: true},
			nodeB: {generation: testGeneration, panelNodeKey: secondBandwidthKey, automaticPolicy: true},
		},
		targets: []bandwidthexchange.Target{
			{URL: url + "/a/exchange", NodeID: nodeA, Generation: testGeneration, Authorization: "Bearer private-test-token"},
			{URL: url + "/b/exchange", NodeID: nodeB, Generation: testGeneration, Authorization: "Bearer private-test-token"},
		},
	}
}

func testBandwidthAttachment(protocol, fingerprint string) BandwidthAttachment {
	return BandwidthAttachment{Bindings: []bandwidthexchange.PolicyBinding{{Protocol: protocol, Fingerprint: fingerprint}}}
}

func TestAutomaticAuthorityRequiresConfirmedSharedPolicy(t *testing.T) {
	const id = 21
	firstCredential := bandwidthexchange.CredentialFingerprint("vless", "first-test-credential")
	secondCredential := bandwidthexchange.CredentialFingerprint("vless", "second-test-credential")
	hysteriaCredential := bandwidthexchange.CredentialFingerprint("hysteria", "hysteria-test-credential")
	var expectedVLESS atomic.Value
	expectedVLESS.Store(firstCredential)
	row := BandwidthAccount{ID: id, Email: "new@example.test",
		Attachments: map[string]BandwidthAttachment{
			firstBandwidthKey: testBandwidthAttachment("vless", firstCredential), secondBandwidthKey: testBandwidthAttachment("hysteria", hysteriaCredential),
		},
	}
	reader := &testBandwidthInventory{rows: []BandwidthAccount{row, {
		ID: 50, Email: "missing-credential@example.test",
		Attachments: map[string]BandwidthAttachment{firstBandwidthKey: {}, secondBandwidthKey: {}},
	}}}
	var responseB atomic.Int32
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer private-test-token" {
			t.Error("policy must authenticate over POST")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		snapshot, err := bandwidthexchange.ReadPolicySnapshot(r.Body)
		if err != nil {
			t.Errorf("invalid policy snapshot: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ack := bandwidthexchange.PolicyAck{Digest: snapshot.Digest()}
		for _, account := range snapshot.Accounts {
			if account.Email == "missing-credential@example.test" {
				t.Error("an incomplete account entered the policy snapshot")
			}
			ack.ReadyEmails = append(ack.ReadyEmails, account.Email)
		}
		switch r.URL.Path {
		case "/a/policy":
			if snapshot.NodeID != nodeA {
				t.Errorf("unexpected node ID at first policy endpoint: %q", snapshot.NodeID)
			}
			for _, account := range snapshot.Accounts {
				if account.VLESSFingerprint != expectedVLESS.Load().(string) || account.HysteriaFingerprint != "" {
					t.Error("unexpected protocol fingerprints at first policy endpoint")
				}
			}
		case "/b/policy":
			if snapshot.NodeID != nodeB {
				t.Errorf("unexpected node ID at second policy endpoint: %q", snapshot.NodeID)
			}
			for _, account := range snapshot.Accounts {
				if account.VLESSFingerprint != "" || account.HysteriaFingerprint != hysteriaCredential {
					t.Error("unexpected protocol fingerprints at second policy endpoint")
				}
			}
			switch responseB.Load() {
			case 1:
				ack.Digest = strings.Repeat("a", 64)
			case 2:
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case 3:
				ack.ReadyEmails = nil
			case 4:
				ack.ReadyEmails = []string{"unknown@example.test"}
			}
		default:
			t.Errorf("unexpected policy path %q", r.URL.Path)
		}
		data, _ := json.Marshal(ack)
		_, _ = w.Write(data)
	}))
	defer server.Close()
	cfg := automaticTestPanel(server.URL)
	auto, err := startAutomaticAuthority(cfg, reader, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	panel := &PanelRuntime{automaticPolicy: auto}
	ctx := t.Context()
	prepare := func(index int, wantReady bool, wantIDs int) {
		t.Helper()
		ids, ready, err := auto.prepare(ctx, cfg.targets[index])
		if ready != wantReady || (err == nil) != wantReady || len(ids) != wantIDs {
			t.Fatalf("prepare(%d) = %v, %t, %v", index, ids, ready, err)
		}
	}
	prepare(0, true, 0)
	if panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("partially confirmed unrestricted account is available")
	}
	prepare(1, true, 0)
	if !panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("confirmed unrestricted account is unavailable")
	}
	row.Attachments[firstBandwidthKey] = testBandwidthAttachment("vless", secondCredential)
	expectedVLESS.Store(secondCredential)
	reader.rows[0] = row
	if panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("an acknowledgement of the old credential is available after rotation")
	}
	prepare(0, true, 0)
	if !panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("the acknowledged replacement credential is unavailable")
	}
	reader.rows[0].Policy.TotalBitsPerSecond = 100 * mbps
	row = reader.rows[0]
	canonical, err := auto.canonicalID(row)
	if err != nil {
		t.Fatal(err)
	}
	prepare(0, true, 1)
	responseB.Store(1)
	prepare(1, false, 0)
	if _, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical); ok || panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("an unconfirmed transition enabled a new shared grant")
	}
	responseB.Store(0)
	prepare(1, true, 1)
	limits, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical)
	if !ok || limits.TotalBitsPerSecond != 100*mbps || !panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatalf("current policy should be eligible on both peers, got %v, %v", limits, ok)
	}
	responseB.Store(3)
	prepare(1, true, 1)
	if _, ok := auto.resolveLimits(ctx, nodeB, testGeneration, canonical); !ok || panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("an unready live account should report unavailable while preserving the policy acknowledgement")
	}
	responseB.Store(4)
	prepare(1, false, 1)
	responseB.Store(2)
	prepare(1, false, 1)
	if _, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical); !ok || panel.ClientBandwidthPolicyAvailable(row) {
		t.Fatal("known unchanged offline policy should permit healthy renewals while reporting unavailable")
	}
	// A failed attempt to apply a different policy is ambiguous, even if
	// the database is then rolled back to the last acknowledged policy.
	reader.rows[0].Policy.TotalBitsPerSecond = 0
	prepare(1, false, 1)
	reader.rows[0] = row
	prepare(0, true, 1)
	if _, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical); ok {
		t.Fatal("an uncertain previous transition permitted a shared grant")
	}
	responseB.Store(0)
	prepare(1, true, 1)
	reader.rows[0].Attachments = map[string]BandwidthAttachment{firstBandwidthKey: testBandwidthAttachment("vless", secondCredential)}
	prepare(0, true, 1)
	if _, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical); ok {
		t.Fatal("a detached peer with stale membership permitted a shared grant")
	}
	prepare(1, true, 0)
	if _, ok := auto.resolveLimits(ctx, nodeA, testGeneration, canonical); !ok {
		t.Fatal("removing the detached membership did not resume shared grants")
	}
	// Delete the client and recreate its email on the other node. An
	// unconfirmed old same-email membership must still block new grants.
	reader.rows[0].ID++
	reader.rows[0].Attachments = map[string]BandwidthAttachment{secondBandwidthKey: testBandwidthAttachment("hysteria", hysteriaCredential)}
	replacementID, err := auto.canonicalID(reader.rows[0])
	if err != nil || replacementID == canonical {
		t.Fatalf("recreated account identity = %q, %v", replacementID, err)
	}
	prepare(1, true, 1)
	if _, ok := auto.resolveLimits(ctx, nodeB, testGeneration, replacementID); ok {
		t.Fatal("a stale same-email membership permitted a recreated account grant")
	}
	prepare(0, true, 0)
	if _, ok := auto.resolveLimits(ctx, nodeB, testGeneration, replacementID); !ok {
		t.Fatal("removing the stale same-email membership did not resume grants")
	}
	before := requests.Load()
	reader.err = errors.New("database temporarily unavailable")
	prepare(1, false, 1)
	if requests.Load() != before {
		t.Fatal("a failed inventory read published a policy")
	}
}

func TestAutomaticAuthorityLegacyFallbackAndNodeOnlyPolicy(t *testing.T) {
	cfg := automaticTestPanel("https://example.test")
	peer := cfg.limits[nodeA]
	peer.clients = map[string]bandwidthlease.Limits{sharedClient: {TotalBitsPerSecond: 100 * mbps, NodeBitsPerSecond: 10 * mbps}}
	cfg.limits[nodeA] = peer
	cfg.panelCanonicalIDs = map[int]string{21: sharedClient}
	auto, err := startAutomaticAuthority(cfg, &testBandwidthInventory{}, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	attachment := testBandwidthAttachment("vless", bandwidthexchange.CredentialFingerprint("vless", "legacy-test-credential"))
	legacy := BandwidthAccount{ID: 21, Email: "old@example.test",
		Attachments: map[string]BandwidthAttachment{firstBandwidthKey: attachment, secondBandwidthKey: attachment},
		Policy:      ClientBandwidthPolicy{NodeBitsPerSecond: map[string]int64{firstBandwidthKey: 0}},
	}
	plan, err := auto.enrollment(legacy)
	if err != nil || plan.peers[nodeA].account.ClientID != sharedClient || plan.peers[nodeA].limits.NodeBitsPerSecond != 0 ||
		plan.peers[nodeB].limits.TotalBitsPerSecond != 100*mbps {
		t.Fatalf("legacy fallback lost the canonical ID, total or explicit node override: %+v, %v", plan, err)
	}
	current := legacy
	current.ID, current.Email = 22, "new@example.test"
	current.Policy.NodeBitsPerSecond = map[string]int64{secondBandwidthKey: MaxPanelBitsPerSecond}
	plan, err = auto.enrollment(current)
	if err != nil || plan.peers[nodeA].account.ClientID != "" || plan.peers[nodeB].account.ClientID == "" ||
		plan.peers[nodeB].limits.TotalBitsPerSecond != math.MaxInt64 || plan.peers[nodeB].account.RequestedBitsPerSecond != MaxPanelBitsPerSecond {
		t.Fatalf("node-only rate should leave peer without an override unrestricted: %+v, %v", plan, err)
	}
	current.Policy = ClientBandwidthPolicy{TotalBitsPerSecond: 100 * mbps}
	attachment.Unsupported = true
	current.Attachments[secondBandwidthKey] = attachment
	plan, err = auto.enrollment(current)
	if err != nil || plan.available || len(plan.peers) != 0 {
		t.Fatalf("unsupported attachment silently split a positive shared total: %+v, %v", plan, err)
	}
	current.Attachments[secondBandwidthKey] = BandwidthAttachment{}
	plan, err = auto.enrollment(current)
	if err != nil || plan.available || len(plan.peers) != 0 {
		t.Fatalf("missing protocol credential silently split a positive shared total: %+v, %v", plan, err)
	}
	current.Policy = ClientBandwidthPolicy{}
	plan, err = auto.enrollment(current)
	if _, attached := plan.peers[nodeB]; err != nil || plan.available || len(plan.peers) != 1 || attached {
		t.Fatalf("missing protocol credential did not isolate the affected peer: %+v, %v", plan, err)
	}
}

func TestAutomaticAuthorityRequiresEveryPeerToConfirmExactGenericBindings(t *testing.T) {
	const id = 25
	firstKey := bandwidthexchange.PolicyBinding{Protocol: "wireguard", Fingerprint: bandwidthexchange.CredentialFingerprint("wireguard", "first")}
	secondKey := bandwidthexchange.PolicyBinding{Protocol: "wireguard", Fingerprint: bandwidthexchange.CredentialFingerprint("wireguard", "second")}
	tuicKey := bandwidthexchange.PolicyBinding{Protocol: "tuic", Fingerprint: bandwidthexchange.CredentialFingerprint("tuic", "test")}
	cfg := automaticTestPanel("https://example.test")
	auto, err := startAutomaticAuthority(cfg, &testBandwidthInventory{}, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	row := BandwidthAccount{ID: id, Email: "multi@example.test", Policy: ClientBandwidthPolicy{TotalBitsPerSecond: 500},
		Attachments: map[string]BandwidthAttachment{
			firstBandwidthKey:  {Bindings: []bandwidthexchange.PolicyBinding{tuicKey}},
			secondBandwidthKey: {Bindings: []bandwidthexchange.PolicyBinding{secondKey, firstKey, secondKey}},
		}}
	plan, err := auto.enrollment(row)
	if err != nil || !plan.available || len(plan.peers[nodeB].account.Bindings) != 2 {
		t.Fatalf("generic enrollment: %+v, %v", plan, err)
	}
	for _, node := range []string{nodeA, nodeB} {
		account := plan.peers[node]
		auto.ack[node] = acknowledgedBandwidthPolicy{
			accounts: map[int]enrolledAccount{id: account}, clientIDs: map[string]struct{}{account.account.ClientID: {}},
		}
	}
	if !auto.confirmed(id, plan, false) {
		t.Fatal("every desired binding was acknowledged")
	}
	row.Attachments[secondBandwidthKey] = BandwidthAttachment{Bindings: []bandwidthexchange.PolicyBinding{firstKey, secondKey}}
	plan, err = auto.enrollment(row)
	if err != nil || !auto.confirmed(id, plan, false) {
		t.Fatal("reordered bindings unexpectedly required another acknowledgement")
	}
	row.Attachments[secondBandwidthKey] = BandwidthAttachment{Bindings: []bandwidthexchange.PolicyBinding{secondKey}}
	plan, err = auto.enrollment(row)
	if err != nil || auto.confirmed(id, plan, false) {
		t.Fatal("a removed credential was still considered confirmed across peers")
	}
}

func TestPolicyAccountUsesLegacyFieldOnlyForOneFingerprintPerProtocol(t *testing.T) {
	vless := bandwidthexchange.PolicyBinding{Protocol: "vless", Fingerprint: bandwidthexchange.CredentialFingerprint("vless", "first")}
	otherVLESS := bandwidthexchange.PolicyBinding{Protocol: "vless", Fingerprint: bandwidthexchange.CredentialFingerprint("vless", "second")}
	hysteria := bandwidthexchange.PolicyBinding{Protocol: "hysteria", Fingerprint: bandwidthexchange.CredentialFingerprint("hysteria", "first")}
	attachment := BandwidthAttachment{Bindings: []bandwidthexchange.PolicyBinding{vless, hysteria, vless}}
	account := attachment.policyAccount("test@example.test")
	if account.VLESSFingerprint != vless.Fingerprint || account.HysteriaFingerprint != hysteria.Fingerprint || len(account.Bindings) != 0 {
		t.Fatalf("expected legacy wire fields for one binding per protocol: %+v", account)
	}
	attachment.Bindings = append(attachment.Bindings, otherVLESS)
	account = attachment.policyAccount("test@example.test")
	if account.VLESSFingerprint != "" || account.HysteriaFingerprint != hysteria.Fingerprint || len(account.Bindings) != 2 {
		t.Fatalf("expected two VLESS wire bindings plus the legacy Hysteria field: %+v", account)
	}
}

func TestAutomaticAuthorityDoesNotFollowRedirectOrSendToUntrustedPeer(t *testing.T) {
	var redirectRequests atomic.Int32
	var initialRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirectRequests.Add(1)
			return
		}
		initialRequests.Add(1)
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	cfg := automaticTestPanel(server.URL)
	records := &testBandwidthInventory{}
	for _, client := range []*http.Client{server.Client(), {}} {
		auto, err := startAutomaticAuthority(cfg, records, client)
		if err != nil {
			t.Fatal(err)
		}
		if ids, ready, err := auto.prepare(t.Context(), cfg.targets[0]); err == nil || ready || ids != nil {
			t.Fatalf("unverified policy was acknowledged: %v, %v, %v", ids, ready, err)
		}
	}
	if initialRequests.Load() != 1 || redirectRequests.Load() != 0 {
		t.Fatalf("expected one verified initial request only, got initial=%d redirected=%d", initialRequests.Load(), redirectRequests.Load())
	}
}
