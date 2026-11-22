package bandwidthruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

func TestAutomaticNodePolicyActivationAndRestart(t *testing.T) {
	spec := `{"node":` + strings.Replace(testPanelNode, `"id":`, `"automaticPolicyFile":"policy.json","allowUnmeteredXrayAccounts":true,"id":`, 1) + `}`
	path, _ := writePanelTestConfig(t, spec, testPanelToken)
	start := func() *PanelRuntime {
		t.Helper()
		cfg, err := LoadPanelConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		panel, err := StartPanelRuntime(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = panel.Close() })
		return panel
	}
	panel := start()
	lookup := panel.AutomaticAccountLookup()
	if lookup == nil {
		t.Fatal("automatic Xray accounts must use an empty allowlist before the first snapshot")
	}
	for _, email := range []string{"Local.User", "Unknown.User"} {
		if id, ok := lookup("vless", email, "old-vless-id"); id != "" || ok {
			t.Fatalf("account %q allowed before the first snapshot: id=%q allowed=%t", email, id, ok)
		}
	}
	changes, activations := 0, 0
	startErr := errors.New("child refused configuration")
	handler := panel.PolicyHandler(func(_ context.Context, install func() (bool, error)) (XrayPolicyLiveAccounts, error) {
		activations++
		changed, err := install()
		if changed {
			changes++
		}
		return nil, errors.Join(err, startErr)
	})
	vlessPin := bandwidthexchange.CredentialFingerprint("vless", "old-vless-id")
	hysteriaPin := bandwidthexchange.CredentialFingerprint("hysteria", "old-hysteria-auth")
	httpCredential := bandwidthexchange.CredentialParts("Exact.User", "password:one")
	httpPin := bandwidthexchange.PolicyBinding{Protocol: "http", Fingerprint: bandwidthexchange.CredentialFingerprint("http", httpCredential)}
	snapshot := bandwidthexchange.PolicySnapshot{
		NodeID: "node-a", Generation: "generation-a", Accounts: []bandwidthexchange.PolicyAccount{
			{Email: "Exempt.User", VLESSFingerprint: vlessPin},
			{Email: "Exact.User", ClientID: "auto-user", RequestedBitsPerSecond: 4000, VLESSFingerprint: vlessPin, HysteriaFingerprint: hysteriaPin, Bindings: []bandwidthexchange.PolicyBinding{httpPin}},
		},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	send := func(body, scheme string, bearer []string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, scheme+"://node.test"+bandwidthexchange.PolicyPath, strings.NewReader(body))
		for _, value := range bearer {
			r.Header.Add("Authorization", value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		if response.Code != want {
			t.Fatalf("status = %d, want %d (%s)", response.Code, want, response.Body.String())
		}
		return response
	}
	authorized := []string{"Bearer " + testPanelToken}
	send(string(data), "http", authorized, http.StatusForbidden)
	send(string(data), "https", []string{"Bearer invalid"}, http.StatusForbidden)
	send(string(data), "https", append(authorized, authorized...), http.StatusForbidden)
	send(strings.Replace(string(data), `"generation-a"`, `"other-generation"`, 1), "https", authorized, http.StatusConflict)
	send(strings.Replace(string(data), `"node-a"`, `"other-node"`, 1), "https", authorized, http.StatusConflict)
	send(strings.Replace(string(data), `,"client_id":""`, "", 1), "https", authorized, http.StatusBadRequest)
	send(strings.Replace(string(data), `,"vless_fingerprint":"`+vlessPin+`"`, "", 1), "https", authorized, http.StatusBadRequest)
	if activations != 0 {
		t.Fatal("unauthorized, wrong-generation or incomplete requests activated the policy")
	}
	send(string(data), "https", authorized, http.StatusServiceUnavailable)
	if err := panel.Close(); err != nil {
		t.Fatal(err)
	}
	panel = start()
	lookup = panel.XrayAutomaticAccounts()
	if lookup == nil {
		t.Fatal("persisted snapshot absent after a failed activation and restart")
	}
	if id, ok := lookup("vless", "Exact.User", "old-vless-id"); !ok || id != "auto-user" {
		t.Fatalf("managed account after restart = %q, %t", id, ok)
	}
	if id, ok := lookup("vless", "Exempt.User", "old-vless-id"); !ok || id != "" {
		t.Fatalf("explicit unrestricted account after restart = %q, %t", id, ok)
	}
	if _, ok := lookup("vless", "exact.user", "old-vless-id"); ok {
		t.Fatal("exact policy email matched a differently cased email")
	}
	if _, ok := lookup("vless", "Local.User", "old-vless-id"); ok {
		t.Fatal("absent account fell back to the old generated Xray policy")
	}
	if id, ok := panel.AccountID("Local.User"); !ok || id != "canonical-a" {
		t.Fatal("non-Xray legacy resolver lost its account")
	}
	if _, ok := lookup("vless", "Exempt.User", "replacement-vless-id"); ok {
		t.Fatal("a replacement credential inherited the old unrestricted authorization")
	}
	if _, ok := lookup("hysteria", "Exempt.User", "old-vless-id"); ok {
		t.Fatal("a VLESS fingerprint authorized Hysteria")
	}
	if id, ok := lookup("http", "Exact.User", httpCredential); !ok || id != "auto-user" {
		t.Fatalf("managed HTTP account after restart = %q, %t", id, ok)
	}
	if _, ok := lookup("mixed", "Exact.User", httpCredential); ok {
		t.Fatal("an HTTP fingerprint authorized mixed")
	}
	live := make(XrayPolicyLiveAccounts)
	live.Add("Exact.User", bandwidthexchange.PolicyBinding{Protocol: "vless", Fingerprint: vlessPin})
	live.Add("Exempt.User", bandwidthexchange.PolicyBinding{Protocol: "vless", Fingerprint: vlessPin})
	live.Add("Outside.User", bandwidthexchange.PolicyBinding{Protocol: "hysteria", Fingerprint: hysteriaPin})
	live.Add("Exact.User", bandwidthexchange.PolicyBinding{Protocol: "hysteria", Fingerprint: hysteriaPin})
	live.Add("Exact.User", bandwidthexchange.PolicyBinding{Protocol: "http", Fingerprint: bandwidthexchange.CredentialFingerprint("http", "different-auth")})
	handler = panel.PolicyHandler(func(_ context.Context, install func() (bool, error)) (XrayPolicyLiveAccounts, error) {
		changed, err := install()
		if changed {
			changes++
		}
		return live, err
	})
	response := send(string(data), "https", authorized, http.StatusOK)
	ack, err := bandwidthexchange.ReadPolicyAck(response.Body)
	if err != nil || ack.Digest != snapshot.Digest() || changes != 1 || !slices.Equal(ack.ReadyEmails, []string{"Exempt.User"}) {
		t.Fatalf("unchanged policy retry = %v, %v, installed changes %d", ack, err, changes)
	}
	live.Add("Exact.User", httpPin)
	response = send(string(data), "https", authorized, http.StatusOK)
	ack, err = bandwidthexchange.ReadPolicyAck(response.Body)
	if err != nil || changes != 1 || !slices.Equal(ack.ReadyEmails, []string{"Exact.User", "Exempt.User"}) {
		t.Fatalf("unchanged policy did not refresh sorted live readiness: %v, %v, installed changes %d", ack, err, changes)
	}
	leaseNode := panel.Node()
	challenge, err := leaseNode.leases.Issue("auto-user")
	if err != nil {
		t.Fatal(err)
	}
	if err := leaseNode.leases.Apply(bandwidthlease.Grant{Challenge: challenge, BitsPerSecond: 1000}); err != nil {
		t.Fatal(err)
	}
	leaseNode.demand["auto-user"] = time.Now().Add(time.Minute)
	send(`{"node_id":"node-a","generation":"generation-a","accounts":[]}`, "https", authorized, http.StatusOK)
	if _, active := leaseNode.leases.Current("auto-user"); active {
		t.Fatal("withdrawn policy account kept an active lease")
	}
	if err := leaseNode.Acquire(t.Context(), "auto-user", 1); !errors.Is(err, bandwidthlease.ErrNoActiveLease) {
		t.Fatalf("removed account acquire = %v", err)
	}
	if err := leaseNode.withSnapshot(t.Context(), "authority-a", func(s bandwidthexchange.Snapshot) error {
		if len(s.Clients) != 0 {
			t.Fatalf("stale demand remained after withdrawal: %v", s.Clients)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
