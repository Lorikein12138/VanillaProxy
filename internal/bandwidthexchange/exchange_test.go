package bandwidthexchange

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

func exchangeFixture(t *testing.T, wrappers ...func(http.Handler) http.Handler) (*bandwidthlease.Node, *httptest.Server, Target, *atomic.Pointer[Snapshot]) {
	t.Helper()
	node, err := bandwidthlease.NewNode("node-1")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &atomic.Pointer[Snapshot]{}
	snapshot.Store(&Snapshot{
		Generation: "gen-1",
		Clients:    []ClientDemand{{ClientID: "client-1", RequestedBitsPerSecond: 40_000}},
	})
	handler, err := NewHandler(node, "node-1", func(r *http.Request) (string, bool) {
		switch r.Header.Get("Authorization") {
		case "Bearer root", "Bearer rotated":
			return r.Header.Get("Authorization"), true
		default:
			return "", false
		}
	}, func(_ context.Context, _ string, use func(Snapshot) error) error {
		return use(*snapshot.Load())
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wrap := range wrappers {
		handler = wrap(handler)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return node, server, Target{
		URL: server.URL, NodeID: "node-1", Generation: "gen-1",
		ClientIDs: map[string]struct{}{"client-1": {}}, Authorization: "Bearer root",
	}, snapshot
}

func exchangeOne(t *testing.T, server *httptest.Server, target Target, grants ...bandwidthlease.Grant) Demand {
	t.Helper()
	demands, err := Exchange(t.Context(), server.Client(), target, grants)
	if err != nil || len(demands) != 1 {
		t.Fatalf("Exchange = %v, %v; want one verified demand", demands, err)
	}
	return demands[0]
}

func TestVerifiedExchangeAppliesToSharedGate(t *testing.T) {
	node, server, target, _ := exchangeFixture(t)
	if err := node.Wait(t.Context(), "client-1", 1); !errors.Is(err, bandwidthlease.ErrNoActiveLease) {
		t.Fatalf("ungranted traffic = %v", err)
	}
	demand := exchangeOne(t, server, target)
	if demand.RequestedBitsPerSecond != 40_000 || demand.Challenge.NodeID != target.NodeID ||
		demand.Challenge.ClientID != "client-1" || demand.Challenge.IncarnationID == "" {
		t.Fatalf("unexpected demand: %+v", demand)
	}
	if again := exchangeOne(t, server, target); again != demand {
		t.Fatalf("pending challenge was replaced: %+v", again)
	}
	oversized := bandwidthlease.Grant{
		Challenge: demand.Challenge, BitsPerSecond: demand.RequestedBitsPerSecond + 1,
	}
	if again := exchangeOne(t, server, target, oversized); again != demand {
		t.Fatalf("out-of-range grant replaced the valid pending challenge: %+v", again)
	}
	if _, active := node.Current("client-1"); active {
		t.Fatal("grant above the current local ceiling was applied")
	}

	now := time.Now()
	authority := bandwidthlease.NewAuthority(func() time.Time { return now })
	now = now.Add(bandwidthlease.Retention)
	grant, err := authority.Issue(demand.Challenge, demand.RequestedBitsPerSecond, bandwidthlease.Limits{
		TotalBitsPerSecond: 24_000, NodeBitsPerSecond: 20_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	next := exchangeOne(t, server, target, grant)
	if next.Challenge == grant.Challenge || next.Challenge.IncarnationID != grant.Challenge.IncarnationID {
		t.Fatalf("unexpected renewal challenge: %+v", next.Challenge)
	}
	if got, ok := node.Current("client-1"); !ok || got != grant || got.BitsPerSecond != 20_000 {
		t.Fatalf("active lease = %+v, %v", got, ok)
	}
	if err := node.Wait(t.Context(), "client-1", 1); err != nil {
		t.Fatalf("granted traffic rejected: %v", err)
	}

	replay := grant
	replay.BitsPerSecond *= 2
	if again := exchangeOne(t, server, target, replay); again != next {
		t.Fatalf("replay replaced the next pending challenge: %+v", again)
	}
	if got, ok := node.Current("client-1"); !ok || got != grant {
		t.Fatalf("replay changed active lease: %+v, %v", got, ok)
	}
}

func dropTLSResponse(drop *atomic.Bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if drop.Swap(false) {
				next.ServeHTTP(httptest.NewRecorder(), r)
				panic(http.ErrAbortHandler)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestExchangeRetriesExactReceiptAfterLostTLSResponse(t *testing.T) {
	var drop atomic.Bool
	node, server, target, _ := exchangeFixture(t, dropTLSResponse(&drop))
	first := exchangeOne(t, server, target)
	grant := bandwidthlease.Grant{Challenge: first.Challenge, BitsPerSecond: 20_000}
	drop.Store(true)
	demands, applied, err := ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{grant})
	if err == nil || demands != nil || applied != nil {
		t.Fatalf("lost reply yielded demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	if got, ok := node.Current(first.Challenge.ClientID); !ok || got != grant {
		t.Fatalf("grant did not apply before reply was lost: %+v, %v", got, ok)
	}
	demands, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{grant})
	if err != nil || len(demands) != 1 || !slices.Equal(applied, []bandwidthlease.Grant{grant}) {
		t.Fatalf("retry yielded demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	renewal := bandwidthlease.Grant{Challenge: demands[0].Challenge, BitsPerSecond: 10_000}
	if renewal.Challenge.Sequence != first.Challenge.Sequence+1 {
		t.Fatalf("retry replaced the pending renewal: %+v", renewal.Challenge)
	}
	exchangeOne(t, server, target, renewal)
	_, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{grant})
	if err != nil || len(applied) != 0 {
		t.Fatalf("superseded grant returned %v, %v", applied, err)
	}
	if got, ok := node.Current(first.Challenge.ClientID); !ok || got != renewal {
		t.Fatalf("replayed grant changed the active rate: %+v, %v", got, ok)
	}
}

func TestExchangeRetriesLostZeroReceiptWhenDemandDisappears(t *testing.T) {
	var drop atomic.Bool
	node, server, target, snapshot := exchangeFixture(t, dropTLSResponse(&drop))
	initial := exchangeOne(t, server, target)
	exchangeOne(t, server, target, bandwidthlease.Grant{Challenge: initial.Challenge, BitsPerSecond: 20_000})
	snapshot.Store(&Snapshot{Generation: target.Generation, Clients: []ClientDemand{{"client-1", 0}}})
	stop := bandwidthlease.Grant{Challenge: exchangeOne(t, server, target).Challenge}
	drop.Store(true)
	if _, _, err := ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{stop}); err == nil {
		t.Fatal("lost zero grant receipt returned successfully")
	}
	if _, ok := node.Current("client-1"); ok {
		t.Fatal("zero grant did not stop traffic before reply was lost")
	}
	snapshot.Store(&Snapshot{Generation: target.Generation})
	demands, applied, err := ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{stop})
	if err != nil || len(demands) != 0 || !slices.Equal(applied, []bandwidthlease.Grant{stop}) {
		t.Fatalf("retry without demand returned demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	target.Authorization = "Bearer rotated"
	_, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{stop})
	if err != nil || len(applied) != 0 {
		t.Fatalf("retry with rotated authority returned %v, %v", applied, err)
	}
}

func TestExchangeReissuesPendingOnZeroCrossings(t *testing.T) {
	node, server, target, snapshot := exchangeFixture(t)
	clientID := "client-1"
	setDemand := func(rate int64) {
		snapshot.Store(&Snapshot{Generation: target.Generation, Clients: []ClientDemand{{clientID, rate}}})
	}
	first := exchangeOne(t, server, target)
	older := bandwidthlease.Grant{Challenge: first.Challenge}
	setDemand(0)
	demands, applied, err := ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{older})
	if err != nil || len(demands) != 1 || demands[0].RequestedBitsPerSecond != 0 ||
		demands[0].Challenge.Sequence <= first.Challenge.Sequence || len(applied) != 0 {
		t.Fatalf("zero demand returned demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	stop := bandwidthlease.Grant{Challenge: demands[0].Challenge}
	demands, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{stop})
	if err != nil || len(demands) != 1 || !slices.Equal(applied, []bandwidthlease.Grant{stop}) {
		t.Fatalf("zero grant returned demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	zeroPending := demands[0].Challenge
	_, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{stop})
	if err != nil || !slices.Equal(applied, []bandwidthlease.Grant{stop}) {
		t.Fatalf("zero grant retry returned %v, %v", applied, err)
	}
	setDemand(10_000)
	demands, applied, err = ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{{Challenge: zeroPending}})
	if err != nil || len(demands) != 1 || demands[0].RequestedBitsPerSecond != 10_000 ||
		demands[0].Challenge.Sequence <= zeroPending.Sequence || len(applied) != 0 {
		t.Fatalf("restored demand returned demands %v and applied grants %v, error = %v", demands, applied, err)
	}
	if _, ok := node.Current(clientID); ok {
		t.Fatal("zero grant left active traffic")
	}
}

func TestExchangeRejectsWrongAuthorizationAndPriorGeneration(t *testing.T) {
	node, server, target, snapshot := exchangeFixture(t)
	first := exchangeOne(t, server, target)
	grant := bandwidthlease.Grant{Challenge: first.Challenge, BitsPerSecond: 20_000}

	unauthorized := target
	unauthorized.Authorization = "Bearer invalid"
	if _, err := Exchange(t.Context(), server.Client(), unauthorized, []bandwidthlease.Grant{grant}); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Fatalf("unauthorized exchange = %v", err)
	}
	rotated := target
	rotated.Authorization = "Bearer rotated"
	afterRotation := exchangeOne(t, server, rotated, grant)
	if afterRotation.Challenge == grant.Challenge {
		t.Fatal("prior authorization challenge was reused")
	}
	if _, ok := node.Current("client-1"); ok {
		t.Fatal("prior authorization grant was applied")
	}

	nextSnapshot := *snapshot.Load()
	nextSnapshot.Generation = "gen-2"
	snapshot.Store(&nextSnapshot)
	grant.Challenge = afterRotation.Challenge
	if _, err := Exchange(t.Context(), server.Client(), rotated, []bandwidthlease.Grant{grant}); err == nil ||
		!strings.Contains(err.Error(), "409") {
		t.Fatalf("stale generation exchange = %v", err)
	}
	rotated.Generation = nextSnapshot.Generation
	afterChange := exchangeOne(t, server, rotated, grant)
	if afterChange.Challenge == grant.Challenge {
		t.Fatal("prior generation challenge was reused")
	}
	if _, ok := node.Current("client-1"); ok {
		t.Fatal("prior generation grant was applied")
	}
}

func TestExchangeRejectsRedirectAndInsecureTransport(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		http.Redirect(w, r, "/unexpected", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	target := Target{URL: server.URL, NodeID: "node-1", Generation: "gen-1"}
	if _, err := Exchange(t.Context(), server.Client(), target, nil); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirected exchange = %v", err)
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("redirect followed, calls = %d", got)
	}
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := Exchange(t.Context(), insecure, target, nil); err == nil {
		t.Fatal("insecure transport accepted")
	}
	target.URL = strings.Replace(target.URL, "https://", "http://", 1)
	if _, err := Exchange(t.Context(), server.Client(), target, nil); err == nil {
		t.Fatal("HTTP accepted")
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("rejected settings still sent requests, calls = %d", got)
	}
}

func TestExchangeRejectsUnconfiguredOrMalformedResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"wrong node", `{"node_id":"node-2","generation":"gen-1","demands":[],"applied":[]}`},
		{"wrong generation", `{"node_id":"node-1","generation":"gen-2","demands":[],"applied":[]}`},
		{"unknown field", `{"node_id":"node-1","generation":"gen-1","demands":[],"applied":[],"extra":0}`},
		{"duplicate field", `{"node_id":"node-2","node_id":"node-1","generation":"gen-1","demands":[],"applied":[]}`},
		{"trailing JSON", `{"node_id":"node-1","generation":"gen-1","demands":[],"applied":[]}{}`},
		{"oversized", strings.Repeat(" ", maxBody+1)},
		{"ineligible client", `{"node_id":"node-1","generation":"gen-1","demands":[{"client_id":"other","incarnation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sequence":1,"bits_per_second":1}],"applied":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(server.Close)
			target := Target{URL: server.URL, NodeID: "node-1", Generation: "gen-1", ClientIDs: map[string]struct{}{"client-1": {}}}
			if _, err := Exchange(t.Context(), server.Client(), target, nil); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestExchangeValidatesAllAppliedGrants(t *testing.T) {
	const incarnation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const grantJSON = `{"client_id":"client-1","incarnation_id":"` + incarnation + `","nonce":"` + nonce + `","sequence":1,"bits_per_second":10}`
	const demandJSON = `{"client_id":"client-1","incarnation_id":"` + incarnation + `","nonce":"` + nonce + `","sequence":2,"bits_per_second":10}`
	grant := bandwidthlease.Grant{
		Challenge: bandwidthlease.Challenge{
			ClientID: "client-1", NodeID: "node-1", IncarnationID: incarnation, Nonce: nonce, Sequence: 1,
		},
		BitsPerSecond: 10,
	}
	for _, tt := range []struct {
		name    string
		applied string
		count   int
	}{
		{"empty", `,"applied":[]`, 0},
		{"matched", `,"applied":[` + grantJSON + `]`, 1},
		{"missing", "", -1},
		{"null", `,"applied":null`, -1},
		{"object", `,"applied":{}`, -1},
		{"duplicated entry", `,"applied":[` + grantJSON + `,` + grantJSON + `]`, -1},
		{"changed rate", `,"applied":[` + strings.Replace(grantJSON, `:10`, `:11`, 1) + `]`, -1},
		{"unknown grant", `,"applied":[` + demandJSON + `]`, -1},
		{"missing sequence", `,"applied":[` + strings.Replace(grantJSON, `"sequence":1,`, "", 1) + `]`, -1},
		{"zero sequence", `,"applied":[` + strings.Replace(grantJSON, `"sequence":1`, `"sequence":0`, 1) + `]`, -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, `{"node_id":"node-1","generation":"gen-1","demands":[`+demandJSON+`]`+tt.applied+`}`)
			}))
			t.Cleanup(server.Close)
			target := Target{
				URL: server.URL, NodeID: "node-1", Generation: "gen-1", ClientIDs: map[string]struct{}{"client-1": {}},
			}
			demands, applied, err := ExchangeWithApplied(t.Context(), server.Client(), target, []bandwidthlease.Grant{grant})
			if tt.count < 0 {
				if err == nil || demands != nil || applied != nil {
					t.Fatalf("invalid receipt yielded demands %v and applied grants %v, error = %v", demands, applied, err)
				}
				return
			}
			if err != nil || len(demands) != 1 || applied == nil || len(applied) != tt.count ||
				(tt.count == 1 && applied[0] != grant) {
				t.Fatalf("valid receipt yielded demands %v and applied grants %v, error = %v", demands, applied, err)
			}
		})
	}
}

func TestExchangeRespectsDeadlineWhileWaitingForResponseBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "{")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	target := Target{URL: server.URL, NodeID: "node-1", Generation: "gen-1"}
	if _, err := Exchange(ctx, server.Client(), target, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled exchange = %v; want context deadline", err)
	}
}
