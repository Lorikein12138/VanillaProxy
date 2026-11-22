package bandwidthlease

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func authorityTestClock() (*Authority, func(time.Duration)) {
	now := time.Unix(0, 0)
	return NewAuthority(func() time.Time { return now }), func(elapsed time.Duration) {
		now = now.Add(elapsed)
	}
}

func assertAuthorityGrant(t *testing.T, authority *Authority, challenge Challenge, requested int64, limits Limits, want int64) {
	t.Helper()
	grant, err := authority.Issue(challenge, requested, limits)
	if err != nil || grant.Challenge != challenge || grant.BitsPerSecond != want {
		t.Fatalf("Issue(%+v) = %+v, %v, want a grant for %d bits per second", challenge, grant, err, want)
	}
}

func TestAuthorityStartupHoldoff(t *testing.T) {
	authority, advance := authorityTestClock()
	request := Challenge{ClientID: "client", NodeID: "a", IncarnationID: "instance", Nonce: "first", Sequence: 1}
	advance(Retention - time.Nanosecond)
	if _, err := authority.Issue(request, 100, Limits{}); err != ErrAuthorityWarmingUp {
		t.Fatalf("Issue during startup = %v, want %v", err, ErrAuthorityWarmingUp)
	}
	advance(time.Nanosecond)
	assertAuthorityGrant(t, authority, request, 100, Limits{}, 100)
}

func TestAuthorityConcurrentGrantsForOneIncarnationUseMaximum(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	limits := Limits{TotalBitsPerSecond: 100}
	assertAuthorityGrant(t, authority, Challenge{"client", "a", "instance", "first", 1}, 100,
		Limits{TotalBitsPerSecond: 100, NodeBitsPerSecond: 60}, 60)

	advance(Retention / 2)
	assertAuthorityGrant(t, authority, Challenge{"client", "a", "instance", "second", 2}, 30, limits, 30)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "first", 1}, 100, limits, 40)
	assertAuthorityGrant(t, authority, Challenge{"other-client", "b", "instance", "first", 2}, 100, limits, 100)

	advance(Retention/2 - time.Nanosecond)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "second", 3}, 100, limits, 40)
	advance(time.Nanosecond)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "third", 4}, 100, limits, 70)
}

func TestAuthorityReplayDoesNotExtendReservation(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	limits := Limits{TotalBitsPerSecond: 100}
	request := Challenge{"client", "a", "instance", "first", 1}
	assertAuthorityGrant(t, authority, request, 100, limits, 100)
	advance(Retention - time.Nanosecond)
	assertAuthorityGrant(t, authority, request, 1, Limits{TotalBitsPerSecond: 1}, 100)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "first", 1}, 100, limits, 0)
	advance(time.Nanosecond)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "second", 2}, 100, limits, 100)
}

func TestAuthorityConfirmAppliedReleasesOnlyEarlierReservations(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	limits := Limits{TotalBitsPerSecond: 100}
	old := Challenge{"client", "a", "instance", "first", 1}
	stop := Grant{Challenge: Challenge{"client", "a", "instance", "second", 2}}
	newer := Challenge{"client", "a", "instance", "third", 3}
	replacement := Challenge{"client", "a", "replacement", "first", 1}
	otherClient := Challenge{"other-client", "a", "instance", "first", 1}
	peer := Challenge{"client", "b", "instance", "first", 1}
	assertAuthorityGrant(t, authority, old, 80, limits, 80)
	assertAuthorityGrant(t, authority, stop.Challenge, 0, limits, 0)
	assertAuthorityGrant(t, authority, old, 0, limits, 80)
	assertAuthorityGrant(t, authority, replacement, 20, limits, 20)
	assertAuthorityGrant(t, authority, otherClient, 100, limits, 100)
	assertAuthorityGrant(t, authority, peer, 100, limits, 0)
	for _, change := range []func(*Grant){
		func(grant *Grant) { grant.BitsPerSecond++ },
		func(grant *Grant) { grant.Challenge.Nonce = "unissued" },
		func(grant *Grant) { grant.Challenge.IncarnationID = "another" },
	} {
		forged := stop
		change(&forged)
		if authority.ConfirmApplied(forged) {
			t.Fatalf("confirmed forged receipt: %+v", forged)
		}
	}
	assertAuthorityGrant(t, authority, old, 0, limits, 80)

	confirmed := make(chan bool, 1)
	go func() { confirmed <- authority.ConfirmApplied(stop) }()
	assertAuthorityGrant(t, authority, newer, 30, limits, 30)
	if !<-confirmed {
		t.Error("exact zero grant receipt was rejected")
	}
	if !authority.ConfirmApplied(stop) {
		t.Fatal("duplicate exact receipt was rejected")
	}
	if _, err := authority.Issue(old, 80, limits); err != ErrInvalidLeaseRequest {
		t.Fatalf("reissuing a released reservation returned %v", err)
	}
	peer.Nonce = "second"
	peer.Sequence++
	assertAuthorityGrant(t, authority, peer, 100, limits, 50)
	assertAuthorityGrant(t, authority, otherClient, 0, limits, 100)
}

func TestAuthorityConfirmAppliedDoesNotExtendReservation(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	grant := Grant{Challenge: Challenge{"client", "a", "instance", "first", 1}, BitsPerSecond: 100}
	limits := Limits{TotalBitsPerSecond: 100}
	assertAuthorityGrant(t, authority, grant.Challenge, 100, limits, 100)
	advance(Retention - time.Nanosecond)
	if !authority.ConfirmApplied(grant) || !authority.ConfirmApplied(grant) {
		t.Fatal("live matching receipt was rejected")
	}
	advance(time.Nanosecond)
	if authority.ConfirmApplied(grant) {
		t.Fatal("expired receipt was confirmed")
	}
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "first", 1}, 100, limits, 100)
}

func TestAuthorityLoweredCapsWaitForOutstandingGrants(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	a := Challenge{"client", "a", "instance", "first", 1}
	assertAuthorityGrant(t, authority, a, 60, Limits{}, 60)
	assertAuthorityGrant(t, authority, Challenge{"client", "b", "instance", "first", 1}, 30, Limits{}, 30)

	a.Nonce = "second"
	a.Sequence++
	for _, limits := range []Limits{{TotalBitsPerSecond: 70}, {NodeBitsPerSecond: 50}} {
		if _, err := authority.Issue(a, 10, limits); err != ErrRateReductionPending {
			t.Fatalf("Issue with lowered limits %+v = %v, want %v", limits, err, ErrRateReductionPending)
		}
	}
	advance(Retention)
	assertAuthorityGrant(t, authority, a, 100, Limits{TotalBitsPerSecond: 70, NodeBitsPerSecond: 50}, 50)
}

func TestAuthorityZeroAndInvalidLimits(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	a := Challenge{"client", "a", "instance", "first", 1}
	assertAuthorityGrant(t, authority, a, 0, Limits{}, 0)
	assertAuthorityGrant(t, authority, Challenge{"client", "a", "instance", "second", 2}, 500, Limits{NodeBitsPerSecond: 250}, 250)
	assertAuthorityGrant(t, authority, Challenge{"client", "a", "replacement", "first", 1}, math.MaxInt64, Limits{}, math.MaxInt64)
	request := Challenge{"client", "a", "instance", "third", 3}
	if _, err := authority.Issue(request, 100, Limits{TotalBitsPerSecond: math.MaxInt64}); err != ErrRateReductionPending {
		t.Fatalf("Issue with outstanding allocations above int64 range = %v, want %v", err, ErrRateReductionPending)
	}
	if _, err := authority.Issue(request, 100, Limits{NodeBitsPerSecond: math.MaxInt64}); err != ErrRateReductionPending {
		t.Fatalf("Issue with outstanding node allocations above int64 range = %v, want %v", err, ErrRateReductionPending)
	}
	for _, invalid := range []struct {
		request   Challenge
		requested int64
		limits    Limits
	}{
		{Challenge{"client", "a", "instance", "", 1}, 10, Limits{}},
		{Challenge{"client", "a", "", "first", 1}, 10, Limits{}},
		{Challenge{"client", "a", "instance", "first", 0}, 10, Limits{}},
		{a, -1, Limits{}},
		{a, 10, Limits{TotalBitsPerSecond: -1}},
		{a, 10, Limits{NodeBitsPerSecond: -1}},
	} {
		if _, err := authority.Issue(invalid.request, invalid.requested, invalid.limits); err != ErrInvalidLeaseRequest {
			t.Fatalf("Issue(%+v) = %v, want %v", invalid, err, ErrInvalidLeaseRequest)
		}
	}
}

func TestAuthorityConcurrentIssuesRespectClientTotal(t *testing.T) {
	authority, advance := authorityTestClock()
	advance(Retention)
	const total = 100
	const nodes = 20
	var wg sync.WaitGroup
	results := make(chan int64, nodes)
	for i := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			challenge := Challenge{"client", fmt.Sprintf("node-%d", i), "instance", "first", 1}
			grant, err := authority.Issue(challenge, 20, Limits{TotalBitsPerSecond: total})
			if err != nil {
				t.Errorf("Issue(%+v) = %v", challenge, err)
			}
			results <- grant.BitsPerSecond
		}()
	}
	wg.Wait()
	close(results)

	var sum int64
	for rate := range results {
		sum += rate
	}
	if sum != total {
		t.Fatalf("concurrent grants total %d, want %d", sum, total)
	}
}
