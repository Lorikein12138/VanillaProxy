package bandwidthlease

import (
	"context"
	"errors"
	"math"
	"testing"
	"testing/synctest"
	"time"
)

func makeTestNode(t *testing.T) (*Node, *time.Time) {
	t.Helper()
	now := time.Now()
	node, err := newNode("node-a", func() (time.Time, error) { return now, nil })
	if err != nil {
		t.Fatal(err)
	}
	return node, &now
}

func issueTestChallenge(t *testing.T, node *Node, clientID string) Challenge {
	t.Helper()
	challenge, err := node.Issue(clientID)
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func applyTestRate(t *testing.T, node *Node, challenge Challenge, rate int64) Grant {
	t.Helper()
	grant := Grant{Challenge: challenge, BitsPerSecond: rate}
	if err := node.Apply(grant); err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestNodeRejectsMismatchedAndReplayedGrants(t *testing.T) {
	node, _ := makeTestNode(t)
	first := issueTestChallenge(t, node, "client-a")
	second := issueTestChallenge(t, node, "client-a")
	other := issueTestChallenge(t, node, "client-b")

	for _, invalid := range []Grant{
		{Challenge: first, BitsPerSecond: 100},
		{Challenge: second, BitsPerSecond: -1},
		{Challenge: Challenge{second.ClientID, "node-b", second.IncarnationID, second.Nonce, second.Sequence}, BitsPerSecond: 100},
		{Challenge: Challenge{other.ClientID, second.NodeID, second.IncarnationID, second.Nonce, second.Sequence}, BitsPerSecond: 100},
		{Challenge: Challenge{second.ClientID, second.NodeID, "another-process", second.Nonce, second.Sequence}, BitsPerSecond: 100},
		{Challenge: Challenge{second.ClientID, second.NodeID, "", second.Nonce, second.Sequence}, BitsPerSecond: 100},
		{Challenge: Challenge{second.ClientID, second.NodeID, second.IncarnationID, second.Nonce, 0}, BitsPerSecond: 100},
	} {
		if err := node.Apply(invalid); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("grant %+v returned %v", invalid, err)
		}
	}

	grant := applyTestRate(t, node, second, 100)
	if err := node.Apply(grant); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replay returned %v", err)
	}
	if current, ok := node.Current(second.ClientID); !ok || current != grant {
		t.Fatalf("current grant = %+v, %v", current, ok)
	}
	if _, ok := node.Current(other.ClientID); ok {
		t.Fatal("grant leaked into a different client")
	}
}

func TestNodeZeroGrantStopsExistingTraffic(t *testing.T) {
	node, now := makeTestNode(t)
	const clientID = "client-a"
	applyTestRate(t, node, issueTestChallenge(t, node, clientID), 100)
	stopped := applyTestRate(t, node, issueTestChallenge(t, node, clientID), 0)
	if err := node.Wait(context.Background(), clientID, 1); !errors.Is(err, ErrNoActiveLease) {
		t.Fatalf("zero grant returned %v", err)
	}
	if err := node.Apply(stopped); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replayed zero grant returned %v", err)
	}
	if !node.Applied(stopped) {
		t.Fatal("applied zero grant has no receipt")
	}
	*now = now.Add(Lifetime)
	if node.Applied(stopped) {
		t.Fatal("zero grant receipt survived the original challenge deadline")
	}
}

func TestNodeChallengeSequenceSurvivesLeaseClearing(t *testing.T) {
	node, now := makeTestNode(t)
	first := issueTestChallenge(t, node, "client-a")
	second := issueTestChallenge(t, node, "client-b")
	if first.Sequence == 0 || second.Sequence != first.Sequence+1 {
		t.Fatalf("unexpected challenge sequences: %d, %d", first.Sequence, second.Sequence)
	}
	grant := applyTestRate(t, node, second, 10)
	*now = now.Add(-time.Second)
	if node.Applied(grant) {
		t.Fatal("clock rollback retained the applied grant receipt")
	}
	third := issueTestChallenge(t, node, "client-a")
	if third.Sequence != second.Sequence+1 {
		t.Fatalf("challenge sequence after clock rollback: %d", third.Sequence)
	}
	node.sequence = math.MaxUint64 - 1
	if last := issueTestChallenge(t, node, "client-a"); last.Sequence != math.MaxUint64 {
		t.Fatalf("last sequence = %d", last.Sequence)
	}
	if _, err := node.Issue("client-a"); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("exhausted sequence returned %v", err)
	}
}

func TestNodeStartsLeaseAtChallengeAndKeepsBucketOnRenewal(t *testing.T) {
	node, now := makeTestNode(t)
	first := issueTestChallenge(t, node, "client-a")
	*now = now.Add(Lifetime / 2)
	applyTestRate(t, node, first, 100)
	firstEpoch, _, remaining := node.currentEpoch(first.ClientID)
	if remaining != Lifetime/2 {
		t.Fatalf("first lease remaining = %s", remaining)
	}

	renewal := issueTestChallenge(t, node, first.ClientID)
	*now = now.Add(Lifetime / 4)
	if current, ok := node.Current(first.ClientID); !ok || current.Challenge != first {
		t.Fatal("pending renewal replaced live grant")
	}
	applyTestRate(t, node, renewal, 100)
	lastEpoch, _, remaining := node.currentEpoch(first.ClientID)
	if firstEpoch != lastEpoch || remaining != 3*Lifetime/4 {
		t.Fatalf("renewal epoch changed = %v, remaining = %s", firstEpoch != lastEpoch, remaining)
	}
	if err := lastEpoch.lifetime.Err(); err != nil {
		t.Fatalf("renewal canceled current waiters: %v", err)
	}

	*now = now.Add(remaining)
	if _, ok := node.Current(first.ClientID); ok {
		t.Fatal("grant survived its original deadline")
	}
	if err := lastEpoch.lifetime.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired epoch returned %v", err)
	}
	if err := node.Wait(context.Background(), first.ClientID, 0); !errors.Is(err, ErrNoActiveLease) {
		t.Fatalf("expired wait returned %v", err)
	}
}

func TestNodeRejectsLateGrantsAndOldGrantsAfterRestart(t *testing.T) {
	node, now := makeTestNode(t)
	challenge := issueTestChallenge(t, node, "client-a")
	grant := Grant{Challenge: challenge, BitsPerSecond: 100}
	*now = now.Add(Lifetime)
	if err := node.Apply(grant); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("late grant returned %v", err)
	}

	restarted, _ := makeTestNode(t)
	replacement := issueTestChallenge(t, restarted, challenge.ClientID)
	if err := restarted.Apply(grant); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("grant from before restart returned %v", err)
	}
	applyTestRate(t, restarted, replacement, 100)
}

func TestNodeInvalidatesGrantsOnElapsedClockRollback(t *testing.T) {
	node, now := makeTestNode(t)
	active := issueTestChallenge(t, node, "client-a")
	applyTestRate(t, node, active, 100)
	pending := issueTestChallenge(t, node, "client-b")
	*now = now.Add(-time.Second)

	if _, ok := node.Current(active.ClientID); ok {
		t.Fatal("elapsed clock rollback kept an existing grant")
	}
	*now = now.Add(2 * time.Second)
	if _, ok := node.Current(active.ClientID); ok {
		t.Fatal("clock recovery resurrected a previously cleared grant")
	}
	if err := node.Apply(Grant{Challenge: pending, BitsPerSecond: 100}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("grant pending during rollback returned %v", err)
	}
	applyTestRate(t, node, issueTestChallenge(t, node, active.ClientID), 100)
}

func TestNodeExpiresLeasesAcrossSuspend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		node, elapsed := makeTestNode(t)
		active := issueTestChallenge(t, node, "client-a")
		applyTestRate(t, node, active, 100)
		pending := issueTestChallenge(t, node, "client-b")

		// Advance the boot clock only. The process clock used for context
		// timeouts can remain at its pre-suspend reading across resume.
		*elapsed = elapsed.Add(Lifetime)
		if err := node.Wait(context.Background(), active.ClientID, 1); !errors.Is(err, ErrNoActiveLease) {
			t.Fatalf("wait after suspend returned %v", err)
		}
		if err := node.Apply(Grant{Challenge: pending, BitsPerSecond: 100}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("pending grant after suspend returned %v", err)
		}
	})
}

func TestNodeClockFailureClearsLeases(t *testing.T) {
	now := time.Now()
	clockFailure := errors.New("unable to read boot clock")
	var clockErr error
	clock := func() (time.Time, error) { return now, clockErr }
	clockErr = clockFailure
	if _, err := newNode("node-a", clock); !errors.Is(err, ErrLeaseClock) || !errors.Is(err, clockFailure) {
		t.Fatalf("create node with unavailable clock returned %v", err)
	}
	clockErr = nil
	node, err := newNode("node-a", clock)
	if err != nil {
		t.Fatal(err)
	}
	active := issueTestChallenge(t, node, "client-a")
	applyTestRate(t, node, active, 100)
	pending := issueTestChallenge(t, node, "client-b")

	clockErr = clockFailure
	if _, err := node.Issue("client-c"); !errors.Is(err, ErrLeaseClock) {
		t.Fatalf("issue with unavailable clock returned %v", err)
	}
	if err := node.Apply(Grant{Challenge: pending, BitsPerSecond: 100}); !errors.Is(err, ErrLeaseClock) {
		t.Fatalf("apply with unavailable clock returned %v", err)
	}
	if err := node.Wait(context.Background(), active.ClientID, 1); !errors.Is(err, ErrNoActiveLease) {
		t.Fatalf("wait with unavailable clock returned %v", err)
	}

	clockErr = nil
	if _, ok := node.Current(active.ClientID); ok {
		t.Fatal("clock recovery resurrected an active grant")
	}
	if err := node.Apply(Grant{Challenge: pending, BitsPerSecond: 100}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("clock recovery restored a pending grant: %v", err)
	}
	applyTestRate(t, node, issueTestChallenge(t, node, active.ClientID), 100)
}

func TestNodeRechecksLeaseAfterSchedulerWait(t *testing.T) {
	node, now := makeTestNode(t)
	challenge := issueTestChallenge(t, node, "client-a")
	applyTestRate(t, node, challenge, 100)
	ctx := deadlineCallbackContext{
		Context: context.Background(),
		callback: func() {
			// Elapsed time advances while traffic is being admitted.
			*now = now.Add(Lifetime)
			node.Current(challenge.ClientID)
		},
	}
	if err := node.Wait(ctx, challenge.ClientID, 1); !errors.Is(err, ErrNoActiveLease) {
		t.Fatalf("wait past the lease returned %v", err)
	}
}

func TestNodeRateChangeChargesNewBucketOnce(t *testing.T) {
	node, _ := makeTestNode(t)
	const clientID = "client-a"
	applyTestRate(t, node, issueTestChallenge(t, node, clientID), 16)
	renewal := issueTestChallenge(t, node, clientID)

	// The new rate earns one byte per second. The deadline allows a single
	// charge and expires before the new bucket can pay for the same byte twice.
	parent, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	changed := false
	ctx := deadlineCallbackContext{
		Context: parent,
		callback: func() {
			if !changed {
				changed = true
				applyTestRate(t, node, renewal, 8)
			}
		},
	}
	if err := node.Wait(ctx, clientID, 1); err != nil {
		t.Fatalf("wait through rate change returned %v", err)
	}
	if !changed {
		t.Fatal("expected the rate to change while the wait was starting")
	}
}

func TestNodeWaitPreservesChargeWhenRequestWindowExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const clientID = "client-a"
		node, _ := makeTestNode(t)
		applyTestRate(t, node, issueTestChallenge(t, node, clientID), 8)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		epoch, _, _ := node.currentEpoch(clientID)
		epoch.lifetime = waitCleanupContext{Context: epoch.lifetime, beforeStop: func() {
			// Let the request expire after the scheduler's charge has succeeded.
			<-ctx.Done()
		}}
		if err := node.Wait(ctx, clientID, 1); err != nil {
			t.Fatalf("completed charge returned %v", err)
		}
		if err := node.Wait(ctx, clientID, 1); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wait started after cancellation returned %v", err)
		}
	})
}

type waitCleanupContext struct {
	context.Context
	beforeStop func()
}

// Hide the underlying cancellation implementation so context.AfterFunc uses
// the registration hook on this wrapper.
func (ctx waitCleanupContext) Value(key any) any { return nil }

func (ctx waitCleanupContext) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(ctx.Context, f)
	return func() bool {
		ctx.beforeStop()
		return stop()
	}
}

type deadlineCallbackContext struct {
	context.Context
	callback func()
}

func (ctx deadlineCallbackContext) Deadline() (time.Time, bool) {
	ctx.callback()
	return ctx.Context.Deadline()
}
