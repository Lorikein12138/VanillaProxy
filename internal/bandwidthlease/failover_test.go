package bandwidthlease

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDisconnectedNodeStopsBeforeAuthorityReassignsItsRate(t *testing.T) {
	const (
		clientID = "shared-client"
		mbps     = 1_000_000
	)
	now := time.Now()
	clock := func() time.Time { return now }
	nodeClock := func() (time.Time, error) { return now, nil }
	authority := NewAuthority(clock)
	now = now.Add(Retention)
	nodeA, err := newNode("node-a", nodeClock)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := newNode("node-b", nodeClock)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{TotalBitsPerSecond: 100 * mbps}

	applyFromAuthority := func(node *Node, challenge Challenge, requested, want int64) {
		t.Helper()
		grant, err := authority.Issue(challenge, requested, limits)
		if err != nil || grant.BitsPerSecond != want {
			t.Fatalf("node %s received %d, %v, want %d", challenge.NodeID, grant.BitsPerSecond, err, want)
		}
		if err := node.Apply(grant); err != nil {
			t.Fatal(err)
		}
	}

	challengeA := issueTestChallenge(t, nodeA, clientID)
	now = now.Add(time.Second) // The authority receives A's challenge after it was sent.
	applyFromAuthority(nodeA, challengeA, 60*mbps, 60*mbps)
	applyFromAuthority(nodeB, issueTestChallenge(t, nodeB, clientID), 100*mbps, 40*mbps)

	now = now.Add(Lifetime - time.Second)
	if err := nodeA.Wait(context.Background(), clientID, 1); !errors.Is(err, ErrNoActiveLease) {
		t.Fatalf("expired node A returned %v", err)
	}
	applyFromAuthority(nodeB, issueTestChallenge(t, nodeB, clientID), 100*mbps, 40*mbps)

	now = now.Add(Retention - Lifetime + time.Second)
	applyFromAuthority(nodeB, issueTestChallenge(t, nodeB, clientID), 100*mbps, 100*mbps)
}

func TestConcurrentIncarnationsShareNodeAndClientCaps(t *testing.T) {
	const clientID = "shared-client"
	now := time.Now()
	clock := func() time.Time { return now }
	nodeClock := func() (time.Time, error) { return now, nil }
	authority := NewAuthority(clock)
	now = now.Add(Retention)
	limits := Limits{TotalBitsPerSecond: 100, NodeBitsPerSecond: 60}
	makeNode := func(id string) *Node {
		t.Helper()
		node, err := newNode(id, nodeClock)
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	first := makeNode("node-a")
	replacement := makeNode("node-a")
	other := makeNode("node-b")

	issueAndApply := func(node *Node, requested, want int64) Challenge {
		t.Helper()
		challenge := issueTestChallenge(t, node, clientID)
		grant, err := authority.Issue(challenge, requested, limits)
		if err != nil || grant.BitsPerSecond != want {
			t.Fatalf("Issue(%+v, %d) = %d, %v, want %d", challenge, requested, grant.BitsPerSecond, err, want)
		}
		if err := node.Apply(grant); err != nil {
			t.Fatal(err)
		}
		return challenge
	}

	initial := issueAndApply(first, 45, 45)
	second := issueAndApply(replacement, 100, 15)
	if initial.NodeID != second.NodeID || initial.IncarnationID == second.IncarnationID {
		t.Fatal("expected separate incarnations of the same node")
	}
	issueAndApply(other, 100, 40)

	now = now.Add(Retention / 2)
	renewal := issueAndApply(first, 100, 45)
	if renewal.IncarnationID != initial.IncarnationID {
		t.Fatal("renewal changed the incarnation")
	}
	issueAndApply(first, 0, 0)
	issueAndApply(replacement, 100, 15)

	now = now.Add(Retention - time.Nanosecond)
	issueAndApply(replacement, 100, 15)
	now = now.Add(time.Nanosecond)
	issueAndApply(replacement, 100, 60)
}
