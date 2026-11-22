package bandwidth

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestNodeAndTotalConsumeTheSamePayload(t *testing.T) {
	start := time.Unix(0, 0)
	now := start.Add(time.Second)
	policy := clientPolicy{
		total: bucket{rate: 8_000, last: start},
		nodes: map[string]bucket{"a": {rate: 4_800, last: start}},
	}
	if delay := policy.acquire(now, "a", 400*creditPerByte); delay != 0 {
		t.Fatalf("first stream on a must be admitted, delay %v", delay)
	}
	if delay := policy.acquire(now, "a", 300*creditPerByte); delay != 166666667*time.Nanosecond {
		t.Fatalf("second stream on a must wait for the shared node cap, delay %v", delay)
	}
	if delay := policy.acquire(now, "b", 600*creditPerByte); delay != 0 {
		t.Fatalf("a rejected charge must leave the remaining total for b, delay %v", delay)
	}
	if delay := policy.acquire(now, "b", creditPerByte); delay != time.Millisecond {
		t.Fatalf("b is still subject to the total cap, delay %v", delay)
	}
}

func TestNodeMayUseUnusedTotalAndNoNodePolicyIsGlobal(t *testing.T) {
	start := time.Unix(0, 0)
	policy := clientPolicy{total: bucket{rate: 8_000, last: start}}
	now := start.Add(time.Second)
	if delay := policy.acquire(now, "a", 1_000*creditPerByte); delay != 0 {
		t.Fatalf("the active node may use the full total, delay %v", delay)
	}
	if delay := policy.acquire(now, "b", creditPerByte); delay != time.Millisecond {
		t.Fatalf("all nodes must share the same total, delay %v", delay)
	}
}

func TestConcurrentNodesCannotSpendTheSameCredit(t *testing.T) {
	s := NewScheduler()
	if err := s.SetPolicy("client", Policy{TotalBitsPerSecond: 1}); err != nil {
		t.Fatal(err)
	}
	s.clients["client"].total.credit = maxCredit
	const streams = 8
	ready := sync.WaitGroup{}
	ready.Add(streams)
	start := make(chan struct{})
	results := make(chan error, streams)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := range streams {
		go func() {
			ready.Done()
			<-start
			node := "a"
			if i%2 != 0 {
				node = "b"
			}
			results <- s.Wait(ctx, "client", node, MaxChunkBytes/4)
		}()
	}
	ready.Wait()
	close(start)
	admitted := 0
	for range streams {
		switch err := <-results; {
		case err == nil:
			admitted++
		case errors.Is(err, context.DeadlineExceeded):
		default:
			t.Fatal(err)
		}
	}
	if admitted != 4 {
		t.Fatalf("admitted %d streams with enough credit for four", admitted)
	}
}

func TestPolicyUpdatePreservesUnchangedBucketsAndWakesWaiters(t *testing.T) {
	s := NewScheduler()
	limits := map[string]int64{"node": 1}
	if err := s.SetPolicy("client", Policy{TotalBitsPerSecond: 1, NodeBitsPerSecond: limits}); err != nil {
		t.Fatal(err)
	}
	limits["node"] = 2
	first := s.clients["client"]
	first.total.credit = 99
	if err := s.SetPolicy("client", Policy{TotalBitsPerSecond: 1, NodeBitsPerSecond: limits}); err != nil {
		t.Fatal(err)
	}
	current := s.clients["client"]
	if current.total.credit != 99 || first.nodes["node"].rate != 1 || current.nodes["node"].rate != 2 {
		t.Fatalf("unexpected update: old node %v, current %v", first.nodes["node"], current)
	}
	select {
	case <-first.changed:
	default:
		t.Fatal("policy replacement did not notify waiters")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Wait(ctx, "client", "node", MaxChunkBytes) }()
	if err := s.SetPolicy("client", Policy{}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("removed limits must release the waiter: %v", err)
	}
}

func TestExtremeRatesAndChunkValidation(t *testing.T) {
	start := time.Unix(0, 0)
	b := bucket{rate: math.MaxInt64, last: start}
	if delay := b.delay(start.Add(time.Nanosecond), maxCredit); delay != 0 || b.credit != maxCredit {
		t.Fatalf("extreme rate must saturate without overflow, delay %v, credit %d", delay, b.credit)
	}
	var s Scheduler
	ctx := context.Background()
	if err := s.Wait(ctx, "client", "node", MaxChunkBytes); err != nil {
		t.Fatalf("zero policy should permit valid input: %v", err)
	}
	if err := s.Wait(ctx, "client", "node", MaxChunkBytes+1); !errors.Is(err, ErrInvalidChunk) {
		t.Fatalf("oversized input: %v", err)
	}
	if err := s.Wait(ctx, "client", "", 1); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("empty node: %v", err)
	}
	if err := s.SetPolicy("client", Policy{NodeBitsPerSecond: map[string]int64{"node": -1}}); !errors.Is(err, ErrInvalidRate) {
		t.Fatalf("negative node rate: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Wait(ctx, "client", "node", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context should not admit traffic: %v", err)
	}
}
