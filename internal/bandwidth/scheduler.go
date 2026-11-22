package bandwidth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MaxChunkBytes is the maximum payload a caller may forward after one Wait.
// TCP callers must split larger writes. This bound also allows an intact UDP
// datagram to be charged once, without reserving credit for an unbounded write.
const MaxChunkBytes = 64 * 1024

const creditPerByte = 8 * int64(time.Second)
const maxCredit = MaxChunkBytes * creditPerByte

var (
	ErrInvalidIdentity = errors.New("bandwidth requires client and node identities")
	ErrInvalidRate     = errors.New("bandwidth rates must be non-negative")
	ErrInvalidChunk    = errors.New("bandwidth chunk is outside the supported size")
)

// Policy limits the combined upload and download payload of one client. A zero
// total or node rate leaves that particular constraint unlimited.
type Policy struct {
	TotalBitsPerSecond int64
	NodeBitsPerSecond  map[string]int64
}

// Scheduler is the authority for a set of clients. All traffic for each
// client must reach the same authority with a stable authenticated client ID
// and node ID. Its zero value is usable.
type Scheduler struct {
	mu      sync.Mutex
	clients map[string]*clientPolicy
}

type clientPolicy struct {
	total   bucket
	nodes   map[string]bucket
	changed chan struct{}
}

// Each bucket stores bit-nanoseconds. An elapsed nanosecond earns rate units,
// which preserves fractional bytes without floating-point rounding.
type bucket struct {
	rate   int64
	credit int64
	last   time.Time
}

func NewScheduler() *Scheduler {
	return &Scheduler{clients: make(map[string]*clientPolicy)}
}

// SetPolicy replaces a client's policy atomically. Existing waiters recheck
// their limits as soon as it changes. Credit is preserved only for unchanged
// rates. An empty policy removes the client's limits.
func (s *Scheduler) SetPolicy(clientID string, policy Policy) error {
	if clientID == "" {
		return ErrInvalidIdentity
	}
	if policy.TotalBitsPerSecond < 0 {
		return ErrInvalidRate
	}
	for nodeID, rate := range policy.NodeBitsPerSecond {
		if nodeID == "" {
			return ErrInvalidIdentity
		}
		if rate < 0 {
			return fmt.Errorf("node %q: %w", nodeID, ErrInvalidRate)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	previous := s.clients[clientID]
	next := &clientPolicy{
		total:   bucket{rate: policy.TotalBitsPerSecond, last: now},
		nodes:   make(map[string]bucket),
		changed: make(chan struct{}),
	}
	if previous != nil && previous.total.rate == next.total.rate {
		next.total = previous.total
	}
	for nodeID, rate := range policy.NodeBitsPerSecond {
		if rate == 0 {
			continue
		}
		if previous != nil {
			if node, ok := previous.nodes[nodeID]; ok && node.rate == rate {
				next.nodes[nodeID] = node
				continue
			}
		}
		next.nodes[nodeID] = bucket{rate: rate, last: now}
	}
	if previous != nil {
		close(previous.changed)
	}
	if next.total.rate == 0 && len(next.nodes) == 0 {
		delete(s.clients, clientID)
	} else {
		if s.clients == nil {
			s.clients = make(map[string]*clientPolicy)
		}
		s.clients[clientID] = next
	}
	return nil
}

// Wait charges the payload to the client's total and node buckets together.
// No budget is consumed until both constraints can admit the entire chunk.
func (s *Scheduler) Wait(ctx context.Context, clientID, nodeID string, payloadBytes int) error {
	if clientID == "" || nodeID == "" {
		return ErrInvalidIdentity
	}
	if payloadBytes < 0 || payloadBytes > MaxChunkBytes {
		return ErrInvalidChunk
	}
	cost := int64(payloadBytes) * creditPerByte
	for {
		s.mu.Lock()
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		policy := s.clients[clientID]
		if policy == nil || cost == 0 {
			s.mu.Unlock()
			return nil
		}
		delay := policy.acquire(time.Now(), nodeID, cost)
		changed := policy.changed
		s.mu.Unlock()
		if delay == 0 {
			return nil
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (p *clientPolicy) acquire(now time.Time, nodeID string, cost int64) time.Duration {
	node := p.nodes[nodeID]
	delay := max(p.total.delay(now, cost), node.delay(now, cost))
	if delay == 0 {
		if p.total.rate > 0 {
			p.total.credit -= cost
		}
		if node.rate > 0 {
			node.credit -= cost
		}
	}
	if node.rate > 0 {
		p.nodes[nodeID] = node
	}
	return delay
}

func (b *bucket) delay(now time.Time, cost int64) time.Duration {
	if b.rate == 0 {
		return 0
	}
	if elapsed := now.Sub(b.last).Nanoseconds(); elapsed > 0 {
		missing := maxCredit - b.credit
		if elapsed >= divideUp(missing, b.rate) {
			b.credit = maxCredit
		} else {
			b.credit += elapsed * b.rate
		}
		b.last = now
	}
	if b.credit >= cost {
		return 0
	}
	return time.Duration(divideUp(cost-b.credit, b.rate))
}

func divideUp(numerator, denominator int64) int64 {
	if numerator == 0 {
		return 0
	}
	return (numerator-1)/denominator + 1
}
