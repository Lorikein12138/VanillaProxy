package bandwidthlease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidth"
)

var (
	ErrInvalidGrant      = errors.New("bandwidth grant does not match an unexpired challenge")
	ErrNoActiveLease     = errors.New("no active bandwidth lease")
	ErrLeaseClock        = errors.New("bandwidth lease clock unavailable")
	ErrSequenceExhausted = errors.New("bandwidth lease challenge sequence exhausted")
)

// Node admits traffic for clients with a rate grant from the authority. Its
// caller supplies authenticated, canonical client IDs and verifies that a
// received grant came from the authority before calling Apply.
type Node struct {
	mu            sync.Mutex
	id            string
	incarnationID string
	sequence      uint64
	now           func() (time.Time, error)
	lastObserved  time.Time
	nextSweep     time.Time
	clients       map[string]*nodeClientLease
}

type nodeClientLease struct {
	pending         Challenge
	pendingDeadline time.Time
	// A zero grant remains available for receipt verification until its deadline.
	active         Grant
	activeDeadline time.Time
	// Keep the epoch across seamless renewals of the same rate. Waiters can
	// then finish using the same bucket without charging their payload twice.
	epoch *rateEpoch
}

type rateEpoch struct {
	rate      int64
	scheduler bandwidth.Scheduler
	lifetime  context.Context
	cancel    context.CancelFunc
}

func NewNode(nodeID string) (*Node, error) {
	return newNode(nodeID, bootTimeNow)
}

func newNode(nodeID string, now func() (time.Time, error)) (*Node, error) {
	if nodeID == "" {
		return nil, bandwidth.ErrInvalidIdentity
	}
	started, err := now()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLeaseClock, err)
	}
	var incarnation [16]byte
	if _, err := rand.Read(incarnation[:]); err != nil {
		return nil, err
	}
	return &Node{
		id:            nodeID,
		incarnationID: hex.EncodeToString(incarnation[:]),
		now:           now,
		lastObserved:  started,
		clients:       make(map[string]*nodeClientLease),
	}, nil
}

// Issue starts the lease lifetime before sending a challenge. A new challenge
// supersedes any pending renewal for this client while its active lease runs.
func (n *Node) Issue(clientID string) (Challenge, error) {
	if clientID == "" {
		return Challenge{}, bandwidth.ErrInvalidIdentity
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	now, err := n.observeTime()
	if err != nil {
		return Challenge{}, err
	}
	if n.sequence == math.MaxUint64 {
		return Challenge{}, ErrSequenceExhausted
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Challenge{}, err
	}
	n.sequence++
	challenge := Challenge{
		ClientID:      clientID,
		NodeID:        n.id,
		IncarnationID: n.incarnationID,
		Nonce:         hex.EncodeToString(nonce[:]),
		Sequence:      n.sequence,
	}
	client := n.liveState(clientID, now)
	if client == nil {
		client = &nodeClientLease{}
		n.clients[clientID] = client
	}
	client.pending = challenge
	client.pendingDeadline = now.Add(Lifetime)
	return challenge, nil
}

// Apply consumes the pending challenge and enables its grant for the
// remainder of the challenge's original lifetime. A zero grant stops traffic.
func (n *Node) Apply(grant Grant) error {
	challenge := grant.Challenge
	if challenge.NodeID != n.id || challenge.IncarnationID == "" || challenge.IncarnationID != n.incarnationID ||
		challenge.ClientID == "" || challenge.Nonce == "" || challenge.Sequence == 0 || grant.BitsPerSecond < 0 {
		return ErrInvalidGrant
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	now, err := n.observeTime()
	if err != nil {
		return err
	}
	client := n.liveState(challenge.ClientID, now)
	if client == nil || challenge != client.pending {
		return ErrInvalidGrant
	}
	if grant.BitsPerSecond == 0 {
		client.clearEpoch()
	} else if client.epoch == nil || client.epoch.rate != grant.BitsPerSecond {
		// Waiters holding the previous epoch can only charge its bucket.
		epoch := &rateEpoch{rate: grant.BitsPerSecond}
		if err := epoch.scheduler.SetPolicy(challenge.ClientID, bandwidth.Policy{TotalBitsPerSecond: epoch.rate}); err != nil {
			return err
		}
		epoch.lifetime, epoch.cancel = context.WithCancel(context.Background())
		client.clearEpoch()
		client.epoch = epoch
	}
	client.active = grant
	client.activeDeadline = client.pendingDeadline
	client.pending = Challenge{}
	client.pendingDeadline = time.Time{}
	return nil
}

// Applied reports whether grant is the latest successful application for its
// client and the original deadline is still live, including for zero grants.
func (n *Node) Applied(grant Grant) bool {
	if grant.Challenge.Sequence == 0 {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	now, err := n.observeTime()
	if err != nil {
		return false
	}
	client := n.liveState(grant.Challenge.ClientID, now)
	return client != nil && client.active == grant
}

// Current reports the rate authorized at this instant.
func (n *Node) Current(clientID string) (Grant, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	now, err := n.observeTime()
	if err != nil {
		return Grant{}, false
	}
	client := n.liveState(clientID, now)
	if client == nil || client.epoch == nil {
		return Grant{}, false
	}
	return client.active, true
}

// Revoke cancels the local epoch and any pending challenge for a client.
func (n *Node) Revoke(clientID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if prior := n.clients[clientID]; prior != nil {
		prior.clearEpoch()
		delete(n.clients, clientID)
	}
}

// Wait charges this bounded payload to the client's shared node bucket.
// Callers must check Wait for each chunk, including on existing connections.
func (n *Node) Wait(ctx context.Context, clientID string, payloadBytes int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		epoch, deadline, remaining := n.currentEpoch(clientID)
		if epoch == nil {
			return ErrNoActiveLease
		}
		leaseContext, cancel := context.WithTimeout(ctx, remaining)
		stop := context.AfterFunc(epoch.lifetime, cancel)
		err := epoch.scheduler.Wait(leaseContext, clientID, n.id, payloadBytes)
		stop()
		cancel()

		current, currentDeadline, _ := n.currentEpoch(clientID)
		if err == nil && epoch == current {
			// The scheduler committed this charge. A deadline that elapsed
			// afterward must not make the caller retry the same payload.
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if current == nil {
			return ErrNoActiveLease
		}
		if epoch == current {
			if !errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if currentDeadline.Equal(deadline) {
				return ErrNoActiveLease
			}
		}
	}
}

func (n *Node) currentEpoch(clientID string) (*rateEpoch, time.Time, time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()

	now, err := n.observeTime()
	if err != nil {
		return nil, time.Time{}, 0
	}
	client := n.liveState(clientID, now)
	if client == nil || client.epoch == nil {
		return nil, time.Time{}, 0
	}
	return client.epoch, client.activeDeadline, client.activeDeadline.Sub(now)
}

// observeTime is called with n.mu held. The production clock counts elapsed
// time since boot, including suspend, independently of wall time.
func (n *Node) observeTime() (time.Time, error) {
	now, err := n.now()
	if err != nil {
		n.clearLeases()
		return time.Time{}, fmt.Errorf("%w: %w", ErrLeaseClock, err)
	}
	if now.Before(n.lastObserved) {
		n.clearLeases()
		n.lastObserved = now
		return time.Time{}, fmt.Errorf("%w: elapsed time moved backward", ErrLeaseClock)
	}
	n.lastObserved = now
	if !now.Before(n.nextSweep) {
		for clientID := range n.clients {
			n.liveState(clientID, now)
		}
		n.nextSweep = now.Add(Lifetime)
	}
	return now, nil
}

func (n *Node) clearLeases() {
	for clientID, client := range n.clients {
		client.clearEpoch()
		delete(n.clients, clientID)
	}
	n.nextSweep = time.Time{}
}

func (n *Node) liveState(clientID string, now time.Time) *nodeClientLease {
	client := n.clients[clientID]
	if client == nil {
		return nil
	}
	if !now.Before(client.pendingDeadline) {
		client.pending = Challenge{}
		client.pendingDeadline = time.Time{}
	}
	if !now.Before(client.activeDeadline) {
		client.clearEpoch()
		client.active = Grant{}
		client.activeDeadline = time.Time{}
	}
	if client.active.Challenge.Sequence == 0 && client.pending.Sequence == 0 {
		delete(n.clients, clientID)
		return nil
	}
	return client
}

func (client *nodeClientLease) clearEpoch() {
	if client.epoch != nil {
		client.epoch.cancel()
		client.epoch = nil
	}
}
