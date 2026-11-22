package bandwidthlease

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrAuthorityWarmingUp   = errors.New("bandwidth lease authority is waiting for prior grants to expire")
	ErrRateReductionPending = errors.New("bandwidth rate reduction is waiting for outstanding grants to expire")
	ErrInvalidLeaseRequest  = errors.New("invalid bandwidth lease request")
)

// Limits is the client's configured total and the requested node's ceiling.
// Zero disables a ceiling. A grant for zero bits per second permits no traffic.
type Limits struct {
	TotalBitsPerSecond int64
	NodeBitsPerSecond  int64
}

type reservation struct {
	grant Grant
	until time.Time
}

type leaseInstance struct {
	nodeID        string
	incarnationID string
}

// Authority reserves issued rates until they are safe for another node
// incarnation to use. The caller must run a single authority for each client
// and authenticate the node ID and incarnation of each request.
type Authority struct {
	mu           sync.Mutex
	now          func() time.Time
	warmUntil    time.Time
	nextSweep    time.Time
	reservations map[string]map[Challenge]reservation
}

// NewAuthority starts with a quiet period in case nodes still hold grants from
// the prior instance. A supplied test clock must preserve elapsed-time order.
// The default time.Now retains monotonic readings for expiration comparisons.
func NewAuthority(now func() time.Time) *Authority {
	if now == nil {
		now = time.Now
	}
	warmUntil := now().Add(Retention)
	return &Authority{
		now:          now,
		warmUntil:    warmUntil,
		nextSweep:    warmUntil,
		reservations: make(map[string]map[Challenge]reservation),
	}
}

// Issue grants up to the requested rate. The caller supplies current limits for
// the authenticated client and node. A still-reserved challenge returns its
// original result without extending the reservation, even when limits change.
// The node must match the challenge and enforce the deadline it started before
// submitting it. An expired challenge can never reopen a lease at the node.
func (a *Authority) Issue(challenge Challenge, requestedBitsPerSecond int64, limits Limits) (Grant, error) {
	if challenge.ClientID == "" || challenge.NodeID == "" || challenge.IncarnationID == "" || challenge.Nonce == "" ||
		challenge.Sequence == 0 || requestedBitsPerSecond < 0 || limits.TotalBitsPerSecond < 0 || limits.NodeBitsPerSecond < 0 {
		return Grant{}, ErrInvalidLeaseRequest
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	if now.Before(a.warmUntil) {
		return Grant{}, ErrAuthorityWarmingUp
	}
	a.sweep(now)

	active := a.reservations[challenge.ClientID]
	instanceRates := make(map[leaseInstance]int64)
	ownInstance := leaseInstance{nodeID: challenge.NodeID, incarnationID: challenge.IncarnationID}
	var stale bool
	for key, record := range active {
		if !now.Before(record.until) {
			delete(active, key)
			continue
		}
		if key == challenge {
			return record.grant, nil
		}
		instance := leaseInstance{nodeID: key.NodeID, incarnationID: key.IncarnationID}
		if instance == ownInstance && key.Sequence >= challenge.Sequence {
			stale = true
		}
		instanceRates[instance] = max(instanceRates[instance], record.grant.BitsPerSecond)
	}
	if stale {
		return Grant{}, ErrInvalidLeaseRequest
	}

	totalRemaining := limits.TotalBitsPerSecond
	nodeRemaining := limits.NodeBitsPerSecond
	for instance, reserved := range instanceRates {
		if limits.TotalBitsPerSecond > 0 {
			if reserved > totalRemaining {
				return Grant{}, ErrRateReductionPending
			}
			totalRemaining -= reserved
		}
		if limits.NodeBitsPerSecond > 0 && instance.nodeID == challenge.NodeID {
			if reserved > nodeRemaining {
				return Grant{}, ErrRateReductionPending
			}
			nodeRemaining -= reserved
		}
	}

	rate := requestedBitsPerSecond
	// Only this incarnation can replace its previous rate with the new grant.
	ownRate := instanceRates[ownInstance]
	if limits.NodeBitsPerSecond > 0 {
		rate = min(rate, ownRate+nodeRemaining)
	}
	if limits.TotalBitsPerSecond > 0 {
		rate = min(rate, ownRate+totalRemaining)
	}

	if active == nil {
		active = make(map[Challenge]reservation)
		a.reservations[challenge.ClientID] = active
	}
	grant := Grant{Challenge: challenge, BitsPerSecond: rate}
	active[challenge] = reservation{grant: grant, until: now.Add(Retention)}
	return grant, nil
}

// ConfirmApplied releases older reservations that the authenticated node has
// superseded. The exact applied reservation keeps its original deadline.
func (a *Authority) ConfirmApplied(grant Grant) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	a.sweep(now)
	challenge := grant.Challenge
	active := a.reservations[challenge.ClientID]
	record, ok := active[challenge]
	if !ok || record.grant != grant || !now.Before(record.until) {
		return false
	}
	for older := range active {
		if older.NodeID == challenge.NodeID && older.IncarnationID == challenge.IncarnationID && older.Sequence < challenge.Sequence {
			delete(active, older)
		}
	}
	return true
}

func (a *Authority) sweep(now time.Time) {
	if now.Before(a.nextSweep) {
		return
	}
	a.nextSweep = now.Add(Retention)
	for clientID, active := range a.reservations {
		for challenge, record := range active {
			if !now.Before(record.until) {
				delete(active, challenge)
			}
		}
		if len(active) == 0 {
			delete(a.reservations, clientID)
		}
	}
}
