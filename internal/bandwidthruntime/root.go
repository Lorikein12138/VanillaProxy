package bandwidthruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// LimitsResolver checks current eligibility and caps in root configuration.
// Return false when the client or generation is no longer configured. A
// managed client requires a positive total cap. A zero node cap is unset.
// Implementations must honor cancellation and support calls for different
// nodes concurrently.
type LimitsResolver func(ctx context.Context, nodeID, generation, clientID string) (bandwidthlease.Limits, bool)

// RootTarget binds exchange credentials to an explicitly configured HTTPS node.
type RootTarget struct {
	Target bandwidthexchange.Target
	Client *http.Client
	// Prepare publishes the current policy and returns the acknowledged client
	// set. On error a non-nil set permits an exchange without offering or
	// issuing grants, while prior reservations keep their original deadlines.
	Prepare func(context.Context, bandwidthexchange.Target) (map[string]struct{}, bool, error)
}

type rootPeer struct {
	config RootTarget

	mu     sync.Mutex
	grants []bandwidthlease.Grant
}

type demandSnapshot struct {
	deadline time.Time
	rates    map[string]int64
}

// Poller exchanges grants with configured nodes using one shared authority.
// That authority must outlive reconfiguration of the poller.
type Poller struct {
	authority *bandwidthlease.Authority
	limits    LimitsResolver
	peers     map[string]*rootPeer
	running   sync.Mutex

	demandMu sync.Mutex
	demands  map[string]demandSnapshot
}

// NewPoller validates and copies the configured targets. It starts no polling.
func NewPoller(authority *bandwidthlease.Authority, targets []RootTarget, limits LimitsResolver) (*Poller, error) {
	if authority == nil || limits == nil || len(targets) == 0 {
		return nil, errors.New("root bandwidth polling requires one authority, a limits resolver and configured nodes")
	}
	poller := &Poller{
		authority: authority, limits: limits, peers: make(map[string]*rootPeer, len(targets)),
		demands: make(map[string]demandSnapshot, len(targets)),
	}
	for _, peer := range targets {
		if err := peer.Target.Validate(); err != nil {
			return nil, err
		}
		id := peer.Target.NodeID
		if peer.Client == nil || poller.peers[id] != nil || len(peer.Target.ClientIDs) > bandwidthexchange.MaxClients {
			return nil, fmt.Errorf("invalid or duplicate bandwidth polling node %q", id)
		}
		for clientID := range peer.Target.ClientIDs {
			if !bandwidthexchange.ValidIdentity(clientID) {
				return nil, fmt.Errorf("invalid configured bandwidth client for node %q", id)
			}
		}
		peer.Target.ClientIDs = maps.Clone(peer.Target.ClientIDs)
		poller.peers[id] = &rootPeer{config: peer}
	}
	return poller, nil
}

// Poll performs one exchange. Earlier grants are offered before the next
// demands are accepted. The authority releases capacity after a verified
// receipt or reservation expiry. Losing a response keeps earlier grants queued
// for retry without extending them.
func (p *Poller) Poll(ctx context.Context, nodeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	peer := p.peers[nodeID]
	if peer == nil {
		return errors.New("bandwidth node is not configured for polling")
	}
	if !peer.mu.TryLock() {
		return errors.New("bandwidth node already has an exchange in progress")
	}
	defer peer.mu.Unlock()

	target := peer.config.Target
	if peer.config.Prepare != nil {
		clientIDs, ready, policyErr := peer.config.Prepare(ctx, target)
		if clientIDs == nil {
			return policyErr
		}
		target.ClientIDs = clientIDs
		if !ready || policyErr != nil {
			_, _, exchangeErr := bandwidthexchange.ExchangeWithApplied(ctx, peer.config.Client, target, nil)
			return errors.Join(policyErr, exchangeErr)
		}
	}
	// Drop grants for clients withdrawn since the previous poll. Reservations
	// stay intact. The node continues enforcing any delivered lease until expiry.
	forward := make([]bandwidthlease.Grant, 0, len(peer.grants))
	for _, grant := range peer.grants {
		if _, eligible := target.ClientIDs[grant.Challenge.ClientID]; !eligible {
			continue
		}
		limits, eligible := p.limits(ctx, nodeID, target.Generation, grant.Challenge.ClientID)
		if eligible && limits.TotalBitsPerSecond > 0 && grant.BitsPerSecond <= limits.TotalBitsPerSecond &&
			(limits.NodeBitsPerSecond == 0 || grant.BitsPerSecond <= limits.NodeBitsPerSecond) {
			forward = append(forward, grant)
		}
	}
	demands, applied, err := bandwidthexchange.ExchangeWithApplied(ctx, peer.config.Client, target, forward)
	if err != nil {
		return err
	}
	for _, grant := range applied {
		p.authority.ConfirmApplied(grant)
	}
	snapshots := p.recordDemands(nodeID, demands)

	next := make([]bandwidthlease.Grant, 0, len(demands))
	var failures []error
	for _, demand := range demands {
		if err := ctx.Err(); err != nil {
			return err
		}
		limits, eligible := p.limits(ctx, nodeID, target.Generation, demand.Challenge.ClientID)
		if !eligible || limits.TotalBitsPerSecond <= 0 {
			continue
		}
		share := p.softShare(ctx, nodeID, demand, limits, snapshots)
		if err := ctx.Err(); err != nil {
			return err
		}
		grant, err := p.authority.Issue(demand.Challenge, share, limits)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		next = append(next, grant)
	}
	peer.grants = next
	return errors.Join(failures...)
}

// Each successful exchange replaces the peer's complete demand set. A missing
// or stale snapshot only affects allocation targets. It cannot free reservations.
func (p *Poller) recordDemands(nodeID string, demands []bandwidthexchange.Demand) map[string]demandSnapshot {
	rates := make(map[string]int64, len(demands))
	for _, demand := range demands {
		if demand.RequestedBitsPerSecond > 0 {
			rates[demand.Challenge.ClientID] = demand.RequestedBitsPerSecond
		}
	}
	p.demandMu.Lock()
	defer p.demandMu.Unlock()
	now := time.Now()
	if len(rates) == 0 {
		delete(p.demands, nodeID)
	} else {
		p.demands[nodeID] = demandSnapshot{deadline: now.Add(bandwidthlease.Lifetime), rates: rates}
	}
	for peerID, snapshot := range p.demands {
		if !now.Before(snapshot.deadline) || !now.Round(0).Before(snapshot.deadline.Round(0)) {
			delete(p.demands, peerID)
		}
	}
	// Snapshot maps are immutable after publication. Resolve current limits
	// outside this lock, which is shared across all peer polls.
	return maps.Clone(p.demands)
}

func (p *Poller) softShare(ctx context.Context, nodeID string, demand bandwidthexchange.Demand, limits bandwidthlease.Limits, snapshots map[string]demandSnapshot) int64 {
	requested := cappedDemand(demand.RequestedBitsPerSecond, limits)
	if requested == 0 {
		return 0
	}
	contenders := make([]nodeDemand, 0, len(snapshots))
	contenders = append(contenders, nodeDemand{nodeID: nodeID, rate: requested})
	clientID := demand.Challenge.ClientID
	for peerID, snapshot := range snapshots {
		if ctx.Err() != nil {
			return 0
		}
		rate := snapshot.rates[clientID]
		if peerID == nodeID || rate == 0 {
			continue
		}
		peerLimits, eligible := p.limits(ctx, peerID, p.peers[peerID].config.Target.Generation, clientID)
		if eligible {
			if cap := cappedDemand(rate, peerLimits); cap > 0 {
				contenders = append(contenders, nodeDemand{nodeID: peerID, rate: cap})
			}
		}
	}
	return fairShare(nodeID, limits.TotalBitsPerSecond, contenders)
}

func cappedDemand(requested int64, limits bandwidthlease.Limits) int64 {
	if limits.TotalBitsPerSecond <= 0 || limits.NodeBitsPerSecond < 0 {
		return 0
	}
	requested = min(requested, limits.TotalBitsPerSecond)
	if limits.NodeBitsPerSecond > 0 {
		requested = min(requested, limits.NodeBitsPerSecond)
	}
	return requested
}

type nodeDemand struct {
	nodeID string
	rate   int64
}

// fairShare consumes the smallest demands that fit below the equal share.
// The remaining nodes divide the rest, with extra bits assigned by node ID.
func fairShare(nodeID string, remaining int64, contenders []nodeDemand) int64 {
	slices.SortFunc(contenders, func(a, b nodeDemand) int { return cmp.Compare(a.rate, b.rate) })
	for i, contender := range contenders {
		count := int64(len(contenders) - i)
		share := remaining / count
		if contender.rate <= share {
			if contender.nodeID == nodeID {
				return contender.rate
			}
			remaining -= contender.rate
			continue
		}
		var earlier int64
		for _, other := range contenders[i:] {
			if other.nodeID < nodeID {
				earlier++
			}
		}
		if earlier < remaining%count {
			share++
		}
		return share
	}
	return 0
}

// Run polls each target independently and waits for cancellation. Zero uses
// a one-second interval. A failed node retries on its next tick without
// delaying the other nodes. onError, if supplied, must return promptly and
// support concurrent calls.
func (p *Poller) Run(ctx context.Context, interval time.Duration, onError func(nodeID string, err error)) error {
	if interval == 0 {
		interval = time.Second
	}
	if interval < 0 || interval >= bandwidthlease.Lifetime/2 {
		return errors.New("invalid bandwidth polling interval")
	}
	if !p.running.TryLock() {
		return errors.New("bandwidth polling is already running")
	}
	defer p.running.Unlock()

	var workers sync.WaitGroup
	for nodeID := range p.peers {
		workers.Go(func() {
			ticks := time.NewTicker(interval)
			defer ticks.Stop()
			for ctx.Err() == nil {
				if err := p.Poll(ctx, nodeID); err != nil && ctx.Err() == nil && onError != nil {
					onError(nodeID, err)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticks.C:
				}
			}
		})
	}
	workers.Wait()
	return ctx.Err()
}
