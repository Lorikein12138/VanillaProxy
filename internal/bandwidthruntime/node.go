// Package bandwidthruntime composes the distributed bandwidth lease pieces
// for explicitly configured nodes and their root controller.
package bandwidthruntime

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

const (
	defaultDemandIdle = 15 * time.Second
	maxActivationWait = 5 * time.Second
)

// NodeConfig describes one opt-in node. ClientRates maps configured canonical
// IDs to their requested rate and hard local ceiling, in bits per second.
// Zero DemandIdle and ActivationWait use 15 seconds and up to five seconds,
// respectively. Root polling must fit two exchanges into the activation wait
// to grant the first attempt.
// Use a new generation when the client set or its configuration changes.
type NodeConfig struct {
	NodeID          string
	Generation      string
	ClientRates     map[string]int64
	Authorize       bandwidthexchange.Authorize
	DemandIdle      time.Duration
	ActivationWait  time.Duration
	automaticPolicy *nodePolicyFile
}

// Node owns one local lease gate shared by its private IPC server and HTTPS
// handler. The caller controls where, or whether, the HTTPS handler is mounted.
type Node struct {
	leases         *bandwidthlease.Node
	ipc            *bandwidthipc.Server
	handler        http.Handler
	generation     string
	clientRates    map[string]int64
	clientIDs      []string
	demandIdle     time.Duration
	activationWait time.Duration
	policy         *automaticNodePolicy

	mu       sync.Mutex
	lastWall time.Time
	demand   map[string]time.Time
	changed  chan struct{}
	closed   bool
	close    sync.Once
	closeErr error
}

var errNodeClosed = errors.New("bandwidth node runtime is closed")

// StartNode opens only a private loopback IPC listener. Pass IPCInfo to the
// managed data-plane child over its private startup channel.
func StartNode(config NodeConfig) (*Node, error) {
	if !bandwidthexchange.ValidIdentity(config.NodeID) || !bandwidthexchange.ValidIdentity(config.Generation) ||
		config.Authorize == nil || (len(config.ClientRates) == 0 && config.automaticPolicy == nil) || len(config.ClientRates) > bandwidthexchange.MaxClients {
		return nil, errors.New("invalid bandwidth node configuration")
	}
	if config.DemandIdle == 0 {
		config.DemandIdle = defaultDemandIdle
	}
	if config.ActivationWait == 0 {
		config.ActivationWait = min(maxActivationWait, config.DemandIdle)
	}
	if config.DemandIdle <= 0 || config.DemandIdle >= bandwidthlease.Lifetime || config.ActivationWait <= 0 ||
		config.ActivationWait > min(maxActivationWait, config.DemandIdle) {
		return nil, errors.New("invalid bandwidth demand or activation timing")
	}
	node := &Node{
		generation:     config.Generation,
		clientRates:    make(map[string]int64, len(config.ClientRates)),
		clientIDs:      make([]string, 0, len(config.ClientRates)),
		demandIdle:     config.DemandIdle,
		activationWait: config.ActivationWait,
		demand:         make(map[string]time.Time),
		changed:        make(chan struct{}),
	}
	for clientID, rate := range config.ClientRates {
		if !bandwidthexchange.ValidIdentity(clientID) || rate <= 0 {
			return nil, errors.New("invalid managed bandwidth client")
		}
		node.clientRates[clientID] = rate
		node.clientIDs = append(node.clientIDs, clientID)
	}
	slices.Sort(node.clientIDs)
	var err error
	node.leases, err = bandwidthlease.NewNode(config.NodeID)
	if err != nil {
		return nil, err
	}
	if config.automaticPolicy != nil {
		if err := node.startAutomaticPolicy(config); err != nil {
			return nil, err
		}
	}
	node.handler, err = bandwidthexchange.NewHandler(node.leases, config.NodeID, config.Authorize, node.withSnapshot)
	if err != nil {
		return nil, err
	}
	node.ipc, err = bandwidthipc.Listen(node.acquire)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// Handler returns the exchange endpoint for explicit mounting on HTTPS.
func (n *Node) Handler() http.Handler { return n.handler }

// IPCInfo returns the current private startup capability.
func (n *Node) IPCInfo() bandwidthipc.Info { return n.ipc.Info() }

// Acquire admits sidecar payload against the same lease gate used by IPC.
func (n *Node) Acquire(ctx context.Context, clientID string, payloadBytes int) error {
	return n.acquire(ctx, clientID, payloadBytes)
}

// Close disables exchanges and cancels outstanding local permits.
func (n *Node) Close() error {
	n.close.Do(func() {
		n.mu.Lock()
		n.closed = true
		close(n.changed)
		n.mu.Unlock()
		n.closeErr = n.ipc.Close()
	})
	return n.closeErr
}

func (n *Node) acquire(ctx context.Context, clientID string, payloadBytes int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return errNodeClosed
	}
	if _, managed := n.clientRates[clientID]; !managed {
		n.mu.Unlock()
		return bandwidthlease.ErrNoActiveLease
	}
	n.demand[clientID] = n.observeTimeLocked().Add(n.demandIdle)
	changed := n.changed
	n.mu.Unlock()

	// On the first permit a node with no lease needs two root polls: one to
	// advertise the challenge and one to receive the grant. Wait briefly
	// for those polls, then fail closed if they cannot complete in time.
	var activation *time.Timer
	defer func() {
		if activation != nil {
			activation.Stop()
		}
	}()
	for {
		err := n.leases.Wait(ctx, clientID, payloadBytes)
		n.mu.Lock()
		closed := n.closed
		_, managed := n.clientRates[clientID]
		n.mu.Unlock()
		if closed {
			return errNodeClosed
		}
		if !managed {
			return bandwidthlease.ErrNoActiveLease
		}
		if !errors.Is(err, bandwidthlease.ErrNoActiveLease) {
			return err
		}
		if activation == nil {
			activation = time.NewTimer(n.activationWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-activation.C:
			return bandwidthlease.ErrNoActiveLease
		case <-changed:
			n.mu.Lock()
			changed = n.changed
			n.mu.Unlock()
		}
	}
}

func (n *Node) withSnapshot(ctx context.Context, _ string, use func(bandwidthexchange.Snapshot) error) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errNodeClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := n.observeTimeLocked()
	clients := make([]bandwidthexchange.ClientDemand, 0, len(n.demand))
	for _, clientID := range n.clientIDs {
		deadline := n.demand[clientID]
		if !now.Before(deadline) || !now.Round(0).Before(deadline.Round(0)) {
			delete(n.demand, clientID)
			if _, active := n.leases.Current(clientID); active {
				clients = append(clients, bandwidthexchange.ClientDemand{ClientID: clientID})
			}
			continue
		}
		clients = append(clients, bandwidthexchange.ClientDemand{ClientID: clientID, RequestedBitsPerSecond: n.clientRates[clientID]})
	}
	if err := use(bandwidthexchange.Snapshot{Generation: n.generation, Clients: clients}); err != nil {
		return err
	}
	close(n.changed)
	n.changed = make(chan struct{})
	return nil
}

func (n *Node) observeTimeLocked() time.Time {
	now := time.Now()
	wall := now.Round(0)
	if wall.Before(n.lastWall) {
		clear(n.demand)
	}
	n.lastWall = wall
	return now
}
