package bandwidthexchange

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// Authorize verifies the request credentials and returns the authorized root's
// stable local identity. Change that identity when replacing its authorization
// if challenges issued under the prior authorization must be invalidated.
type Authorize func(*http.Request) (authorityID string, allowed bool)

// ClientDemand identifies an active client by its canonical configured ID.
type ClientDemand struct {
	ClientID               string
	RequestedBitsPerSecond int64
}

// Snapshot is the complete active demand set for the authenticated root.
// Generation must change without reuse when relevant bandwidth configuration
// changes. Clients must be immutable for the duration of the callback.
type Snapshot struct {
	Generation string
	Clients    []ClientDemand
}

// WithSnapshot calls use exactly once, synchronously, with current config for
// the authorized root. Configuration must stay current while use runs, e.g.
// by holding a read lock. The provider must honor context cancellation.
type WithSnapshot func(ctx context.Context, authorityID string, use func(Snapshot) error) error

type pending struct {
	challenge   bandwidthlease.Challenge
	deadline    time.Time
	authorityID string
	requested   int64
}

type receipt struct {
	grant       bandwidthlease.Grant
	authorityID string
}

type nodeHandler struct {
	node         *bandwidthlease.Node
	nodeID       string
	authorize    Authorize
	withSnapshot WithSnapshot

	mu         sync.Mutex
	generation string
	lastWall   time.Time
	pending    map[string]pending
	applied    map[string]receipt
}

// NewHandler builds an exchange endpoint for explicit mounting on a TLS
// server. It uses the same node lease gate as the data plane. No other caller
// should issue challenges on this gate.
func NewHandler(node *bandwidthlease.Node, nodeID string, authorize Authorize, withSnapshot WithSnapshot) (http.Handler, error) {
	if node == nil || !ValidIdentity(nodeID) || authorize == nil || withSnapshot == nil {
		return nil, errors.New("invalid bandwidth exchange handler configuration")
	}
	return &nodeHandler{
		node: node, nodeID: nodeID, authorize: authorize, withSnapshot: withSnapshot,
		pending: make(map[string]pending),
		applied: make(map[string]receipt),
	}, nil
}

var errGeneration = errors.New("bandwidth exchange generation mismatch")

func (h *nodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "HTTPS required", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	r = r.WithContext(ctx)
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)

	var incoming request
	if err := readJSON(r.Body, &incoming); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "invalid exchange request", status)
		return
	}
	if incoming.NodeID != h.nodeID || !ValidIdentity(incoming.Generation) || !validEntries(incoming.Grants) {
		http.Error(w, "invalid exchange request", http.StatusBadRequest)
		return
	}

	if !h.mu.TryLock() {
		http.Error(w, "exchange busy", http.StatusServiceUnavailable)
		return
	}
	defer h.mu.Unlock()

	authorityID, allowed := h.authorize(r)
	if !allowed || authorityID == "" {
		http.Error(w, "authority authorization required", http.StatusForbidden)
		return
	}
	var outgoing *response
	err := h.withSnapshot(ctx, authorityID, func(snapshot Snapshot) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := h.process(snapshot, authorityID, incoming)
		outgoing = result
		return err
	})
	if errors.Is(err, errGeneration) {
		http.Error(w, "configuration generation mismatch", http.StatusConflict)
		return
	}
	if err != nil || outgoing == nil {
		http.Error(w, "exchange unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.MarshalWrite(w, outgoing)
}

func (h *nodeHandler) process(snapshot Snapshot, authorityID string, incoming request) (*response, error) {
	if !ValidIdentity(snapshot.Generation) || len(snapshot.Clients) > MaxClients {
		return nil, errors.New("invalid bandwidth exchange snapshot")
	}
	active := make(map[string]int64, len(snapshot.Clients))
	for _, client := range snapshot.Clients {
		if !ValidIdentity(client.ClientID) || client.RequestedBitsPerSecond < 0 {
			return nil, errors.New("invalid client demand")
		}
		if _, duplicate := active[client.ClientID]; duplicate {
			return nil, errors.New("duplicate client demand")
		}
		active[client.ClientID] = client.RequestedBitsPerSecond
	}

	now := time.Now()
	wall := now.Round(0)
	if h.generation != snapshot.Generation || wall.Before(h.lastWall) {
		clear(h.pending)
		clear(h.applied)
		h.generation = snapshot.Generation
	}
	h.lastWall = wall
	if incoming.Generation != snapshot.Generation {
		return nil, errGeneration
	}
	for clientID, entry := range h.pending {
		if requested, ok := active[clientID]; !ok || entry.authorityID != authorityID ||
			(requested == 0) != (entry.requested == 0) ||
			!now.Before(entry.deadline) || !wall.Before(entry.deadline.Round(0)) {
			delete(h.pending, clientID)
		}
	}
	for clientID, applied := range h.applied {
		if applied.authorityID != authorityID {
			delete(h.applied, clientID)
		}
	}
	outgoing := &response{
		NodeID: h.nodeID, Generation: snapshot.Generation,
		Demands: make([]wireEntry, 0, len(snapshot.Clients)),
		Applied: make([]wireEntry, 0, len(incoming.Grants)),
	}
	for _, entry := range incoming.Grants {
		grant := entry.grant(h.nodeID)
		clientID := grant.Challenge.ClientID
		requested, activeClient := active[clientID]
		if activeClient && grant.BitsPerSecond > requested {
			continue
		}
		if previous, ok := h.applied[clientID]; ok && previous.grant == grant && h.node.Applied(grant) {
			outgoing.Applied = append(outgoing.Applied, entry)
			continue
		}
		if current, ok := h.pending[clientID]; !activeClient || !ok || current.challenge != grant.Challenge {
			continue
		}
		err := h.node.Apply(grant)
		delete(h.pending, clientID)
		if errors.Is(err, bandwidthlease.ErrInvalidGrant) {
			continue
		}
		if err != nil {
			return nil, err
		}
		h.rememberApplied(grant, authorityID)
		outgoing.Applied = append(outgoing.Applied, entry)
	}
	for _, client := range snapshot.Clients {
		entry, ok := h.pending[client.ClientID]
		if !ok {
			challenge, err := h.node.Issue(client.ClientID)
			if err != nil {
				return nil, err
			}
			if challenge.NodeID != h.nodeID {
				return nil, errors.New("bandwidth exchange node ID differs from its lease gate")
			}
			entry = pending{
				challenge: challenge, deadline: now.Add(bandwidthlease.Lifetime), authorityID: authorityID,
				requested: client.RequestedBitsPerSecond,
			}
			h.pending[client.ClientID] = entry
		}
		outgoing.Demands = append(outgoing.Demands, toWire(entry.challenge, client.RequestedBitsPerSecond))
	}
	return outgoing, nil
}

func (h *nodeHandler) rememberApplied(grant bandwidthlease.Grant, authorityID string) {
	clientID := grant.Challenge.ClientID
	if _, exists := h.applied[clientID]; !exists && len(h.applied) == MaxClients {
		// Clients can leave the demand set before receiving a receipt for their
		// zero grant. Keep receipts across this transition within the same cap.
		var oldestID string
		var oldestSequence uint64
		for id, applied := range h.applied {
			sequence := applied.grant.Challenge.Sequence
			if oldestID == "" || sequence < oldestSequence {
				oldestID, oldestSequence = id, sequence
			}
		}
		delete(h.applied, oldestID)
	}
	h.applied[clientID] = receipt{grant: grant, authorityID: authorityID}
}
