package bandwidthruntime

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// MaxPanelBitsPerSecond is the largest exact JavaScript integer.
const MaxPanelBitsPerSecond = 1<<53 - 1

// ClientBandwidthPolicy contains the overrides for one persistent client ID.
type ClientBandwidthPolicy struct {
	TotalBitsPerSecond int64            `json:"totalBitsPerSecond"`
	NodeBitsPerSecond  map[string]int64 `json:"nodeBitsPerSecond"`
}

// PolicyReader returns overrides for an existing client, or an error if its
// record cannot be read. An existing client without overrides inherits defaults.
type PolicyReader interface {
	ReadClientBandwidth(ctx context.Context, clientID int) (ClientBandwidthPolicy, error)
}

func (cfg *PanelConfig) registerPanelPeer(peer panelPeerFile) error {
	key := peer.PanelNodeKey
	if key == "" {
		return nil
	}
	if !validPanelNodeKey(key) {
		return errors.New("invalid bandwidth panel authority node binding")
	}
	if _, exists := cfg.panelPeers[key]; exists {
		return errors.New("duplicate bandwidth panel authority node binding")
	}
	if key == "local" && (cfg.node == nil || cfg.node.NodeID != peer.ID || cfg.node.Generation != peer.Generation) {
		return errors.New("local bandwidth panel authority node binding requires the matching node role")
	}
	cfg.panelPeers[key] = peer.ID
	return nil
}

func validPanelNodeKey(key string) bool {
	if key == "local" {
		return true
	}
	if guid, ok := strings.CutPrefix(key, "guid:"); ok {
		return bandwidthexchange.ValidIdentity(guid)
	}
	if rawID, ok := strings.CutPrefix(key, "node:"); ok {
		return validPanelNodeID(rawID)
	}
	if path, ok := strings.CutPrefix(key, "via:"); ok {
		parent, descendant, hasDescendant := strings.Cut(path, ":")
		return hasDescendant && validPanelNodeID(parent) && validPanelNodeID(descendant) && parent != descendant
	}
	return false
}

func validPanelNodeID(rawID string) bool {
	id, err := strconv.Atoi(rawID)
	return err == nil && id > 0 && strconv.Itoa(id) == rawID
}

func (cfg *PanelConfig) resolveLimits(ctx context.Context, nodeID, generation, clientID string, reader PolicyReader) (bandwidthlease.Limits, bool) {
	peer, configured := cfg.limits[nodeID]
	if ctx.Err() != nil || !configured || peer.generation != generation {
		return bandwidthlease.Limits{}, false
	}
	limits, eligible := peer.clients[clientID]
	if !eligible {
		return bandwidthlease.Limits{}, false
	}
	recordID, bound := cfg.panelClients[clientID]
	if !bound {
		return limits, true
	}
	if reader == nil {
		return bandwidthlease.Limits{}, false
	}
	policy, err := reader.ReadClientBandwidth(ctx, recordID)
	if err != nil || ctx.Err() != nil || policy.TotalBitsPerSecond < 0 || policy.TotalBitsPerSecond > MaxPanelBitsPerSecond {
		return bandwidthlease.Limits{}, false
	}
	if policy.TotalBitsPerSecond > 0 {
		limits.TotalBitsPerSecond = policy.TotalBitsPerSecond
	}
	if peer.panelNodeKey != "" {
		if rate, exists := policy.NodeBitsPerSecond[peer.panelNodeKey]; exists {
			if rate < 0 || rate > MaxPanelBitsPerSecond {
				return bandwidthlease.Limits{}, false
			}
			limits.NodeBitsPerSecond = rate
		}
	}
	limits.NodeBitsPerSecond = min(limits.NodeBitsPerSecond, limits.TotalBitsPerSecond)
	return limits, true
}

// ClientBandwidthAvailable reports whether each associated physical node has
// a startup binding that can enforce the database policy for this client.
func (panel *PanelRuntime) ClientBandwidthAvailable(clientID int, email string, nodeKeys map[string]struct{}) bool {
	if panel == nil || panel.policyConfig == nil || len(nodeKeys) == 0 {
		return false
	}
	cfg := panel.policyConfig
	canonicalID, bound := cfg.panelCanonicalIDs[clientID]
	if !bound {
		return false
	}
	for key := range nodeKeys {
		peerID := cfg.panelPeers[key]
		if _, eligible := cfg.limits[peerID].clients[canonicalID]; !eligible {
			return false
		}
		if key == "local" && cfg.accounts[email] != canonicalID {
			return false
		}
	}
	return true
}

// ClientBandwidthPolicyAvailable checks the committed policy and membership
// against acknowledged automatic enrollment or the legacy startup bindings.
func (panel *PanelRuntime) ClientBandwidthPolicyAvailable(row BandwidthAccount) bool {
	if panel == nil {
		return false
	}
	if automatic := panel.automaticPolicy; automatic != nil {
		plan, err := automatic.enrollment(row)
		if err != nil || !plan.available {
			return false
		}
		automatic.mu.RLock()
		defer automatic.mu.RUnlock()
		return automatic.desired != nil && automatic.confirmed(row.ID, plan, true)
	}
	keys := make(map[string]struct{}, len(row.Attachments))
	for key := range row.Attachments {
		keys[key] = struct{}{}
	}
	return panel.ClientBandwidthAvailable(row.ID, row.Email, keys)
}
