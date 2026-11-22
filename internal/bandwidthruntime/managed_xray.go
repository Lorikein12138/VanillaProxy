package bandwidthruntime

import (
	"errors"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

// NewManagedXrayProcess connects an opt-in Xray process to this node's lease gate.
// Clients maps inbound tags to authenticated emails and configured canonical IDs
// or launch.UnmeteredXrayAccountID for an explicit Xray account exception.
// The caller owns the process lifecycle and should stop it before closing the node.
func (n *Node) NewManagedXrayProcess(config *xray.Config, clients map[string]map[string]string) (*xray.Process, error) {
	return n.NewManagedXrayWithRelays(config, clients, nil)
}

// NewManagedXrayWithRelays also accepts a core serving authenticated sidecar
// relays whose bandwidth gate runs before Xray routing.
func (n *Node) NewManagedXrayWithRelays(config *xray.Config, clients map[string]map[string]string, relays map[string]launch.SidecarRelay) (*xray.Process, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, errNodeClosed
	}
	if config == nil || len(clients)+len(relays) == 0 {
		return nil, errors.New("managed Xray requires a configuration and inbound bindings")
	}
	for _, users := range clients {
		for _, id := range users {
			if id == launch.UnmeteredXrayAccountID {
				continue
			}
			if _, known := n.clientRates[id]; !known {
				return nil, errors.New("managed Xray binding references an unconfigured bandwidth client")
			}
		}
	}
	for _, relay := range relays {
		if len(relay.Accounts) == 0 {
			return nil, errors.New("managed Xray sidecar relay requires account bindings")
		}
		for _, id := range relay.Accounts {
			if relay.Automatic && id == "" {
				continue
			}
			if _, known := n.clientRates[id]; !known {
				return nil, errors.New("managed Xray relay references an unconfigured bandwidth client")
			}
		}
	}
	return xray.NewProcessWithBandwidth(config, launch.Handshake{IPC: n.IPCInfo(), Clients: clients, Relays: relays})
}
