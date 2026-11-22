package xraybandwidth

import (
	"context"
	"errors"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/wireguard"
)

type wireGuardFlowKey struct{}

type wireGuardFlow struct {
	dispatcher *dispatcher
	tag        string
	user       *protocol.MemoryUser
	client     string
}

// VanillaProxyWireGuardClients binds the native server's immutable peer set
// to the same node-bound accounts used by the routing dispatcher.
func (d *dispatcher) VanillaProxyWireGuardClients(ctx context.Context, users []*protocol.MemoryUser) (map[[32]byte]string, bool, error) {
	_, managed, err := d.resolve(ctx, nil)
	if !managed {
		return nil, false, err
	}
	// A managed resolver normally rejects the nil user above. Resolve each
	// native account separately, preserving its inbound tag and protocol.
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "wireguard" || inbound.Tag == "" {
		return nil, true, errors.New("managed WireGuard requires a native tagged inbound")
	}
	clients := make(map[[32]byte]string, len(users))
	for _, user := range users {
		id, err := d.resolveWireGuard(session.ContextWithInbound(ctx, &session.Inbound{Name: inbound.Name, Tag: inbound.Tag, User: user}))
		if err != nil {
			return nil, true, err
		}
		key := user.Account.(*wireguard.MemoryAccount).Pub
		if _, duplicate := clients[key]; duplicate {
			return nil, true, errors.New("duplicate managed WireGuard public key")
		}
		clients[key] = id
	}
	return clients, true, nil
}

func (d *dispatcher) resolveWireGuard(ctx context.Context) (string, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "wireguard" || inbound.Tag == "" || inbound.User == nil {
		return "", errors.New("WireGuard packet gate requires an authenticated inbound")
	}
	if account, ok := inbound.User.Account.(*wireguard.MemoryAccount); !ok || account == nil {
		return "", errors.New("WireGuard packet gate requires native WireGuard credentials")
	}
	client, managed, err := d.resolve(ctx, inbound.User)
	if err != nil {
		return "", err
	}
	if !managed || client == "" {
		return "", errors.New("managed WireGuard peer has no bound account")
	}
	return client, nil
}

// VanillaProxyWaitWireGuardPacket admits a complete inner packet for the
// account already selected by the native authenticated TUN boundary.
func (d *dispatcher) VanillaProxyWaitWireGuardPacket(ctx context.Context, clientID string, n int) error {
	if clientID == "" || n <= 0 || n > maxChunkBytes {
		return errors.New("invalid WireGuard packet admission")
	}
	// The native gate receives this ID only from its frozen authenticated
	// peer set. Keep the packet boundary enabled for all peers in the tunnel.
	if clientID == launch.UnmeteredXrayAccountID {
		return ctx.Err()
	}
	return admit(ctx, d.wait, clientID, n)
}

// VanillaProxyMarkWireGuardFlow identifies a stack flow metered at the TUN.
func (d *dispatcher) VanillaProxyMarkWireGuardFlow(ctx context.Context) (context.Context, error) {
	client, err := d.resolveWireGuard(ctx)
	if err != nil {
		return ctx, err
	}
	inbound := session.InboundFromContext(ctx)
	return context.WithValue(ctx, wireGuardFlowKey{}, wireGuardFlow{
		dispatcher: d, tag: inbound.Tag, user: inbound.User, client: client,
	}), nil
}

func (d *dispatcher) isMeteredWireGuardFlow(ctx context.Context, inbound *session.Inbound, client string) bool {
	flow, ok := ctx.Value(wireGuardFlowKey{}).(wireGuardFlow)
	return ok && flow.dispatcher == d && inbound.Name == "wireguard" &&
		flow.tag == inbound.Tag && flow.user == inbound.User && flow.client == client
}
