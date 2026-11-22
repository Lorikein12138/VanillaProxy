package xraybandwidth

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/masque"
)

type masqueFlowKey struct{}

type masqueFlow struct {
	dispatcher *dispatcher
	tag        string
	user       *protocol.MemoryUser
	client     string
}

func (d *dispatcher) resolveMASQUE(ctx context.Context) (*session.Inbound, string, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "masque" || inbound.User == nil {
		return nil, "", errors.New("MASQUE packet gate requires an authenticated inbound")
	}
	if account, ok := inbound.User.Account.(*masque.MemoryAccount); !ok || account == nil {
		return nil, "", errors.New("MASQUE packet gate requires native MASQUE credentials")
	}
	client, managed, err := d.resolve(ctx, inbound.User)
	if err != nil || !managed {
		return inbound, "", err
	}
	if inbound.Tag == "" || client == "" {
		return nil, "", errors.New("managed MASQUE inbound has no authenticated account")
	}
	return inbound, client, nil
}

// VanillaProxyWaitMASQUEPacket admits one complete inner IP packet. The pinned
// Xray patch calls it from the authenticated tunnel's upload and download paths.
func (d *dispatcher) VanillaProxyWaitMASQUEPacket(ctx context.Context, n int) error {
	if n <= 0 || n > maxChunkBytes {
		return errors.New("invalid MASQUE packet size")
	}
	_, client, err := d.resolveMASQUE(ctx)
	if err != nil || client == "" {
		return err
	}
	return admit(ctx, d.wait, client, n)
}

// VanillaProxyMarkMASQUEFlow identifies a native netstack flow whose packets
// are already admitted at the tunnel boundary.
func (d *dispatcher) VanillaProxyMarkMASQUEFlow(ctx context.Context) (context.Context, error) {
	inbound, client, err := d.resolveMASQUE(ctx)
	if err != nil || client == "" {
		return ctx, err
	}
	return context.WithValue(ctx, masqueFlowKey{}, masqueFlow{
		dispatcher: d, tag: inbound.Tag, user: inbound.User, client: client,
	}), nil
}

func (d *dispatcher) isMeteredMASQUEFlow(ctx context.Context, inbound *session.Inbound, client string) bool {
	flow, ok := ctx.Value(masqueFlowKey{}).(masqueFlow)
	return ok && flow.dispatcher == d && inbound.Name == "masque" &&
		flow.tag == inbound.Tag && flow.user == inbound.User && flow.client == client
}
