package xraybandwidth

import (
	"context"
	"errors"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func TestWireGuardPacketBindingAndFlowMarker(t *testing.T) {
	const account = "stable"
	peer := &protocol.MemoryUser{Email: "first", Account: &wireguard.MemoryAccount{Pub: [32]byte{1}}}
	other := &protocol.MemoryUser{Email: "second", Account: &wireguard.MemoryAccount{Pub: [32]byte{2}}}
	d := &dispatcher{
		resolve: func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
			inbound := session.InboundFromContext(ctx)
			if inbound.Tag != "managed" {
				return "", false, nil
			}
			if inbound.User != user || (user != peer && user != other) {
				return "", true, errors.New("unknown peer")
			}
			if user == other {
				return launch.UnmeteredXrayAccountID, true, nil
			}
			return account, true, nil
		},
		wait: func(_ context.Context, id string, n int) error {
			if id != account || n != 63 {
				t.Fatalf("unexpected WireGuard packet charge %q %d", id, n)
			}
			return nil
		},
	}
	identity := session.Inbound{Tag: "managed", Name: "wireguard"}
	ctx := session.ContextWithInbound(t.Context(), &identity)
	ids, managed, err := d.VanillaProxyWireGuardClients(ctx, []*protocol.MemoryUser{peer, other})
	if err != nil || !managed || len(ids) != 2 || ids[[32]byte{1}] != account || ids[[32]byte{2}] != launch.UnmeteredXrayAccountID {
		t.Fatalf("unexpected WireGuard peer bindings: %v, %t, %v", ids, managed, err)
	}
	if _, _, err := d.VanillaProxyWireGuardClients(ctx, []*protocol.MemoryUser{peer, peer}); err == nil {
		t.Fatal("duplicate native peer was accepted")
	}
	if _, _, err := d.VanillaProxyWireGuardClients(ctx, []*protocol.MemoryUser{{Email: "foreign"}}); err == nil {
		t.Fatal("foreign account was accepted")
	}

	identity.User = peer
	marked, err := d.VanillaProxyMarkWireGuardFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, client, err := d.prepare(marked); err != nil || client != "" {
		t.Fatalf("native metered flow would be charged twice: %q, %v", client, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*session.Inbound)
		probe  *dispatcher
	}{
		{"peer", func(b *session.Inbound) { b.User = other }, d},
		{"tag", func(b *session.Inbound) { b.Tag = "renamed" }, d},
		{"protocol", func(b *session.Inbound) { b.Name = "other" }, d},
		{"dispatcher", func(*session.Inbound) {}, &dispatcher{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := identity
			test.mutate(&changed)
			if test.probe.isMeteredWireGuardFlow(marked, &changed, account) {
				t.Fatal("native flow marker was accepted for a different identity")
			}
		})
	}
	if d.isMeteredWireGuardFlow(marked, &identity, "other") {
		t.Fatal("native flow marker survived a client ID change")
	}
	if err := d.VanillaProxyWaitWireGuardPacket(ctx, account, 63); err != nil {
		t.Fatal(err)
	}
	if err := d.VanillaProxyWaitWireGuardPacket(ctx, ids[[32]byte{2}], 63); err != nil {
		t.Fatal(err)
	}
	if err := d.VanillaProxyWaitWireGuardPacket(ctx, account, maxChunkBytes+1); err == nil {
		t.Fatal("oversized packet was accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.VanillaProxyWaitWireGuardPacket(canceled, account, 63); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if err := d.VanillaProxyWaitWireGuardPacket(canceled, ids[[32]byte{2}], 63); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation for exempt peer, got %v", err)
	}
}
