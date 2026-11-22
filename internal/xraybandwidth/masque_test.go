package xraybandwidth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/transport"
)

func TestMASQUEPacketGateAndFlowIdentity(t *testing.T) {
	user := &protocol.MemoryUser{Email: "account", Account: &masque.MemoryAccount{Password: "secret"}}
	inbound := &session.Inbound{Tag: "tag", Name: "masque", User: user}
	ctx := session.ContextWithInbound(t.Context(), inbound)
	dest := net.TCPDestination(net.DomainAddress("example.test"), 443)
	link := &transport.Link{
		Reader: readerFunc(func() (buf.MultiBuffer, error) {
			return buf.MultiBuffer{testBuffer(5)}, nil
		}),
		Writer: writerFunc(func(mb buf.MultiBuffer) error {
			buf.ReleaseMulti(mb)
			return nil
		}),
	}
	var passed *transport.Link
	base := testDispatcher{dispatchLink: func(_ context.Context, _ net.Destination, got *transport.Link) error {
		passed = got
		mb, err := got.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		return got.Writer.WriteMultiBuffer(mb)
	}}
	clientID := "client"
	resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user == nil || user.Email != "account" {
			return "", true, errors.New("unknown user")
		}
		return clientID, true, nil
	}
	var charges []int
	wait := func(_ context.Context, client string, n int) error {
		if clientID != client {
			return errors.New("incorrect account key")
		}
		charges = append(charges, n)
		return nil
	}
	wrapped, err := Wrap(base, resolve, wait)
	if err != nil {
		t.Fatal(err)
	}
	d := wrapped.(*dispatcher)
	marked, err := d.VanillaProxyMarkMASQUEFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VanillaProxyWaitMASQUEPacket(ctx, 27); err != nil {
		t.Fatal(err)
	}
	if err := d.DispatchLink(marked, dest, link); err != nil {
		t.Fatal(err)
	}
	if passed != link || !slices.Equal(charges, []int{27}) {
		t.Fatalf("native flow reached dispatcher with original link=%t, charges %v, want [27]", passed == link, charges)
	}

	for _, mutation := range []string{"dispatcher", "tag", "protocol", "user", "client"} {
		t.Run(mutation, func(t *testing.T) {
			changed := *inbound
			dispatch := wrapped
			switch mutation {
			case "dispatcher":
				separate, err := Wrap(base, resolve, wait)
				if err != nil {
					t.Fatal(err)
				}
				dispatch = separate
			case "tag":
				changed.Tag = "other"
			case "protocol":
				changed.Name = "vless"
			case "user":
				userCopy := *user
				changed.User = &userCopy
			case "client":
				clientID = "other"
			}
			charges = nil
			if err := dispatch.DispatchLink(session.ContextWithInbound(marked, &changed), dest, link); err != nil {
				t.Fatal(err)
			}
			if passed == link || !slices.Equal(charges, []int{5, 5}) {
				t.Fatalf("flow reached dispatcher with original link=%t, charges %v, want [5 5]", passed == link, charges)
			}
		})
	}
}

func TestMASQUEPacketGateRejectsUnboundCredentialsAndCancelledContexts(t *testing.T) {
	wrapped, err := Wrap(testDispatcher{}, func(_ context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user.Email == "unmanaged" {
			return "", false, nil
		}
		if user.Email != "bound" {
			return "", true, errors.New("unknown user")
		}
		return "client", true, nil
	}, func(context.Context, string, int) error {
		t.Fatal("unexpected packet admission")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	d := wrapped.(*dispatcher)
	user := &protocol.MemoryUser{Email: "unknown", Account: &masque.MemoryAccount{Password: "secret"}}
	inbound := &session.Inbound{Name: "masque", Tag: "tag", User: user}
	ctx, cancel := context.WithCancel(session.ContextWithInbound(t.Context(), inbound))
	defer cancel()
	if err := d.VanillaProxyWaitMASQUEPacket(ctx, 20); err == nil || !strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("unexpected packet rejection: %v", err)
	}
	_, err = d.VanillaProxyMarkMASQUEFlow(ctx)
	if err == nil || !strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("unexpected flow rejection: %v", err)
	}

	user.Email = "unmanaged"
	inbound.Tag = ""
	if err := d.VanillaProxyWaitMASQUEPacket(ctx, 20); err != nil {
		t.Fatal(err)
	}
	marked, err := d.VanillaProxyMarkMASQUEFlow(ctx)
	if err != nil || marked != ctx {
		t.Fatalf("unexpected unmanaged flow change: marked=%t, err=%v", marked != ctx, err)
	}

	user.Email, inbound.Tag = "bound", "tag"
	if err := d.VanillaProxyWaitMASQUEPacket(ctx, maxChunkBytes+1); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected packet size rejection: %v", err)
	}
	cancel()
	if err := d.VanillaProxyWaitMASQUEPacket(ctx, 20); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled packet wait returned %v", err)
	}
}
