// Package xraybandwidth connects an authenticated Xray route to a byte budget.
package xraybandwidth

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Gate admits a bounded payload in either direction against the same account.
type Gate func(ctx context.Context, clientID string, n int) error

// ResolveClient returns the stable account ID for the authenticated user.
// Returning managed=false deliberately leaves the route unmanaged. A resolver
// may reject missing or unrecognized credentials on a managed inbound.
type ResolveClient func(ctx context.Context, user *protocol.MemoryUser) (clientID string, managed bool, err error)

type dispatcher struct {
	routing.Dispatcher
	resolve ResolveClient
	wait    Gate
}

type meteredClient struct{}

// Wrap meters traffic that reaches the routing dispatcher. Protocol paths that
// bypass routing, such as reverse VLESS and reattaching an existing XUDP
// association, need an admission check in the inbound implementation.
func Wrap(base routing.Dispatcher, resolve ResolveClient, wait Gate) (routing.Dispatcher, error) {
	if base == nil || resolve == nil || wait == nil {
		return nil, errors.New("Xray bandwidth requires a dispatcher, account resolver and gate")
	}
	return &dispatcher{Dispatcher: base, resolve: resolve, wait: wait}, nil
}

func (d *dispatcher) prepare(ctx context.Context) (context.Context, string, error) {
	inbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if inbound != nil {
		user = inbound.User
	}
	client, managed, err := d.resolve(ctx, user)
	if err != nil || !managed {
		return ctx, "", err
	}
	if user == nil || client == "" {
		return ctx, "", errors.New("managed Xray route has no authenticated account")
	}
	if session.TimeoutOnlyFromContext(ctx) {
		return ctx, "", errors.New("managed Xray routes do not support detachable sessions")
	}
	if d.isMeteredMASQUEFlow(ctx, inbound, client) || d.isMeteredWireGuardFlow(ctx, inbound, client) {
		return ctx, "", nil
	}
	if ctx.Value(meteredClient{}) == client {
		return ctx, "", nil
	}
	// Xray's direct-copy splice can write to the inbound socket without
	// passing through the link writer. Value 3 disables that optimization.
	if inbound.CanSpliceCopy != 3 {
		inbound.CanSpliceCopy = 3
	}
	return context.WithValue(ctx, meteredClient{}, client), client, nil
}

func (d *dispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	ctx, client, err := d.prepare(ctx)
	if err != nil {
		return nil, err
	}
	if client == "" {
		return d.Dispatcher.Dispatch(ctx, dest)
	}
	if !dest.IsValid() {
		return nil, errors.New("invalid Xray destination")
	}

	// Keep the concrete pipe reader expected by Xray's Dispatch callers,
	// and use the normal DispatchLink path for sniffing, routing and stats.
	options := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(options...)
	downlinkReader, downlinkWriter := pipe.New(options...)
	packet := dest.Network == net.Network_UDP
	inbound := newWriter(ctx, uplinkWriter, d.wait, client, packet)
	outbound := newWriter(ctx, downlinkWriter, d.wait, client, packet)
	go func() {
		if err := d.Dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: uplinkReader, Writer: outbound}); err != nil {
			inbound.Interrupt()
			outbound.Interrupt()
		}
	}()
	return &transport.Link{Reader: downlinkReader, Writer: inbound}, nil
}

func (d *dispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	ctx, client, err := d.prepare(ctx)
	if err != nil {
		return err
	}
	if client == "" {
		return d.Dispatcher.DispatchLink(ctx, dest, link)
	}
	if link == nil || link.Reader == nil || link.Writer == nil {
		return errors.New("incomplete Xray link")
	}
	packet := dest.Network == net.Network_UDP
	reader := newReader(ctx, link.Reader, d.wait, client, packet)
	writer := newWriter(ctx, link.Writer, d.wait, client, packet)
	defer reader.release()
	defer writer.cancel()
	if err := d.Dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: reader, Writer: writer}); err != nil {
		_ = common.Interrupt(link.Reader)
		writer.Interrupt()
		return err
	}
	return nil
}
