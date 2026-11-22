package amneziawgnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidth"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// BandwidthOptions enables a server-side bandwidth gate for both directions.
// ClientIDs binds configured WireGuard public keys to canonical client IDs.
// Multiple public keys for one client share the same queues and gate identity.
// Wait receives a full inner IP packet length, including its IP header. It
// may run concurrently and must return promptly when its context is canceled.
// The caller supplies a gate already bound to the node serving traffic.
type BandwidthOptions struct {
	ClientIDs map[string]string
	Wait      func(context.Context, string, int) error

	allowUnrestricted bool
}

var errFixedBandwidthDevice = errors.New("amneziawgnet: recreate the bandwidth-managed device to change its configuration")

const (
	bandwidthPacketsPerDirection = 32
	bandwidthPacketsPerDevice    = 1024
)

type bandwidthRoute struct {
	prefix netip.Prefix
	client *bandwidthClient
}

type bandwidthClient struct {
	id       string
	upload   bandwidthLane
	download bandwidthLane
}

type bandwidthLane struct {
	queue chan *buffer.View
	slots chan struct{}
}

func newBandwidthLane() bandwidthLane {
	return bandwidthLane{
		queue: make(chan *buffer.View, bandwidthPacketsPerDirection),
		slots: make(chan struct{}, bandwidthPacketsPerDirection),
	}
}

type approvedPacket struct {
	view *buffer.View
	lane *bandwidthLane
}

type tunBandwidth struct {
	ctx    context.Context
	cancel context.CancelFunc
	wait   func(context.Context, string, int) error

	routes  []bandwidthRoute
	clients []*bandwidthClient
	slots   chan struct{}
	ready   chan approvedPacket

	// Serialize shutdown with nonblocking enqueues so all packet ownership
	// can be recovered after workers stop.
	mu      sync.RWMutex
	workers sync.WaitGroup
}

func newTunBandwidth(inst amneziawg.Instance, opts DeviceOptions) (*tunBandwidth, error) {
	policy := opts.Bandwidth
	if policy.Wait == nil {
		return nil, errors.New("bandwidth requires a gate")
	}
	// UAPI string fields must each occupy one line so the peer configuration
	// consumed by the engine is exactly the set used to build the index.
	for _, value := range []string{
		inst.Obfuscation.H1, inst.Obfuscation.H2, inst.Obfuscation.H3, inst.Obfuscation.H4,
		inst.Obfuscation.I1, inst.Obfuscation.I2, inst.Obfuscation.I3, inst.Obfuscation.I4, inst.Obfuscation.I5,
		opts.ContentPaddingAddition, opts.RekeyAfterTime, opts.RekeyTimeout, opts.RejectAfterTime,
		opts.KeepaliveTimeout, opts.MaxHandshakeAttempts,
	} {
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("bandwidth-managed device has a multiline UAPI field")
		}
	}
	bindings := make(map[string]string, len(policy.ClientIDs))
	for key, id := range policy.ClientIDs {
		canonicalKey, err := wireguard.KeyToHex(key)
		if err != nil || canonicalKey == "" || (!policy.allowUnrestricted && id == "") || strings.TrimSpace(id) != id {
			return nil, errors.New("invalid bandwidth client binding")
		}
		if _, ok := bindings[canonicalKey]; ok {
			return nil, errors.New("duplicate bandwidth client binding")
		}
		bindings[canonicalKey] = id
	}

	var routes []bandwidthRoute
	var clients []*bandwidthClient
	byID := make(map[string]*bandwidthClient, len(bindings))
	for _, peer := range inst.Peers {
		key, err := wireguard.KeyToHex(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %q: invalid public key: %w", peer.Email, err)
		}
		id, ok := bindings[key]
		if !ok || len(peer.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %q: missing or duplicate bandwidth binding or missing AllowedIPs", peer.Email)
		}
		delete(bindings, key)
		owner := byID[id]
		if owner == nil {
			owner = &bandwidthClient{id: id}
			if id != "" {
				byID[id] = owner
			}
			clients = append(clients, owner)
		}
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("peer %q: invalid bandwidth AllowedIP %q", peer.Email, raw)
			}
			routes = append(routes, bandwidthRoute{prefix: prefix.Masked(), client: owner})
		}
	}
	if len(bindings) != 0 {
		return nil, errors.New("bandwidth binding refers to a peer outside the device")
	}
	slices.SortFunc(routes, func(a, b bandwidthRoute) int {
		return a.prefix.Addr().Compare(b.prefix.Addr())
	})
	for i := 1; i < len(routes); i++ {
		if routes[i-1].prefix.Overlaps(routes[i].prefix) {
			return nil, fmt.Errorf("overlapping bandwidth AllowedIPs %s and %s", routes[i-1].prefix, routes[i].prefix)
		}
	}
	return &tunBandwidth{
		wait: policy.Wait, routes: routes, clients: clients,
		slots: make(chan struct{}, bandwidthPacketsPerDevice),
		ready: make(chan approvedPacket, bandwidthPacketsPerDevice),
	}, nil
}

func (b *tunBandwidth) start(t *stackTun) {
	b.ctx, b.cancel = context.WithCancel(context.Background())
	for _, client := range b.clients {
		client.upload = newBandwidthLane()
		client.download = newBandwidthLane()
		b.workers.Add(2)
		go b.run(t, client.id, &client.upload, true)
		go b.run(t, client.id, &client.download, false)
	}
}

func (b *tunBandwidth) client(addr netip.Addr) *bandwidthClient {
	i := sort.Search(len(b.routes), func(i int) bool {
		return b.routes[i].prefix.Addr().Compare(addr) > 0
	})
	if i != 0 && b.routes[i-1].prefix.Contains(addr) {
		return b.routes[i-1].client
	}
	return nil
}

// Approved downlink packets retain their slots until Read consumes them.
func (b *tunBandwidth) release(lane *bandwidthLane) {
	<-lane.slots
	<-b.slots
}

// enqueue takes ownership of view when it is supplied. Buffer ownership on
// upload still belongs to the engine, so copy only after securing both slots.
func (b *tunBandwidth) enqueue(packet []byte, view *buffer.View, upload bool) {
	addr, ok := bandwidthPacketAddress(packet, upload)
	owner := b.client(addr)
	if !ok || owner == nil || len(packet) > bandwidth.MaxChunkBytes {
		if view != nil {
			view.Release()
		}
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	lane := &owner.download
	if upload {
		lane = &owner.upload
	}
	if !b.reserve(lane) {
		if view != nil {
			view.Release()
		}
		return
	}
	if view == nil {
		view = buffer.NewViewWithData(packet)
	}
	// Every queued packet owns a slot, so the lane always has room here.
	lane.queue <- view
}

func (b *tunBandwidth) read(buf [][]byte, sizes []int, offset int, done <-chan struct{}) (int, error) {
	var p approvedPacket
	select {
	case <-done:
		return 0, os.ErrClosed
	case p = <-b.ready:
	}
	for i := range buf {
		if i != 0 {
			select {
			case p = <-b.ready:
			default:
				return i, nil
			}
		}
		select {
		case <-done:
			p.view.Release()
			b.release(p.lane)
			return i, os.ErrClosed
		default:
		}
		sizes[i] = 0
		if offset < 0 || offset > len(buf[i]) || p.view.Size() > len(buf[i])-offset {
			p.view.Release()
			b.release(p.lane)
			continue
		}
		n, err := p.view.Read(buf[i][offset:])
		p.view.Release()
		b.release(p.lane)
		if err != nil {
			return i, err
		}
		sizes[i] = n
	}
	return len(buf), nil
}

func (b *tunBandwidth) reserve(lane *bandwidthLane) bool {
	if b.ctx.Err() != nil {
		return false
	}
	select {
	case lane.slots <- struct{}{}:
	default:
		return false
	}
	select {
	case b.slots <- struct{}{}:
		return true
	default:
		<-lane.slots
		return false
	}
}

func (b *tunBandwidth) run(t *stackTun, id string, lane *bandwidthLane, upload bool) {
	defer b.workers.Done()
	for b.ctx.Err() == nil {
		select {
		case <-b.ctx.Done():
			return
		case view := <-lane.queue:
			if (id != "" && b.wait(b.ctx, id, view.Size()) != nil) || b.ctx.Err() != nil {
				view.Release()
			} else if upload {
				t.inject(view.AsSlice()[0]>>4, buffer.MakeWithView(view))
			} else {
				// The ready queue can hold every outstanding device slot.
				b.ready <- approvedPacket{view: view, lane: lane}
				continue
			}
			b.release(lane)
		}
	}
}

func (b *tunBandwidth) close() {
	b.mu.Lock()
	b.cancel()
	b.mu.Unlock()
	b.workers.Wait()
	for _, client := range b.clients {
		for _, lane := range []*bandwidthLane{&client.upload, &client.download} {
			for len(lane.queue) > 0 {
				(<-lane.queue).Release()
				b.release(lane)
			}
		}
	}
	for {
		select {
		case p := <-b.ready:
			p.view.Release()
			b.release(p.lane)
		default:
			return
		}
	}
}

func bandwidthPacketAddress(packet []byte, source bool) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	// AWG checked the authenticated peer's AllowedIPs before writing the
	// upload here. Downlink routing uses the same immutable prefix set.
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= header.IPv4MinimumSize {
			h := header.IPv4(packet)
			if source {
				return addrFromTcpip(h.SourceAddress()), true
			}
			return addrFromTcpip(h.DestinationAddress()), true
		}
	case 6:
		if len(packet) >= header.IPv6MinimumSize {
			h := header.IPv6(packet)
			if source {
				return addrFromTcpip(h.SourceAddress()), true
			}
			return addrFromTcpip(h.DestinationAddress()), true
		}
	}
	return netip.Addr{}, false
}
