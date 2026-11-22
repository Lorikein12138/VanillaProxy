package amneziawgnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

func bandwidthKeypair(t *testing.T) (string, string) {
	t.Helper()
	priv, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestBandwidthRejectsAmbiguousPeerBindings(t *testing.T) {
	_, keyA := bandwidthKeypair(t)
	_, keyB := bandwidthKeypair(t)
	canonicalKeyA, _ := wireguard.KeyToHex(keyA)
	for _, tt := range []struct {
		name   string
		keys   []string
		routes []string
		ids    map[string]string
	}{
		{"missing", []string{keyA, keyB}, []string{"10.4.0.1/32", "10.4.0.2/32"}, map[string]string{keyA: "a"}},
		{"duplicate peer", []string{keyA, keyA}, []string{"10.4.0.1/32", "10.4.0.2/32"}, map[string]string{keyA: "a"}},
		{"duplicate key alias", []string{keyA, keyB}, []string{"10.4.0.1/32", "10.4.0.2/32"}, map[string]string{keyA: "a", canonicalKeyA: "c", keyB: "b"}},
		{"overlapping IPv4", []string{keyA, keyB}, []string{"10.4.0.1/24", "10.4.0.2/32"}, map[string]string{keyA: "a", keyB: "b"}},
		{"overlap within one client", []string{keyA, keyB}, []string{"10.4.0.1/24", "10.4.0.2/32"}, map[string]string{keyA: "a", keyB: "a"}},
		{"overlapping IPv6", []string{keyA, keyB}, []string{"fd00:4::1/64", "fd00:4::2/128"}, map[string]string{keyA: "a", keyB: "b"}},
		{"malformed", []string{keyA, keyB}, []string{"10.4.0.1", "10.4.0.2/32"}, map[string]string{keyA: "a", keyB: "b"}},
		{"mapped IPv6", []string{keyA, keyB}, []string{"::ffff:10.4.0.1/128", "10.4.0.2/32"}, map[string]string{keyA: "a", keyB: "b"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inst := amneziawg.Instance{Peers: []amneziawg.Peer{
				{PublicKey: tt.keys[0], AllowedIPs: []string{tt.routes[0]}},
				{PublicKey: tt.keys[1], AllowedIPs: []string{tt.routes[1]}},
			}}
			opts := DeviceOptions{Bandwidth: &BandwidthOptions{
				ClientIDs: tt.ids, Wait: func(context.Context, string, int) error { return nil },
			}}
			if _, err := newTunBandwidth(inst, opts); err == nil {
				t.Fatal("accepted invalid bandwidth binding")
			}
		})
	}
}

func TestBandwidthTUNSharesQueuesAcrossKeysAndIsolatesClients(t *testing.T) {
	_, keyA := bandwidthKeypair(t)
	_, secondKeyA := bandwidthKeypair(t)
	_, keyB := bandwidthKeypair(t)
	a := netip.MustParseAddrPort("10.77.0.2:40000")
	secondA := netip.MustParseAddrPort("10.77.0.4:40000")
	b := netip.MustParseAddrPort("10.77.0.3:40000")
	dest := netip.MustParseAddrPort("10.77.9.9:5353")
	blocked := make(chan struct{}, 2)
	it := amneziawg.Instance{Peers: []amneziawg.Peer{
		{PublicKey: keyA, AllowedIPs: []string{"10.77.0.2/32"}},
		{PublicKey: secondKeyA, AllowedIPs: []string{"10.77.0.4/32"}},
		{PublicKey: keyB, AllowedIPs: []string{"10.77.0.3/32"}},
	}}
	opts := DeviceOptions{Bandwidth: &BandwidthOptions{
		ClientIDs: map[string]string{keyA: "a", secondKeyA: "a", keyB: "b"},
		Wait: func(ctx context.Context, id string, n int) error {
			if id == "a" {
				blocked <- struct{}{}
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
	}}
	gate, err := newTunBandwidth(it, opts)
	if err != nil {
		t.Fatal(err)
	}
	ownerA := gate.client(a.Addr())
	if ownerA == nil || ownerA.id != "a" || gate.client(secondA.Addr()) != ownerA {
		t.Fatal("two keys for one client did not resolve to the same queue and canonical identity")
	}
	tun, gstack, err := createNetTUNWithBandwidth([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, 1420, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	received := make(chan netip.AddrPort, 1)
	AttachUDPHandler(gstack, func(src, _ netip.AddrPort, _ []byte) { received <- src })
	payload := []byte("packet")
	clientAddresses := []netip.AddrPort{a, secondA}
	for i := 0; i < bandwidthPacketsPerDirection*2; i++ {
		src := clientAddresses[i%len(clientAddresses)]
		_, _ = tun.Write([][]byte{udpDatagram(src, dest, payload)}, 0)
		if err := WriteUDPReply(gstack, dest, src, payload); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-blocked:
		case <-time.After(time.Second):
			t.Fatal("both directions did not reach the gate")
		}
	}
	if len(ownerA.upload.slots) != bandwidthPacketsPerDirection || len(ownerA.download.slots) != bandwidthPacketsPerDirection {
		t.Fatalf("client occupancy = %d upload / %d download", len(ownerA.upload.slots), len(ownerA.download.slots))
	}

	_, _ = tun.Write([][]byte{udpDatagram(b, dest, payload)}, 0)
	if err := WriteUDPReply(gstack, dest, b, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != b {
			t.Fatalf("handler got %s, want %s", got, b)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting client blocked another client's upload")
	}
	delivered := make(chan netip.Addr, 1)
	go func() {
		buf := [][]byte{make([]byte, 1420)}
		sizes := make([]int, 1)
		if n, err := tun.Read(buf, sizes, 0); n == 1 && err == nil {
			addr, _ := bandwidthPacketAddress(buf[0][:sizes[0]], false)
			delivered <- addr
		}
	}()
	select {
	case got := <-delivered:
		if got != b.Addr() {
			t.Fatalf("TUN emitted packet to %s, want %s", got, b.Addr())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting client blocked another client's download")
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(gate.slots); got != 0 {
		t.Fatalf("close retained %d queued packets", got)
	}
}

func TestBandwidthDeviceGatesEncryptedUDPRoundTrip(t *testing.T) {
	t.Run("metered", func(t *testing.T) { testBandwidthDeviceEncryptedUDPRoundTrip(t, false) })
	t.Run("unrestricted", func(t *testing.T) { testBandwidthDeviceEncryptedUDPRoundTrip(t, true) })
}

func testBandwidthDeviceEncryptedUDPRoundTrip(t *testing.T, unrestricted bool) {
	t.Helper()
	serverPriv, serverPub := bandwidthKeypair(t)
	clientPriv, clientPub := bandwidthKeypair(t)
	clientAddr := netip.MustParseAddr("10.207.0.2")
	inst := amneziawg.Instance{
		PrivateKey: serverPriv, Listen: "127.0.0.1", Address: []string{"10.207.0.1/24"}, MTU: 1420,
		Peers: []amneziawg.Peer{{PublicKey: clientPub, Email: "display@example.test", AllowedIPs: []string{"10.207.0.2/32"}}},
	}
	const clientID = "canonical-client"
	const payload = "udp request"
	type permit struct {
		id      string
		n       int
		release chan bool
	}
	requests := make(chan permit, 8)
	opts := DeviceOptions{Bandwidth: &BandwidthOptions{
		ClientIDs: map[string]string{clientPub: clientID},
		Wait: func(ctx context.Context, id string, n int) error {
			if unrestricted {
				t.Error("an unrestricted peer reached the bandwidth gate")
				return errors.New("unexpected lease")
			}
			p := permit{id: id, n: n, release: make(chan bool, 1)}
			select {
			case requests <- p:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case allow := <-p.release:
				if allow {
					return nil
				}
				return errors.New("denied")
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}}
	if unrestricted {
		opts.Bandwidth.allowUnrestricted = true
		opts.Bandwidth.ClientIDs[clientPub] = ""
	}
	dev, err := NewUnconfiguredDevice(inst, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	// Refreshing the caller's binding map must not change a running device.
	opts.Bandwidth.ClientIDs[clientPub] = "different"
	replies := make(chan error, 2)
	AttachUDPHandler(dev.Stack, func(src, dst netip.AddrPort, p []byte) {
		replies <- WriteUDPReply(dev.Stack, dst, src, p)
	})
	if err := dev.Configure(inst, opts); err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet("replace_peers=true\n"); !errors.Is(err, errFixedBandwidthDevice) {
		t.Fatalf("managed device accepted raw configuration: %v", err)
	}
	if err := dev.Configure(inst, opts); !errors.Is(err, errFixedBandwidthDevice) {
		t.Fatalf("managed device accepted repeated configuration: %v", err)
	}
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	listenPort, _ := parseUAPIDump(dump)
	if listenPort == 0 {
		t.Fatal("device has no listen port")
	}
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientAddr}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	client := device.NewDevice(clientTun, newListenBind(""), device.NewLogger(device.LogLevelSilent, ""))
	defer client.Close()
	cpriv, _ := wireguard.KeyToHex(clientPriv)
	spub, _ := wireguard.KeyToHex(serverPub)
	conf := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", cpriv, spub, listenPort)
	if err := client.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}
	conn, err := clientNet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.207.9.9:5353"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitPermit := func() permit {
		t.Helper()
		select {
		case p := <-requests:
			if p.id != clientID || p.n != 28+len(payload) {
				t.Fatalf("gate received client %q, %d bytes", p.id, p.n)
			}
			return p
		case <-time.After(5 * time.Second):
			t.Fatal("encrypted packet never reached gate")
			return permit{}
		}
	}
	send := func() {
		t.Helper()
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if unrestricted {
		send()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("unrestricted reply = %q, %v", buf[:n], err)
		}
		return
	}
	noHandler := func() {
		t.Helper()
		select {
		case <-replies:
			t.Fatal("UDP handler observed an unapproved upload")
		default:
		}
	}
	send()
	denied := waitPermit()
	noHandler()
	denied.release <- false
	send()
	upload := waitPermit()
	noHandler()
	upload.release <- true
	down := waitPermit()
	select {
	case err := <-replies:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not complete")
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("client observed an unapproved download")
	}
	down.release <- true
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != payload {
		t.Fatalf("approved reply = %q, %v", buf[:n], err)
	}
}
