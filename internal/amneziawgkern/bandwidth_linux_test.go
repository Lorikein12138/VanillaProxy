//go:build linux

package amneziawgkern

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelBandwidthClassifiesBothHooksAndChargesOriginalLength(t *testing.T) {
	routes, err := validateBandwidthRoutes([]BandwidthRoute{
		{AllowedIP: netip.MustParsePrefix("10.8.0.2/32"), AccountID: "sender"},
		{AllowedIP: netip.MustParsePrefix("10.8.0.3/32"), Unmetered: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := &BandwidthGate{queue: 50000, ifIndex: 7, routes: routes}
	for _, tc := range []struct {
		name        string
		hook        byte
		in, out     uint32
		fullLength  uint32
		wantAccount string
		unmetered   bool
	}{
		{"upload", unix.NF_INET_PRE_ROUTING, 7, 0, 1280, "sender", false},
		{"unmetered download", unix.NF_INET_POST_ROUTING, 0, 7, 1280, "", true},
		{"wrong input interface", unix.NF_INET_PRE_ROUTING, 8, 7, 1280, "", false},
		{"wrong output interface", unix.NF_INET_POST_ROUTING, 7, 8, 1280, "", false},
		{"bad original length", unix.NF_INET_POST_ROUTING, 0, 7, 60, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte{unix.AF_INET, 0, 0, 0}
			binary.BigEndian.PutUint16(msg[2:], gate.queue)
			msg = appendBandwidthAttr(msg, bwAttrPacket, []byte{0, 0, 0, 1, 8, 0, tc.hook})
			msg = appendBandwidthAttr(msg, bwAttrIn, binary.BigEndian.AppendUint32(nil, tc.in))
			msg = appendBandwidthAttr(msg, bwAttrOut, binary.BigEndian.AppendUint32(nil, tc.out))
			msg = appendBandwidthAttr(msg, bwAttrLength, binary.BigEndian.AppendUint32(nil, tc.fullLength))
			payload := make([]byte, bwHeaderBytes)
			payload[0] = 0x45
			binary.BigEndian.PutUint16(payload[2:], 1280)
			copy(payload[12:], []byte{10, 8, 0, 2, 10, 8, 0, 3})
			msg = appendBandwidthAttr(msg, bwAttrPayload, payload)
			packet, known := gate.parseBandwidthPacket(msg)
			if !known || packet.id != 1 || packet.account != tc.wantAccount || packet.unmetered != tc.unmetered ||
				((tc.wantAccount != "" || tc.unmetered) && packet.bytes != 1280) {
				t.Fatalf("classified packet %+v, known %v", packet, known)
			}
		})
	}
}

func TestKernelBandwidthRejectsOverlappingRoutes(t *testing.T) {
	_, err := validateBandwidthRoutes([]BandwidthRoute{
		{AllowedIP: netip.MustParsePrefix("10.8.0.2/24"), AccountID: "first"},
		{AllowedIP: netip.MustParsePrefix("10.8.0.3/32"), AccountID: "second"},
	})
	if err == nil {
		t.Fatal("accepted an overlapping peer route")
	}
}

// Run only in a disposable network namespace with nft and NFQUEUE available.
func TestKernelBandwidthNFQueue(t *testing.T) {
	if os.Getenv("VANILLAPROXY_TEST_NFQUEUE") != "1" {
		t.Skip("requires an explicitly isolated Linux namespace and CAP_NET_ADMIN")
	}
	mustRun := func(name string, args ...string) {
		t.Helper()
		if output, err := run("", name, args...); err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, output)
		}
	}
	const name = "xui-awg94321"
	mustRun("ip", "link", "add", name, "type", "dummy")
	linkExists := true
	t.Cleanup(func() {
		if linkExists {
			mustRun("ip", "link", "del", name)
		}
	})
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := parseOwnedInterfaceName(name)
	const generation = "00112233445566778899aabbccddeeff"
	nat := bandwidthNAT{Generation: generation, IfIndex: iface.Index, Egress: "lo", Subnets: []netip.Prefix{netip.MustParsePrefix("10.203.42.0/24")}}
	if err := nftBandwidthWrite(nat.create(id, name)); err != nil {
		t.Fatal(err)
	}
	permits := make(chan bandwidthPacket, 1)
	routes := []BandwidthRoute{
		{AllowedIP: netip.MustParsePrefix("10.203.42.2/32"), AccountID: "alice"},
	}
	wait := func(_ context.Context, account string, size int) error {
		select {
		case permits <- bandwidthPacket{account: account, bytes: size}:
		default:
		}
		return nil
	}
	mustRun("nft", "add", "table", "inet", "foreign_queue")
	mustRun("nft", "add", "chain", "inet", "foreign_queue", "output", "{ type filter hook output priority 0; policy accept; }")
	mustRun("nft", "add", "rule", "inet", "foreign_queue", "output", "queue", "num", "40000-40001", "bypass")
	if _, err := OpenBandwidthGate(name, iface.Index, routes, wait); err == nil || !strings.Contains(err.Error(), "external nftables NFQUEUE") {
		t.Fatalf("did not reject foreign queue range: %v", err)
	}
	mustRun("nft", "delete", "table", "inet", "foreign_queue")
	gate, err := OpenBandwidthGate(name, iface.Index, routes, wait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		gate.Block()
		if linkExists {
			mustRun("ip", "link", "del", name)
			linkExists = false
		}
		if err := gate.Close(); err != nil {
			t.Error(err)
		}
	})
	mustRun("ip", "address", "add", "10.203.42.1/24", "dev", name)
	mustRun("ip", "link", "set", name, "up")
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 203, 42, 2), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, 1200)); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-permits:
		if packet.account != "alice" || packet.bytes != 1228 {
			t.Fatalf("unexpected permit %+v", packet)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NFQUEUE never requested a permit")
	}
	if !gate.Healthy() {
		t.Fatal("queue stopped unexpectedly")
	}
	mustRun("nft", "add", "table", "ip", "unrelated_nat")
	mustRun("nft", "add", "chain", "ip", "unrelated_nat", "postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }")
	time.Sleep(100 * time.Millisecond)
	if !gate.Healthy() {
		t.Fatal("an unrelated NAT table stopped the bandwidth gate")
	}
	mustRun("nft", "flush", "chain", "inet", gate.table, "upload")
	deadline := time.Now().Add(3 * time.Second)
	for {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if !gate.Healthy() && iface.Flags&net.FlagUp == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bandwidth rule drift missed: healthy %v, link flags %s", gate.Healthy(), iface.Flags)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := gate.Close(); err == nil {
		t.Fatal("removed guard before deleting its interface")
	}
	if gate.Healthy() {
		t.Fatal("queue is still healthy after blocking")
	}
	mustRun("ip", "link", "del", name)
	linkExists = false
	mustRun("nft", "add", "set", "inet", gate.table, "foreign_set", "{ type ipv4_addr; }")
	if err := gate.Close(); err == nil {
		t.Fatal("removed a bandwidth table containing an unowned object")
	}
	mustRun("nft", "delete", "set", "inet", gate.table, "foreign_set")
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStaleBandwidthGate(name); err != nil {
		t.Fatal(err)
	}
	manager := newManager(osHost{}, t.TempDir())
	if err := manager.removeBandwidthEgress(id, name, nat); err != nil {
		t.Fatalf("matching NAT cleanup failed: %v", err)
	}
	if _, err := run("", "nft", "-an", "list", "table", "ip", bandwidthNATTable(id)); err == nil {
		t.Fatal("NAT table is still present")
	}
	if err := nftBandwidthWrite(bandwidthRules(bandwidthTableName(id), name, iface.Index, 50000, fmt.Sprintf("%s %s %d 50000 %s", bwMarker, name, iface.Index, generation))); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleBandwidthGate(name, "11112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("removed a stale table owned by another generation")
	}
	if err := removeStaleBandwidthGate(name, generation); err != nil {
		t.Fatalf("matching filter cleanup failed: %v", err)
	}
}
