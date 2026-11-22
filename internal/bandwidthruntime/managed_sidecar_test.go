package bandwidthruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"golang.org/x/net/proxy"
)

func TestManagedSidecarsUsePrivateChildWithoutDoubleCharging(t *testing.T) {
	const user, account, password = "Peer.A@example.test", "shared-account", "private-child-test-credential"
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	node, err := StartNode(NodeConfig{
		NodeID: "sidecar-node", Generation: "test-generation",
		ClientRates: map[string]int64{account: 100_000}, Authorize: authorizeTestRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })

	api := listenLoopback(t)
	apiPort := api.Addr().(*net.TCPAddr).Port
	_ = api.Close()
	var cfg xray.Config
	configJSON := fmt.Sprintf(`{
		"log":{"loglevel":"none"},
		"api":{"tag":"api","services":["StatsService"]},
		"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"rewriteAddress":"127.0.0.1"}}],
		"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]},
		"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"ip":["127.0.0.1/32"],"action":"allow"}]}}]
	}`, apiPort)
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatal(err)
	}
	relays := make(map[string]launch.SidecarRelay)
	for _, relay := range []struct {
		kind string
		port func(int) int
	}{
		{launch.TUICRelay, tuic.SOCKSPortForInbound},
		{launch.AmneziaWGRelay, amneziawgnet.SOCKSPortForInbound},
	} {
		id, port := reserveSidecarTestPort(t, relay.port)
		tag := "private-" + relay.kind
		inbound := xray.InboundConfig{Protocol: "socks", Tag: tag, Port: port, Settings: []byte(fmt.Sprintf(`{"accounts":[{"user":%q,"pass":%q}]}`, user, password))}
		if relay.kind == launch.TUICRelay {
			inbound.TuicRelay, inbound.TuicInboundID = true, id
		} else {
			inbound.AmneziaWGRelay, inbound.AmneziaWGInboundID = true, id
		}
		cfg.InboundConfigs = append(cfg.InboundConfigs, inbound)
		relays[tag] = launch.SidecarRelay{
			Kind: relay.kind, InboundID: id, Port: port, Password: password, Accounts: map[string]string{user: account},
		}
		if relay.kind == launch.AmneziaWGRelay {
			relay := relays[tag]
			relay.Automatic = true
			relay.Accounts[user] = ""
			relays[tag] = relay
		}
	}
	process, err := node.NewManagedXrayWithRelays(&cfg, nil, relays)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Stop() })
	disk, err := os.ReadFile(xray.GetConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{password, "private-tuic", "private-amneziawg"} {
		if strings.Contains(string(disk), private) {
			t.Fatalf("on-disk Xray configuration contains private relay material %q", private)
		}
	}
	for tag, relay := range relays {
		t.Run(tag, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			backend := listenLoopback(t)
			_ = backend.SetDeadline(time.Now().Add(5 * time.Second))
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(relay.Port))
			for _, auth := range []proxy.Auth{{User: "unknown", Password: password}, {User: user, Password: "wrong"}} {
				rejected, err := proxy.SOCKS5("tcp4", addr, &auth, proxy.Direct)
				if err != nil {
					t.Fatal(err)
				}
				if conn, err := rejected.(proxy.ContextDialer).DialContext(ctx, "tcp4", backend.Addr().String()); err == nil {
					conn.Close()
					t.Fatal("unknown or wrong private relay credential was accepted")
				}
			}
			dialer, err := proxy.SOCKS5("tcp4", addr, &proxy.Auth{User: user, Password: password}, proxy.Direct)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp4", backend.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			peer, err := backend.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
			// No root exchange or active client lease exists. The already
			// metered SOCKS traffic must not hit the node gate a second time.
			for _, flow := range [][2]net.Conn{{conn, peer}, {peer, conn}} {
				if _, err := flow[0].Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				var got [2]byte
				if _, err := io.ReadFull(flow[1], got[:]); err != nil || string(got[:]) != "ok" {
					t.Fatalf("sidecar relay payload = %q, err = %v", got, err)
				}
			}
			verifyManagedSidecarUDP(t, ctx, addr, user, password)
		})
	}
}

func verifyManagedSidecarUDP(t *testing.T, ctx context.Context, addr, user, password string) {
	t.Helper()
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	relay := tuic.SocksRelay{Addr: addr, Password: password, RequireBoundUDP: true}
	session, err := relay.DialUDP(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	target := backend.LocalAddr().(*net.UDPAddr)
	destination := &tuic.Address{Type: tuic.AddrTypeIPv4, IP: target.IP, Port: uint16(target.Port)}
	if _, err := session.Send(destination, []byte("udp")); err != nil {
		t.Fatal(err)
	}
	_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	var packet [16]byte
	n, from, err := backend.ReadFromUDP(packet[:])
	if err != nil || string(packet[:n]) != "udp" {
		t.Fatalf("UDP backend payload = %q, err = %v", packet[:n], err)
	}
	if _, err := backend.WriteToUDP(packet[:n], from); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		var response [64]byte
		source, payload, err := session.Receive(response[:])
		if err == nil && (source.Port != destination.Port || string(payload) != "udp") {
			err = fmt.Errorf("unexpected relayed UDP response: %v, %q", source, payload)
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func reserveSidecarTestPort(t *testing.T, resolvePort func(int) int) (int, int) {
	t.Helper()
	for id := 1; id <= 50; id++ {
		port := resolvePort(id)
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = listener.Close()
			return id, port
		}
	}
	t.Fatal("no reserved sidecar test port available")
	return 0, 0
}
