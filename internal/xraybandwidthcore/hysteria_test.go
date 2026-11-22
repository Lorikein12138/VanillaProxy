package xraybandwidthcore

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"google.golang.org/protobuf/proto"
)

func TestManagedHysteriaRejectsUnsupportedReceiver(t *testing.T) {
	config, _, _, _ := wireConfigs(t, "hysteria@client.test")
	for _, tc := range []struct {
		name   string
		change func(*proxyman.ReceiverConfig)
		want   string
	}{
		{
			name: "zero port", want: "requires one UDP port",
			change: func(c *proxyman.ReceiverConfig) { c.PortList.Range[0] = xnet.SinglePortRange(0) },
		},
		{
			name: "multiple ports", want: "requires one UDP port",
			change: func(c *proxyman.ReceiverConfig) { c.PortList.Range[0].To++ },
		},
		{
			name: "unix", want: "requires an IP listen address",
			change: func(c *proxyman.ReceiverConfig) { c.Listen = xnet.NewIPOrDomain(xnet.DomainAddress("/tmp/hy.sock")) },
		},
		{
			name: "malformed listen address", want: "requires an IP listen address",
			change: func(c *proxyman.ReceiverConfig) { c.Listen = &xnet.IPOrDomain{} },
		},
		{
			name: "original destination", want: "does not support transparent reception",
			change: func(c *proxyman.ReceiverConfig) { c.ReceiveOriginalDestination = true },
		},
		{
			name: "transparent socket", want: "does not support transparent reception",
			change: func(c *proxyman.ReceiverConfig) {
				c.StreamSettings.SocketSettings = &internet.SocketConfig{Tproxy: internet.SocketConfig_TProxy}
			},
		},
		{
			name: "shared auth", want: "requires per-user auth",
			change: func(c *proxyman.ReceiverConfig) {
				c.StreamSettings.TransportSettings[0].Settings = serial.ToTypedMessage(&hytransport.Config{Auth: "shared"})
			},
		},
		{
			name: "proxy masquerade", want: "must not proxy masquerade requests",
			change: func(c *proxyman.ReceiverConfig) {
				c.StreamSettings.TransportSettings[0].Settings = serial.ToTypedMessage(&hytransport.Config{MasqType: "PrOxY"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := proto.CloneOf(config)
			inbound := input.Inbound[1]
			var receiver proxyman.ReceiverConfig
			if err := proto.Unmarshal(inbound.ReceiverSettings.Value, &receiver); err != nil {
				t.Fatal(err)
			}
			tc.change(&receiver)
			inbound.ReceiverSettings = serial.ToTypedMessage(&receiver)
			instance, err := NewWithManagedInbounds(t.Context(), input, guardTestResolver, guardTestGate, ManagedInboundTags{
				Hysteria: []string{"hysteria"},
			})
			if err == nil {
				_ = instance.Close()
				t.Fatal("accepted unsupported Hysteria receiver")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestManagedHysteriaMetersUDP(t *testing.T) {
	const (
		email = "udp@client.test"
		id    = "udp-account"
		up    = "upload datagram"
		down  = "download datagram"
	)
	var mu sync.Mutex
	remaining := len(up) + len(down)
	resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || inbound.Tag != "hysteria" || inbound.Name != "hysteria" || user == nil || user.Email != email {
			return "", false, errors.New("expected the authenticated Hysteria association")
		}
		return id, true, nil
	}
	gate := func(_ context.Context, account string, size int) error {
		mu.Lock()
		defer mu.Unlock()
		if account != id || size < 1 || size > remaining {
			return errors.New("unexpected datagram grant")
		}
		remaining -= size
		return nil
	}

	config, _, clientConfig, release := wireConfigs(t, email)
	server, err := NewWithManagedInbounds(t.Context(), config, resolve, gate, ManagedInboundTags{Hysteria: []string{"hysteria"}})
	if err != nil {
		t.Fatal(err)
	}
	release()
	startWireCore(t, server)
	client, err := core.New(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	startWireCore(t, client)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: xnet.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(target.LocalAddr().(*net.UDPAddr).Port))
	tunnel, err := core.Dial(ctx, client, dest)
	if err != nil {
		t.Fatal(err)
	}
	stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
	defer func() {
		if stop() {
			_ = tunnel.Close()
		}
	}()
	if _, err := tunnel.Write([]byte(up)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, peer, err := target.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != up {
		t.Fatalf("target received %q with error %v", buffer[:n], err)
	}
	if _, err := target.WriteToUDP([]byte(down), peer); err != nil {
		t.Fatal(err)
	}
	n, err = tunnel.Read(buffer)
	if err != nil || string(buffer[:n]) != down {
		t.Fatalf("client received %q with error %v", buffer[:n], err)
	}
	mu.Lock()
	defer mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining datagram budget = %d, want 0", remaining)
	}
}
