package xraybandwidthchild

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/transport/internet"
	masquetransport "github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestPatchedMASQUECONNECTIPMetersLoopback(t *testing.T) {
	if !hasNativeMASQUEPacketGate() {
		t.Skip("requires the patched native MASQUE server")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	target := listenTCP(t)
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: xnet.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := xnet.Port(udp.LocalAddr().(*net.UDPAddr).Port)
	certificate, pin := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true

	config := testMASQUEConfig(t)
	config.Inbound[0].ReceiverSettings = serial.ToTypedMessage(&proxyman.ReceiverConfig{
		Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
		PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
		StreamSettings: masqueWireStream(&tls.Config{
			Certificate: []*tls.Certificate{serverCertificate},
		}, &masquetransport.Config{Path: masquetransport.DefaultPath}),
	})
	config.Outbound = []*core.OutboundHandlerConfig{{
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(target.Addr().(*net.TCPAddr).Port),
			}},
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	}}
	bound, tags, err := bindClients(config, map[string]map[string]string{masqueTestTag: {masqueUser: clientID}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var bytes, packets int
	instance, err := xraybandwidthcore.NewWithManagedInbounds(ctx, config, bound.resolve, func(_ context.Context, client string, n int) error {
		if client != clientID || n < 20 {
			return errors.New("expected a complete IP packet for the bound MASQUE account")
		}
		mu.Lock()
		defer mu.Unlock()
		bytes += n
		packets++
		return nil
	}, tags)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := bound.verifyMASQUEPacketGates(ctx, instance); err != nil {
		t.Fatal(err)
	}
	_ = udp.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("auth-user:"+masquePass))
	client, err := core.New(&core.Config{
		App: config.App,
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&masque.ClientConfig{
				Server:    &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port)},
				RemoteDns: []string{"127.0.0.1"},
			}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: masqueWireStream(&tls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{pin[:]}},
					&masquetransport.Config{Path: masquetransport.DefaultPath, Headers: map[string]string{"Authorization": auth}}),
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	// The target inside the tunnel is redirected to the local test listener.
	tunnel, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 7))
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
	defer stop()

	const upload, download = "CONNECT-IP upload", "CONNECT-IP download"
	if _, err := io.WriteString(tunnel, upload); err != nil {
		t.Fatal(err)
	}
	backend, err := target.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err := backend.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(upload))
	if _, err := io.ReadFull(backend, got); err != nil || string(got) != upload {
		t.Fatalf("CONNECT-IP upload = %q, error = %v", got, err)
	}
	if _, err := io.WriteString(backend, download); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(download))
	if _, err := io.ReadFull(tunnel, got); err != nil || string(got) != download {
		t.Fatalf("CONNECT-IP download = %q, error = %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if packets < 2 || bytes <= len(upload)+len(download) {
		t.Fatalf("CONNECT-IP charged %d bytes over %d packets", bytes, packets)
	}
}

func masqueWireStream(security *tls.Config, config *masquetransport.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName: "masque",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "masque", Settings: serial.ToTypedMessage(config),
		}},
		SecurityType:     serial.GetMessageType(security),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
	}
}
