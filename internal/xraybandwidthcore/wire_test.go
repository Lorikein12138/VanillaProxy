package xraybandwidthcore

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestVLESSAndHysteria2ShareTCPBudget(t *testing.T) {
	const (
		request  = "upstream payload"
		response = "downstream payload"
		budget   = len(request) + len(response)
		email    = "shared@client.test"
		clientID = "shared-account"
	)
	var (
		mu        sync.Mutex
		remaining = budget
		denials   int
	)
	resolve := func(_ context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user == nil || user.Account == nil || user.Email != email {
			return "", false, errors.New("expected the authenticated test account")
		}
		return clientID, true, nil
	}
	gate := func(_ context.Context, id string, size int) error {
		if id != clientID || size <= 0 {
			return errors.New("unexpected account or grant size")
		}
		mu.Lock()
		defer mu.Unlock()
		if size > remaining {
			denials++
			return errors.New("test account has exhausted its byte budget")
		}
		remaining -= size
		return nil
	}
	balance := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return remaining, denials
	}
	serverConfig, vlessConfig, hysteriaConfig, releasePorts := wireConfigs(t, email)
	server, err := NewWithManagedInbounds(t.Context(), serverConfig, resolve, gate, ManagedInboundTags{
		VLESS: []string{"vless"}, Hysteria: []string{"hysteria"},
	})
	if err != nil {
		t.Fatalf("create metered Xray server: %v", err)
	}
	releasePorts()
	startWireCore(t, server)
	newClient := func(config *core.Config) *core.Instance {
		t.Helper()
		client, err := core.New(config)
		if err != nil {
			t.Fatalf("create Xray client: %v", err)
		}
		startWireCore(t, client)
		return client
	}
	vlessClient := newClient(vlessConfig)
	hysteriaClient := newClient(hysteriaConfig)

	exchange := func(t *testing.T, client *core.Instance, blocked bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		target := listenWireTCP(t)
		defer target.Close()
		if err := target.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target.Addr().(*net.TCPAddr).Port))
		conn, err := core.Dial(ctx, client, dest)
		if err != nil {
			t.Fatalf("dial through Xray: %v", err)
		}
		// core.Dial returns a pipe-backed connection with no socket deadlines.
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer func() {
			if stop() {
				_ = conn.Close()
			}
		}()
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write upload: %v", err)
		}
		backend, err := target.AcceptTCP()
		if err != nil {
			t.Fatalf("accept at TCP target: %v", err)
		}
		defer backend.Close()
		if err := backend.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		upload := make([]byte, len(request))
		n, err := io.ReadFull(backend, upload)
		if blocked {
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("target read %d denied upload bytes with error %v, want EOF before payload", n, err)
			}
			if left, rejected := balance(); left != 0 || rejected == 0 {
				t.Fatalf("after denied upload, remaining=%d denials=%d", left, rejected)
			}
			return
		}
		if err != nil || string(upload) != request {
			t.Fatalf("target read %q with error %v, want %q", upload[:n], err, request)
		}
		if left, _ := balance(); left != len(response) {
			t.Fatalf("after upload, remaining=%d, want %d", left, len(response))
		}
		if _, err := io.WriteString(backend, response); err != nil {
			t.Fatalf("write download: %v", err)
		}
		download := make([]byte, len(response))
		n, err = io.ReadFull(conn, download)
		if err != nil || string(download) != response {
			t.Fatalf("client read %q with error %v, want %q", download[:n], err, response)
		}
		if left, _ := balance(); left != 0 {
			t.Fatalf("after download, remaining=%d, want 0", left)
		}
	}
	if !t.Run("VLESS charges both directions", func(t *testing.T) {
		exchange(t, vlessClient, false)
	}) {
		return
	}
	if !t.Run("Hysteria2 is denied on the same exhausted account", func(t *testing.T) {
		exchange(t, hysteriaClient, true)
	}) {
		return
	}
	mu.Lock()
	remaining = budget
	mu.Unlock()
	t.Run("Hysteria2 charges both directions after refill", func(t *testing.T) {
		exchange(t, hysteriaClient, false)
	})
}

func wireConfigs(t *testing.T, email string) (server, vl, hy *core.Config, releasePorts func()) {
	t.Helper()
	const (
		vlessID = "1ebb16a5-d32a-45bf-9d3a-0ada9d8789c0"
		hyAuth  = "hysteria-test-password"
	)
	vlessPort := listenWireTCP(t)
	t.Cleanup(func() { _ = vlessPort.Close() })
	hysteriaPort, err := net.ListenUDP("udp4", &net.UDPAddr{IP: xnet.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hysteriaPort.Close() })
	releasePorts = func() {
		_ = vlessPort.Close()
		_ = hysteriaPort.Close()
	}
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	vlessUser := &protocol.User{Email: email, Account: serial.ToTypedMessage(&vless.Account{Id: vlessID})}
	hysteriaUser := &protocol.User{Email: email, Account: serial.ToTypedMessage(&hyaccount.Account{Auth: hyAuth})}
	vlessEndpoint := &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
		Port:    uint32(vlessPort.Addr().(*net.TCPAddr).Port),
		User:    vlessUser,
	}
	hysteriaEndpoint := &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
		Port:    uint32(hysteriaPort.LocalAddr().(*net.UDPAddr).Port),
	}
	hysteriaInbound := wireHysteriaStream("", &tls.Config{
		Certificate: []*tls.Certificate{serverCertificate},
	})
	hysteriaOutbound := wireHysteriaStream(hyAuth, &tls.Config{
		PinnedPeerCertSha256: [][]byte{hash[:]},
	})
	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	server = &core.Config{
		App: apps,
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vless",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					Listen:   vlessEndpoint.Address,
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(vlessEndpoint.Port))}},
				}),
				ProxySettings: serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{vlessUser}}),
			},
			{
				Tag: "hysteria",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					Listen:         hysteriaEndpoint.Address,
					PortList:       &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(hysteriaEndpoint.Port))}},
					StreamSettings: hysteriaInbound,
				}),
				ProxySettings: serial.ToTypedMessage(&hysteria.ServerConfig{Users: []*protocol.User{hysteriaUser}}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}
	vl = &core.Config{
		App: apps,
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: vlessEndpoint}),
		}},
	}
	hy = &core.Config{
		App: apps,
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: hysteriaOutbound}),
			ProxySettings:  serial.ToTypedMessage(&hysteria.ClientConfig{Server: hysteriaEndpoint}),
		}},
	}
	return server, vl, hy, releasePorts
}

func wireHysteriaStream(auth string, security *tls.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName: "hysteria",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "hysteria",
			Settings:     serial.ToTypedMessage(&hytransport.Config{Auth: auth, UdpIdleTimeout: 2}),
		}},
		SecurityType:     serial.GetMessageType(security),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
	}
}

func listenWireTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: xnet.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func startWireCore(t *testing.T, instance *core.Instance) {
	t.Helper()
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatalf("start Xray: %v", err)
	}
}
