package xraybandwidthcore

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestManagedVLESSVisionTLSMetersDirectCopy(t *testing.T) {
	testManagedVLESSWire(t, visionWireOptions{flow: vless.XRV})
}

func TestManagedVLESSREALITYMetersBothDirections(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		testManagedVLESSWire(t, visionWireOptions{useREALITY: true})
	})
	t.Run("vision", func(t *testing.T) {
		testManagedVLESSWire(t, visionWireOptions{flow: vless.XRV, useREALITY: true})
	})
}

func TestManagedVLESSREALITYVisionEncryptionMetersBothDirections(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	testManagedVLESSWire(t, visionWireOptions{
		flow: vless.XRV, useREALITY: true,
		decryption: "mlkem768x25519plus.native.600s." + privateKey,
		encryption: "mlkem768x25519plus.native.0rtt." + publicKey,
	})
}

func TestManagedVLESSREALITYVisionEncryptionRejectsWrongCredentials(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, accountID string
		key             *ecdh.PublicKey
	}{
		{name: "encryption key", accountID: visionTestUUID, key: otherKey.PublicKey()},
		{name: "VLESS UUID", accountID: "2e2394a1-f126-40e4-bd2b-975995ab2cef", key: key.PublicKey()},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			var resolved, granted atomic.Bool
			resolve := func(context.Context, *protocol.MemoryUser) (string, bool, error) {
				resolved.Store(true)
				return "vision-account", true, nil
			}
			gate := func(context.Context, string, int) error {
				granted.Store(true)
				return nil
			}
			var uploadWire, downloadWire visionWireBytes
			client := startVisionWire(t, ctx, visionWireOptions{
				email: "managed", flow: vless.XRV, useREALITY: true, accountID: test.accountID,
				decryption: "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes()),
				encryption: "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(test.key.Bytes()),
			}, resolve, gate, &uploadWire, &downloadWire)
			target := listenWireTCP(t)
			defer target.Close()
			tunnel, err := core.Dial(ctx, client, xnet.DestinationFromAddr(target.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Close()
			stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
			defer stop()
			if _, err := io.WriteString(tunnel, "invalid credentials"); err != nil {
				t.Fatal(err)
			}
			var packet [1]byte
			if n, err := tunnel.Read(packet[:]); n != 0 || err == nil || ctx.Err() != nil {
				t.Fatalf("expected the authenticated inbound to close the connection, received %d bytes: %v (context: %v)", n, err, ctx.Err())
			}
			if resolved.Load() || granted.Load() {
				t.Fatal("unauthenticated traffic reached account metering")
			}
		})
	}
}

const visionTestUUID = "e42a4e08-1ba4-40bc-9251-13acd2d8139b"
const visionExemptUUID = "80d0ff86-4f9f-4b74-9ea9-666c8cae37cc"

func TestManagedVLESSVisionTLSExemptAccountXUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resolve := func(_ context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user != nil {
			if account, ok := user.Account.(*vless.MemoryAccount); ok && account.ID != nil && account.Flow == vless.XRV {
				switch {
				case user.Email == "exempt" && account.ID.String() == visionExemptUUID:
					return "", false, nil
				case user.Email == "managed" && account.ID.String() == visionTestUUID:
					return "vision-account", true, nil
				}
			}
		}
		return "", false, errors.New("unrecognized VLESS credentials")
	}
	gate := func(context.Context, string, int) error {
		return errors.New("XUDP used the bandwidth gate for an exempt account")
	}
	var uploadWire, downloadWire visionWireBytes
	client := startVisionWire(t, ctx, visionWireOptions{email: "exempt", flow: vless.XRV}, resolve, gate, &uploadWire, &downloadWire)
	target := authTestListenUDP(t)
	deadline, _ := ctx.Deadline()
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	tunnel, err := core.Dial(ctx, client, xnet.DestinationFromAddr(target.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
	defer stop()
	if _, err := tunnel.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	var packet [16]byte
	n, peer, err := target.ReadFromUDP(packet[:])
	if err != nil || string(packet[:n]) != "upload" {
		t.Fatalf("XUDP target received %q: %v", packet[:n], err)
	}
	if _, err := target.WriteToUDP([]byte("download"), peer); err != nil {
		t.Fatal(err)
	}
	n, err = tunnel.Read(packet[:])
	if err != nil || string(packet[:n]) != "download" {
		t.Fatalf("XUDP client received %q: %v", packet[:n], err)
	}
}

func testManagedVLESSWire(t *testing.T, options visionWireOptions) {
	t.Helper()
	options.email = "managed"
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const clientID = "vision-account"
	var grants atomic.Int64
	var blocked atomic.Pointer[visionGateBlock]
	resolve := func(_ context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user == nil || user.Email != "managed" {
			return "", false, errors.New("expected the authenticated VLESS account")
		}
		if account, ok := user.Account.(*vless.MemoryAccount); !ok || account.ID == nil ||
			account.ID.String() != visionTestUUID || account.Flow != options.flow {
			return "", false, errors.New("expected the VLESS credentials for this connection")
		}
		return clientID, true, nil
	}
	gate := func(_ context.Context, id string, n int) error {
		if id != clientID || n <= 0 {
			return errors.New("unexpected VLESS account or grant size")
		}
		if block := blocked.Load(); block != nil {
			block.once.Do(func() { close(block.entered) })
			select {
			case <-block.release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		grants.Add(int64(n))
		return nil
	}

	var uploadWire, downloadWire visionWireBytes
	target := listenWireTCP(t)
	defer target.Close()
	client := startVisionWire(t, ctx, options, resolve, gate, &uploadWire, &downloadWire)
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target.Addr().(*net.TCPAddr).Port))
	conn, err := core.Dial(ctx, client, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stopClient := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClient()

	// The inner ordinary TLS session uses a different certificate. Its encrypted
	// application records only appear on the relay once Vision switches to raw TCP.
	innerCert, _ := cert.MustGenerate(nil, cert.CommonName("origin.test"), cert.DNSNames("origin.test"))
	certPEM, keyPEM := innerCert.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("parse inner TLS certificate")
	}
	var uploadInner, downloadInner visionWireBytes
	innerClient := gotls.Client(visionRecordedConn{Conn: conn, written: &uploadInner}, &gotls.Config{
		MinVersion: gotls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "origin.test",
	})
	backend, innerServer := startVisionOrigin(t, ctx, target, keyPair, &downloadInner, innerClient)
	defer backend.Close()

	// Read the first application record in both directions before blocking the
	// gate. In Vision mode these records mark the transition to direct copy.
	for _, direction := range []struct {
		from *gotls.Conn
		to   *gotls.Conn
	}{
		{from: innerClient, to: innerServer},
		{from: innerServer, to: innerClient},
	} {
		if _, err := io.WriteString(direction.from, "prime"); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len("prime"))
		if _, err := io.ReadFull(direction.to, received); err != nil || string(received) != "prime" {
			t.Fatalf("prime Vision TLS received %q: %v", received, err)
		}
	}

	for _, direction := range []struct {
		name  string
		from  *gotls.Conn
		to    *gotls.Conn
		inner *visionWireBytes
		wire  *visionWireBytes
	}{
		{name: "upload", from: innerClient, to: innerServer, inner: &uploadInner, wire: &uploadWire},
		{name: "download", from: innerServer, to: innerClient, inner: &downloadInner, wire: &downloadWire},
	} {
		if !t.Run(direction.name, func(t *testing.T) {
			const silence = 100 * time.Millisecond
			accounted := grants.Load()
			innerStart, wireStart := direction.inner.Len(), direction.wire.Len()
			block := &visionGateBlock{entered: make(chan struct{}), release: make(chan struct{})}
			blocked.Store(block)
			release := sync.OnceFunc(func() {
				blocked.Store(nil)
				close(block.release)
			})
			defer release()

			payload := bytes.Repeat([]byte("meter "+direction.name), 512)
			write := make(chan error, 1)
			go func() {
				_, err := direction.from.Write(payload)
				write <- err
			}()
			firstRead := make(chan error, 1)
			read := make(chan error, 1)
			received := make([]byte, len(payload))
			go func() {
				n, err := direction.to.Read(received)
				firstRead <- err
				if err == nil {
					_, err = io.ReadFull(direction.to, received[n:])
				}
				read <- err
			}()
			select {
			case <-block.entered:
			case err := <-firstRead:
				t.Fatalf("peer received data before the account gate: %v", err)
			case <-ctx.Done():
				t.Fatal("data did not reach the account gate")
			}
			select {
			case err := <-firstRead:
				t.Fatalf("peer received data while the account gate was held: %v", err)
			case <-time.After(silence):
			}
			if got := grants.Load(); got != accounted {
				t.Fatalf("gate granted %d bytes while blocked", got-accounted)
			}
			release()
			if err := <-write; err != nil {
				t.Fatal(err)
			}
			if err := <-read; err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("peer did not receive the released payload: %v", err)
			}
			record := direction.inner.Since(innerStart)
			if len(record) <= len(payload) {
				t.Fatalf("missing inner TLS ciphertext for a %d byte payload", len(payload))
			}
			if options.flow == vless.XRV && options.encryption == "" && !bytes.Contains(direction.wire.Since(wireStart), record) {
				t.Fatalf("inner TLS ciphertext (%d bytes) did not appear on the raw Vision wire", len(record))
			}
			if options.encryption != "" {
				verifyVisionREALITYDirectCopy(t, direction.wire.Since(wireStart), record)
			}
			if got := grants.Load() - accounted; got != int64(len(record)) {
				t.Fatalf("accounted %d bytes, want %d inner TLS record bytes", got, len(record))
			}
		}) {
			return
		}
	}
	if want := int64(uploadInner.Len() + downloadInner.Len()); grants.Load() != want {
		t.Fatalf("accounted %d bytes across both directions, want %d inner TLS bytes", grants.Load(), want)
	}
}

func verifyVisionREALITYDirectCopy(t *testing.T, wire, innerRecord []byte) {
	t.Helper()
	if bytes.Contains(wire, innerRecord) {
		t.Fatalf("inner TLS ciphertext (%d bytes) appeared outside REALITY", len(innerRecord))
	}
	const tlsHeader = 5
	const tls13Overhead = 16 + 1 // AEAD tag and encrypted content type.
	payload := 0
	for len(wire) > 0 {
		if len(wire) < tlsHeader || wire[0] != 23 {
			t.Fatal("expected a TLS application record on the outer REALITY wire")
		}
		size := int(binary.BigEndian.Uint16(wire[3:tlsHeader]))
		if size < tls13Overhead || tlsHeader+size > len(wire) {
			t.Fatalf("invalid outer REALITY record length %d", size)
		}
		payload += size - tls13Overhead
		wire = wire[tlsHeader+size:]
	}
	if payload != len(innerRecord) {
		t.Fatalf("outer REALITY carried %d bytes after the TLS overhead, want exactly %d inner TLS bytes after the Vision switch", payload, len(innerRecord))
	}
}

type visionGateBlock struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type visionWireBytes struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *visionWireBytes) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *visionWireBytes) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Len()
}

func (b *visionWireBytes) Since(offset int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data.Bytes()[offset:])
}

type visionRecordedConn struct {
	net.Conn
	written *visionWireBytes
}

func (c visionRecordedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	_, _ = c.written.Write(p[:n])
	return n, err
}

func startVisionOrigin(t *testing.T, ctx context.Context, listener *net.TCPListener, cert gotls.Certificate,
	written *visionWireBytes, client *gotls.Conn,
) (*net.TCPConn, *gotls.Conn) {
	t.Helper()
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	type originResult struct {
		raw *net.TCPConn
		tls *gotls.Conn
		err error
	}
	origin := make(chan originResult, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			origin <- originResult{err: err}
			return
		}
		server := gotls.Server(visionRecordedConn{Conn: conn, written: written}, &gotls.Config{
			MinVersion:             gotls.VersionTLS13,
			Certificates:           []gotls.Certificate{cert},
			SessionTicketsDisabled: true,
		})
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			origin <- originResult{err: err}
			return
		}
		err = server.HandshakeContext(ctx)
		if err != nil {
			_ = conn.Close()
		}
		origin <- originResult{raw: conn, tls: server, err: err}
	}()
	clientErr := client.HandshakeContext(ctx)
	result := <-origin
	if clientErr != nil || result.err != nil {
		if result.raw != nil {
			_ = result.raw.Close()
		}
		t.Fatalf("inner TLS handshake failed, client: %v, origin: %v", clientErr, result.err)
	}
	return result.raw, result.tls
}

type visionWireOptions struct {
	email      string
	flow       string
	useREALITY bool
	decryption string
	encryption string
	accountID  string
}

func startVisionWire(t *testing.T, ctx context.Context, options visionWireOptions,
	resolve func(context.Context, *protocol.MemoryUser) (string, bool, error),
	gate func(context.Context, string, int) error, upload, download *visionWireBytes,
) *core.Instance {
	t.Helper()
	serverPort := listenWireTCP(t)
	defer serverPort.Close()
	relay := listenWireTCP(t)
	t.Cleanup(func() { _ = relay.Close() })
	serverAddress := serverPort.Addr().(*net.TCPAddr)
	relayAddress := relay.Addr().(*net.TCPAddr)
	var serverStream, clientStream *internet.StreamConfig
	if options.useREALITY {
		serverStream, clientStream = startWireREALITYCover(t, ctx)
	} else {
		certificate, hash := cert.MustGenerate(nil, cert.CommonName("outer.test"))
		serverCertificate := tls.ParseCertificate(certificate)
		serverCertificate.OneTimeLoading = true
		serverStream = wireVisionTLSStream(&tls.Config{
			Certificate: []*tls.Certificate{serverCertificate},
			MinVersion:  "1.3",
		})
		clientStream = wireVisionTLSStream(&tls.Config{
			PinnedPeerCertSha256: [][]byte{hash[:]},
			MinVersion:           "1.3",
		})
	}
	config := newGuardTestConfig()
	managed := newGuardTestUser("managed", &vless.Account{Id: visionTestUUID, Flow: options.flow})
	exempt := newGuardTestUser("exempt", &vless.Account{Id: visionExemptUUID, Flow: options.flow})
	user := managed
	if options.email == "exempt" {
		user = exempt
	}
	serverSettings := serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{managed, exempt}})
	clientSettings := serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
		Port:    uint32(relayAddress.Port),
		User:    user,
	}})
	if options.encryption != "" {
		serverConfig := &conf.VLessInboundConfig{
			Decryption: options.decryption,
			Flow:       options.flow,
			Clients: []json.RawMessage{
				json.RawMessage(`{"email":"managed","id":"` + visionTestUUID + `"}`),
				json.RawMessage(`{"email":"exempt","id":"` + visionExemptUUID + `"}`),
			},
		}
		serverProxy, err := serverConfig.Build()
		if err != nil {
			t.Fatal(err)
		}
		serverSettings = serial.ToTypedMessage(serverProxy)
		accountID := options.accountID
		if accountID == "" {
			accountID = visionTestUUID
		}
		clientConfig := &conf.VLessOutboundConfig{
			Address:    &conf.Address{Address: xnet.LocalHostIP},
			Port:       uint16(relayAddress.Port),
			Email:      options.email,
			Id:         accountID,
			Flow:       options.flow,
			Encryption: options.encryption,
		}
		clientProxy, err := clientConfig.Build()
		if err != nil {
			t.Fatal(err)
		}
		clientSettings = serial.ToTypedMessage(clientProxy)
	}
	config.Inbound[0].ProxySettings = serverSettings
	config.Inbound[0].ReceiverSettings = serial.ToTypedMessage(&proxyman.ReceiverConfig{
		Listen:         xnet.NewIPOrDomain(xnet.LocalHostIP),
		PortList:       &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(serverAddress.Port))}},
		StreamSettings: serverStream,
	})
	config.Outbound = []*core.OutboundHandlerConfig{{
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	}}
	server, err := NewWithManagedVLESS(ctx, config, resolve, gate, []string{"managed"})
	if err != nil {
		t.Fatal(err)
	}
	_ = serverPort.Close()
	startWireCore(t, server)

	go relayVisionWire(ctx, relay, serverAddress, upload, download)
	client, err := core.New(&core.Config{
		App: config.App,
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: clientStream}),
			ProxySettings:  clientSettings,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	startWireCore(t, client)
	return client
}

func wireVisionTLSStream(security *tls.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		SecurityType:     serial.GetMessageType(security),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
	}
}

func startWireREALITYCover(t *testing.T, ctx context.Context) (*internet.StreamConfig, *internet.StreamConfig) {
	t.Helper()
	const serverName = "cover.test"
	cover := listenWireTCP(t)
	t.Cleanup(func() { _ = cover.Close() })
	certificate, _ := cert.MustGenerate(nil, cert.CommonName(serverName), cert.DNSNames(serverName))
	certPEM, keyPEM := certificate.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &gotls.Config{
		MinVersion:             gotls.VersionTLS13,
		MaxVersion:             gotls.VersionTLS13,
		Certificates:           []gotls.Certificate{keyPair},
		CurvePreferences:       []gotls.CurveID{gotls.X25519},
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
	}
	go func() {
		for {
			conn, err := cover.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = gotls.Server(conn, tlsConfig).HandshakeContext(ctx)
			}()
		}
	}()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	return wireREALITYStream(&reality.Config{
			Type:        "tcp",
			Dest:        cover.Addr().String(),
			ServerNames: []string{serverName},
			PrivateKey:  key.Bytes(),
			ShortIds:    [][]byte{shortID},
		}), wireREALITYStream(&reality.Config{
			Fingerprint: "chrome",
			ServerName:  serverName,
			PublicKey:   key.PublicKey().Bytes(),
			ShortId:     shortID,
		})
}

func wireREALITYStream(security *reality.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName:     "tcp",
		SecurityType:     serial.GetMessageType(security),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
	}
}

func relayVisionWire(ctx context.Context, relay *net.TCPListener, server *net.TCPAddr, upload, download *visionWireBytes) {
	client, err := relay.AcceptTCP()
	if err != nil {
		return
	}
	defer client.Close()
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp4", server.String())
	if err != nil {
		return
	}
	defer backend.Close()
	deadline, _ := ctx.Deadline()
	_ = client.SetDeadline(deadline)
	_ = backend.SetDeadline(deadline)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, io.TeeReader(client, upload))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, io.TeeReader(backend, download))
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
