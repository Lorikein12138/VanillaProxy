package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/google/uuid"
)

func newManagerBandwidthFixture(t *testing.T) (*Manager, Instance) {
	t.Helper()
	cert, key := generateTestCert(t)
	manager := &Manager{servers: map[int]*managed{}, lastStartErr: map[int]string{}}
	t.Cleanup(manager.StopAll)
	return manager, Instance{
		Id: 99129, Tag: "bandwidth-manager", Listen: "127.0.0.1",
		Certificate: string(cert), PrivateKey: string(key), ALPN: []string{"h3"}, LogLevel: "error",
		Clients: []TuicClientSettings{{UUID: "ec0bb914-6b1b-46f8-a266-dcf19901178c", Password: "native-password", Email: "Case.Sensitive@example.test", TrafficID: 29}},
	}
}

func TestManagerBandwidthConfigureBeforeFirstSuccessfulStart(t *testing.T) {
	wait := func(context.Context, string, int) error { return nil }
	resolve := func(string) (string, bool) { return "account", true }
	manager, inst := newManagerBandwidthFixture(t)
	if err := manager.ConfigureBandwidth(nil, resolve); err == nil {
		t.Fatal("configured a nil gate")
	}
	if err := manager.ConfigureBandwidth(wait, nil); err == nil {
		t.Fatal("configured a nil account resolver")
	}
	inst.Certificate = ""
	if err := manager.Ensure(inst); err == nil {
		t.Fatal("failed fixture should not start")
	}
	if err := manager.ConfigureBandwidth(wait, resolve); err != nil {
		t.Fatalf("configure after unsuccessful start: %v", err)
	}
	if err := manager.ConfigureBandwidth(wait, resolve); err == nil {
		t.Fatal("configured a second time")
	}

	stock, inst := newManagerBandwidthFixture(t)
	if err := stock.Ensure(inst); err != nil {
		t.Fatal(err)
	}
	server := stock.servers[inst.Id].server
	if server.bandwidth != nil || server.bandwidthClient != nil || server.relay.RequireBoundUDP {
		t.Fatal("stock server inherited managed options")
	}
	stock.StopAll()
	if err := stock.ConfigureBandwidth(wait, resolve); err == nil {
		t.Fatal("configured after the first server had been stopped")
	}
}

func TestManagerAutomaticBandwidthMatchesRunningAuthentication(t *testing.T) {
	manager, inst := newManagerBandwidthFixture(t)
	if err := manager.ConfigureAutomaticBandwidth(func(context.Context, string, int) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := manager.Ensure(inst); err == nil {
		t.Fatal("automatic listener accepted a regular start without policy bindings")
	}
	client := inst.Clients[0]
	desired := BandwidthDesired{Instance: inst, ClientIDs: map[string]string{client.Email: ""}}
	if err := manager.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil {
		t.Fatal(err)
	}
	live := manager.servers[inst.Id].server
	gate := live.relay.Gate
	t.Cleanup(func() { gate.Invalidate(inst.Id) })
	if manager.MatchesBandwidth(desired) {
		t.Fatal("reported a listener whose relay was unavailable")
	}
	update, err := gate.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	update.Finish(inst.Id, []string{client.Email}, true)
	if !manager.MatchesBandwidth(desired) {
		t.Fatal("listener and relay were both ready for the exact client")
	}
	if err := manager.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil || manager.servers[inst.Id].server != live {
		t.Fatalf("reapplying the same binding replaced a running listener: %v", err)
	}
	desired.Instance.Clients = append([]TuicClientSettings(nil), inst.Clients...)
	desired.Instance.Clients[0].Password = "rotated"
	if manager.MatchesBandwidth(desired) {
		t.Fatal("reported a running listener for a password never applied")
	}
	if err := manager.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil {
		t.Fatal(err)
	}
	if live.IsRunning() || !manager.MatchesBandwidth(desired) {
		t.Fatal("rotated authentication did not replace the old listener")
	}
	desired.Instance.Certificate = ""
	if err := manager.ReconcileBandwidth([]BandwidthDesired{desired}); err == nil || manager.HasRunning() {
		t.Fatal("failed replacement retained a listener")
	}
}

func TestManagerBandwidthReconcileReplacesChangedSnapshots(t *testing.T) {
	manager, inst := newManagerBandwidthFixture(t)
	client := &inst.Clients[0]
	accountByEmail := map[string]string{client.Email: "account-a", "alternate@example.test": "account-new"}
	var chargedAccount string
	if err := manager.ConfigureBandwidth(func(_ context.Context, id string, _ int) error {
		chargedAccount = id
		return nil
	}, func(email string) (string, bool) {
		id, ok := accountByEmail[email]
		return id, ok
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Ensure(inst); err != nil {
		t.Fatal(err)
	}
	server := manager.servers[inst.Id].server
	checkBinding := func(server *Server, expected string) {
		t.Helper()
		if !server.relay.RequireBoundUDP || server.relay.Password != SocksPassword() {
			t.Fatal("managed startup did not secure the SOCKS relay")
		}
		id := uuid.MustParse(client.UUID)
		user := server.users.users[id]
		if user == nil || user.Password != client.Password || user.Email != client.Email {
			t.Fatal("managed startup did not use the current authentication settings")
		}
		if err := server.waitBandwidth(context.Background(), user, 1); err != nil || chargedAccount != expected {
			t.Fatalf("account charged = %q, err = %v, want %q", chargedAccount, err, expected)
		}
		if _, ok := server.bandwidthClient(id, client.UUID); ok {
			t.Fatal("accepted a UUID in place of the password")
		}
		if _, ok := server.bandwidthClient(uuid.New(), client.Password); ok {
			t.Fatal("accepted an unknown UUID")
		}
	}
	checkBinding(server, "account-a")

	client.UUID = "urn:uuid:" + strings.ToUpper(client.UUID)
	manager.Reconcile([]Instance{inst})
	if manager.servers[inst.Id].server != server {
		t.Fatal("restarted for equivalent UUID spelling")
	}
	accountByEmail[client.Email] = "account-new"
	checkBinding(server, "account-a") // The live resolver does not consult the mutable account directory.
	nextServer := func(expected string) {
		t.Helper()
		manager.Reconcile([]Instance{inst})
		current := manager.servers[inst.Id]
		if current == nil || current.server == server || server.IsRunning() {
			t.Fatal("changed authentication or account data did not replace the listener")
		}
		server = current.server
		checkBinding(server, expected)
	}
	nextServer("account-new")
	oldPassword := client.Password
	client.Password = "rotated-password"
	nextServer("account-new")
	if _, ok := server.bandwidthClient(uuid.MustParse(client.UUID), oldPassword); ok {
		t.Fatal("replacement resolver accepted an old password")
	}
	client.UUID = "c6fabb6d-1a45-4ac7-8a4d-cef873eca2a3"
	nextServer("account-new")
	client.Email = "alternate@example.test"
	nextServer("account-new")
	if !manager.AddTestTraffic(inst.Id, client.Email, 8, 5) {
		t.Fatal("record traffic on managed server")
	}
	client.Email = strings.ToUpper(client.Email)
	if err := manager.Ensure(inst); err == nil || manager.HasRunning() {
		t.Fatalf("unbound exact email should stop the old server: %v", err)
	}
	deltas := manager.CollectClientTraffic()
	if len(deltas) != 1 || deltas[0].TrafficID != client.TrafficID || deltas[0].Up != 8 || deltas[0].Down != 5 {
		t.Fatalf("traffic lost when rejecting replacement: %+v", deltas)
	}
	manager.Reconcile([]Instance{inst})
	if manager.HasRunning() {
		t.Fatal("reconcile fell back to an unbound server")
	}
}

func TestManagerBandwidthChargesAuthenticatedQUICTraffic(t *testing.T) {
	manager, inst := newManagerBandwidthFixture(t)
	user := inst.Clients[0]
	port := SOCKSPortForInbound(inst.Id)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayGate := ManagedRelayGate(port)
	update, err := relayGate.BeginUpdate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	update.Finish(inst.Id, []string{user.Email}, true)
	defer relayGate.Invalidate(inst.Id)

	var charged atomic.Int64
	if err := manager.ConfigureBandwidth(func(_ context.Context, id string, n int) error {
		if id != "account-from-directory" {
			t.Errorf("wrong account charged: %q", id)
		}
		charged.Add(int64(n))
		return nil
	}, func(email string) (string, bool) {
		return "account-from-directory", email == user.Email
	}); err != nil {
		t.Fatal(err)
	}
	manager.Reconcile([]Instance{inst})
	if manager.servers[inst.Id] == nil {
		t.Fatalf("reconcile could not start listener: %s", manager.lastStartErr[inst.Id])
	}
	server := manager.servers[inst.Id].server
	client, err := quic.DialAddr(ctx, server.packetConn.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "test complete") })
	id := uuid.MustParse(user.UUID)
	tlsState := client.ConnectionState().TLS
	token, err := tlsState.ExportKeyingMaterial(string(id[:]), []byte(user.Password), 32)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{ProtocolVersion, CmdAuthenticate}, id[:]...)
	if _, err := auth.Write(append(frame, token...)); err != nil {
		t.Fatal(err)
	}
	closeUniStream(t, auth)
	authenticatedServerConnection(t, server, id)
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	request := bytes.NewBuffer([]byte{ProtocolVersion, CmdConnect})
	target := &Address{Type: AddrTypeIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if err := WriteAddress(request, target); err != nil {
		t.Fatal(err)
	}
	payload := []byte("manager bandwidth")
	request.Write(payload)
	if _, err := stream.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetDeadline(deadline)
	relay, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	_ = relay.SetDeadline(deadline)
	expectSocksBytes(t, relay, []byte{5, 1, 2})
	writeSocksTestBytes(t, relay, []byte{5, 2})
	password := SocksPassword()
	authRequest := append([]byte{1, byte(len(user.Email))}, user.Email...)
	authRequest = append(authRequest, byte(len(password)))
	expectSocksBytes(t, relay, append(authRequest, password...))
	writeSocksTestBytes(t, relay, []byte{1, 0})
	relayRequest := buildSocks5ConnectRequest(target)
	expectSocksBytes(t, relay, relayRequest)
	relayRequest[1] = 0
	writeSocksTestBytes(t, relay, relayRequest)
	expectSocksBytes(t, relay, payload)
	writeSocksTestBytes(t, relay, payload)

	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echo); err != nil || !bytes.Equal(echo, payload) {
		t.Fatalf("SOCKS echo = %q, err = %v", echo, err)
	}
	if got := charged.Load(); got != int64(2*len(payload)) {
		t.Fatalf("charged %d bytes, want %d", got, 2*len(payload))
	}
}

func TestManagerBandwidthRejectsPredictableRelayPassword(t *testing.T) {
	for _, password := range []string{"", "tuic-fallback-000000000000000000000000000000000000000000000000", strings.Repeat("a", 256)} {
		if err := requireManagedRelayPassword(password); err == nil {
			t.Fatal("accepted unusable managed relay password")
		}
	}
	if err := requireManagedRelayPassword(SocksPassword()); err != nil {
		t.Fatal(err)
	}
}
