package xraybandwidthcore

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	socksclient "golang.org/x/net/proxy"
	"google.golang.org/protobuf/proto"
)

const (
	authTestTag      = "managed"
	authTestUser     = "local-user"
	authTestPassword = "local-test-password"
	authTestMaster   = "YWFhYWFhYWFhYWFhYWFhYQ=="
	authTestUserKey  = "YmJiYmJiYmJiYmJiYmJiYg=="
	authTestOther    = "other-user"
	authTestOtherKey = "Y2NjY2NjY2NjY2NjY2NjYw=="
)

func TestManagedAuthenticatedProxiesMeterTCP(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, key string
		config              proto.Message
		tags                ManagedInboundTags
	}{
		{
			name: "http", protocol: "http",
			config: &httpproxy.ServerConfig{Accounts: map[string]string{authTestUser: authTestPassword}},
			tags:   ManagedInboundTags{HTTP: []string{authTestTag}},
		},
		{
			name: "mixed HTTP", protocol: "http",
			config: &socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{authTestUser: authTestPassword}},
			tags:   ManagedInboundTags{Mixed: []string{authTestTag}},
		},
		{
			name: "mixed SOCKS5", protocol: "socks",
			config: &socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{authTestUser: authTestPassword}},
			tags:   ManagedInboundTags{Mixed: []string{authTestTag}},
		},
		{
			name: "SS2022 single-user", protocol: "shadowsocks-2022", key: authTestMaster,
			config: &ss2022.ServerConfig{
				Method: ss2022.MethodAES128GCM, Key: authTestMaster, Email: authTestUser, Network: []xnet.Network{xnet.Network_TCP},
			},
			tags: ManagedInboundTags{Shadowsocks2022: []string{authTestTag}},
		},
		{
			name: "SS2022 multi-user", protocol: "shadowsocks-2022-multi", key: authTestMaster + ":" + authTestUserKey,
			config: &ss2022.MultiUserServerConfig{
				Method: ss2022.MethodAES128GCM, Key: authTestMaster, Network: []xnet.Network{xnet.Network_TCP},
				Users: []*protocol.User{{Email: authTestUser, Account: serial.ToTypedMessage(&ss2022.Account{Key: authTestUserKey})}},
			},
			tags: ManagedInboundTags{Shadowsocks2022Multi: []string{authTestTag}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const upload, download = "test upload", "test download"
			var mu sync.Mutex
			remaining := len(upload) + len(download)
			resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
				inbound := session.InboundFromContext(ctx)
				if inbound == nil || inbound.Tag != authTestTag || inbound.Name != tc.protocol ||
					user == nil || user.Email != authTestUser {
					return "", false, errors.New("expected the authenticated proxy username")
				}
				if tc.protocol == "shadowsocks-2022-multi" {
					protocol, key := TypedAccountIdentity(user.Account)
					want, _ := base64.StdEncoding.DecodeString(authTestUserKey)
					if protocol != tc.protocol || key != string(want) {
						return "", false, errors.New("expected the authenticated Shadowsocks 2022 user key")
					}
				} else if user.Account != nil {
					return "", false, errors.New("unexpected account on statically authenticated proxy")
				}
				return authTestUser, true, nil
			}
			gate := func(_ context.Context, id string, size int) error {
				mu.Lock()
				defer mu.Unlock()
				if id != authTestUser || size <= 0 || size > remaining {
					return errors.New("unexpected proxy grant")
				}
				remaining -= size
				return nil
			}

			config, reservation := authTestConfig(t, tc.config)
			server, err := NewWithManagedInbounds(t.Context(), config, resolve, gate, tc.tags)
			if err != nil {
				t.Fatal(err)
			}
			listen := reservation.Addr().(*net.TCPAddr)
			_ = reservation.Close()
			startWireCore(t, server)

			target := listenWireTCP(t)
			defer target.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			if err := target.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			var conn net.Conn
			var reader io.Reader
			switch {
			case tc.key != "":
				conn = authTestSS2022Dial(t, ctx, config, xnet.DestinationFromAddr(listen), xnet.DestinationFromAddr(target.Addr()), tc.key)
				reader = conn
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
			case tc.protocol == "socks":
				client, err := socksclient.SOCKS5("tcp", listen.String(), &socksclient.Auth{User: authTestUser, Password: authTestPassword}, &net.Dialer{})
				if err != nil {
					t.Fatal(err)
				}
				conn, err = client.(socksclient.ContextDialer).DialContext(ctx, "tcp", target.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				reader = conn
			default:
				bad, _, status := authTestHTTPConnect(t, ctx, listen.String(), target.Addr().String(), "wrong-password")
				_ = bad.Close()
				if status != http.StatusProxyAuthRequired {
					t.Fatalf("wrong password status = %d", status)
				}
				var statusOK int
				conn, reader, statusOK = authTestHTTPConnect(t, ctx, listen.String(), target.Addr().String(), authTestPassword)
				if statusOK != http.StatusOK {
					_ = conn.Close()
					t.Fatalf("valid CONNECT status = %d", statusOK)
				}
			}
			defer conn.Close()
			if tc.key == "" {
				if err := conn.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := io.WriteString(conn, upload); err != nil {
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
			request := make([]byte, len(upload))
			if _, err := io.ReadFull(backend, request); err != nil || string(request) != upload {
				t.Fatalf("target received %q, error = %v", request, err)
			}
			if _, err := io.WriteString(backend, download); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(download))
			if _, err := io.ReadFull(reader, response); err != nil || string(response) != download {
				t.Fatalf("client received %q, error = %v", response, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if remaining != 0 {
				t.Fatalf("remaining proxy budget = %d, want 0", remaining)
			}
		})
	}
}

func TestManagedStaticGuardRequiresAuthenticatedMetadata(t *testing.T) {
	guard := guardStaticDispatcher{handler: &guardedStatic{
		name: "socks", alternate: "http", users: map[string]struct{}{authTestUser: {}},
	}}
	for _, tc := range []session.Inbound{
		{Name: "socks", User: &protocol.MemoryUser{}},
		{Name: "socks", User: &protocol.MemoryUser{Email: "other"}},
		{Name: "http", User: &protocol.MemoryUser{Email: strings.ToUpper(authTestUser)}},
		{Name: "vmess", User: &protocol.MemoryUser{Email: authTestUser}},
	} {
		ctx := session.ContextWithInbound(t.Context(), &tc)
		if _, err := guard.authorize(ctx); err == nil {
			t.Fatalf("accepted unauthenticated metadata %+v", tc)
		}
	}
	metadata := &session.Inbound{Name: "http", CanSpliceCopy: 1, User: &protocol.MemoryUser{Email: authTestUser}}
	ctx := session.ContextWithInbound(t.Context(), metadata)
	authorized, err := guard.authorize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	metadata.User.Email = "another-user"
	snapshot := session.InboundFromContext(authorized)
	if snapshot.User.Email != authTestUser || snapshot.CanSpliceCopy != 3 {
		t.Fatalf("authenticated request snapshot = %+v", snapshot)
	}
}

func TestManagedSS2022SingleUserMetersUDP(t *testing.T) {
	const upload, download = "upload datagram", "download datagram"
	var mu sync.Mutex
	remaining := len(upload) + len(download)
	denied := make(chan struct{}, 1)
	resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || inbound.Tag != authTestTag || inbound.Name != "shadowsocks-2022" ||
			user == nil || user.Email != authTestUser || user.Account != nil {
			return "", false, errors.New("expected authenticated Shadowsocks 2022 user")
		}
		return authTestUser, true, nil
	}
	gate := func(_ context.Context, user string, size int) error {
		mu.Lock()
		defer mu.Unlock()
		if user != authTestUser || size <= 0 {
			return errors.New("unexpected datagram grant")
		}
		if size > remaining {
			select {
			case denied <- struct{}{}:
			default:
			}
			return errors.New("datagram budget exhausted")
		}
		remaining -= size
		return nil
	}
	listenUDP := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: xnet.LocalHostIP.IP()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	reservation := listenUDP()
	listen := xnet.DestinationFromAddr(reservation.LocalAddr())
	config := authTestConfigAtPort(listen.Port, &ss2022.ServerConfig{
		Method: ss2022.MethodAES128GCM, Key: authTestMaster, Email: authTestUser, Network: []xnet.Network{xnet.Network_UDP},
	})
	server, err := NewWithManagedInbounds(t.Context(), config, resolve, gate, ManagedInboundTags{Shadowsocks2022: []string{authTestTag}})
	if err != nil {
		t.Fatal(err)
	}
	_ = reservation.Close()
	startWireCore(t, server)
	target := listenUDP()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	conn := authTestSS2022Dial(t, ctx, config, listen, xnet.DestinationFromAddr(target.LocalAddr()), authTestMaster)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := io.WriteString(conn, upload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, peer, err := target.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != upload {
		t.Fatalf("target received %q with error %v", buffer[:n], err)
	}
	if _, err := target.WriteToUDP([]byte(download), peer); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buffer)
	if err != nil || string(buffer[:n]) != download {
		t.Fatalf("client received %q with error %v", buffer[:n], err)
	}
	mu.Lock()
	left := remaining
	mu.Unlock()
	if left != 0 {
		t.Fatalf("remaining datagram budget = %d, want 0", left)
	}
	if _, err := io.WriteString(conn, upload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-denied:
	case <-ctx.Done():
		t.Fatal("existing Shadowsocks 2022 UDP session did not check the exhausted budget")
	}
}

func TestManagedMixedUDPSharedAcrossAssociations(t *testing.T) {
	config, reservation := authTestConfig(t, &socks.ServerConfig{
		AuthType: socks.AuthType_PASSWORD, UdpEnabled: true,
		Accounts: map[string]string{authTestUser: authTestPassword, authTestOther: "other-test-password"},
	})
	relayAddress := reservation.Addr().String()
	server := authTestStartMeteredUDP(t, config, reservation, "socks", ManagedInboundTags{Mixed: []string{authTestTag}})
	relay := &tuic.SocksRelay{Addr: relayAddress, Password: "incorrect-password"}
	if session, err := relay.DialUDP(server.ctx, authTestUser); err == nil {
		_ = session.Close()
		t.Fatal("Mixed accepted a UDP association with the wrong password")
	}
	open := func(user, password string, bound bool) authTestUDPExchange {
		t.Helper()
		relay := &tuic.SocksRelay{Addr: relayAddress, Password: password, RequireBoundUDP: bound}
		session, err := relay.DialUDP(server.ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = session.Close() })
		target := server.target.LocalAddr().(*net.UDPAddr)
		destination := &tuic.Address{Type: tuic.AddrTypeIPv4, IP: target.IP, Port: uint16(target.Port)}
		return authTestUDPExchange{
			send: func(payload []byte) error {
				_, err := session.Send(destination, payload)
				return err
			},
			receive: func(buffer []byte) (int, error) {
				source, payload, err := session.Receive(buffer)
				if err == nil && (source.Port != destination.Port || !source.IP.Equal(destination.IP)) {
					return 0, fmt.Errorf("unexpected Mixed UDP source: %v", source)
				}
				return copy(buffer, payload), err
			},
		}
	}
	// Test both a standard wildcard UDP association and a client that reports
	// its already-bound UDP endpoint. They use separate control connections.
	server.verify(t, open(authTestUser, authTestPassword, false), open(authTestUser, authTestPassword, true),
		open(authTestOther, "other-test-password", false))
}

func TestManagedSS2022MultiUserUDPSharesAccountAcrossSessions(t *testing.T) {
	if _, patched := any((*ss2022.MultiUserInbound)(nil)).(interface{ EnableManagedUDP() }); !patched {
		t.Skip("requires the patched Xray build")
	}
	reservation := authTestListenUDP(t)
	listen := xnet.DestinationFromAddr(reservation.LocalAddr())
	config := authTestConfigAtPort(listen.Port, &ss2022.MultiUserServerConfig{
		Method: ss2022.MethodAES128GCM, Key: authTestMaster, Network: []xnet.Network{xnet.Network_UDP},
		Users: []*protocol.User{
			{Email: authTestUser, Account: serial.ToTypedMessage(&ss2022.Account{Key: authTestUserKey})},
			{Email: authTestOther, Account: serial.ToTypedMessage(&ss2022.Account{Key: authTestOtherKey})},
		},
	})
	server := authTestStartMeteredUDP(t, config, reservation, "shadowsocks-2022-multi", ManagedInboundTags{
		Shadowsocks2022Multi: []string{authTestTag},
	})
	target := xnet.DestinationFromAddr(server.target.LocalAddr())
	open := func(userKey string) authTestUDPExchange {
		t.Helper()
		conn := authTestSS2022Dial(t, server.ctx, config, listen, target, authTestMaster+":"+userKey)
		t.Cleanup(func() { _ = conn.Close() })
		return authTestUDPExchange{
			send: func(payload []byte) error {
				_, err := conn.Write(payload)
				return err
			},
			receive: conn.Read,
		}
	}
	server.verify(t, open(authTestUserKey), open(authTestUserKey), open(authTestOtherKey))
}

const (
	authTestDatagramUpload   = "upload"
	authTestDatagramDownload = "download"
	authTestDatagramSize     = len(authTestDatagramUpload) + len(authTestDatagramDownload)
	authTestSharedAccount    = "shared-test-account"
	authTestSeparateAccount  = "separate-test-account"
)

type authTestUDPExchange struct {
	send    func([]byte) error
	receive func([]byte) (int, error)
}

type authTestUDPServer struct {
	ctx       context.Context
	target    *net.UDPConn
	denied    chan string
	mu        sync.Mutex
	remaining map[string]int
}

func authTestListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: xnet.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func authTestStartMeteredUDP(t *testing.T, config *core.Config, reservation io.Closer, protocolName string,
	tags ManagedInboundTags,
) *authTestUDPServer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	t.Cleanup(cancel)
	server := &authTestUDPServer{
		ctx: ctx, target: authTestListenUDP(t), denied: make(chan string, 2),
		remaining: map[string]int{authTestSharedAccount: 2 * authTestDatagramSize, authTestSeparateAccount: authTestDatagramSize},
	}
	resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || inbound.Tag != authTestTag || inbound.Name != protocolName || user == nil {
			return "", false, errors.New("expected authenticated UDP inbound metadata")
		}
		var id, key string
		switch user.Email {
		case authTestUser:
			id, key = authTestSharedAccount, authTestUserKey
		case authTestOther:
			id, key = authTestSeparateAccount, authTestOtherKey
		default:
			return "", false, errors.New("unexpected UDP account")
		}
		if protocolName == "shadowsocks-2022-multi" {
			name, actualKey := TypedAccountIdentity(user.Account)
			expectedKey, _ := base64.StdEncoding.DecodeString(key)
			if name != protocolName || actualKey != string(expectedKey) {
				return "", false, errors.New("unexpected authenticated Shadowsocks 2022 credential")
			}
		} else if user.Account != nil {
			return "", false, errors.New("expected an authenticated Mixed username")
		}
		return id, true, nil
	}
	gate := func(_ context.Context, id string, size int) error {
		server.mu.Lock()
		defer server.mu.Unlock()
		if size <= 0 || size > server.remaining[id] {
			select {
			case server.denied <- id:
			default:
			}
			return errors.New("UDP account budget exhausted")
		}
		server.remaining[id] -= size
		return nil
	}
	instance, err := NewWithManagedInbounds(ctx, config, resolve, gate, tags)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	startWireCore(t, instance)
	deadline, _ := ctx.Deadline()
	if err := server.target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return server
}

func (s *authTestUDPServer) verify(t *testing.T, first, second, separate authTestUDPExchange) {
	t.Helper()
	for _, association := range []authTestUDPExchange{first, second, separate} {
		var packet [128]byte
		if err := association.send([]byte(authTestDatagramUpload)); err != nil {
			t.Fatal(err)
		}
		n, peer, err := s.target.ReadFromUDP(packet[:])
		if err != nil || string(packet[:n]) != authTestDatagramUpload {
			t.Fatalf("target received %q: %v", packet[:n], err)
		}
		if _, err := s.target.WriteToUDP([]byte(authTestDatagramDownload), peer); err != nil {
			t.Fatal(err)
		}
		response := make(chan error, 1)
		go func() {
			var packet [128]byte
			n, err := association.receive(packet[:])
			if err == nil && string(packet[:n]) != authTestDatagramDownload {
				err = fmt.Errorf("client received %q", packet[:n])
			}
			response <- err
		}()
		select {
		case err := <-response:
			if err != nil {
				t.Fatal(err)
			}
		case <-s.ctx.Done():
			t.Fatal("UDP response did not arrive")
		}
	}
	s.mu.Lock()
	shared, other := s.remaining[authTestSharedAccount], s.remaining[authTestSeparateAccount]
	s.mu.Unlock()
	if shared != 0 || other != 0 {
		t.Fatalf("remaining UDP balances: shared=%d separate=%d", shared, other)
	}
	for _, association := range []authTestUDPExchange{first, second} {
		if err := association.send([]byte(authTestDatagramUpload)); err != nil {
			t.Fatal(err)
		}
		select {
		case id := <-s.denied:
			if id != authTestSharedAccount {
				t.Fatalf("datagram denied for %q, want shared account", id)
			}
		case <-s.ctx.Done():
			t.Fatal("UDP session did not check the shared exhausted budget")
		}
	}
	if err := s.target.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var packet [128]byte
	n, _, err := s.target.ReadFromUDP(packet[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("target received data past the shared account limit: %q, error = %v", packet[:n], err)
	}
}

func TestManagedStaticAndSS2022RejectInvalidConfig(t *testing.T) {
	networks := []xnet.Network{xnet.Network_TCP}
	multiUser := func(email, key string) *protocol.User {
		return &protocol.User{Email: email, Account: serial.ToTypedMessage(&ss2022.Account{Key: key})}
	}
	for _, tc := range []struct {
		name string
		cfg  proto.Message
		tags ManagedInboundTags
		want string
	}{
		{"anonymous HTTP", &httpproxy.ServerConfig{}, ManagedInboundTags{HTTP: []string{authTestTag}}, "username/password"},
		{"anonymous Mixed", &socks.ServerConfig{}, ManagedInboundTags{Mixed: []string{authTestTag}}, "requires password authentication"},
		{"Mixed UDP no accounts", &socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, UdpEnabled: true}, ManagedInboundTags{Mixed: []string{authTestTag}}, "username/password"},
		{"SS2022 unnamed", &ss2022.ServerConfig{Method: ss2022.MethodAES128GCM, Key: authTestMaster}, ManagedInboundTags{Shadowsocks2022: []string{authTestTag}}, "non-empty email"},
		{"SS2022 bad key", &ss2022.ServerConfig{Method: ss2022.MethodAES128GCM, Key: "short", Email: authTestUser}, ManagedInboundTags{Shadowsocks2022: []string{authTestTag}}, "invalid managed Shadowsocks 2022 server key"},
		{"SS2022 relay", &ss2022.RelayServerConfig{}, ManagedInboundTags{Shadowsocks2022: []string{authTestTag}}, "requires native proxy settings"},
		{
			"SS2022 multi unsupported network",
			&ss2022.MultiUserServerConfig{Network: []xnet.Network{xnet.Network_UNIX}},
			ManagedInboundTags{Shadowsocks2022Multi: []string{authTestTag}}, "TCP or UDP network",
		},
		{
			"SS2022 multi repeated key",
			&ss2022.MultiUserServerConfig{Method: ss2022.MethodAES128GCM, Key: authTestMaster, Network: networks,
				Users: []*protocol.User{multiUser("one", authTestUserKey), multiUser("two", authTestUserKey)}},
			ManagedInboundTags{Shadowsocks2022Multi: []string{authTestTag}}, "duplicate Shadowsocks 2022",
		},
		{
			"SS2022 multi shared server key",
			&ss2022.MultiUserServerConfig{Method: ss2022.MethodAES128GCM, Key: authTestMaster, Network: networks,
				Users: []*protocol.User{multiUser(authTestUser, authTestMaster)}},
			ManagedInboundTags{Shadowsocks2022Multi: []string{authTestTag}}, "distinct from the server key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := newGuardTestConfig()
			config.Inbound = []*core.InboundHandlerConfig{legacyTestInbound(authTestTag, tc.cfg)}
			instance, err := NewWithManagedInbounds(t.Context(), config, guardTestResolver, guardTestGate, tc.tags)
			if err == nil {
				_ = instance.Close()
				t.Fatal("accepted unsafe managed configuration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestManagedSS2022MultiUserUDPRequiresPatchedCore(t *testing.T) {
	if _, patched := any((*ss2022.MultiUserInbound)(nil)).(interface{ EnableManagedUDP() }); patched {
		t.Skip("requires the stock Xray build")
	}
	config := authTestConfigAtPort(20222, &ss2022.MultiUserServerConfig{
		Method: ss2022.MethodAES128GCM, Key: authTestMaster,
		Users: []*protocol.User{{Email: authTestUser, Account: serial.ToTypedMessage(&ss2022.Account{Key: authTestUserKey})}},
	})
	instance, err := NewWithManagedInbounds(t.Context(), config, guardTestResolver, guardTestGate, ManagedInboundTags{
		Shadowsocks2022Multi: []string{authTestTag},
	})
	if err == nil {
		_ = instance.Close()
		t.Fatal("stock Xray accepted managed multi-user Shadowsocks 2022 UDP")
	}
	if !strings.Contains(err.Error(), "requires the patched Xray build") {
		t.Fatal(err)
	}
}

func authTestConfig(t *testing.T, proxyConfig proto.Message) (*core.Config, *net.TCPListener) {
	t.Helper()
	reservation := listenWireTCP(t)
	t.Cleanup(func() { _ = reservation.Close() })
	port := xnet.Port(reservation.Addr().(*net.TCPAddr).Port)
	return authTestConfigAtPort(port, proxyConfig), reservation
}

func authTestConfigAtPort(port xnet.Port, proxyConfig proto.Message) *core.Config {
	inbound := legacyTestInbound(authTestTag, proxyConfig)
	inbound.ReceiverSettings = serial.ToTypedMessage(&proxyman.ReceiverConfig{
		Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
		PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
	})
	config := newGuardTestConfig()
	config.Inbound = []*core.InboundHandlerConfig{inbound}
	config.Outbound = []*core.OutboundHandlerConfig{{
		ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
	}}
	return config
}

func authTestHTTPConnect(t *testing.T, ctx context.Context, proxyAddr, destination, password string) (net.Conn, io.Reader, int) {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	credential := base64.StdEncoding.EncodeToString([]byte(authTestUser + ":" + password))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", destination, destination, credential); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, response.StatusCode
}

func authTestSS2022Dial(t *testing.T, ctx context.Context, config *core.Config, listen, target xnet.Destination, key string) net.Conn {
	t.Helper()
	client, err := core.New(&core.Config{
		App: config.App,
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&ss2022.ClientConfig{
				Address: xnet.NewIPOrDomain(listen.Address), Port: uint32(listen.Port),
				Method: ss2022.MethodAES128GCM, Key: key,
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	startWireCore(t, client)
	conn, err := core.Dial(ctx, client, target)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
