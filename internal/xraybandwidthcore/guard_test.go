package xraybandwidthcore

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestManagedVLESSWrapsSelectedHandler(t *testing.T) {
	config := newGuardTestConfig()
	config.Inbound = append(config.Inbound, newGuardTestInbound("stock", &vless.Account{Flow: vless.XRV}))
	original := proto.CloneOf(config)

	ctx := t.Context()
	resolve := func(context.Context, *protocol.MemoryUser) (string, bool, error) {
		return "managed", true, nil
	}
	instance, err := NewWithManagedVLESS(ctx, config, resolve, guardTestGate, []string{"managed"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if !proto.Equal(config, original) {
		t.Fatal("constructor changed the caller's config")
	}

	manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	managed, err := manager.GetHandler(ctx, "managed")
	if err != nil {
		t.Fatal(err)
	}
	handler := managed.(proxy.GetInbound).GetInbound()
	if _, ok := handler.(*guardedVLESS); !ok {
		t.Fatalf("managed handler = %T", handler)
	}
	if _, ok := handler.(common.Closable); !ok {
		t.Fatal("managed handler lost close support")
	}
	stock, err := manager.GetHandler(ctx, "stock")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stock.(proxy.GetInbound).GetInbound().(*vlessinbound.Handler); !ok {
		t.Fatal("stock handler was wrapped")
	}
	if !proto.Equal(stock.ProxySettings(), original.Inbound[1].ProxySettings) {
		t.Fatal("stock handler settings changed")
	}

	users := handler.(proxy.UserManager)
	user := users.GetUser(ctx, "managed")
	if user == nil || users.GetUsersCount(ctx) != 1 {
		t.Fatal("managed handler lost configured user")
	}
	for _, unsupported := range []*vless.Account{
		{Flow: vless.XRV},
		{Reverse: &vless.Reverse{Tag: "reverse"}},
	} {
		candidate := newGuardTestUser("dynamic", unsupported)
		memory, err := candidate.ToMemoryUser()
		if err != nil {
			t.Fatal(err)
		}
		if err := users.AddUser(ctx, memory); err == nil {
			t.Fatal("managed handler accepted unsupported credentials")
		}
	}
	if users.GetUsersCount(ctx) != 1 {
		t.Fatal("failed add changed the user count")
	}
	dynamic := newGuardTestUser("dynamic", &vless.Account{Id: "6e45abb0-c265-4add-97d9-2e6b9588a2a0"})
	memory, err := dynamic.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := users.AddUser(ctx, memory); err != nil {
		t.Fatal(err)
	}
	if users.GetUser(ctx, "dynamic") == nil || users.GetUsersCount(ctx) != 2 {
		t.Fatal("managed handler did not add the supported user")
	}
	if err := users.RemoveUser(ctx, "dynamic"); err != nil {
		t.Fatal(err)
	}
	if users.GetUser(ctx, "dynamic") != nil {
		t.Fatal("managed handler did not remove the supported user")
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		wrote <- encoding.EncodeRequestHeader(client, &protocol.RequestHeader{
			Command: protocol.RequestCommandMux, User: user,
		}, &encoding.Addons{})
	}()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "managed"})
	if err := handler.Process(ctx, xnet.Network_TCP, server, nil); !errors.Is(err, errManagedVLESSMux) {
		t.Fatalf("VLESS mux request error = %v", err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

func TestManagedVLESSRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		tags   []string
		change func(*core.Config)
		want   string
	}{
		{name: "missing inbound", tags: []string{"missing"}, want: "was not found"},
		{name: "empty tag", tags: []string{""}, want: "must not be empty"},
		{name: "duplicate tag", tags: []string{"managed", "managed"}, want: "duplicate managed"},
		{
			name: "duplicate inbound", tags: []string{"managed"}, want: "multiple Xray inbounds",
			change: func(c *core.Config) { c.Inbound = append(c.Inbound, proto.CloneOf(c.Inbound[0])) },
		},
		{
			name: "wrong protocol", tags: []string{"managed"}, want: "requires VLESS proxy settings",
			change: func(c *core.Config) { c.Inbound[0].ProxySettings = serial.ToTypedMessage(&dispatcher.Config{}) },
		},
		{
			name: "invalid VLESS payload", tags: []string{"managed"}, want: "decode managed VLESS inbound",
			change: func(c *core.Config) { c.Inbound[0].ProxySettings.Value = []byte{0xff} },
		},
		{
			name: "fallback", tags: []string{"managed"}, want: "does not support fallbacks",
			change: func(c *core.Config) {
				c.Inbound[0].ProxySettings = serial.ToTypedMessage(&vlessinbound.Config{Fallbacks: []*vlessinbound.Fallback{{Dest: "example.com:80"}}})
			},
		},
		{
			name: "reverse", tags: []string{"managed"}, want: "reverse credentials",
			change: func(c *core.Config) {
				c.Inbound[0] = newGuardTestInbound("managed", &vless.Account{Reverse: &vless.Reverse{}})
			},
		},
		{
			name: "vision without TLS", tags: []string{"managed"}, want: "Vision flow requires raw TCP",
			change: func(c *core.Config) { c.Inbound[0] = newGuardTestInbound("managed", &vless.Account{Flow: vless.XRV}) },
		},
		{
			name: "injected marker", want: "internal managed inbound marker",
			change: func(c *core.Config) {
				c.Inbound[0].ProxySettings = serial.ToTypedMessage(wrapperspb.Bytes([]byte("managed")))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := newGuardTestConfig()
			if test.change != nil {
				test.change(config)
			}
			instance, err := NewWithManagedVLESS(t.Context(), config, guardTestResolver, guardTestGate, test.tags)
			if err == nil {
				_ = instance.Close()
				t.Fatal("accepted invalid managed VLESS config")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestManagedVLESSVisionTLSAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*internet.StreamConfig, *vlessinbound.Config, *vless.Account)
		want   string
	}{
		{name: "default raw TCP"},
		{
			name: "explicit raw TCP with no header",
			change: func(s *internet.StreamConfig, v *vlessinbound.Config, _ *vless.Account) {
				s.ProtocolName = "tcp"
				s.TransportSettings = []*internet.TransportConfig{{
					ProtocolName: "tcp",
					Settings:     serial.ToTypedMessage(&tcp.Config{HeaderSettings: serial.ToTypedMessage(&noop.ConnectionConfig{})}),
				}}
				v.Decryption = "none"
			},
		},
		{
			name: "REALITY missing server settings for empty flow", want: "REALITY requires raw TCP and valid server settings",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, a *vless.Account) {
				a.Flow = ""
				security := serial.ToTypedMessage(&reality.Config{Fingerprint: "chrome"})
				s.SecurityType, s.SecuritySettings = security.Type, []*serial.TypedMessage{security}
			},
		},
		{
			name: "REALITY short ID length", want: "REALITY requires raw TCP and valid server settings",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				security := serial.ToTypedMessage(&reality.Config{
					Type: "tcp", Dest: "cover.test:443", PrivateKey: make([]byte, 32),
					ServerNames: []string{"cover.test"}, ShortIds: [][]byte{{1}},
				})
				s.SecurityType, s.SecuritySettings = security.Type, []*serial.TypedMessage{security}
			},
		},
		{
			name: "missing typed TLS settings", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.SecuritySettings = nil
			},
		},
		{
			name: "security type has no matching settings", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&reality.Config{})}
			},
		},
		{
			name: "malformed TLS settings", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.SecuritySettings[0].Value = []byte{0xff}
			},
		},
		{
			name: "WebSocket", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.ProtocolName = "websocket"
			},
		},
		{
			name: "TCP mask", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.Tcpmasks = []*serial.TypedMessage{serial.ToTypedMessage(&noop.Config{})}
			},
		},
		{
			name: "TCP HTTP header", want: "Vision flow requires raw TCP",
			change: func(s *internet.StreamConfig, _ *vlessinbound.Config, _ *vless.Account) {
				s.TransportSettings = []*internet.TransportConfig{{
					ProtocolName: "tcp",
					Settings:     serial.ToTypedMessage(&tcp.Config{HeaderSettings: serial.ToTypedMessage(&httpheader.Config{})}),
				}}
			},
		},
		{
			name: "additional VLESS encryption", want: "Vision flow requires raw TCP",
			change: func(_ *internet.StreamConfig, v *vlessinbound.Config, _ *vless.Account) {
				v.Decryption = "encrypted"
			},
		},
		{
			name: "client-only Vision flow", want: "unsupported VLESS flow",
			change: func(_ *internet.StreamConfig, _ *vlessinbound.Config, a *vless.Account) {
				a.Flow = vless.XRV + "-udp443"
			},
		},
		{
			name: "reverse", want: "reverse credentials",
			change: func(_ *internet.StreamConfig, _ *vlessinbound.Config, a *vless.Account) {
				a.Reverse = &vless.Reverse{Tag: "reverse"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := newGuardTestConfig()
			account := &vless.Account{Flow: vless.XRV}
			settings := &vlessinbound.Config{}
			stream := wireVisionTLSStream(&tls.Config{})
			if test.change != nil {
				test.change(stream, settings, account)
			}
			settings.Users = []*protocol.User{newGuardTestUser("managed", account)}
			config.Inbound[0].ProxySettings = serial.ToTypedMessage(settings)
			config.Inbound[0].ReceiverSettings = serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{}, StreamSettings: stream,
			})
			ctx := t.Context()
			instance, err := NewWithManagedVLESS(ctx, config, guardTestResolver, guardTestGate, []string{"managed"})
			if test.want != "" {
				if err == nil {
					_ = instance.Close()
					t.Fatal("accepted invalid managed VLESS Vision configuration")
				}
				if !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
			handler, err := manager.GetHandler(ctx, "managed")
			if err != nil {
				t.Fatal(err)
			}
			users := handler.(proxy.GetInbound).GetInbound().(proxy.UserManager)
			for _, dynamic := range []struct {
				account *vless.Account
				want    string
			}{
				{account: &vless.Account{Flow: vless.XRV, Reverse: &vless.Reverse{Tag: "reverse"}}, want: "reverse credentials"},
				{account: &vless.Account{Flow: vless.XRV + "-udp443"}, want: "unsupported VLESS flow"},
				{account: &vless.Account{Flow: vless.XRV, Id: "6e45abb0-c265-4add-97d9-2e6b9588a2a0"}},
			} {
				user, err := newGuardTestUser("dynamic", dynamic.account).ToMemoryUser()
				if err != nil {
					t.Fatal(err)
				}
				err = users.AddUser(ctx, user)
				if dynamic.want == "" && err != nil ||
					dynamic.want != "" && (err == nil || !strings.Contains(err.Error(), dynamic.want)) {
					t.Fatalf("AddUser error = %v, want %q", err, dynamic.want)
				}
			}
			if user := users.GetUser(ctx, "dynamic"); user == nil || user.Account.(*vless.MemoryAccount).Flow != vless.XRV {
				t.Fatalf("registered Vision user = %v", user)
			}
		})
	}
}

func TestManagedVLESSREALITYEncryptionAdmission(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		name   string
		change func(*vlessinbound.Config)
	}{
		{name: "native 600 seconds"},
		{name: "xorpub", change: func(c *vlessinbound.Config) { c.XorMode = 1 }},
		{name: "random", change: func(c *vlessinbound.Config) { c.XorMode = 2 }},
		{name: "other duration", change: func(c *vlessinbound.Config) { c.SecondsFrom = 300 }},
		{name: "duration range", change: func(c *vlessinbound.Config) { c.SecondsTo = 900 }},
		{name: "custom padding", change: func(c *vlessinbound.Config) { c.Padding = "100-111-222" }},
		{name: "key chain", change: func(c *vlessinbound.Config) { c.Decryption += "." + key }},
		{name: "invalid key", change: func(c *vlessinbound.Config) { c.Decryption += "!" }},
		{name: "ML-KEM key", change: func(c *vlessinbound.Config) {
			c.Decryption = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := newGuardTestInbound("managed", &vless.Account{Flow: vless.XRV})
			inbound.ReceiverSettings = serial.ToTypedMessage(&proxyman.ReceiverConfig{
				StreamSettings: wireREALITYStream(&reality.Config{
					Type: "tcp", Dest: "cover.test:443", PrivateKey: make([]byte, 32),
					ServerNames: []string{"cover.test"}, ShortIds: [][]byte{make([]byte, 8)},
				}),
			})
			settings := &vlessinbound.Config{
				Users:      []*protocol.User{newGuardTestUser("managed", &vless.Account{Flow: vless.XRV})},
				Decryption: key, SecondsFrom: 600,
			}
			if test.change != nil {
				test.change(settings)
			}
			inbound.ProxySettings = serial.ToTypedMessage(settings)
			guarded, err := parseManagedVLESS(inbound)
			if test.change == nil {
				if err != nil || !guarded.vision {
					t.Fatalf("expected encrypted REALITY Vision to be admitted: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "requires native.600s encryption") {
				t.Fatalf("expected decryption constraints to reject the profile: %v", err)
			}
		})
	}
}

func TestManagedVLESSMarkerRequiresMatchingConstructorState(t *testing.T) {
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: "managed"})
	marker := wrapperspb.Bytes([]byte("managed"))
	if _, err := common.CreateObject(ctx, marker); err == nil {
		t.Fatal("accepted marker without a constructor")
	}
	ctx = context.WithValue(ctx, managedInboundsKey{}, managedInboundConfigs{"managed": {proxy: &vlessinbound.Config{}}})
	for _, marker := range []*wrapperspb.BytesValue{wrapperspb.Bytes(nil), wrapperspb.Bytes([]byte("other"))} {
		if _, err := common.CreateObject(ctx, marker); err == nil {
			t.Fatal("accepted marker with missing or mismatched tag")
		}
	}
}

func TestManagedVLESSGuardRejectsMuxDispatch(t *testing.T) {
	guard := guardMuxDispatcher{}
	target := xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), 0)
	if link, err := guard.Dispatch(t.Context(), target); link != nil || !errors.Is(err, errManagedVLESSMux) {
		t.Fatalf("Dispatch returned link %v and error %v", link, err)
	}
	if err := guard.DispatchLink(t.Context(), target, nil); !errors.Is(err, errManagedVLESSMux) {
		t.Fatalf("DispatchLink returned error %v", err)
	}
}

func TestManagedVLESSGuardAllowsMuxOnlyForExemptAccounts(t *testing.T) {
	const exemptID = "6e45abb0-c265-4add-97d9-2e6b9588a2a0"
	exempt, err := newGuardTestUser("exempt", &vless.Account{Id: exemptID}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	wrongCredential := &protocol.MemoryUser{Email: exempt.Email}
	resolve := func(user *protocol.MemoryUser) (string, bool, error) {
		switch user.Email {
		case "exempt":
			account, ok := user.Account.(*vless.MemoryAccount)
			if ok && account.ID.String() == exemptID {
				return "", false, nil
			}
		case "managed":
			return "target", true, nil
		case "unexpected ID":
			return "target", false, nil
		}
		return "", false, errors.New("unrecognized VLESS credentials")
	}
	mux := xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), 0)
	ordinary := xnet.TCPDestination(xnet.DomainAddress("example.test"), 443)
	for _, test := range []struct {
		name    string
		inbound *session.Inbound
		dest    xnet.Destination
		allow   bool
	}{
		{name: "exempt", inbound: &session.Inbound{Tag: "managed", Name: "vless", User: exempt}, dest: mux, allow: true},
		{name: "managed", inbound: &session.Inbound{Tag: "managed", Name: "vless", User: &protocol.MemoryUser{Email: "managed"}}, dest: mux},
		{name: "unknown", inbound: &session.Inbound{Tag: "managed", Name: "vless", User: &protocol.MemoryUser{Email: "unknown"}}, dest: mux},
		{name: "wrong credential", inbound: &session.Inbound{Tag: "managed", Name: "vless", User: wrongCredential}, dest: mux},
		{name: "unexpected ID", inbound: &session.Inbound{Tag: "managed", Name: "vless", User: &protocol.MemoryUser{Email: "unexpected ID"}}, dest: mux},
		{name: "missing user", inbound: &session.Inbound{Tag: "managed", Name: "vless"}, dest: mux},
		{name: "missing inbound", dest: mux},
		{name: "wrong tag", inbound: &session.Inbound{Tag: "other", Name: "vless", User: exempt}, dest: mux},
		{name: "wrong protocol", inbound: &session.Inbound{Tag: "managed", Name: "trojan", User: exempt}, dest: mux},
		{name: "ordinary destination", dest: ordinary, allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.inbound != nil {
				ctx = session.ContextWithInbound(ctx, test.inbound)
			}
			link := &transport.Link{}
			native := &guardTestDispatcher{link: link}
			resolveForInbound := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
				inbound := session.InboundFromContext(ctx)
				if test.dest != mux || inbound == nil || inbound.Tag != "managed" || inbound.Name != "vless" || inbound.User != user || user == nil {
					t.Fatal("resolver called outside authenticated mux dispatch for the expected inbound")
				}
				return resolve(user)
			}
			guard := guardMuxDispatcher{Dispatcher: native, allowMux: allowExemptVLESSMux("managed", resolveForInbound)}
			gotLink, dispatchErr := guard.Dispatch(ctx, test.dest)
			linkErr := guard.DispatchLink(ctx, test.dest, link)
			if !test.allow {
				if gotLink != nil || !errors.Is(dispatchErr, errManagedVLESSMux) || !errors.Is(linkErr, errManagedVLESSMux) || native.calls != 0 {
					t.Fatalf("rejected dispatch returned link %v, errors (%v, %v), and %d native calls", gotLink, dispatchErr, linkErr, native.calls)
				}
				return
			}
			if gotLink != link || dispatchErr != nil || linkErr != nil || native.calls != 2 || native.dest != test.dest || native.passedLink != link {
				t.Fatalf("forwarded dispatch returned link %v, errors (%v, %v), and native calls %+v", gotLink, dispatchErr, linkErr, native)
			}
		})
	}
}

type guardTestDispatcher struct {
	routing.Dispatcher
	link       *transport.Link
	passedLink *transport.Link
	dest       xnet.Destination
	calls      int
}

func (d *guardTestDispatcher) Dispatch(_ context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.calls++
	d.dest = dest
	return d.link, nil
}

func (d *guardTestDispatcher) DispatchLink(_ context.Context, dest xnet.Destination, link *transport.Link) error {
	d.calls++
	d.dest = dest
	d.passedLink = link
	return nil
}

func newGuardTestConfig() *core.Config {
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{newGuardTestInbound("managed", &vless.Account{})},
	}
}

func newGuardTestInbound(tag string, account *vless.Account) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag:              tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &xnet.PortList{}}),
		ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
			Users: []*protocol.User{newGuardTestUser(tag, account)},
		}),
	}
}

func newGuardTestUser(email string, account *vless.Account) *protocol.User {
	if account.Id == "" {
		account.Id = "88f16dc8-1412-4fed-8d80-bf90ab816437"
	}
	return &protocol.User{Email: email, Account: serial.ToTypedMessage(account)}
}

func guardTestResolver(context.Context, *protocol.MemoryUser) (string, bool, error) {
	return "", false, nil
}

func guardTestGate(context.Context, string, int) error { return nil }
