package xraybandwidthcore

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

const legacyTestVMessID = "88f16dc8-1412-4fed-8d80-bf90ab816437"

func TestManagedLegacyInboundPreservesNativeHandlers(t *testing.T) {
	user := func(email string, account proto.Message) *protocol.User {
		return &protocol.User{Email: email, Account: serial.ToTypedMessage(account)}
	}
	config := newGuardTestConfig()
	config.Inbound = []*core.InboundHandlerConfig{
		legacyTestInbound("vmess", &vmessinbound.Config{User: []*protocol.User{user("vmess", &vmess.Account{Id: legacyTestVMessID})}}),
		legacyTestInbound("trojan", &trojan.ServerConfig{Users: []*protocol.User{user("trojan", &trojan.Account{Password: "trojan-test"})}}),
		legacyTestInbound("shadowsocks", &shadowsocks.ServerConfig{Users: []*protocol.User{user("shadowsocks", &shadowsocks.Account{
			Password: "shadowsocks-test", CipherType: shadowsocks.CipherType_AES_128_GCM,
		})}}),
	}
	original := proto.CloneOf(config)
	ctx := t.Context()
	instance, err := NewWithManagedInbounds(ctx, config, guardTestResolver, guardTestGate, ManagedInboundTags{
		VMess: []string{"vmess"}, Trojan: []string{"trojan"}, Shadowsocks: []string{"shadowsocks"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if !proto.Equal(config, original) {
		t.Fatal("constructor changed the caller's config")
	}
	manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	for _, name := range []string{"vmess", "trojan", "shadowsocks"} {
		outer, err := manager.GetHandler(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		raw := outer.(proxy.GetInbound).GetInbound()
		handler, ok := raw.(*guardedLegacy)
		if !ok || handler.name != name {
			t.Fatalf("managed %s handler = %T", name, raw)
		}
		if name == "vmess" {
			if _, ok := handler.nativeLegacyInbound.(common.Closable); !ok {
				t.Fatal("VMess handler lost its native close")
			}
			if _, has := raw.(interface {
				GetOrGenerateUser(string) *protocol.MemoryUser
			}); has {
				t.Fatal("managed VMess exposes auto-generated users")
			}
		}
		users := raw.(proxy.UserManager)
		configured := users.GetUser(ctx, name)
		if configured == nil || users.GetUsersCount(ctx) != 1 {
			t.Fatalf("%s handler lost configured user", name)
		}
		if err := users.AddUser(ctx, &protocol.MemoryUser{Email: "alias", Account: configured.Account}); err == nil {
			t.Fatalf("%s handler accepted a duplicate credential", name)
		}
		if err := users.AddUser(ctx, &protocol.MemoryUser{Email: "unsupported"}); err == nil {
			t.Fatalf("%s handler accepted missing credentials", name)
		}
	}
}

func TestManagedLegacyRejectsUnsafeConfig(t *testing.T) {
	trojanUser := func(email, secret string) *protocol.User {
		return &protocol.User{Email: email, Account: serial.ToTypedMessage(&trojan.Account{Password: secret})}
	}
	vmessUnknown := &vmessinbound.Config{}
	vmessUnknown.ProtoReflect().SetUnknown([]byte{0x1a, 0x00})
	for _, tc := range []struct {
		name  string
		proxy proto.Message
		tags  ManagedInboundTags
		want  string
	}{
		{"wrong proxy", &trojan.ServerConfig{}, ManagedInboundTags{VMess: []string{"test"}}, "requires native proxy settings"},
		{"unknown VMess fields", vmessUnknown, ManagedInboundTags{VMess: []string{"test"}}, "unknown configuration fields"},
		{"Trojan fallback", &trojan.ServerConfig{Fallbacks: []*trojan.Fallback{{Dest: "localhost:80"}}}, ManagedInboundTags{Trojan: []string{"test"}}, "does not support fallbacks"},
		{"duplicate Trojan email", &trojan.ServerConfig{Users: []*protocol.User{trojanUser("test", "one"), trojanUser("TEST", "two")}}, ManagedInboundTags{Trojan: []string{"test"}}, "unique non-empty email"},
		{"duplicate Trojan auth", &trojan.ServerConfig{Users: []*protocol.User{trojanUser("first", "same"), trojanUser("second", "same")}}, ManagedInboundTags{Trojan: []string{"test"}}, "duplicate trojan credentials"},
		{"empty Trojan password", &trojan.ServerConfig{Users: []*protocol.User{trojanUser("test", "")}}, ManagedInboundTags{Trojan: []string{"test"}}, "invalid trojan credentials"},
		{
			"wrong account type", &vmessinbound.Config{User: []*protocol.User{trojanUser("test", "test-password")}},
			ManagedInboundTags{VMess: []string{"test"}}, "requires native vmess credentials",
		},
		{
			"unsupported Shadowsocks cipher", &shadowsocks.ServerConfig{Users: []*protocol.User{{
				Email: "test", Account: serial.ToTypedMessage(&shadowsocks.Account{Password: "test-password", CipherType: shadowsocks.CipherType_UNKNOWN}),
			}}},
			ManagedInboundTags{Shadowsocks: []string{"test"}}, "invalid shadowsocks credentials",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := newGuardTestConfig()
			config.Inbound = []*core.InboundHandlerConfig{legacyTestInbound("test", tc.proxy)}
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

func TestManagedVMessMetersTCP(t *testing.T) {
	const email, account = "vmess@client.test", "canonical-client"
	const upload, download = "vmess upload", "vmess download"
	var mu sync.Mutex
	remaining := len(upload) + len(download)
	resolve := func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		meta := session.InboundFromContext(ctx)
		if meta == nil || meta.Tag != "vmess" || meta.Name != "vmess" || user == nil || user.Email != email {
			return "", false, errors.New("expected the authenticated VMess account")
		}
		return account, true, nil
	}
	gate := func(_ context.Context, id string, n int) error {
		mu.Lock()
		defer mu.Unlock()
		if id != account || n <= 0 || n > remaining {
			return errors.New("unexpected VMess grant")
		}
		remaining -= n
		return nil
	}

	reservation := listenWireTCP(t)
	defer reservation.Close()
	listenPort := xnet.Port(reservation.Addr().(*net.TCPAddr).Port)
	user := &protocol.User{
		Email: email, Account: serial.ToTypedMessage(&vmess.Account{
			Id: legacyTestVMessID, SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM},
		}),
	}
	serverConfig := newGuardTestConfig()
	receiver := &proxyman.ReceiverConfig{
		Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
		PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(listenPort)}},
	}
	listener := legacyTestInbound("vmess", &vmessinbound.Config{User: []*protocol.User{user}})
	listener.ReceiverSettings = serial.ToTypedMessage(receiver)
	serverConfig.Inbound = []*core.InboundHandlerConfig{listener}
	serverConfig.Outbound = []*core.OutboundHandlerConfig{{
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	}}
	server, err := NewWithManagedInbounds(t.Context(), serverConfig, resolve, gate, ManagedInboundTags{VMess: []string{"vmess"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = reservation.Close()
	startWireCore(t, server)
	client, err := core.New(&core.Config{
		App: serverConfig.App,
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&vmessoutbound.Config{Receiver: &protocol.ServerEndpoint{
				Address: receiver.Listen, Port: uint32(listenPort), User: user,
			}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	startWireCore(t, client)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	target := listenWireTCP(t)
	defer target.Close()
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target.Addr().(*net.TCPAddr).Port))
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
	received := make([]byte, len(upload))
	if _, err := io.ReadFull(backend, received); err != nil || string(received) != upload {
		t.Fatalf("VMess upload = %q, error = %v", received, err)
	}
	if _, err := io.WriteString(backend, download); err != nil {
		t.Fatal(err)
	}
	received = make([]byte, len(download))
	if _, err := io.ReadFull(tunnel, received); err != nil || string(received) != download {
		t.Fatalf("VMess download = %q, error = %v", received, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining VMess budget = %d, want 0", remaining)
	}
}

func legacyTestInbound(tag string, settings proto.Message) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag:              tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &xnet.PortList{}}),
		ProxySettings:    serial.ToTypedMessage(settings),
	}
}
