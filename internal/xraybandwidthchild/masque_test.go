package xraybandwidthchild

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	"github.com/xtls/xray-core/common/protocol"
	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/masque"
)

const (
	masqueTestTag = "limit-masque"
	masqueUser    = "Auth-User"
	masquePass    = "masque-test-password"
)

func TestUnpatchedMASQUERejectsManagedBinding(t *testing.T) {
	if hasNativeMASQUEPacketGate() {
		t.Skip("uses the patched native MASQUE server")
	}
	cfg := testMASQUEConfig(t)
	if _, _, err := bindClients(cfg, map[string]map[string]string{masqueTestTag: {masqueUser: clientID}}, nil); err == nil ||
		!strings.Contains(err.Error(), "requires the patched native MASQUE packet gate") {
		t.Fatalf("unpatched binding error = %v", err)
	}
}

func TestPatchedMASQUEEnablesGateOnNativeInbound(t *testing.T) {
	if !hasNativeMASQUEPacketGate() {
		t.Skip("requires the patched native MASQUE server")
	}
	ctx := t.Context()
	cfg := testMASQUEConfig(t)
	bound, tags, err := bindClients(cfg, map[string]map[string]string{masqueTestTag: {masqueUser: clientID}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stockDispatcher, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stockDispatcher.Close() })
	if err := bound.verifyMASQUEPacketGates(ctx, stockDispatcher); err == nil || !strings.Contains(err.Error(), "no enabled native packet gate") {
		t.Fatalf("ordinary dispatcher gate error = %v", err)
	}

	total := 0
	instance, err := xraybandwidthcore.NewWithManagedInbounds(ctx, cfg, bound.resolve, func(_ context.Context, client string, n int) error {
		if client != clientID {
			return errors.New("unexpected MASQUE client ID")
		}
		total += n
		return nil
	}, tags)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := bound.verifyMASQUEPacketGates(ctx, instance); err != nil {
		t.Fatal(err)
	}
	manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	handler, err := manager.GetHandler(ctx, masqueTestTag)
	if err != nil {
		t.Fatal(err)
	}
	server := handler.(proxy.GetInbound).GetInbound().(*masque.Server)
	user := server.GetUser(ctx, strings.ToLower(masqueUser))
	if user == nil || user.Email != masqueUser {
		t.Fatal("native MASQUE did not preserve the configured username")
	}
	dispatcher := instance.GetFeature(routing.DispatcherType()).(interface {
		VanillaProxyWaitMASQUEPacket(context.Context, int) error
	})
	packetCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: masqueTestTag, Name: protocolMASQUE, User: user})
	if err := dispatcher.VanillaProxyWaitMASQUEPacket(packetCtx, 1200); err != nil || total != 1200 {
		t.Fatalf("native-authenticated packet grant = %d bytes, %v", total, err)
	}
	wrong := &protocol.MemoryUser{Email: masqueUser, Account: &masque.MemoryAccount{Password: "wrong"}}
	deniedCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: masqueTestTag, Name: protocolMASQUE, User: wrong})
	if err := dispatcher.VanillaProxyWaitMASQUEPacket(deniedCtx, 1200); err == nil || total != 1200 {
		t.Fatalf("wrong-password packet grant = %d bytes, %v", total, err)
	}
}

func TestMASQUEBindingValidatesNativeCredentials(t *testing.T) {
	user := func(email string, account *xserial.TypedMessage) *protocol.User {
		return &protocol.User{Email: email, Account: account}
	}
	credential := xserial.ToTypedMessage(&masque.Account{Password: masquePass})
	clients := map[string]string{masqueUser: clientID}
	if _, err := bindAccounts(protocolMASQUE, []*protocol.User{user(masqueUser, credential), user("different", credential)}, clients, false); err != nil {
		t.Fatalf("shared passwords with distinct usernames are valid: %v", err)
	}
	for _, tc := range []struct {
		users []*protocol.User
		want  string
	}{
		{[]*protocol.User{user(masqueUser, credential), user(strings.ToLower(masqueUser), credential)}, "unique non-empty emails"},
		{[]*protocol.User{user("bad:username", credential)}, "cannot contain a colon"},
		{[]*protocol.User{user(masqueUser, xserial.ToTypedMessage(&masque.Account{}))}, "invalid configured credentials"},
		{[]*protocol.User{user(masqueUser, nil)}, "require native credentials"},
	} {
		if _, err := bindAccounts(protocolMASQUE, tc.users, clients, false); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("invalid MASQUE account error = %v, want %q", err, tc.want)
		}
	}
}

func testMASQUEConfig(t *testing.T) *core.Config {
	t.Helper()
	const input = `{"inbounds":[{
		"tag":"` + masqueTestTag + `","listen":"127.0.0.1","port":22001,"protocol":"masque",
		"settings":{"address":["10.19.23.1/24"],"users":[{"email":"` + masqueUser + `","pass":"` + masquePass + `"}]},
		"streamSettings":{"network":"masque","security":"tls"}
	}]}`
	config, err := serial.LoadJSONConfig(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return config
}
