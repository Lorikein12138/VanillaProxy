package xraybandwidthchild

import (
	"context"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/wireguard"
)

const (
	wireGuardTag      = "limit-wireguard"
	wireGuardOtherTag = "limit-wireguard-other"
	wireGuardEmail    = "Case-Sensitive"
	wireGuardAltEmail = "case-sensitive"
	wireGuardKey      = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	wireGuardAltKey   = "2222222222222222222222222222222222222222222222222222222222222222"
	wireGuardOtherKey = "3333333333333333333333333333333333333333333333333333333333333333"
)

const wireGuardJSON = `{"inbounds":[{
	"tag":"` + wireGuardTag + `","listen":"127.0.0.1","port":22003,"protocol":"wireguard",
	"settings":{"secretKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","address":["10.19.24.1/24"],"peers":[
		{"email":"` + wireGuardEmail + `","publicKey":"` + wireGuardKey + `","allowedIPs":["10.19.24.2/32"]},
		{"email":"` + wireGuardAltEmail + `","publicKey":"` + wireGuardAltKey + `","allowedIPs":["10.19.24.3/32"]}
	]}
},{
	"tag":"` + wireGuardOtherTag + `","listen":"127.0.0.1","port":22004,"protocol":"wireguard",
	"settings":{"secretKey":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","address":["10.19.25.1/24"],"peers":[
		{"email":"` + wireGuardEmail + `","publicKey":"` + wireGuardOtherKey + `","allowedIPs":["10.19.25.2/32"]}
	]}
}]}`

func TestUnpatchedWireGuardRejectsManagedBinding(t *testing.T) {
	if hasNativeWireGuardPacketGate() {
		t.Skip("uses the patched native WireGuard server")
	}
	config := loadWireGuardTestConfig(t, wireGuardJSON)
	if _, _, err := bindClients(config, testWireGuardBindings(), nil); err == nil ||
		!strings.Contains(err.Error(), "requires the patched native WireGuard packet gate") {
		t.Fatalf("unpatched binding error = %v", err)
	}
}

func TestPatchedWireGuardEnablesGateOnNativeInbound(t *testing.T) {
	if !hasNativeWireGuardPacketGate() {
		t.Skip("requires the patched native WireGuard server")
	}
	ctx := t.Context()
	config := loadWireGuardTestConfig(t, wireGuardJSON)
	clients := testWireGuardBindings()
	clients[wireGuardTag][wireGuardAltEmail] = launch.UnmeteredXrayAccountID
	bound, guarded, err := bindClients(config, clients, map[string]bool{wireGuardTag: true, wireGuardOtherTag: true})
	if err != nil {
		t.Fatal(err)
	}
	stockDispatcher, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stockDispatcher.Close() })
	if err := bound.verifyWireGuardPacketGates(ctx, stockDispatcher); err == nil ||
		!strings.Contains(err.Error(), "no enabled native packet gate") {
		t.Fatalf("ordinary dispatcher gate error = %v", err)
	}

	instance, err := xraybandwidthcore.NewWithManagedInbounds(ctx, config, bound.resolve, allowWireGuardTestPacket, guarded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := bound.verifyWireGuardPacketGates(ctx, instance); err != nil {
		t.Fatal(err)
	}
	manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	getUser := func(tag, email string) *protocol.MemoryUser {
		t.Helper()
		handler, err := manager.GetHandler(ctx, tag)
		if err != nil {
			t.Fatal(err)
		}
		user := handler.(proxy.GetInbound).GetInbound().(*wireguard.Server).GetUser(ctx, email)
		if user == nil {
			t.Fatalf("missing configured peer %q on %q", email, tag)
		}
		return user
	}
	first := getUser(wireGuardTag, wireGuardEmail)
	second := getUser(wireGuardTag, wireGuardAltEmail)
	other := getUser(wireGuardOtherTag, wireGuardEmail)
	changedKey := *second.Account.(*wireguard.MemoryAccount)
	changedKey.PreSharedKey = wireGuardKey
	for _, tc := range []struct {
		name, tag string
		user      *protocol.MemoryUser
		want      string
	}{
		{"first native peer", wireGuardTag, first, "first-client"},
		{"case-distinct exempt native peer", wireGuardTag, second, launch.UnmeteredXrayAccountID},
		{"same email on another inbound", wireGuardOtherTag, other, "other-client"},
		{"different tag", wireGuardOtherTag, first, ""},
		{"different email", wireGuardTag, &protocol.MemoryUser{Email: wireGuardAltEmail, Account: first.Account}, ""},
		{"different public key", wireGuardTag, &protocol.MemoryUser{Email: wireGuardEmail, Account: second.Account}, ""},
		{"different preshared key", wireGuardTag, &protocol.MemoryUser{Email: wireGuardAltEmail, Account: &changedKey}, ""},
		{"missing public key", wireGuardTag, &protocol.MemoryUser{Email: wireGuardEmail}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := session.ContextWithInbound(ctx, &session.Inbound{Tag: tc.tag, Name: protocolWireGuard, User: tc.user})
			if id, managed, err := bound.resolve(packet, tc.user); !managed || id != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("peer resolved to %q, managed=%v, error=%v; want %q", id, managed, err, tc.want)
			}
		})
	}
}

func TestPatchedWireGuardRejectsInvalidSource(t *testing.T) {
	if !hasNativeWireGuardPacketGate() {
		t.Skip("requires the patched native WireGuard server")
	}
	for _, tc := range []struct {
		name, source, want string
		omitPeer           bool
	}{
		{"invalid public key", strings.Replace(wireGuardJSON, wireGuardKey, "AAAA", 1), "invalid configured credentials", false},
		{"duplicate public key", strings.Replace(wireGuardJSON, wireGuardAltKey, strings.ToUpper(wireGuardKey), 1), "duplicate configured credentials", false},
		{"overlapping allowed IPs", strings.Replace(wireGuardJSON, "10.19.24.3/32", "10.19.24.0/24", 1), "overlapping managed WireGuard AllowedIPs", false},
		{"unbound configured peer", wireGuardJSON, "requires a known authenticated account", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := loadWireGuardTestConfig(t, tc.source)
			clients := testWireGuardBindings()
			if tc.omitPeer {
				delete(clients[wireGuardTag], wireGuardAltEmail)
			}
			bound, guarded, err := bindClients(config, clients, nil)
			if err == nil {
				var instance *core.Instance
				instance, err = xraybandwidthcore.NewWithManagedInbounds(t.Context(), config, bound.resolve, allowWireGuardTestPacket, guarded)
				if instance != nil {
					t.Cleanup(func() { _ = instance.Close() })
				}
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid config error = %v, want %q", err, tc.want)
			}
		})
	}
}

func loadWireGuardTestConfig(t *testing.T, source string) *core.Config {
	t.Helper()
	config, err := serial.LoadJSONConfig(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testWireGuardBindings() map[string]map[string]string {
	return map[string]map[string]string{
		wireGuardTag:      {wireGuardEmail: "first-client", wireGuardAltEmail: "second-client"},
		wireGuardOtherTag: {wireGuardEmail: "other-client"},
	}
}

func allowWireGuardTestPacket(context.Context, string, int) error { return nil }
