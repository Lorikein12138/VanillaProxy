package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

func TestBandwidthAutomaticSidecarInventoryUsesExactNativeCredentials(t *testing.T) {
	setupBulkDB(t)
	restore := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(restore) })
	const tuicEmail, awgEmail = "tuic@example.test", "awg@example.test"
	const rotatedEmail = "rotated@example.test"
	const uuidA = "a0000000-0000-0000-0000-000000000071"
	const uuidB = "a0000000-0000-0000-0000-000000000072"
	clients := []model.Client{
		{Email: tuicEmail, ID: uuidA, Password: "exact", Enable: true},
		{Email: rotatedEmail, ID: uuidB, Password: "new", Enable: true},
	}
	tuicInbound := mkInbound(t, 45371, model.TUIC, clientsSettings(t, clients))
	if err := (&ClientService{}).SyncInbound(nil, tuicInbound.Id, clients); err != nil {
		t.Fatal(err)
	}
	psk, public, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	awgInbound := amneziawgInbound(0, "automatic-awg", []model.Client{
		{Email: awgEmail, Enable: true, PublicKey: public, PreSharedKey: psk, AllowedIPs: []string{"10.8.1.2/32"}},
	})
	awgInbound.Port = 45372
	if err := database.GetDB().Create(awgInbound).Error; err != nil {
		t.Fatal(err)
	}
	lookup := func(protocol, email, credential string) (string, bool) {
		switch protocol {
		case string(model.TUIC):
			return "", (email == tuicEmail && credential == tuic.BandwidthCredential(uuidA, "exact")) ||
				(email == rotatedEmail && credential == tuic.BandwidthCredential(uuidB, "old"))
		case string(model.AmneziaWG):
			return "shared-canonical", email == awgEmail && credential == amneziawg.BandwidthCredential(public, psk)
		}
		return "", false
	}
	var inventory bandwidthSidecarInventory
	config, err := (&XrayService{}).getXrayConfigWithBandwidthSidecars(lookup, &inventory)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.tuic) != 1 || len(inventory.tuic[0].Instance.Clients) != 1 || inventory.tuic[0].Instance.Clients[0].Email != tuicEmail ||
		len(inventory.awg) != 1 || len(inventory.awg[0].Instance.Peers) != 1 {
		t.Fatalf("unexpected authorized native inventory sizes: TUIC=%d AWG=%d", len(inventory.tuic), len(inventory.awg))
	}
	relays, err := prepareBandwidthSidecarRelays(config, func(string) (string, bool) {
		t.Fatal("automatic relays used the legacy resolver")
		return "", false
	}, &inventory)
	if err != nil || len(relays) != 2 {
		t.Fatalf("relay inventory size=%d, err=%v", len(relays), err)
	}
	relay := relays[tuicInbound.Tag]
	id, ok := relay.Accounts[tuicEmail]
	if !relay.Automatic || !ok || id != "" || len(relay.Accounts) != 1 || relays[awgInbound.Tag].Accounts[awgEmail] != "shared-canonical" {
		t.Fatal("private relay policy did not match its authorized client inventory")
	}
	if _, err := liveBandwidthSidecarAccounts(nil, &inventory); err == nil {
		t.Fatal("reported authorization from saved state without a running process")
	}
	var revoked bandwidthSidecarInventory
	config, err = (&XrayService{}).getXrayConfigWithBandwidthSidecars(func(string, string, string) (string, bool) {
		return "", false
	}, &revoked)
	if err != nil {
		t.Fatal(err)
	}
	relays, err = prepareBandwidthSidecarRelays(config, nil, &revoked)
	if err != nil || len(relays) != 0 || len(revoked.tuic)+len(revoked.awg) != 0 {
		t.Fatalf("revoked clients remained in the public or private inventory: relays=%d err=%v", len(relays), err)
	}
}

func TestBandwidthManagedServiceBuildsSidecarOnlyInventory(t *testing.T) {
	setupBulkDB(t)
	restore := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(restore) })
	const tuicEmail, awgEmail = "Tuic.Peer@example.test", "Awg.Peer@example.test"
	clients := []model.Client{
		{Email: tuicEmail, ID: "a0000000-0000-0000-0000-000000000071", Password: "native-password", Enable: true},
		{Email: "disabled@example.test", ID: "a0000000-0000-0000-0000-000000000072", Password: "disabled-password", Enable: false},
	}
	tuicInbound := mkInbound(t, 45371, model.TUIC, clientsSettings(t, clients))
	if err := (&ClientService{}).SyncInbound(nil, tuicInbound.Id, clients); err != nil {
		t.Fatal(err)
	}
	awgInbound := amneziawgInbound(0, "managed-awg", []model.Client{
		{Email: awgEmail, Enable: true, PublicKey: "test-key", AllowedIPs: []string{"10.8.1.2/32"}},
	})
	awgInbound.Port = 45372
	if err := database.GetDB().Create(awgInbound).Error; err != nil {
		t.Fatal(err)
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(email string) (string, bool) {
		return "shared-canonical", email == tuicEmail || email == awgEmail
	}
	prepared, xrayBindings, err := prepareBandwidthXrayConfig(false, config, resolve)
	if err != nil || len(xrayBindings) != 0 {
		t.Fatalf("sidecar-only inventory produced direct Xray bindings or error: %d, %v", len(xrayBindings), err)
	}
	relays, err := prepareBandwidthSidecarRelays(prepared, resolve)
	if err != nil || len(relays) != 2 {
		t.Fatalf("wanted native TUIC and AWG relays: %d, %v", len(relays), err)
	}
	for _, want := range []struct {
		tag, kind, email string
		port             int
	}{
		{tuicInbound.Tag, launch.TUICRelay, tuicEmail, tuic.SOCKSPortForInbound(tuicInbound.Id)},
		{awgInbound.Tag, launch.AmneziaWGRelay, awgEmail, amneziawgnet.SOCKSPortForInbound(awgInbound.Id)},
	} {
		spec := relays[want.tag]
		if spec.Port != want.port || spec.Kind != want.kind || len(spec.Accounts) != 1 || spec.Accounts[want.email] != "shared-canonical" {
			t.Fatalf("wrong private relay for %s", want.tag)
		}
	}
	view, err := (&ServerService{}).GetConfigJson()
	if err != nil {
		t.Fatal(err)
	}
	export, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	internal, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, pass := range []string{tuic.SocksPassword(), amneziawgnet.SocksPassword()} {
		if strings.Contains(string(export), pass) || !strings.Contains(string(internal), pass) {
			t.Fatal("admin Xray config view exposed or mutated internal relay credentials")
		}
	}
}

func TestBandwidthManagedSidecarRelayTrustBoundary(t *testing.T) {
	resolve := func(email string) (string, bool) { return "shared", email == "Case@example.test" }
	cfg := &xray.Config{}
	if err := injectTuicRelay(cfg, []tuic.Instance{{
		Id: 7, Tag: "generated-tuic", Clients: []tuic.TuicClientSettings{{Email: "Case@example.test"}},
	}}); err != nil {
		t.Fatal(err)
	}
	original := cfg.InboundConfigs[0]
	for _, tc := range []struct {
		name   string
		change func(*xray.InboundConfig)
	}{
		{"public", func(inbound *xray.InboundConfig) { inbound.Listen = []byte(`"0.0.0.0"`) }},
		{"wrong port", func(inbound *xray.InboundConfig) { inbound.Port++ }},
		{"conflicting owner", func(inbound *xray.InboundConfig) { inbound.AmneziaWGRelay = true }},
		{"no auth", func(inbound *xray.InboundConfig) { inbound.Settings = []byte(`{"auth":"noauth","udp":true}`) }},
		{"arbitrary password", func(inbound *xray.InboundConfig) {
			inbound.Settings = []byte(`{"auth":"password","udp":true,"accounts":[{"user":"Case@example.test","pass":"wrong"}]}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := original
			tc.change(&inbound)
			if _, err := bandwidthSidecarRelay(inbound, resolve); err == nil {
				t.Fatal("accepted an invalid generated sidecar relay")
			}
		})
	}
	if _, err := bandwidthSidecarRelay(original, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("accepted a generated relay whose account is not canonically bound")
	}
	var forged xray.InboundConfig
	if err := json.Unmarshal([]byte(`{"TuicRelay":true,"TuicInboundID":7,"AmneziaWGRelay":true,"AmneziaWGInboundID":7}`), &forged); err != nil {
		t.Fatal(err)
	}
	if forged.IsSidecarRelay() || forged.TuicInboundID != 0 || forged.AmneziaWGInboundID != 0 {
		t.Fatal("JSON can forge an internal sidecar relay owner")
	}
}
