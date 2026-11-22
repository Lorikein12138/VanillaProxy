package amneziawgnet

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

const managerBandwidthEmail = "Peer.A@example.test"

func managerBandwidthDesired(t *testing.T) Desired {
	t.Helper()
	priv, _ := bandwidthKeypair(t)
	_, peerKey := bandwidthKeypair(t)
	return Desired{Instance: amneziawg.Instance{
		Id:            13,
		InterfaceName: "awgtest13",
		PrivateKey:    priv,
		Address:       []string{"10.207.0.1/24"},
		Peers: []amneziawg.Peer{{
			Email: managerBandwidthEmail, PublicKey: peerKey, AllowedIPs: []string{"10.207.0.2/32"},
		}},
	}}
}

func managerBandwidthWait(context.Context, string, int) error { return nil }

func managerBandwidthTestRelay(amneziawg.Instance) (SocksRelay, error) {
	// Lifecycle tests send no traffic through the relay.
	return SocksRelay{RequireBoundUDP: true}, nil
}

func TestManagerAutomaticBandwidthMatchesRunningPeerKeys(t *testing.T) {
	d := managerBandwidthDesired(t)
	m := &Manager{ifaces: map[int]*managed{}, managedRelay: boundSocksRelayForInstance}
	t.Cleanup(m.StopAll)
	if err := m.ConfigureAutomaticBandwidth(managerBandwidthWait); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(d); err == nil {
		t.Fatal("automatic interface accepted a regular start without policy bindings")
	}
	desired := BandwidthDesired{Desired: d, ClientIDs: map[string]string{managerBandwidthEmail: ""}}
	if err := m.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil || !m.MatchesBandwidth(desired) {
		t.Fatalf("exact embedded interface is not ready: %v", err)
	}
	first, _, _ := m.Lookup(d.Instance.Id)
	if err := m.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil {
		t.Fatal(err)
	}
	if current, _, _ := m.Lookup(d.Instance.Id); current != first {
		t.Fatal("reapplying the same binding replaced the running device")
	}
	desired.Instance.Peers = cloneBandwidthPeers(desired.Instance.Peers)
	desired.Instance.Peers[0].PresharedKey, _ = bandwidthKeypair(t)
	if m.MatchesBandwidth(desired) {
		t.Fatal("reported a running interface for a PSK never applied")
	}
	if err := m.ReconcileBandwidth([]BandwidthDesired{desired}); err != nil || !m.MatchesBandwidth(desired) {
		t.Fatalf("rotated interface is not ready: %v", err)
	}
	select {
	case <-first.Wait():
	default:
		t.Fatal("old interface survived PSK rotation")
	}
	desired.Instance.Peers[0].PresharedKey = "invalid"
	if err := m.ReconcileBandwidth([]BandwidthDesired{desired}); err == nil || m.HasRunning() {
		t.Fatal("failed replacement retained an interface")
	}
}

func TestManagerBandwidthRequiresPreconfigurationAndStrictRelay(t *testing.T) {
	d := managerBandwidthDesired(t)
	resolve := func(string) (string, bool) { return "canonical", true }
	stock := &Manager{ifaces: map[int]*managed{}}
	t.Cleanup(stock.StopAll)
	direct := d
	direct.Options.Bandwidth = &BandwidthOptions{Wait: managerBandwidthWait}
	if err := stock.Ensure(direct); err == nil || stock.HasRunning() {
		t.Fatalf("direct manager bandwidth options: error = %v, running = %t", err, stock.HasRunning())
	}
	if err := stock.Ensure(d); err != nil {
		t.Fatal(err)
	}
	stock.StopAll()
	if err := stock.ConfigureBandwidth(managerBandwidthWait, resolve); err == nil {
		t.Fatal("accepted bandwidth configuration after a successful stock start")
	}

	m := &Manager{ifaces: map[int]*managed{}}
	t.Cleanup(m.StopAll)
	if err := m.ConfigureBandwidth(nil, resolve); err == nil {
		t.Fatal("accepted nil gate")
	}
	if err := m.ConfigureBandwidth(managerBandwidthWait, nil); err == nil {
		t.Fatal("accepted nil account resolver")
	}
	if err := m.ConfigureBandwidth(managerBandwidthWait, resolve); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureBandwidth(managerBandwidthWait, resolve); err == nil {
		t.Fatal("accepted duplicate bandwidth configuration")
	}
	if err := m.Ensure(d); err == nil || m.HasRunning() {
		t.Fatalf("managed start with no strict relay: error = %v, running = %t", err, m.HasRunning())
	}
	m.managedRelay = func(amneziawg.Instance) (SocksRelay, error) { return SocksRelay{}, nil }
	if err := m.Ensure(d); err == nil || m.HasRunning() {
		t.Fatalf("managed start with a stock relay: error = %v, running = %t", err, m.HasRunning())
	}
	m.managedRelay = boundSocksRelayForInstance
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	relay := m.ifaces[d.Instance.Id].udpRelay.relay
	if !relay.RequireBoundUDP || relay.Password != SocksPassword() {
		t.Fatal("managed device did not receive the authenticated relay")
	}
}

func TestManagerBandwidthSharesEnsureReconcileSnapshot(t *testing.T) {
	d := managerBandwidthDesired(t)
	m := &Manager{ifaces: map[int]*managed{}, managedRelay: managerBandwidthTestRelay}
	t.Cleanup(m.StopAll)
	canonical := "canonical"
	resolved := 0
	if err := m.ConfigureBandwidth(managerBandwidthWait, func(email string) (string, bool) {
		resolved++
		return canonical, email == managerBandwidthEmail && canonical != ""
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	original := m.ifaces[d.Instance.Id]
	key, err := wireguard.KeyToHex(d.Instance.Peers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if original.dev.bandwidthConfig == "" || original.bandwidthIDs[key] != canonical {
		t.Fatal("initial Ensure did not install canonical key binding")
	}
	m.Reconcile([]Desired{d})
	if m.ifaces[d.Instance.Id] != original || resolved != 2 {
		t.Fatal("unchanged Reconcile must refresh the account binding and keep the existing device")
	}
	canonical = "another-account"
	m.Reconcile([]Desired{d})
	current := m.ifaces[d.Instance.Id]
	if current == nil || current == original || current.bandwidthIDs[key] != canonical {
		t.Fatal("changed account binding did not rebuild with the new account")
	}
	select {
	case <-original.dev.Wait():
	default:
		t.Fatal("old device survived replacement")
	}

	_, d.Instance.Peers[0].PublicKey = bandwidthKeypair(t)
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	afterKey := m.ifaces[d.Instance.Id]
	if afterKey == nil || afterKey == current {
		t.Fatal("changed peer key did not rebuild")
	}
	d.Instance.Peers[0].AllowedIPs[0] = "10.207.0.3/32"
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	afterAllowedIP := m.ifaces[d.Instance.Id]
	if afterAllowedIP == nil || afterAllowedIP == afterKey ||
		afterKey.inst.Peers[0].AllowedIPs[0] != "10.207.0.2/32" {
		t.Fatal("changed AllowedIPs did not rebuild from an independent snapshot")
	}
	d.Options.DisableCookies = true
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	afterUAPI := m.ifaces[d.Instance.Id]
	if afterUAPI == afterAllowedIP {
		t.Fatal("changed UAPI options did not rebuild")
	}
	d.Instance.Address[0] = "10.207.0.9/24"
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	if m.ifaces[d.Instance.Id] == afterUAPI {
		t.Fatal("changed interface address did not rebuild")
	}

	canonical = ""
	m.Reconcile([]Desired{d})
	if m.HasRunning() {
		t.Fatal("unbound peer preserved a running interface")
	}
	if err := m.Ensure(d); err == nil || m.HasRunning() {
		t.Fatalf("unbound peer via Ensure: error = %v, running = %t", err, m.HasRunning())
	}
}

func TestManagerBandwidthReplacementFailureRemovesIPv6Aliases(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Manager, *Desired)
	}{
		{"kernel mode", func(_ *Manager, d *Desired) { d.Instance.KernelMode = true }},
		{"port forwards", func(_ *Manager, d *Desired) { d.Instance.Peers[0].ForwardedPorts = "8080" }},
		{"relay preparation", func(m *Manager, _ *Desired) {
			m.managedRelay = func(amneziawg.Instance) (SocksRelay, error) {
				return SocksRelay{}, errors.New("relay unavailable")
			}
		}},
		{"invalid AllowedIPs", func(_ *Manager, d *Desired) {
			d.Instance.Peers[0].AllowedIPs = append(d.Instance.Peers[0].AllowedIPs, "10.207.0.0/24")
		}},
		{"device preparation", func(_ *Manager, d *Desired) { d.Instance.Address[0] = "invalid" }},
		{"device configuration", func(_ *Manager, d *Desired) { d.Options.RekeyAfterTime = "invalid" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := withFakeRunIP(t, func(context.Context, ...string) (string, error) { return "", nil })
			m := &Manager{ifaces: map[int]*managed{}, managedRelay: managerBandwidthTestRelay}
			t.Cleanup(m.StopAll)
			if err := m.ConfigureBandwidth(managerBandwidthWait, func(string) (string, bool) { return "canonical", true }); err != nil {
				t.Fatal(err)
			}
			d := managerBandwidthDesired(t)
			d.Instance.IPv6Enabled = true
			d.Instance.IPv6ExternalInterface = "eth-test"
			d.Instance.Peers[0].AllowedIPs = append(d.Instance.Peers[0].AllowedIPs, "fd00:207::2/128")
			if err := m.Ensure(d); err != nil {
				t.Fatal(err)
			}
			old := m.ifaces[d.Instance.Id].dev
			tt.change(m, &d)
			if err := m.Ensure(d); err == nil || m.HasRunning() {
				t.Fatalf("invalid replacement: error = %v, running = %t", err, m.HasRunning())
			}
			select {
			case <-old.Wait():
			default:
				t.Fatal("old device survived failed replacement")
			}
			want := []string{"-6", "addr", "del", "fd00:207::2/128", "dev", "eth-test"}
			if len(*calls) != 2 || !slices.Equal((*calls)[1], want) {
				t.Fatalf("alias commands = %v, want initial add then %v", *calls, want)
			}
		})
	}
}
