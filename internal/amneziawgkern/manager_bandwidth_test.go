package amneziawgkern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
)

type fakeInterfaceBandwidthGate struct {
	blocked    bool
	closed     bool
	closeCheck func() error
}

func (g *fakeInterfaceBandwidthGate) Healthy() bool { return !g.blocked }
func (g *fakeInterfaceBandwidthGate) Block()        { g.blocked = true }
func (g *fakeInterfaceBandwidthGate) Close() error {
	if err := g.closeCheck(); err != nil {
		return err
	}
	g.closed = true
	return nil
}

func bandwidthTestManager(t *testing.T) (*Manager, *fakeHost, Desired, *[]*fakeInterfaceBandwidthGate) {
	t.Helper()
	m, h, _ := newTestManager(t)
	d := managerDesired(81)
	d.Instance.KernelMode = true
	d.Instance.Peers = []amneziawg.Peer{
		{Email: "device-one", PublicKey: publicKeyOf(t, strings.Repeat("02", 32)), AllowedIPs: []string{"10.8.1.2/32"}},
		{Email: "device-two", PublicKey: publicKeyOf(t, otherPrivateKey), AllowedIPs: []string{"10.8.1.3/32"}},
	}
	if err := m.ConfigureBandwidth(func(_ context.Context, account string, _ int) error {
		if account != "one-account" {
			t.Errorf("permit account = %q", account)
		}
		return nil
	}, func(email string) (string, bool) {
		return "one-account", email == "device-one" || email == "device-two"
	}, nil); err != nil {
		t.Fatal(err)
	}
	var gates []*fakeInterfaceBandwidthGate
	m.bandwidth.lookup = func(name string) (*net.Interface, error) {
		link, ok := h.links[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		iface := &net.Interface{Index: 81, Name: name}
		if link.up {
			iface.Flags = net.FlagUp
		}
		return iface, nil
	}
	m.bandwidth.open = func(name string, index int, _ string, routes []BandwidthRoute, permit func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
		link := h.links[name]
		if link == nil || link.up || link.publicKey == "" || len(link.addresses) == 0 || index != 81 {
			t.Fatal("gate opened before configuration was installed on a down link")
		}
		if len(routes) != 2 || routes[0].AccountID != routes[1].AccountID {
			t.Fatalf("expected two devices to share one account, routes = %v", routes)
		}
		for _, route := range routes {
			if err := permit(context.Background(), route.AccountID, 1200); err != nil {
				t.Fatal(err)
			}
		}
		gate := &fakeInterfaceBandwidthGate{}
		gate.closeCheck = func() error {
			if !gate.blocked || h.linkExists(name) {
				t.Error("gate closed before it was blocked and its link removed")
			}
			return nil
		}
		gates = append(gates, gate)
		return gate, nil
	}
	m.bandwidth.removeStale = func(name, _ string) error {
		if h.linkExists(name) {
			t.Errorf("attempted stale gate removal while %s still exists", name)
		}
		return nil
	}
	return m, h, d, &gates
}

func TestKernelBandwidthManagerKeepsGateUntilSuccessfulTeardown(t *testing.T) {
	m, h, d, gates := bandwidthTestManager(t)
	name := ownedInterfaceName(d.Instance.Id)
	if err := m.ReconcileBandwidth(nil); err != nil || len(h.commands) != 0 {
		t.Fatalf("empty reconciliation touched host: %v, %v", err, h.commands)
	}
	if err := m.ReconcileBandwidth([]Desired{d}); err != nil {
		t.Fatal(err)
	}
	if len(*gates) != 1 || !h.links[name].up {
		t.Fatal("reconcile did not bring the guarded link up")
	}
	state, ok := m.TrafficStateFor(d.Instance.Id)
	if !ok || state.PeerEmails[d.Instance.Peers[0].PublicKey] != "device-one" {
		t.Fatalf("traffic state identifies the wrong installed peer: %+v", state)
	}
	delete(state.PeerEmails, d.Instance.Peers[0].PublicKey)
	state, ok = m.TrafficStateFor(d.Instance.Id)
	if !ok || state.PeerEmails[d.Instance.Peers[0].PublicKey] != "device-one" {
		t.Fatal("traffic state returned a mutable alias to the installed peer mapping")
	}
	commands := len(h.commands)
	if err := m.Ensure(d); err != nil || len(h.commands) != commands {
		t.Fatalf("unchanged live policy rebuilt the interface: %v", err)
	}
	h.failing["ip link del"] = errInjected
	d.Instance.Peers[0].AllowedIPs = []string{"10.8.1.4/32"}
	if err := m.ReconcileBandwidth([]Desired{d}); !errors.Is(err, errInjected) {
		t.Fatalf("expected deletion error, got %v", err)
	}
	first := (*gates)[0]
	if !h.linkExists(name) || h.links[name].up || !first.blocked || first.closed {
		t.Fatal("failed teardown dropped the live interface's protection")
	}
	delete(h.failing, "ip link del")
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	if !first.closed || len(*gates) != 2 || !h.links[name].up || h.ran("awg syncconf") {
		t.Fatal("change did not fully replace the old protected interface")
	}
	d.Instance.Peers[0].AllowedIPs = []string{"10.8.1.0/24"}
	if err := m.Ensure(d); err == nil || h.linkExists(name) || !(*gates)[1].closed {
		t.Fatalf("invalid policy retained forwarding: %v", err)
	}
}

func TestKernelBandwidthGateFailureLeavesNoUpLink(t *testing.T) {
	m, h, d, gates := bandwidthTestManager(t)
	name := ownedInterfaceName(d.Instance.Id)
	m.bandwidth.open = func(string, int, string, []BandwidthRoute, func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
		return nil, errInjected
	}
	if err := m.ReconcileBandwidth([]Desired{d}); !errors.Is(err, errInjected) {
		t.Fatalf("expected gate setup error, got %v", err)
	}
	if h.linkExists(name) || len(*gates) != 0 || h.ran("ip link set") {
		t.Fatal("setup failure activated an unguarded link")
	}
}

func TestKernelBandwidthGateCreationFailureKeepsRecoveryGeneration(t *testing.T) {
	m, h, d, _ := bandwidthTestManager(t)
	name := ownedInterfaceName(d.Instance.Id)
	open := m.bandwidth.open
	var createdGeneration string
	m.bandwidth.open = func(_ string, _ int, generation string, _ []BandwidthRoute, _ func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
		createdGeneration = generation
		return nil, errInjected
	}
	cleanupErr := errors.New("cleanup interrupted")
	m.bandwidth.removeStale = func(gotName, generation string) error {
		if gotName != name || generation == "" || generation != createdGeneration || h.linkExists(name) {
			t.Fatalf("recovery got name %s generation %s while link state is %t", gotName, generation, h.linkExists(name))
		}
		return cleanupErr
	}
	err := m.Ensure(d)
	if !errors.Is(err, errInjected) || !errors.Is(err, cleanupErr) {
		t.Fatalf("setup failure did not retain cleanup error: %v", err)
	}
	conf, found, err := readOwnedConfig(m.confDir, d.Instance.Id)
	nat, valid := bandwidthNATState(conf)
	if err != nil || !found || !valid || nat.GateGeneration != createdGeneration {
		t.Fatalf("persisted recovery generation was lost: found=%t valid=%t err=%v", found, valid, err)
	}
	m.bandwidth.open = open
	m.bandwidth.removeStale = func(gotName, generation string) error {
		if gotName != name || generation != createdGeneration || h.linkExists(name) {
			t.Fatal("retry did not recover the exact generation before recreating the interface")
		}
		return nil
	}
	if err := m.Ensure(d); err != nil || !h.links[name].up {
		t.Fatalf("unable to recover the protected interface: %v", err)
	}
}

func TestKernelBandwidthQuiescesChangedAuthorizationBeforeCounters(t *testing.T) {
	m, h, d, gates := bandwidthTestManager(t)
	d.Instance.Peers[0].TrafficID = 91
	name := ownedInterfaceName(d.Instance.Id)
	allowBoth := true
	m.bandwidth.snapshot = func() func(string, string, string) (string, bool) {
		both := allowBoth
		return func(_, email, _ string) (string, bool) { return "one-account", both || email == "device-one" }
	}
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	if err := m.QuiesceBandwidthPolicy(false); err != nil || !h.links[name].up || (*gates)[0].blocked {
		t.Fatalf("unchanged entitlement interrupted the interface: %v", err)
	}
	allowBoth = false
	if ready := m.ReadyBandwidthBindings(); len(ready) != 0 {
		t.Fatalf("ready bindings included a generation with changed authorization: %v", ready)
	}
	if err := m.QuiesceBandwidthPolicy(false); err != nil || h.links[name].up || !(*gates)[0].blocked || h.ran("ip link del") {
		t.Fatalf("changed entitlement should drain and down the link before deletion: %v", err)
	}
	if state, ok := m.TrafficStateFor(d.Instance.Id); !ok || state.PeerTrafficIDs[d.Instance.Peers[0].PublicKey] != 91 {
		t.Fatal("quiescing lost the final generation's traffic attribution")
	}
}

func TestNftTableCommentRequiresExactPlainHeaderAndTopLevelToken(t *testing.T) {
	const table = "xui_awg_managed_nat_81"
	const token = "vanillaproxy-awg-nat-v1 xui-awg81 00112233445566778899aabbccddeeff"
	const plain = "table ip " + table + " { # handle 37\n\tcomment \"" + token + "\"\n\n\tchain postrouting { # handle 1\n\t\tcomment \"nested\"\n\t}\n}"
	const compact = `{"family":"ip","name":"` + table + `","handle":37}`
	for _, tc := range []struct {
		name  string
		text  string
		valid bool
	}{
		{"exact", plain, true},
		{"handle", strings.Replace(plain, "handle 37", "handle 42", 1), false},
		{"family", strings.Replace(plain, "table ip", "table inet", 1), false},
		{"name", strings.Replace(plain, table, "imposter", 1), false},
		{"nested", strings.Replace(plain, "\tcomment \""+token+"\"", "", 1), false},
		{"duplicate", strings.Replace(plain, "\n\n", "\n\tcomment \"duplicate\"\n", 1), false},
		{"extra table", plain + "\ntable inet imposter {\n}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := func(_ string, bin string, args ...string) (string, error) {
				if got := bin + " " + strings.Join(args, " "); got != "nft -an list table ip "+table {
					return "", fmt.Errorf("unexpected lookup %s", got)
				}
				return tc.text, nil
			}
			comment, ok := nftTableComment(json.RawMessage(compact), "", "ip", table, 37, command)
			if ok != tc.valid || (ok && comment != token) {
				t.Fatalf("comment %q, valid %t", comment, ok)
			}
		})
	}
}

func TestAutomaticKernelBandwidthInstallsOnlyExactBindings(t *testing.T) {
	m, h, d, gates := bandwidthTestManager(t)
	first, second := &d.Instance.Peers[0], &d.Instance.Peers[1]
	first.AllowedIPs = []string{"10.8.1.8/29"}
	first.PresharedKey = otherPrivateKey
	first.TrafficID = 91
	second.TrafficID = 92
	secondCredential := amneziawg.BandwidthCredential(second.PublicKey, second.PresharedKey)
	const protocol = "amneziawg"
	credentials := map[string]string{
		"Device-one": amneziawg.BandwidthCredential(first.PublicKey, first.PresharedKey),
		second.Email: secondCredential,
	}
	m.bandwidth.snapshot = func() func(string, string, string) (string, bool) {
		frozen := maps.Clone(credentials)
		return func(p, email, credential string) (string, bool) {
			return "", p == protocol && frozen[email] == credential
		}
	}
	var installed []BandwidthRoute
	m.bandwidth.open = func(name string, _ int, _ string, routes []BandwidthRoute, _ func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
		if h.links[name].up {
			t.Fatal("opened gate on a running link")
		}
		installed = routes
		gate := &fakeInterfaceBandwidthGate{closeCheck: func() error { return nil }}
		*gates = append(*gates, gate)
		return gate, nil
	}
	name := ownedInterfaceName(d.Instance.Id)
	assertReady := func(email, credential string) {
		t.Helper()
		ready := m.ReadyBandwidthBindings()
		want := bandwidthexchange.PolicyBinding{Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, credential)}
		if len(ready) != 1 || len(ready[email]) != 1 || ready[email][0] != want {
			t.Fatalf("incorrect ready bindings: %v", ready)
		}
	}
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	assertReady(second.Email, secondCredential)
	state, _ := m.TrafficStateFor(d.Instance.Id)
	if strings.Contains(h.links[name].conf, first.PublicKey) || len(state.PeerTrafficIDs) != 1 || state.PeerTrafficIDs[second.PublicKey] != 92 ||
		len(installed) != 1 || !installed[0].Unmetered || installed[0].AccountID != "" {
		t.Fatal("installed peers, traffic ledger, or exempt routes differ from authorized peers")
	}
	if err := m.Ensure(d); err != nil || len(*gates) != 1 {
		t.Fatalf("unchanged snapshot rebuilt the link: %v", err)
	}
	(*gates)[0].Block()
	if ready := m.ReadyBandwidthBindings(); len(ready) != 0 {
		t.Fatalf("unhealthy gate advertised %v", ready)
	}
	delete(credentials, second.Email)
	credentials[first.Email] = credentials["Device-one"]
	if err := m.Ensure(d); err != nil {
		t.Fatal(err)
	}
	assertReady(first.Email, credentials[first.Email])
	if len(installed) != 1 || installed[0].AllowedIP.String() != "10.8.1.8/29" {
		t.Fatalf("installed routes: %v", installed)
	}
	first.AllowedIPs = []string{"10.8.1.10/32"}
	if err := m.Ensure(d); err != nil || len(installed) != 1 || installed[0].AllowedIP.String() != "10.8.1.10/32" {
		t.Fatalf("narrower route did not replace old binding: %v, %v", installed, err)
	}
	first.PresharedKey = ""
	if err := m.Ensure(d); err != nil || h.linkExists(name) || len(m.ReadyBandwidthBindings()) != 0 {
		t.Fatalf("credential rotation retained an unauthorized interface: %v", err)
	}
	credentials[first.Email] = amneziawg.BandwidthCredential(first.PublicKey, first.PresharedKey)
	m.bandwidth.open = func(string, int, string, []BandwidthRoute, func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
		return nil, errInjected
	}
	if err := m.Ensure(d); !errors.Is(err, errInjected) || h.linkExists(name) || len(m.ReadyBandwidthBindings()) != 0 {
		t.Fatalf("gate failure retained an interface or marked it ready: %v", err)
	}
}

func TestKernelBandwidthManagerRefusesForeignKeyOnRecovery(t *testing.T) {
	m, h, d, _ := bandwidthTestManager(t)
	name := ownedInterfaceName(d.Instance.Id)
	s, err := buildSpec(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConf(m.confDir, name, s.conf); err != nil {
		t.Fatal(err)
	}
	h.links[name] = &fakeLink{publicKey: publicKeyOf(t, otherPrivateKey), up: true}
	if ok, err := m.RecoverableBandwidthInterface(name); ok || err != nil {
		t.Fatalf("classified a stock interface as managed: %v", err)
	}
	managedConfig := strings.Replace(s.conf, "\n", "\n"+bandwidthOwnershipMarker+"\n", 1)
	if err := writeConf(m.confDir, name, managedConfig); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.RecoverableBandwidthInterface(name); ok || err == nil {
		t.Fatal("classified a foreign live key as managed")
	}
	if err := m.ReconcileBandwidth([]Desired{d}); err == nil || !h.links[name].up || h.ran("ip link del") {
		t.Fatalf("recovery touched the foreign interface: %v", err)
	}
	h.links[name].publicKey = publicKeyOf(t, testPrivateKey)
	if ok, err := m.RecoverableBandwidthInterface(name); !ok || err != nil {
		t.Fatalf("refused the live managed key: %v", err)
	}
	h.links[name].publicKey = ""
	if ok, err := m.RecoverableBandwidthInterface(name); ok || err == nil {
		t.Fatal("classified a keyless live interface as managed")
	}
}

func TestBandwidthNATCleanupRequiresExactOwnedStructure(t *testing.T) {
	nat := bandwidthNAT{
		Generation: "00112233445566778899aabbccddeeff",
		IfIndex:    81,
		Egress:     "eth0",
		Subnets:    []netip.Prefix{netip.MustParsePrefix("10.8.1.0/24")},
	}
	listing := `{"nftables":[
 {"table":{"family":"ip","name":"xui_awg_managed_nat_81","handle":37,"comment":"vanillaproxy-awg-nat-v1 xui-awg81 00112233445566778899aabbccddeeff"}},
 {"chain":{"family":"ip","table":"xui_awg_managed_nat_81","name":"postrouting","handle":1,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
 {"rule":{"family":"ip","table":"xui_awg_managed_nat_81","chain":"postrouting","handle":2,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":"81"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"xui-awg81"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.8.1.0","len":24}}}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"masquerade":null}]}},
 {"table":{"family":"ip","name":"xui_awg81","handle":43}}
]}`
	if handle, err := ownedBandwidthNATHandle(listing, 81, "xui-awg81", nat, nil); err != nil || handle != 37 {
		t.Fatalf("did not identify only the exact table handle: %d, %v", handle, err)
	}
	for _, changed := range []string{
		strings.Replace(listing, nat.Generation, "foreign", 1),
		strings.Replace(listing, `"right":"81"`, `"right":"82"`, 1),
		strings.Replace(listing, `"right":"xui-awg81"`, `"right":"unrelated"`, 1),
		strings.Replace(listing, "eth0", "eth1", 1),
		strings.Replace(listing, `"masquerade":null`, `"masquerade":{"flags":"random"}`, 1),
		strings.Replace(listing, `{"table":{"family":"ip","name":"xui_awg81","handle":43}}`,
			`{"set":{"family":"ip","table":"xui_awg_managed_nat_81","name":"foreign","handle":43}}`, 1),
	} {
		if handle, err := ownedBandwidthNATHandle(changed, 81, "xui-awg81", nat, nil); err == nil || handle != 0 {
			t.Fatalf("classified a modified table as owned: %d, %v", handle, err)
		}
	}
	nat.IfIndex = 0
	m, h, _ := newTestManager(t)
	if err := m.removeBandwidthEgress(81, "xui-awg81", nat); err != nil || len(h.commands) != 0 {
		t.Fatalf("pre-installation metadata must not inspect or delete any table: %v, %v", err, h.commands)
	}
}
