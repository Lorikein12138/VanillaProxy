package amneziawgkern

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

type interfaceBandwidthGate interface {
	Healthy() bool
	Block()
	Close() error
}

type BandwidthRoute struct {
	AllowedIP netip.Prefix
	AccountID string
	Unmetered bool
}

const bandwidthProtocol = "amneziawg"

type bandwidthPeerAuthorization struct {
	email, credential, account string
}

type kernelBandwidthPolicy struct {
	wait        func(context.Context, string, int) error
	resolve     func(string) (string, bool)
	snapshot    func() func(string, string, string) (string, bool)
	lookup      func(string) (*net.Interface, error)
	open        func(string, int, string, []BandwidthRoute, func(context.Context, string, int) error) (interfaceBandwidthGate, error)
	removeStale func(string, string) error
}

// ConfigureBandwidth fixes the permit callback and account mapping before
// any managed link starts. The resolver runs under the manager lock.
func (m *Manager) ConfigureBandwidth(wait func(context.Context, string, int) error, resolveAccount func(string) (string, bool), snapshot func() func(string, string, string) (string, bool)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if wait == nil || resolveAccount == nil {
		return errors.New("amneziawgkern: bandwidth requires a permit callback and account resolver")
	}
	if m.bandwidth != nil || len(m.ifaces) != 0 {
		return errors.New("amneziawgkern: configure bandwidth before managing an interface")
	}
	m.bandwidth = &kernelBandwidthPolicy{
		wait:     wait,
		resolve:  resolveAccount,
		snapshot: snapshot,
		lookup:   net.InterfaceByName,
		open: func(name string, index int, generation string, routes []BandwidthRoute, permit func(context.Context, string, int) error) (interfaceBandwidthGate, error) {
			gate, err := openBandwidthGate(name, index, generation, routes, permit)
			if err != nil {
				return nil, err
			}
			return gate, nil
		},
		removeStale: removeStaleBandwidthGate,
	}
	return nil
}

func (m *Manager) bandwidthAccountLookup() func(string, string, string) (string, bool) {
	if m.bandwidth == nil || m.bandwidth.snapshot == nil {
		return nil
	}
	return m.bandwidth.snapshot()
}

// RecoverableBandwidthInterface identifies a live interface left behind by an
// earlier managed panel process. Neither a project name nor a keyless link
// proves ownership.
func (m *Manager) RecoverableBandwidthInterface(name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := parseOwnedInterfaceName(name)
	if !ok || !m.host.linkExists(name) {
		return false, nil
	}
	config, found, err := readOwnedConfig(m.confDir, id)
	if err != nil || !found || !isBandwidthOwnedConfig(config, name) {
		return false, err
	}
	if err := m.verifyLiveInterfaceKey(name, config, false); err != nil {
		return false, err
	}
	return true, nil
}

// ValidateBandwidthInstance checks the exact peer set that can be installed
// under bandwidth management without consulting or changing the host.
func ValidateBandwidthInstance(inst amneziawg.Instance, resolveAccount func(string) (string, bool)) error {
	_, _, _, err := prepareBandwidthPeers(inst, resolveAccount, nil)
	return err
}

func prepareBandwidthPeers(inst amneziawg.Instance, resolveAccount func(string) (string, bool), lookup func(string, string, string) (string, bool)) ([]amneziawg.Peer, []BandwidthRoute, []bandwidthPeerAuthorization, error) {
	if !inst.KernelMode || resolveAccount == nil {
		return nil, nil, nil, errors.New("amneziawgkern: bandwidth requires a kernel-mode instance and account resolver")
	}
	if err := ValidateInstanceFeatures(inst, inst.RouteThroughXray); err != nil {
		return nil, nil, nil, err
	}
	var interfaceKey string
	if inst.PrivateKey != "" {
		public, err := wireguard.PublicKeyFromPrivate(inst.PrivateKey)
		if err != nil {
			return nil, nil, nil, errors.New("amneziawgkern: invalid interface private key")
		}
		interfaceKey, _ = wireguard.KeyToHex(public)
	}
	keys := make(map[string]bool, len(inst.Peers))
	peers := make([]amneziawg.Peer, 0, len(inst.Peers))
	routes := make([]BandwidthRoute, 0, len(inst.Peers))
	prefixes := make([]netip.Prefix, 0, len(inst.Peers))
	var authorizations []bandwidthPeerAuthorization
	for i, peer := range inst.Peers {
		key, err := wireguard.KeyToHex(peer.PublicKey)
		if err != nil || key == "" || key == interfaceKey || keys[key] {
			return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d needs a unique public key", i+1)
		}
		keys[key] = true
		credential := amneziawg.BandwidthCredential(peer.PublicKey, peer.PresharedKey)
		if credential == "" || amneziawg.ValidateConfigValue("publicKey", peer.PublicKey) != nil || amneziawg.ValidateConfigValue("presharedKey", peer.PresharedKey) != nil {
			return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d needs valid authentication keys", i+1)
		}
		if peer.Email == "" || strings.TrimSpace(peer.Email) != peer.Email || amneziawg.ValidateConfigValue("email", peer.Email) != nil {
			return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d needs an exact account email", i+1)
		}
		var account string
		var allowed bool
		if lookup != nil {
			account, allowed = lookup(bandwidthProtocol, peer.Email, credential)
		} else {
			account, allowed = resolveAccount(peer.Email)
		}
		if (lookup == nil && (!allowed || account == "")) || (allowed && strings.TrimSpace(account) != account) {
			return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d has no valid canonical account", i+1)
		}
		if len(peer.AllowedIPs) == 0 {
			return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d needs at least one IPv4 AllowedIP", i+1)
		}
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Addr().Is4() {
				return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d needs valid IPv4 AllowedIPs", i+1)
			}
			prefix = prefix.Masked()
			for _, existing := range prefixes {
				if existing.Overlaps(prefix) {
					return nil, nil, nil, fmt.Errorf("amneziawgkern: bandwidth peer %d has overlapping AllowedIPs", i+1)
				}
			}
			prefixes = append(prefixes, prefix)
			if allowed {
				routes = append(routes, BandwidthRoute{AllowedIP: prefix, AccountID: account, Unmetered: account == ""})
			}
		}
		if !allowed {
			continue
		}
		peers = append(peers, peer)
		if lookup != nil {
			authorizations = append(authorizations, bandwidthPeerAuthorization{email: peer.Email, credential: credential, account: account})
		}
	}
	return peers, routes, authorizations, nil
}

// ReconcileBandwidth returns setup and cleanup failures to the node's
// readiness check. It refuses to run without the shared permit policy.
func (m *Manager) ReconcileBandwidth(desired []Desired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bandwidth == nil {
		return errors.New("amneziawgkern: bandwidth policy is not installed")
	}
	return m.reconcileLocked(desired)
}

type bandwidthProjection struct {
	spec       spec
	routes     []BandwidthRoute
	emails     map[string]string
	trafficIDs map[string]int
	peers      []bandwidthPeerAuthorization
}

func (m *Manager) projectBandwidth(d Desired, lookup func(string, string, string) (string, bool)) (bandwidthProjection, error) {
	peers, routes, authorizations, err := prepareBandwidthPeers(d.Instance, m.bandwidth.resolve, lookup)
	if err != nil {
		return bandwidthProjection{}, err
	}
	if d.RouteThroughXray {
		return bandwidthProjection{}, errors.New("amneziawgkern: bandwidth requires direct kernel egress")
	}
	if lookup != nil && len(peers) == 0 {
		return bandwidthProjection{}, nil
	}
	d.Instance.Peers = peers
	s, err := buildSpec(d)
	if err != nil {
		return bandwidthProjection{}, err
	}
	emails, trafficIDs := bandwidthPeerLedger(peers)
	return bandwidthProjection{spec: s, routes: routes, emails: emails, trafficIDs: trafficIDs, peers: authorizations}, nil
}

func (m *Manager) ensureBandwidthLocked(d Desired, lookup func(string, string, string) (string, bool)) error {
	id := d.Instance.Id
	next, err := m.projectBandwidth(d, lookup)
	if err != nil {
		return m.rejectBandwidthUpdate(id, err)
	}
	if next.spec.name == "" {
		return m.teardown(id)
	}
	if cur := m.ifaces[id]; cur != nil && maps.Equal(cur.bandwidthPeerTrafficIDs, next.trafficIDs) && m.bandwidthStateCurrent(cur, next.spec, next.routes) {
		cur.bandwidthPeerEmails = next.emails
		cur.bandwidthPeers = next.peers
		return nil
	}
	if err := m.teardown(id); err != nil {
		return err
	}
	if err := m.startBandwidthLink(id, next.spec, next.routes, next.emails, next.trafficIDs); err != nil {
		return err
	}
	m.ifaces[id].bandwidthPeers = next.peers
	return nil
}

// QuiesceBandwidthPolicy blocks interfaces whose installed authorization
// changed in the new snapshot. The caller serializes this with policy install
// and the counter collection job.
func (m *Manager) QuiesceBandwidthPolicy(force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bandwidth == nil {
		return nil
	}
	lookup := m.bandwidthAccountLookup()
	var errs []error
	for id, cur := range m.ifaces {
		if force || !bandwidthPeersAuthorized(cur.bandwidthPeers, lookup) {
			errs = append(errs, m.quiesceBandwidthLink(id, cur))
		}
	}
	return errors.Join(errs...)
}

func bandwidthPeersAuthorized(peers []bandwidthPeerAuthorization, lookup func(string, string, string) (string, bool)) bool {
	if lookup == nil {
		return len(peers) == 0
	}
	for _, peer := range peers {
		if id, allowed := lookup(bandwidthProtocol, peer.email, peer.credential); !allowed || id != peer.account {
			return false
		}
	}
	return len(peers) != 0
}

// QuiesceBandwidthChanges drains and downs a link before the job samples its
// last counters. Unchanged healthy links stay up.
func (m *Manager) QuiesceBandwidthChanges(desired []Desired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bandwidth == nil {
		return errors.New("amneziawgkern: bandwidth policy is not installed")
	}
	lookup := m.bandwidthAccountLookup()
	wanted := make(map[int]Desired, len(desired))
	for _, d := range desired {
		wanted[d.Instance.Id] = d
	}
	var errs []error
	for id, cur := range m.ifaces {
		if d, ok := wanted[id]; ok {
			next, err := m.projectBandwidth(d, lookup)
			if err == nil && next.spec.name != "" && maps.Equal(cur.bandwidthPeerTrafficIDs, next.trafficIDs) && m.bandwidthStateCurrent(cur, next.spec, next.routes) {
				continue
			}
		}
		errs = append(errs, m.quiesceBandwidthLink(id, cur))
	}
	return errors.Join(errs...)
}

func (m *Manager) quiesceBandwidthLink(id int, cur *managed) error {
	if cur.bandwidthGate != nil {
		cur.bandwidthGate.Block()
	}
	name := cur.spec.name
	if !m.host.linkExists(name) {
		return nil
	}
	owned, found, err := readOwnedConfig(m.confDir, id)
	if err != nil {
		return err
	}
	iface, err := m.bandwidth.lookup(name)
	if err != nil {
		return err
	}
	if !found || !isBandwidthOwnedConfig(owned, name) || iface.Index != cur.bandwidthIndex {
		return fmt.Errorf("amneziawgkern: refusing to quiesce an unowned or replaced interface %s", name)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil
	}
	if err := m.verifyLiveInterfaceKey(name, owned, false); err != nil {
		return err
	}
	if out, err := m.host.run("", "ip", "link", "set", "dev", name, "down"); err != nil {
		return fmt.Errorf("amneziawgkern: ip link set %s down: %w (%s)", name, err, out)
	}
	return nil
}

// ReadyBandwidthBindings reports the exact bindings installed on live,
// protected links. Failed or stopped gates cannot acknowledge a policy.
func (m *Manager) ReadyBandwidthBindings() map[string][]bandwidthexchange.PolicyBinding {
	m.mu.Lock()
	defer m.mu.Unlock()
	ready := make(map[string][]bandwidthexchange.PolicyBinding)
	lookup := m.bandwidthAccountLookup()
	for _, cur := range m.ifaces {
		if lookup == nil || !bandwidthPeersAuthorized(cur.bandwidthPeers, lookup) || !m.bandwidthStateCurrent(cur, cur.spec, cur.bandwidthRoutes) {
			continue
		}
		for _, peer := range cur.bandwidthPeers {
			binding := bandwidthexchange.PolicyBinding{Protocol: bandwidthProtocol, Fingerprint: bandwidthexchange.CredentialFingerprint(bandwidthProtocol, peer.credential)}
			ready[peer.email] = append(ready[peer.email], binding)
		}
	}
	return ready
}

func bandwidthPeerLedger(peers []amneziawg.Peer) (map[string]string, map[string]int) {
	emails := make(map[string]string, len(peers))
	trafficIDs := make(map[string]int, len(peers))
	for _, peer := range peers {
		keyHex, _ := wireguard.KeyToHex(peer.PublicKey)
		raw, _ := hex.DecodeString(keyHex)
		key := base64.StdEncoding.EncodeToString(raw)
		emails[key] = peer.Email
		trafficIDs[key] = peer.TrafficID
	}
	return emails, trafficIDs
}

func (m *Manager) rejectBandwidthUpdate(id int, err error) error {
	if id <= 0 {
		return err
	}
	return errors.Join(err, m.teardown(id))
}

func (m *Manager) bandwidthStateCurrent(cur *managed, s spec, routes []BandwidthRoute) bool {
	if cur.bandwidthGate == nil || !cur.bandwidthGate.Healthy() || cur.spec.structFP != s.structFP ||
		cur.spec.conf != s.conf || cur.spec.nat != s.nat || cur.spec.forward != s.forward || !slices.Equal(cur.bandwidthRoutes, routes) {
		return false
	}
	iface, err := m.bandwidth.lookup(s.name)
	return err == nil && iface.Index == cur.bandwidthIndex && iface.Flags&net.FlagUp != 0
}

func (m *Manager) startBandwidthLink(id int, s spec, routes []BandwidthRoute, peerEmails map[string]string, peerTrafficIDs map[string]int) (result error) {
	nat, err := newBandwidthNAT(s, m.host.hasCommand("iptables"))
	if err != nil {
		return err
	}
	natConfig, err := json.Marshal(nat)
	if err != nil {
		return err
	}
	config := strings.Replace(s.conf, "\n", "\n"+bandwidthOwnershipMarker+"\n"+bandwidthNATMarker+string(natConfig)+"\n", 1)
	if err := writeConf(m.confDir, s.name, config); err != nil {
		return err
	}
	created, createErr := m.createLinkDown(s)
	if !created {
		return errors.Join(createErr, os.Remove(ConfPathIn(m.confDir, s.name)))
	}
	cur := m.newManaged(s, false)
	cur.bandwidthRoutes = routes
	m.ifaces[id] = cur
	defer func() {
		if result != nil {
			result = errors.Join(result, m.teardown(id))
		}
	}()
	iface, err := m.bandwidth.lookup(s.name)
	if err != nil {
		return errors.Join(createErr, fmt.Errorf("amneziawgkern: inspect new interface %s: %w", s.name, err))
	}
	cur.bandwidthIndex = iface.Index
	if createErr != nil {
		return createErr
	}
	cur.bandwidthPeerEmails = peerEmails
	cur.bandwidthPeerTrafficIDs = peerTrafficIDs
	cur.bandwidthGate, err = m.bandwidth.open(s.name, iface.Index, nat.GateGeneration, routes, m.bandwidth.wait)
	if err != nil {
		return err
	}
	if !cur.bandwidthGate.Healthy() {
		return fmt.Errorf("amneziawgkern: bandwidth gate for %s stopped during setup", s.name)
	}
	if err := m.applyBandwidthEgress(id, s.name, nat); err != nil {
		return err
	}
	if err := m.activateLink(s); err != nil {
		return err
	}
	if !cur.bandwidthGate.Healthy() {
		return fmt.Errorf("amneziawgkern: bandwidth gate for %s stopped during activation", s.name)
	}
	logger.Info("amneziawgkern: started bandwidth-managed kernel interface ", s.name, " for inbound ", id)
	return nil
}
