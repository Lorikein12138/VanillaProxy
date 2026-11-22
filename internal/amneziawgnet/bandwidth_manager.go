package amneziawgnet

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// ConfigureBandwidth installs one shared gate before the manager's first
// successful start. The resolver receives each peer's exact email under the
// manager lock and must not call back into Manager.
func (m *Manager) ConfigureBandwidth(wait func(context.Context, string, int) error, resolveAccount func(email string) (string, bool)) error {
	if resolveAccount == nil {
		return errors.New("amneziawgnet: bandwidth account resolver is required")
	}
	return m.configureBandwidth(wait, resolveAccount)
}

// ConfigureAutomaticBandwidth requires a preselected account snapshot for each device.
func (m *Manager) ConfigureAutomaticBandwidth(wait func(context.Context, string, int) error) error {
	return m.configureBandwidth(wait, nil)
}

func (m *Manager) configureBandwidth(wait func(context.Context, string, int) error, resolveAccount func(string) (string, bool)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case wait == nil:
		return errors.New("amneziawgnet: bandwidth gate is required")
	case m.bandwidthWait != nil:
		return errors.New("amneziawgnet: bandwidth is already configured")
	case m.started:
		return errors.New("amneziawgnet: configure bandwidth before starting an interface")
	}
	m.bandwidthWait = wait
	m.resolveAccount = resolveAccount
	return nil
}

func (m *Manager) prepareBandwidth(inst amneziawg.Instance, clientIDs map[string]string) (*BandwidthOptions, error) {
	if inst.KernelMode {
		return nil, errors.New("amneziawgnet: bandwidth requires an embedded interface")
	}
	resolve := m.resolveAccount
	automatic := resolve == nil
	if automatic {
		if clientIDs == nil || len(clientIDs) == 0 || len(clientIDs) != len(inst.Peers) {
			return nil, errors.New("amneziawgnet: automatic bandwidth bindings must match the peer list")
		}
		seen := make(map[string]bool, len(clientIDs))
		resolve = func(email string) (string, bool) {
			id, ok := clientIDs[email]
			if seen[email] {
				return "", false
			}
			seen[email] = true
			return id, ok
		}
	}
	bindings := make(map[string]string, len(inst.Peers))
	for i, peer := range inst.Peers {
		if peer.ForwardedPorts != "" {
			return nil, fmt.Errorf("amneziawgnet: bandwidth peer %d has public port forwards", i+1)
		}
		if !validRelayEmail(peer.Email) {
			return nil, fmt.Errorf("amneziawgnet: bandwidth peer %d must have a 1 to 255 byte relay email", i+1)
		}
		key, err := wireguard.KeyToHex(peer.PublicKey)
		if err != nil || key == "" {
			return nil, fmt.Errorf("amneziawgnet: bandwidth peer %d has an invalid public key", i+1)
		}
		if _, duplicate := bindings[key]; duplicate {
			return nil, fmt.Errorf("amneziawgnet: bandwidth peer %d has a duplicate public key", i+1)
		}
		id, ok := resolve(peer.Email)
		if !ok || (!automatic && id == "") || strings.TrimSpace(id) != id {
			return nil, fmt.Errorf("amneziawgnet: bandwidth peer %d has no valid canonical account binding", i+1)
		}
		bindings[key] = id
	}
	// Device construction validates this snapshot against the exact UAPI
	// peer list and builds its immutable packet routes with newTunBandwidth.
	return &BandwidthOptions{ClientIDs: bindings, Wait: m.bandwidthWait, allowUnrestricted: automatic}, nil
}

// BandwidthDesired pairs the exact peer list with the canonical ID for each
// retained relay identity. An empty ID is unrestricted.
type BandwidthDesired struct {
	Desired
	ClientIDs map[string]string
}

// ReconcileBandwidth applies only instances selected by a frozen policy.
func (m *Manager) ReconcileBandwidth(desired []BandwidthDesired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bandwidthWait == nil || m.resolveAccount != nil {
		return errors.New("amneziawgnet: automatic bandwidth is not configured")
	}
	want := make(map[int]struct{}, len(desired))
	for _, entry := range desired {
		want[entry.Instance.Id] = struct{}{}
	}
	m.removeUndesiredLocked(want)
	var failures []error
	for _, entry := range desired {
		if err := m.ensureLocked(entry.Desired, entry.ClientIDs); err != nil {
			failures = append(failures, fmt.Errorf("embedded AmneziaWG inbound %d: %w", entry.Instance.Id, err))
		}
	}
	return errors.Join(failures...)
}

// MatchesBandwidth confirms the device is running the exact selected peers
// and packet routes with the expected canonical account bindings.
func (m *Manager) MatchesBandwidth(desired BandwidthDesired) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, opts := desired.Instance, desired.Options
	cur := m.ifaces[inst.Id]
	if cur == nil || m.bandwidthWait == nil || m.resolveAccount != nil || m.managedRelay == nil {
		return false
	}
	var err error
	opts.Bandwidth, err = m.prepareBandwidth(inst, desired.ClientIDs)
	if err != nil {
		return false
	}
	conf, err := buildUAPIConfig(inst, opts)
	if err != nil {
		return false
	}
	relay, err := m.managedRelay(inst)
	return err == nil && matchesBandwidthDevice(cur, inst, opts, conf, relay)
}

func matchesBandwidthDevice(cur *managed, inst amneziawg.Instance, opts DeviceOptions, conf string, relay SocksRelay) bool {
	select {
	case <-cur.dev.Wait():
		return false
	default:
		return conf == cur.uapiConfig && relay == cur.udpRelay.relay && cur.logger == opts.Logger &&
			maps.Equal(cur.bandwidthIDs, opts.Bandwidth.ClientIDs) && reflect.DeepEqual(cur.inst, inst)
	}
}

func cloneBandwidthInstance(inst amneziawg.Instance) amneziawg.Instance {
	inst.Address = slices.Clone(inst.Address)
	inst.Peers = cloneBandwidthPeers(inst.Peers)
	return inst
}

func cloneBandwidthPeers(peers []amneziawg.Peer) []amneziawg.Peer {
	cloned := slices.Clone(peers)
	for i := range cloned {
		cloned[i].AllowedIPs = slices.Clone(cloned[i].AllowedIPs)
	}
	return cloned
}
