package tuic

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
)

// BandwidthCredential represents the UUID and password used by TUIC together.
func BandwidthCredential(id, password string) string {
	parsed, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil || password == "" {
		return ""
	}
	return bandwidthexchange.CredentialParts(parsed.String(), password)
}

// ConfigureBandwidth installs the shared bandwidth gate before the manager's
// first successful start. The account resolver receives each client's exact
// email under the manager lock and must not call back into Manager.
func (m *Manager) ConfigureBandwidth(wait func(context.Context, string, int) error, resolveAccount func(email string) (string, bool)) error {
	if resolveAccount == nil {
		return errors.New("tuic: bandwidth account resolver is required")
	}
	return m.configureBandwidth(wait, resolveAccount)
}

// ConfigureAutomaticBandwidth requires a preselected account snapshot for every start.
func (m *Manager) ConfigureAutomaticBandwidth(wait func(context.Context, string, int) error) error {
	return m.configureBandwidth(wait, nil)
}

func (m *Manager) configureBandwidth(wait func(context.Context, string, int) error, resolveAccount func(string) (string, bool)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case wait == nil:
		return errors.New("tuic: bandwidth gate is required")
	case m.bandwidthWait != nil:
		return errors.New("tuic: bandwidth is already configured")
	case m.started:
		return errors.New("tuic: configure bandwidth before starting a server")
	}
	m.bandwidthWait = wait
	m.resolveAccount = resolveAccount
	return nil
}

type bandwidthClient struct {
	password  string
	accountID string
	email     string
	trafficID int
}

// bandwidthClients is a snapshot of the authentication and billing state for
// one server, keyed by the same parsed UUID that the user registry uses.
type bandwidthClients map[[16]byte]bandwidthClient

func prepareBandwidthClients(clients []TuicClientSettings, resolveAccount func(string) (string, bool), allowUnrestricted bool) (bandwidthClients, error) {
	bindings := make(bandwidthClients, len(clients))
	for i, client := range clients {
		id, err := uuid.Parse(client.UUID)
		if err != nil {
			return nil, fmt.Errorf("tuic: bandwidth client %d has an invalid UUID", i+1)
		}
		if _, duplicate := bindings[id]; duplicate {
			return nil, fmt.Errorf("tuic: bandwidth client %d has a duplicate UUID", i+1)
		}
		if client.Password == "" {
			return nil, fmt.Errorf("tuic: bandwidth client %d has an empty password", i+1)
		}
		if err := ValidateRelayEmail(client.Email); err != nil {
			return nil, fmt.Errorf("tuic: bandwidth client %d: %w", i+1, err)
		}
		accountID, ok := resolveAccount(client.Email)
		if !ok || (accountID == "" && !allowUnrestricted) {
			return nil, fmt.Errorf("tuic: bandwidth client %d has no canonical account binding", i+1)
		}
		bindings[id] = bandwidthClient{
			password: client.Password, accountID: accountID, email: client.Email, trafficID: client.TrafficID,
		}
	}
	return bindings, nil
}

// BandwidthDesired pairs the exact native authentication list with the
// canonical ID for each retained relay identity. An empty ID is unrestricted.
type BandwidthDesired struct {
	Instance  Instance
	ClientIDs map[string]string
}

func (m *Manager) automaticClients(desired BandwidthDesired) (bandwidthClients, error) {
	if m.bandwidthWait == nil || m.resolveAccount != nil || desired.ClientIDs == nil {
		return nil, errors.New("tuic: automatic bandwidth bindings are required")
	}
	if len(desired.ClientIDs) != len(desired.Instance.Clients) || len(desired.ClientIDs) == 0 {
		return nil, errors.New("tuic: automatic bandwidth bindings must match the client list")
	}
	seen := make(map[string]bool, len(desired.ClientIDs))
	return prepareBandwidthClients(desired.Instance.Clients, func(email string) (string, bool) {
		id, ok := desired.ClientIDs[email]
		if seen[email] {
			return "", false
		}
		seen[email] = true
		return id, ok
	}, true)
}

// ReconcileBandwidth applies only instances selected by a frozen policy.
func (m *Manager) ReconcileBandwidth(desired []BandwidthDesired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bandwidthWait == nil || m.resolveAccount != nil {
		return errors.New("tuic: automatic bandwidth is not configured")
	}
	want := make(map[int]bool, len(desired))
	for _, entry := range desired {
		want[entry.Instance.Id] = true
	}
	for id := range m.servers {
		if !want[id] {
			m.removeLocked(id)
		}
	}
	var failures []error
	for _, entry := range desired {
		bindings, err := m.automaticClients(entry)
		if err != nil {
			m.removeLocked(entry.Instance.Id)
		} else {
			err = m.ensureWithBandwidthLocked(entry.Instance, bindings)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("TUIC inbound %d: %w", entry.Instance.Id, err))
		}
	}
	return errors.Join(failures...)
}

// MatchesBandwidth confirms the running server is configured for every exact
// native credential and the matching authenticated private relay is available.
func (m *Manager) MatchesBandwidth(desired BandwidthDesired) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	bindings, err := m.automaticClients(desired)
	if err != nil {
		return false
	}
	inst := desired.Instance
	live := m.servers[inst.Id]
	return live != nil && live.server.IsRunning() && live.tag == inst.Tag &&
		live.structuralFP == inst.StructuralFingerprint() && maps.Equal(live.bandwidth, bindings) &&
		live.server.relay.Gate != nil && live.server.relay.Gate.readyForBandwidth(inst.Id, bindings)
}

func (bindings bandwidthClients) resolve(id [16]byte, password string) (string, bool) {
	client, ok := bindings[id]
	if !ok || subtle.ConstantTimeCompare([]byte(client.password), []byte(password)) != 1 {
		return "", false
	}
	return client.accountID, true
}

func requireManagedRelayPassword(password string) error {
	// SocksPassword retains its predictable fallback for stock relays.
	if len(password) == 0 || len(password) > 255 || strings.HasPrefix(password, "tuic-fallback-") {
		return errors.New("tuic: secure SOCKS relay password unavailable")
	}
	return nil
}
