package tuic

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

type managed struct {
	server       *Server
	tag          string
	structuralFP string
	usersFP      string
	bandwidth    bandwidthClients
}

type Manager struct {
	mu             sync.Mutex
	servers        map[int]*managed
	lastStartErr   map[int]string
	pendingTraffic map[string]ClientTrafficDelta
	bandwidthWait  func(context.Context, string, int) error
	resolveAccount func(string) (string, bool)
	started        bool
}

var (
	managerInstance *Manager
	managerOnce     sync.Once
)

func GetManager() *Manager {
	managerOnce.Do(func() {
		managerInstance = &Manager{
			servers:        make(map[int]*managed),
			lastStartErr:   make(map[int]string),
			pendingTraffic: make(map[string]ClientTrafficDelta),
		}
	})
	return managerInstance
}

func (m *Manager) HasRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mg := range m.servers {
		if mg.server != nil && mg.server.IsRunning() {
			return true
		}
	}
	return false
}

func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(inst)
}

func (m *Manager) ensureLocked(inst Instance) error {
	var bindings bandwidthClients
	if m.bandwidthWait == nil {
		if err := ValidateClients(inst.Clients); err != nil {
			return err
		}
	} else {
		if m.resolveAccount == nil {
			return fmt.Errorf("tuic: reconcile automatic bandwidth with exact bindings")
		}
		var err error
		bindings, err = prepareBandwidthClients(inst.Clients, m.resolveAccount, false)
		if err != nil {
			m.removeLocked(inst.Id)
			m.reportStartErrorLocked(inst, err)
			return err
		}
	}
	return m.ensureWithBandwidthLocked(inst, bindings)
}

func (m *Manager) ensureWithBandwidthLocked(inst Instance, bindings bandwidthClients) error {
	if len(inst.Clients) == 0 {
		m.removeLocked(inst.Id)
		return nil
	}

	structuralFP := inst.StructuralFingerprint()
	var usersFP string
	if m.bandwidthWait == nil {
		usersFP = inst.UsersFingerprint()
	}

	if existing, ok := m.servers[inst.Id]; ok && existing != nil {
		if existing.server != nil && existing.server.IsRunning() && existing.structuralFP == structuralFP && maps.Equal(existing.bandwidth, bindings) {
			existing.tag = inst.Tag
			existing.server.UpdateRuntimeSettings(inst.Tag, inst.CongestionControl, inst.LogLevel)
			if existing.usersFP != usersFP {
				existing.usersFP = usersFP
				existing.server.UpdateUsers(inst.Clients)
			}
			return nil
		}
		m.stopAndDrainLocked(existing)
		delete(m.servers, inst.Id)
	}

	server, err := m.startLocked(inst, bindings)
	if err != nil {
		m.reportStartErrorLocked(inst, err)
		return err
	}
	m.started = true
	delete(m.lastStartErr, inst.Id)

	m.servers[inst.Id] = &managed{
		server:       server,
		tag:          inst.Tag,
		structuralFP: structuralFP,
		usersFP:      usersFP,
		bandwidth:    bindings,
	}
	return nil
}

func (m *Manager) reportStartErrorLocked(inst Instance, err error) {
	if m.lastStartErr[inst.Id] == err.Error() {
		return
	}
	m.lastStartErr[inst.Id] = err.Error()
	if tuicLogWarn >= parseLogLevel(inst.LogLevel) {
		logger.Warningf("tuic: inbound %d (%s): failed to start server: %v", inst.Id, inst.Tag, err)
	}
}

func (m *Manager) startLocked(inst Instance, bindings bandwidthClients) (*Server, error) {
	port := SOCKSPortForInbound(inst.Id)
	relay := &SocksRelay{
		Gate:      ManagedRelayGate(port),
		InboundID: inst.Id,
		Addr:      fmt.Sprintf("127.0.0.1:%d", port),
		Password:  SocksPassword(),
	}
	var resolve func([16]byte, string) (string, bool)
	if m.bandwidthWait != nil {
		if err := requireManagedRelayPassword(relay.Password); err != nil {
			return nil, err
		}
		relay.RequireBoundUDP = true
		resolve = bindings.resolve
	}
	server, err := NewServerWithBandwidth(inst, relay, m.bandwidthWait, resolve)
	if err != nil {
		return nil, fmt.Errorf("tuic: init server for %d: %w", inst.Id, err)
	}
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("tuic: start server on %s for %d: %w", inst.BindTo(), inst.Id, err)
	}
	return server, nil
}

func (m *Manager) stopAndDrainLocked(mg *managed) {
	if mg == nil || mg.server == nil {
		return
	}
	_ = mg.server.Close()
	m.appendPendingTrafficLocked(mg.server.CollectClientTraffic())
}

func (m *Manager) appendPendingTrafficLocked(deltas []ClientTrafficDelta) {
	if m.pendingTraffic == nil {
		m.pendingTraffic = make(map[string]ClientTrafficDelta)
	}
	for _, delta := range deltas {
		key := delta.Email
		if delta.TrafficID > 0 {
			key = fmt.Sprintf("traffic:%d", delta.TrafficID)
		}
		if delta.TrafficID == 0 && delta.InboundID > 0 && delta.UUID != "" {
			key = fmt.Sprintf("%d:%s", delta.InboundID, delta.UUID)
		}
		current := m.pendingTraffic[key]
		current.Email = delta.Email
		current.UUID = delta.UUID
		current.InboundID = delta.InboundID
		current.TrafficID = delta.TrafficID
		current.Up += delta.Up
		current.Down += delta.Down
		m.pendingTraffic[key] = current
	}
}

func (m *Manager) RequeueClientTraffic(deltas []ClientTrafficDelta) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendPendingTrafficLocked(deltas)
}

func (m *Manager) GetActiveClients(window time.Duration) ([]string, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var emails []string
	var tags []string
	for _, mg := range m.servers {
		if mg.server != nil && mg.server.IsRunning() {
			active := mg.server.GetActiveEmails(window)
			if len(active) > 0 {
				emails = append(emails, active...)
				tags = append(tags, mg.tag)
			}
		}
	}
	return emails, tags
}

type InboundTrafficDelta struct {
	Tag  string
	Up   int64
	Down int64
}

func (m *Manager) CollectClientTraffic() []ClientTrafficDelta {
	_, clients := m.CollectAllTraffic()
	return clients
}

func (m *Manager) CollectAllTraffic() ([]InboundTrafficDelta, []ClientTrafficDelta) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var inbounds []InboundTrafficDelta
	clients := make([]ClientTrafficDelta, 0, len(m.pendingTraffic))
	for email, delta := range m.pendingTraffic {
		clients = append(clients, delta)
		delete(m.pendingTraffic, email)
	}

	for _, mg := range m.servers {
		if mg.server != nil && mg.server.IsRunning() {
			up, down, cDeltas := mg.server.CollectAllTraffic()
			if up > 0 || down > 0 {
				inbounds = append(inbounds, InboundTrafficDelta{
					Tag:  mg.tag,
					Up:   up,
					Down: down,
				})
			}
			clients = append(clients, cDeltas...)
		}
	}
	return inbounds, clients
}

func (m *Manager) AddTestTraffic(id int, email string, up, down int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mg, ok := m.servers[id]; ok && mg.server != nil {
		return mg.server.AddTestTraffic(email, up, down)
	}
	return false
}

func (m *Manager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(id)
}

func (m *Manager) removeLocked(id int) {
	if existing, ok := m.servers[id]; ok && existing != nil {
		m.stopAndDrainLocked(existing)
		delete(m.servers, id)
		delete(m.lastStartErr, id)
	}
}

func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desiredMap := make(map[int]Instance, len(desired))
	for _, inst := range desired {
		desiredMap[inst.Id] = inst
	}

	for id := range m.servers {
		if _, ok := desiredMap[id]; !ok {
			m.removeLocked(id)
		}
	}

	for _, inst := range desired {
		_ = m.ensureLocked(inst)
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mg := range m.servers {
		m.stopAndDrainLocked(mg)
	}
	m.servers = make(map[int]*managed)
}
