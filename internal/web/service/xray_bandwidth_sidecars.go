package service

import (
	"cmp"
	stdjson "encoding/json"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgkern"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

type sidecarRelaySettings struct {
	Auth      string         `json:"auth"`
	UDP       bool           `json:"udp"`
	UserLevel uint32         `json:"userLevel"`
	Accounts  []relayAccount `json:"accounts"`
}

type bandwidthSidecarInventory struct {
	tuic []tuic.BandwidthDesired
	awg  []amneziawgnet.BandwidthDesired
}

func bandwidthSidecarLookup(node *managedBandwidthNode) func(string, string, string) (string, bool) {
	if node == nil || node.panel == nil {
		return nil
	}
	return node.panel.AutomaticAccountLookup()
}

func selectBandwidthTuicInstances(instances []tuic.Instance, lookup func(string, string, string) (string, bool)) ([]tuic.BandwidthDesired, error) {
	var desired []tuic.BandwidthDesired
	for _, inst := range instances {
		clients := inst.Clients
		inst.Clients = nil
		ids := make(map[string]string)
		for _, client := range clients {
			id, allowed, err := selectBandwidthSidecarAccount(launch.TUICRelay, client.Email, tuic.BandwidthCredential(client.UUID, client.Password), ids, lookup)
			if err != nil {
				return nil, fmt.Errorf("TUIC inbound %q: %w", inst.Tag, err)
			}
			if allowed {
				inst.Clients = append(inst.Clients, client)
				ids[client.Email] = id
			}
		}
		if len(ids) != 0 {
			desired = append(desired, tuic.BandwidthDesired{Instance: inst, ClientIDs: ids})
		}
	}
	slices.SortFunc(desired, func(a, b tuic.BandwidthDesired) int { return cmp.Compare(a.Instance.Id, b.Instance.Id) })
	return desired, nil
}

func selectBandwidthAWGInstances(instances []amneziawg.Instance, lookup func(string, string, string) (string, bool)) ([]amneziawgnet.BandwidthDesired, error) {
	var desired []amneziawgnet.BandwidthDesired
	for _, inst := range instances {
		if inst.KernelMode {
			continue
		}
		peers := inst.Peers
		inst.Peers = nil
		ids := make(map[string]string)
		for _, peer := range peers {
			id, allowed, err := selectBandwidthSidecarAccount(launch.AmneziaWGRelay, peer.Email, amneziawg.BandwidthCredential(peer.PublicKey, peer.PresharedKey), ids, lookup)
			if err != nil {
				return nil, fmt.Errorf("embedded AmneziaWG inbound %q: %w", inst.Tag, err)
			}
			if allowed {
				inst.Peers = append(inst.Peers, peer)
				ids[peer.Email] = id
			}
		}
		if len(ids) != 0 {
			desired = append(desired, amneziawgnet.BandwidthDesired{
				Desired: amneziawgnet.Desired{Instance: inst, Options: bandwidthAWGDeviceOptions(inst.Obfuscation)}, ClientIDs: ids,
			})
		}
	}
	slices.SortFunc(desired, func(a, b amneziawgnet.BandwidthDesired) int { return cmp.Compare(a.Instance.Id, b.Instance.Id) })
	return desired, nil
}

func selectBandwidthSidecarAccount(protocol, email, credential string, selected map[string]string, lookup func(string, string, string) (string, bool)) (string, bool, error) {
	if credential == "" {
		return "", false, nil
	}
	id, authorized := lookup(protocol, email, credential)
	if !authorized {
		return "", false, nil
	}
	if _, duplicate := selected[email]; duplicate || len(email) > 255 || !validBandwidthXrayIdentity(email) ||
		(id != "" && !validBandwidthXrayIdentity(id)) {
		return "", false, errors.New("invalid or duplicate automatic sidecar account")
	}
	return id, true, nil
}

func prepareBandwidthSidecarRelays(config *xray.Config, resolveAccount func(string) (string, bool), inventories ...*bandwidthSidecarInventory) (map[string]launch.SidecarRelay, error) {
	relays := make(map[string]launch.SidecarRelay)
	var accountsByTag map[string]map[string]string
	if len(inventories) != 0 && inventories[0] != nil {
		inventory := inventories[0]
		accountsByTag = make(map[string]map[string]string, len(inventory.tuic)+len(inventory.awg))
		for _, desired := range inventory.tuic {
			if _, duplicate := accountsByTag[desired.Instance.Tag]; duplicate {
				return nil, errors.New("duplicate automatic sidecar relay tag")
			}
			accountsByTag[desired.Instance.Tag] = desired.ClientIDs
		}
		for _, desired := range inventory.awg {
			if _, duplicate := accountsByTag[desired.Instance.Tag]; duplicate {
				return nil, errors.New("duplicate automatic sidecar relay tag")
			}
			accountsByTag[desired.Instance.Tag] = desired.ClientIDs
		}
	}
	portCounts := make(map[int]int, len(config.InboundConfigs))
	for _, inbound := range config.InboundConfigs {
		portCounts[inbound.Port]++
	}
	for _, inbound := range config.InboundConfigs {
		if !inbound.IsSidecarRelay() {
			continue
		}
		spec, err := bandwidthSidecarRelay(inbound, resolveAccount, accountsByTag)
		if err != nil {
			return nil, fmt.Errorf("managed Xray relay %q: %w", inbound.Tag, err)
		}
		if portCounts[spec.Port] != 1 {
			return nil, fmt.Errorf("managed Xray relay %q conflicts at its reserved port %d", inbound.Tag, spec.Port)
		}
		relays[inbound.Tag] = spec
	}
	if accountsByTag != nil && len(relays) != len(accountsByTag) {
		return nil, errors.New("automatic sidecar relay inventory is incomplete")
	}
	return relays, nil
}

func bandwidthSidecarRelay(inbound xray.InboundConfig, resolveAccount func(string) (string, bool), inventories ...map[string]map[string]string) (launch.SidecarRelay, error) {
	var spec launch.SidecarRelay
	expectedSniffing := ""
	switch {
	case inbound.TuicRelay && !inbound.AmneziaWGRelay && inbound.AmneziaWGInboundID == 0:
		spec.Kind, spec.InboundID = launch.TUICRelay, inbound.TuicInboundID
		spec.Port, spec.Password = tuic.SOCKSPortForInbound(spec.InboundID), tuic.SocksPassword()
		expectedSniffing = tuicEgressSniffingSettings
	case inbound.AmneziaWGRelay && !inbound.TuicRelay && inbound.TuicInboundID == 0:
		spec.Kind, spec.InboundID = launch.AmneziaWGRelay, inbound.AmneziaWGInboundID
		spec.Port, spec.Password = amneziawgnet.SOCKSPortForInbound(spec.InboundID), amneziawgnet.SocksPassword()
		expectedSniffing = amneziawgEgressSniffingSettings
	default:
		return launch.SidecarRelay{}, errors.New("invalid generated sidecar relay ownership")
	}
	var settings sidecarRelaySettings
	if spec.InboundID <= 0 || inbound.Port != spec.Port || inbound.Protocol != "socks" || string(inbound.Listen) != `"127.0.0.1"` ||
		!jsonEmptyBandwidthXrayObject(inbound.StreamSettings) || string(inbound.Sniffing) != expectedSniffing ||
		json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil ||
		settings.Auth != "password" || !settings.UDP || len(settings.Accounts) == 0 ||
		!validBandwidthXrayIdentity(spec.Password) || len(spec.Password) > 255 || strings.Contains(spec.Password, "-fallback-") ||
		(spec.Kind == launch.AmneziaWGRelay && settings.UserLevel != 0) {
		return launch.SidecarRelay{}, errors.New("requires generated loopback SOCKS5 with password authentication and UDP")
	}
	spec.UserLevel = settings.UserLevel
	var automaticAccounts map[string]string
	if len(inventories) != 0 && inventories[0] != nil {
		automaticAccounts = inventories[0][inbound.Tag]
		if len(automaticAccounts) != len(settings.Accounts) {
			return launch.SidecarRelay{}, errors.New("automatic sidecar relay does not match the native account list")
		}
		spec.Automatic = true
	}
	spec.Accounts = make(map[string]string, len(settings.Accounts))
	for _, account := range settings.Accounts {
		_, duplicate := spec.Accounts[account.User]
		if account.Pass != spec.Password || duplicate || len(account.User) > 255 || !validBandwidthXrayIdentity(account.User) {
			return launch.SidecarRelay{}, errors.New("invalid generated sidecar relay credential")
		}
		var canonical string
		var found bool
		if spec.Automatic {
			canonical, found = automaticAccounts[account.User]
		} else {
			canonical, found = resolveAccount(account.User)
		}
		if !found || (!validBandwidthXrayIdentity(canonical) && !(spec.Automatic && canonical == "")) {
			return launch.SidecarRelay{}, errors.New("sidecar relay has a client without a canonical account binding")
		}
		spec.Accounts[account.User] = canonical
	}
	return spec, nil
}

func redactBandwidthSidecarCredentials(config *xray.Config) error {
	for i := range config.InboundConfigs {
		inbound := &config.InboundConfigs[i]
		if !inbound.IsSidecarRelay() {
			continue
		}
		var settings map[string]stdjson.RawMessage
		if err := stdjson.Unmarshal(inbound.Settings, &settings); err != nil {
			return errors.New("cannot redact managed sidecar relay configuration")
		}
		delete(settings, "accounts")
		redacted, err := stdjson.Marshal(settings)
		if err != nil {
			return errors.New("cannot redact managed sidecar relay configuration")
		}
		inbound.Settings = json_util.RawMessage(redacted)
	}
	return nil
}

func stopBandwidthRelays(process *xray.Process) {
	if process != nil {
		invalidateTuicRelayReadiness(process.GetConfig())
	}
	tuic.GetManager().StopAll()
	amneziawgnet.GetManager().StopAll()
}

// reconcileBandwidthSidecars applies the same immutable inventory used to create
// the child relays. The caller owns the Xray lifecycle lock.
func reconcileBandwidthSidecars(current *xray.Process, inventory *bandwidthSidecarInventory) (bandwidthruntime.XrayPolicyLiveAccounts, error) {
	bandwidthAWGLock.Lock()
	defer bandwidthAWGLock.Unlock()
	if (len(inventory.tuic) != 0 || len(inventory.awg) != 0) && (current == nil || !current.IsRunning()) {
		return nil, errors.New("managed sidecar relays are unavailable")
	}
	for _, desired := range inventory.awg {
		if amneziawgkern.GetManager().Running(desired.Instance.Id) {
			return nil, errors.New("embedded AmneziaWG inbound still has a running kernel device")
		}
	}
	if err := tuic.GetManager().ReconcileBandwidth(inventory.tuic); err != nil {
		return nil, err
	}
	if err := amneziawgnet.GetManager().ReconcileBandwidth(inventory.awg); err != nil {
		return nil, err
	}
	return liveBandwidthSidecarAccounts(current, inventory)
}

// liveBandwidthSidecarAccounts checks both the child and the actual running
// native listeners before reporting their exact credential fingerprints.
func liveBandwidthSidecarAccounts(current *xray.Process, inventory *bandwidthSidecarInventory) (bandwidthruntime.XrayPolicyLiveAccounts, error) {
	accounts := make(bandwidthruntime.XrayPolicyLiveAccounts)
	if inventory == nil || (len(inventory.tuic) == 0 && len(inventory.awg) == 0) {
		return accounts, nil
	}
	if current == nil || !current.IsRunning() {
		return nil, errors.New("managed sidecar relays are unavailable")
	}
	relays, err := prepareBandwidthSidecarRelays(current.GetConfig(), nil, inventory)
	if err != nil {
		return nil, err
	}
	for _, desired := range inventory.tuic {
		relay := relays[desired.Instance.Tag]
		if relay.Kind != launch.TUICRelay || relay.InboundID != desired.Instance.Id || !tuic.GetManager().MatchesBandwidth(desired) {
			return nil, fmt.Errorf("TUIC inbound %d has no exact running bandwidth configuration", desired.Instance.Id)
		}
		for _, client := range desired.Instance.Clients {
			accounts.Add(client.Email, liveBandwidthSidecarBinding(launch.TUICRelay, tuic.BandwidthCredential(client.UUID, client.Password)))
		}
	}
	for _, desired := range inventory.awg {
		relay := relays[desired.Instance.Tag]
		if relay.Kind != launch.AmneziaWGRelay || relay.InboundID != desired.Instance.Id || !amneziawgnet.GetManager().MatchesBandwidth(desired) {
			return nil, fmt.Errorf("embedded AmneziaWG inbound %d has no exact running bandwidth configuration", desired.Instance.Id)
		}
		for _, peer := range desired.Instance.Peers {
			accounts.Add(peer.Email, liveBandwidthSidecarBinding(launch.AmneziaWGRelay, amneziawg.BandwidthCredential(peer.PublicKey, peer.PresharedKey)))
		}
	}
	return accounts, nil
}

func liveBandwidthSidecarBinding(protocol, credential string) bandwidthexchange.PolicyBinding {
	return bandwidthexchange.PolicyBinding{
		Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, credential),
	}
}

func invalidateChangedBandwidthSidecars[T any](applied, desired []T, id func(T) int, isLive func(T) bool, remove func(int)) bool {
	changed := len(applied) != len(desired)
	byID := make(map[int]T, len(desired))
	for _, entry := range desired {
		byID[id(entry)] = entry
	}
	for _, entry := range applied {
		next, found := byID[id(entry)]
		if !found || !isLive(next) {
			remove(id(entry))
			changed = true
		}
	}
	return changed
}

// ReconcileTuicInstances keeps native TUIC synchronized with the ready relay
// inventory on a managed node. Stock TUIC keeps its existing reconcile path.
func ReconcileTuicInstances(instances []tuic.Instance) {
	manager := tuic.GetManager()
	if activeBandwidthNode.Load() == nil {
		manager.Reconcile(instances)
		return
	}
	lock.Lock()
	defer lock.Unlock()
	node := activeBandwidthNode.Load()
	current := currentXrayProcess()
	if lookup := bandwidthSidecarLookup(node); lookup != nil {
		if node.closing.Load() || xrayState.heldBackReason() != "" {
			manager.StopAll()
			return
		}
		desired, err := selectBandwidthTuicInstances(instances, lookup)
		if err != nil {
			manager.StopAll()
			(&XrayService{}).SetToNeedReconcile()
			return
		}
		var applied []tuic.BandwidthDesired
		if node.xraySidecars != nil {
			applied = node.xraySidecars.tuic
		}
		if invalidateChangedBandwidthSidecars(applied, desired,
			func(entry tuic.BandwidthDesired) int { return entry.Instance.Id },
			func(entry tuic.BandwidthDesired) bool {
				return current != nil && current.IsRunning() && manager.MatchesBandwidth(entry)
			},
			manager.Remove,
		) {
			(&XrayService{}).SetToNeedReconcile()
		}
		return
	}
	if node == nil || node.closing.Load() || current == nil || !current.IsRunning() || xrayState.heldBackReason() != "" {
		manager.Reconcile(nil)
		return
	}
	relays := make(map[int]xray.InboundConfig)
	for _, inbound := range current.GetConfig().InboundConfigs {
		if inbound.TuicRelay {
			relays[inbound.TuicInboundID] = inbound
		}
	}
	ready := make([]tuic.Instance, 0, len(instances))
	for _, inst := range instances {
		relay, exists := relays[inst.Id]
		if !exists || relay.Tag != inst.Tag {
			continue
		}
		gate := tuic.ManagedRelayGate(relay.Port)
		if gate != nil && gate.ReadyFor(inst.Id) {
			ready = append(ready, inst)
		}
	}
	manager.Reconcile(ready)
}

// ReconcileBandwidthAmneziaWG runs the embedded-only sidecar against the
// currently ready Xray handlers. The stock job also manages kernel and
// outbound interfaces and is never scheduled on a bandwidth-managed node.
func (s *XrayService) ReconcileBandwidthAmneziaWG() {
	lock.Lock()
	defer lock.Unlock()
	node := activeBandwidthNode.Load()
	if lookup := bandwidthSidecarLookup(node); lookup != nil {
		manager := amneziawgnet.GetManager()
		if node.closing.Load() || xrayState.heldBackReason() != "" {
			manager.StopAll()
			return
		}
		instances, err := s.inboundService.DesiredAmneziaWGInstances()
		var desired []amneziawgnet.BandwidthDesired
		if err == nil {
			desired, err = selectBandwidthAWGInstances(instances, lookup)
		}
		if err != nil {
			manager.StopAll()
			s.SetToNeedReconcile()
			return
		}
		current := currentXrayProcess()
		var applied []amneziawgnet.BandwidthDesired
		if node.xraySidecars != nil {
			applied = node.xraySidecars.awg
		}
		if invalidateChangedBandwidthSidecars(applied, desired,
			func(entry amneziawgnet.BandwidthDesired) int { return entry.Instance.Id },
			func(entry amneziawgnet.BandwidthDesired) bool {
				return current != nil && current.IsRunning() && manager.MatchesBandwidth(entry)
			},
			manager.Remove,
		) {
			s.SetToNeedReconcile()
		}
		return
	}
	s.reconcileBandwidthAmneziaWG()
}

func (s *XrayService) reconcileBandwidthAmneziaWG() {
	bandwidthAWGLock.Lock()
	defer bandwidthAWGLock.Unlock()

	node := activeBandwidthNode.Load()
	current := currentXrayProcess()
	manager := amneziawgnet.GetManager()
	if node == nil || node.closing.Load() || current == nil || !current.IsRunning() || xrayState.heldBackReason() != "" {
		manager.StopAll()
		return
	}
	instances, err := s.inboundService.DesiredAmneziaWGInstances()
	if err != nil {
		manager.StopAll()
		logger.Warning("amneziawg bandwidth reconcile failed:", err)
		return
	}
	relays := make(map[int]xray.InboundConfig)
	for _, inbound := range current.GetConfig().InboundConfigs {
		if inbound.AmneziaWGRelay {
			relays[inbound.AmneziaWGInboundID] = inbound
		}
	}
	desired := make([]amneziawgnet.Desired, 0, len(instances))
	kernel := make(map[int]bool)
	for _, id := range amneziawgkern.GetManager().ManagedIDs() {
		kernel[id] = true
	}
	for _, inst := range instances {
		relay, exists := relays[inst.Id]
		if inst.KernelMode || kernel[inst.Id] || !exists || relay.Tag != inst.Tag || !awgRelayIncludesPeers(relay, inst) {
			continue
		}
		desired = append(desired, amneziawgnet.Desired{Instance: inst, Options: bandwidthAWGDeviceOptions(inst.Obfuscation)})
	}
	manager.Reconcile(desired)
}

func awgRelayIncludesPeers(relay xray.InboundConfig, inst amneziawg.Instance) bool {
	var settings sidecarRelaySettings
	if json.Unmarshal(relay.Settings, &settings) != nil {
		return false
	}
	emails := make(map[string]bool, len(settings.Accounts))
	for _, account := range settings.Accounts {
		emails[account.User] = true
	}
	for _, peer := range inst.Peers {
		if !emails[peer.Email] {
			return false
		}
	}
	return true
}

func bandwidthAWGDeviceOptions(obfuscation amneziawg.Obfuscation31) amneziawgnet.DeviceOptions {
	return amneziawgnet.DeviceOptions{
		HeaderProtectionKey:    obfuscation.HeaderProtectionKey,
		ContentPaddingAddition: obfuscation.ContentPaddingAddition,
		RekeyAfterTime:         obfuscation.RekeyAfterTime,
		RekeyTimeout:           obfuscation.RekeyTimeout,
		RejectAfterTime:        obfuscation.RejectAfterTime,
		KeepaliveTimeout:       obfuscation.KeepaliveTimeout,
		MaxHandshakeAttempts:   obfuscation.MaxHandshakeAttempts,
		RandomTrailers:         obfuscation.RandomTrailers,
		DisableCookies:         obfuscation.DisableCookies,
	}
}
