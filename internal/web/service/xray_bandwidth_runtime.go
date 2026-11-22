package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgkern"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/mtproto"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/infra/conf"
)

type managedBandwidthNode struct {
	panel         *bandwidthruntime.PanelRuntime
	closing       atomic.Bool
	xrayIdle      atomic.Bool
	kernelTraffic bandwidthKernelTrafficQueue
	// Published child bindings are protected by the Xray lifecycle lock.
	xrayBindings       map[string]map[string]string
	xrayRelays         map[string]launch.SidecarRelay
	xraySidecars       *bandwidthSidecarInventory
	xrayPolicyAccounts bandwidthruntime.XrayPolicyLiveAccounts
	xrayPolicyReady    bool
	xrayPolicyPending  bool
}

var activeBandwidthNode atomic.Pointer[managedBandwidthNode]

// Serialize selection and application of the managed AmneziaWG datapath. This
// lock is separate from Xray's lifecycle lock because traffic maintenance may
// apply a committed kernel peer update while Xray is preparing its inventory.
var bandwidthAWGLock sync.Mutex

func validateSavedBandwidthInbound(inbound *model.Inbound) error {
	node := activeBandwidthNode.Load()
	if node == nil {
		return nil
	}
	if err := runtime.ValidateBandwidthInbound(inbound); err != nil {
		return err
	}
	if inbound == nil || !inbound.Enable || inbound.NodeID != nil {
		return nil
	}
	var emails []string
	switch inbound.Protocol {
	case model.TUIC:
		if bandwidthSidecarLookup(node) != nil {
			return nil
		}
		inst, _ := tuic.InstanceFromInbound(inbound)
		for _, client := range inst.Clients {
			emails = append(emails, client.Email)
		}
	case model.AmneziaWG:
		var settings amneziawg.InboundSettings
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return errors.New("invalid managed AmneziaWG settings")
		}
		if settings.Server.KernelMode {
			inst := amneziawg.Instance{
				KernelMode: true, Listen: inbound.Listen, IPv6Enabled: settings.Server.IPv6Enabled,
				PrivateKey: settings.Server.PrivateKey, RouteThroughXray: settings.Server.RouteThroughXray,
			}
			for _, client := range settings.Clients {
				if !client.Enable {
					continue
				}
				allowed, err := normalizeWireguardAllowedIPs(client.AllowedIPs)
				if err != nil {
					return fmt.Errorf("bandwidth-managed kernel AmneziaWG inbound %q: invalid peer AllowedIPs", inbound.Tag)
				}
				inst.Peers = append(inst.Peers, amneziawg.Peer{
					Email: client.Email, PublicKey: client.PublicKey, PresharedKey: client.PreSharedKey,
					AllowedIPs: allowed, ForwardedPorts: client.ForwardedPorts,
				})
			}
			resolve := node.panel.AccountID
			if node.panel.AutomaticAccountLookup() != nil {
				resolve = func(string) (string, bool) { return "validation", true }
			}
			if err := amneziawgkern.ValidateBandwidthInstance(inst, resolve); err != nil {
				return fmt.Errorf("bandwidth-managed kernel AmneziaWG inbound %q: %w", inbound.Tag, err)
			}
			if len(inst.Peers) != 0 && (inbound.Id == 0 || !amneziawgkern.GetManager().Running(inbound.Id)) {
				return amneziawgkern.Preflight(inst, inst.RouteThroughXray)
			}
			return nil
		}
		for _, client := range settings.Clients {
			if client.Enable {
				emails = append(emails, client.Email)
			}
		}
		if bandwidthSidecarLookup(node) != nil {
			for _, email := range emails {
				if len(email) > 255 || !validBandwidthXrayIdentity(email) {
					return fmt.Errorf("embedded AmneziaWG inbound %q requires valid relay emails", inbound.Tag)
				}
			}
			return nil
		}
	}
	for _, email := range emails {
		id, ok := node.panel.AccountID(email)
		if !ok || len(email) > 255 || !validBandwidthXrayIdentity(email) || !validBandwidthXrayIdentity(id) {
			return fmt.Errorf("bandwidth-managed node inbound %q has a client without a canonical account binding", inbound.Tag)
		}
	}
	return nil
}

// BandwidthNodeConfigured reports whether this panel reload owns the already
// configured process-wide node and running sidecars.
func BandwidthNodeConfigured(panel *bandwidthruntime.PanelRuntime) bool {
	current := activeBandwidthNode.Load()
	return current != nil && current.panel == panel && !current.closing.Load()
}

// ConfigureBandwidthNode installs the process-wide node policy before any local
// inbound can start. Reloads reuse the same policy and lease node.
func ConfigureBandwidthNode(panel *bandwidthruntime.PanelRuntime) error {
	if panel.Node() == nil {
		return nil
	}
	lock.Lock()
	defer lock.Unlock()
	if current := activeBandwidthNode.Load(); current != nil {
		if current.panel == panel && !current.closing.Load() {
			return nil
		}
		return errors.New("bandwidth node policy is already installed")
	}
	if process := currentXrayProcess(); process != nil && process.IsRunning() {
		return errors.New("stop the existing Xray data plane before enabling the bandwidth node")
	}
	node := &managedBandwidthNode{panel: panel}
	if err := mtproto.GetManager().ConfigureBandwidth(node.mtprotoOptions); err != nil {
		return err
	}
	if bandwidthSidecarLookup(node) != nil {
		if err := tuic.GetManager().ConfigureAutomaticBandwidth(panel.Node().Acquire); err != nil {
			return err
		}
		if err := amneziawgnet.GetManager().ConfigureAutomaticBandwidth(panel.Node().Acquire); err != nil {
			return err
		}
	} else {
		if err := tuic.GetManager().ConfigureBandwidth(panel.Node().Acquire, panel.AccountID); err != nil {
			return err
		}
		if err := amneziawgnet.GetManager().ConfigureBandwidth(panel.Node().Acquire, panel.AccountID); err != nil {
			return err
		}
	}
	if err := amneziawgkern.GetManager().ConfigureBandwidth(panel.Node().Acquire, panel.AccountID, panel.AutomaticAccountLookup); err != nil {
		return err
	}
	activeBandwidthNode.Store(node)
	return nil
}

// BeginBandwidthShutdown prevents late watchdog, HTTP and MTProto reconcile
// calls from starting another child during a full panel shutdown.
func BeginBandwidthShutdown(panel *bandwidthruntime.PanelRuntime) {
	lock.Lock()
	defer lock.Unlock()
	bandwidthAWGLock.Lock()
	defer bandwidthAWGLock.Unlock()
	if node := activeBandwidthNode.Load(); node != nil && node.panel == panel {
		node.closing.Store(true)
	}
}

// ApplyBandwidthKernelAmneziaWG applies a fresh desired inventory under the
// same lock as the embedded datapath and the beginning of node shutdown.
func ApplyBandwidthKernelAmneziaWG(panel *bandwidthruntime.PanelRuntime, apply func() ([]*xray.ClientTraffic, error)) error {
	bandwidthAWGLock.Lock()
	var queue *bandwidthKernelTrafficQueue
	defer func() {
		bandwidthAWGLock.Unlock()
		if queue != nil {
			queue.startLocked()
			queue.mu.Unlock()
		}
	}()
	node := activeBandwidthNode.Load()
	if panel.Node() == nil || node == nil || node.panel != panel || node.closing.Load() {
		return errors.New("bandwidth node is not ready to reconcile kernel AmneziaWG")
	}
	samples, err := apply()
	// Queue before releasing the datapath lock so apply operations cannot
	// reorder deltas. Release both locks before submission to the writer.
	node.kernelTraffic.mu.Lock()
	queue = &node.kernelTraffic
	queue.pending = append(queue.pending, samples...)
	return err
}

type bandwidthKernelTrafficQueue struct {
	mu      sync.Mutex
	pending []*xray.ClientTraffic
	done    chan struct{}
	err     error
}

func (q *bandwidthKernelTrafficQueue) startLocked() {
	if q.done != nil || len(q.pending) == 0 {
		return
	}
	q.done = make(chan struct{})
	go q.write()
}

func (q *bandwidthKernelTrafficQueue) write() {
	service := &InboundService{}
	q.mu.Lock()
	for len(q.pending) != 0 {
		next := q.pending
		q.pending = nil
		q.mu.Unlock()
		_, _, err := service.AddTraffic(nil, next)
		q.mu.Lock()
		q.err = err
		if err != nil {
			q.pending = append(next, q.pending...)
			logger.Warning("amneziawg job: recording bandwidth-managed kernel traffic:", err)
			break
		}
	}
	close(q.done)
	q.done = nil
	q.mu.Unlock()
}

// FlushBandwidthKernelTraffic finishes outstanding samples after shutdown
// stopped all reconcile work. The traffic writer must still be running.
func FlushBandwidthKernelTraffic(panel *bandwidthruntime.PanelRuntime, final []*xray.ClientTraffic) error {
	node := activeBandwidthNode.Load()
	if node == nil || node.panel != panel || !node.closing.Load() {
		return errors.New("bandwidth node must stop reconciling before draining kernel traffic")
	}
	q := &node.kernelTraffic
	q.mu.Lock()
	q.pending = append(q.pending, final...)
	q.startLocked()
	done := q.done
	q.mu.Unlock()
	if done != nil {
		<-done
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.err
}

func rejectBandwidthAWGOutbounds(config *xray.Config) error {
	var outbounds []json.RawMessage
	if len(config.OutboundConfigs) == 0 {
		return nil
	}
	if err := json.Unmarshal(config.OutboundConfigs, &outbounds); err != nil {
		return err
	}
	for _, raw := range outbounds {
		if amneziawg.IsAmneziaWGOutbound(raw) {
			return errors.New("bandwidth-managed node does not support AmneziaWG outbounds")
		}
	}
	return nil
}

// Keep the synthetic management tag attached exclusively to the management tunnel.
func validateBandwidthAPIRoutes(config *xray.Config) error {
	if jsonEmptyBandwidthXrayObject(config.API) {
		return nil
	}
	var routing conf.RouterConfig
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		return err
	}
	for i, raw := range routing.RuleList {
		if i == 0 {
			continue
		}
		var rule struct {
			OutboundTag string `json:"outboundTag"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			return err
		}
		if rule.OutboundTag == "api" {
			return errors.New("bandwidth-managed Xray cannot route proxy traffic to its management API")
		}
	}
	for _, balancer := range routing.Balancers {
		if balancer == nil {
			return errors.New("invalid bandwidth-managed Xray balancer")
		}
		if balancer.FallbackTag == "api" {
			return errors.New("bandwidth-managed Xray cannot use its management API as a balancer fallback")
		}
		for _, selector := range balancer.Selectors {
			if strings.HasPrefix("api", selector) {
				return errors.New("bandwidth-managed Xray cannot select its management API in a balancer")
			}
		}
	}
	if len(config.OutboundConfigs) != 0 {
		var outbounds []struct {
			Protocol string          `json:"protocol"`
			Settings json.RawMessage `json:"settings"`
		}
		if err := json.Unmarshal(config.OutboundConfigs, &outbounds); err != nil {
			return err
		}
		for _, outbound := range outbounds {
			if !strings.EqualFold(outbound.Protocol, "loopback") || len(outbound.Settings) == 0 {
				continue
			}
			var settings conf.LoopbackConfig
			if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
				return err
			}
			if settings.InboundTag == "api" {
				return errors.New("bandwidth-managed Xray cannot use its management API as a loopback inbound tag")
			}
		}
	}
	return nil
}

// restartBandwidthXray runs exclusively under the Xray lifecycle lock.
func (s *XrayService) restartBandwidthXray(node *managedBandwidthNode, config *xray.Config, force bool, automatic func(string, string, string) (string, bool), inventory *bandwidthSidecarInventory) (err error) {
	defer func() {
		if err != nil {
			current := currentXrayProcess()
			stopBandwidthRelays(current)
			if automatic != nil && current != nil && current.IsRunning() {
				if stopErr := current.Stop(); stopErr != nil && !errors.Is(stopErr, ErrXrayNotRunning) {
					err = errors.Join(err, stopErr)
				}
			}
			node.xrayPolicyReady = false
			node.xrayIdle.Store(false)
			xrayState.holdBack(err.Error())
		}
	}()
	prepared, bindings, err := prepareBandwidthXrayConfigForRuntime(node.panel.AllowsUnmeteredXrayAccounts(), config, node.panel.AccountID, automatic)
	if err != nil {
		return err
	}
	accounts, err := liveBandwidthXrayPolicyAccounts(prepared, bindings)
	if err != nil {
		return err
	}
	if err := validateBandwidthAPIRoutes(prepared); err != nil {
		return err
	}
	relays, err := prepareBandwidthSidecarRelays(prepared, node.panel.AccountID, inventory)
	if err != nil {
		return err
	}
	// A failed Start already attempts to stop its child. Retain a rare
	// failed-to-stop child privately for cleanup, including on full shutdown.
	if sErr := stopUnpublishedBandwidthXray(); sErr != nil {
		return sErr
	}
	current := currentXrayProcess()
	if len(bindings)+len(relays) == 0 {
		stopBandwidthRelays(current)
		if current != nil && current.IsRunning() {
			if err := current.Stop(); err != nil && !errors.Is(err, ErrXrayNotRunning) {
				return err
			}
		}
		xrayState.replace(nil)
		node.xrayBindings = nil
		node.xrayRelays = nil
		node.xraySidecars = inventory
		node.xrayPolicyAccounts = nil
		s.xrayAPI.StatsLastValues = nil
		node.xrayIdle.Store(true)
		return nil
	}
	node.xrayIdle.Store(false)
	if current != nil && current.IsRunning() {
		if !force && !isNeedXrayRestart.Load() && current.GetConfig().Equals(prepared) &&
			equalBandwidthXrayBindings(node.xrayBindings, bindings) && reflect.DeepEqual(node.xrayRelays, relays) {
			if len(unavailableTuicRepairs(prepared)) != 0 {
				if err := publishTuicRelayReadiness(prepared); err != nil {
					return err
				}
			}
			if inventory != nil {
				if _, err := reconcileBandwidthSidecars(current, inventory); err != nil {
					return err
				}
				node.xraySidecars = inventory
			}
			xrayState.holdBack("")
			if inventory == nil {
				s.reconcileBandwidthAmneziaWG()
			}
			return nil
		}
		if conflicts := bindConflicts(prepared, current.GetConfig()); len(conflicts) > 0 {
			return fmt.Errorf("bandwidth-managed Xray config refused: %s", conflicts[0])
		}
	}
	next, err := node.panel.Node().NewManagedXrayWithRelays(prepared, bindings, relays)
	if err != nil {
		return err
	}
	stopBandwidthRelays(current)
	invalidateTuicRelayReadiness(prepared)
	if current != nil && current.IsRunning() {
		if err := current.Stop(); err != nil && !errors.Is(err, ErrXrayNotRunning) {
			return err
		}
	}
	xrayState.replace(nil)
	s.xrayAPI.StatsLastValues = nil
	if err := next.Start(); err != nil {
		if next.IsRunning() {
			unpublishedBandwidthXray = next
		}
		return err
	}
	err = publishTuicRelayReadiness(prepared)
	if err == nil && inventory != nil {
		_, err = reconcileBandwidthSidecars(next, inventory)
	}
	if err != nil {
		invalidateTuicRelayReadiness(prepared)
		stopErr := next.Stop()
		if next.IsRunning() {
			unpublishedBandwidthXray = next
		}
		return errors.Join(err, stopErr)
	}
	xrayState.replace(next)
	node.xrayBindings = bindings
	node.xrayRelays = relays
	node.xraySidecars = inventory
	node.xrayPolicyAccounts = accounts
	if inventory == nil {
		s.reconcileBandwidthAmneziaWG()
	}
	return nil
}

func equalBandwidthXrayBindings(a, b map[string]map[string]string) bool {
	return maps.EqualFunc(a, b, func(first, second map[string]string) bool { return maps.Equal(first, second) })
}

func liveBandwidthXrayPolicyAccounts(config *xray.Config, bindings map[string]map[string]string) (bandwidthruntime.XrayPolicyLiveAccounts, error) {
	accounts := make(bandwidthruntime.XrayPolicyLiveAccounts)
	for _, inbound := range config.InboundConfigs {
		if !inbound.PanelGenerated || len(bindings[inbound.Tag]) == 0 {
			continue
		}
		if len(inbound.BandwidthProxyOwners) != 0 {
			protocol := strings.ToLower(inbound.Protocol)
			proxyAccounts, err := bandwidthProxyAccounts(protocol, inbound.Settings)
			if err != nil {
				return nil, err
			}
			for _, account := range proxyAccounts {
				email := inbound.BandwidthProxyOwners[account.Username]
				if _, bound := bindings[inbound.Tag][account.Username]; bound && email != "" {
					accounts.Add(email, bandwidthexchange.PolicyBinding{
						Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, account.credential()),
					})
				}
			}
			continue
		}
		policy, err := bandwidthXrayPolicyCredentials(inbound)
		if err != nil {
			return nil, err
		}
		for _, entry := range policy.credentials {
			if _, bound := bindings[inbound.Tag][entry.Email]; bound {
				accounts.Add(entry.Email, bandwidthexchange.PolicyBinding{
					Protocol: entry.Protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(entry.Protocol, entry.Credential),
				})
			}
		}
	}
	return accounts, nil
}

// ApplyBandwidthXrayPolicy installs the snapshot under the lifecycle lock and
// acknowledges only the accounts activated by the child and the sidecars.
func (s *XrayService) ApplyBandwidthXrayPolicy(ctx context.Context, panel *bandwidthruntime.PanelRuntime, install func() (bool, error), reconcileKernel func(stop bool) error) (_ bandwidthruntime.XrayPolicyLiveAccounts, err error) {
	lock.Lock()
	defer lock.Unlock()
	node := activeBandwidthNode.Load()
	if node == nil || node.panel != panel || node.closing.Load() || reconcileKernel == nil {
		return nil, errors.New("bandwidth node is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bandwidthAWGLock.Lock()
	changed, err := install()
	if changed {
		err = errors.Join(err, amneziawgkern.GetManager().QuiesceBandwidthPolicy(err != nil))
	}
	bandwidthAWGLock.Unlock()
	if changed {
		node.xrayPolicyPending = true
		node.xrayPolicyReady = false
	}
	defer func() {
		if err != nil {
			node.xrayPolicyReady = false
		}
		if err != nil && node.xrayPolicyPending {
			process := currentXrayProcess()
			stopBandwidthRelays(process)
			if process != nil && process.IsRunning() {
				if stopErr := process.Stop(); stopErr != nil && !errors.Is(stopErr, ErrXrayNotRunning) {
					err = errors.Join(err, stopErr)
				}
			}
			node.xrayIdle.Store(false)
			xrayState.holdBack(err.Error())
		}
	}()
	if err != nil {
		if changed && node.panel.AutomaticAccountLookup() != nil {
			err = errors.Join(err, reconcileKernel(true), mtproto.GetManager().Reconcile(nil))
		}
		return nil, err
	}
	if err := errors.Join(reconcileKernel(false), s.reconcileBandwidthMTProtoPolicy(node)); err != nil {
		return nil, err
	}
	if isManuallyStopped.Load() {
		return nil, errors.New("bandwidth Xray is manually stopped")
	}
	if node.xrayPolicyReady && !isNeedXrayRestart.Load() && !isNeedXrayReconcile.Load() && xrayState.heldBackReason() == "" &&
		bandwidthXrayPolicyLive(node) {
		if accounts, liveErr := node.liveBandwidthPolicyAccounts(); liveErr == nil {
			return accounts, nil
		}
	}
	reconcileRequested := isNeedXrayReconcile.Swap(false)
	restartRequested := s.IsNeedRestartAndSetFalse()
	defer func() {
		if err != nil && reconcileRequested {
			s.SetToNeedReconcile()
		}
		if err != nil && restartRequested {
			s.SetToNeedRestart()
		}
	}()
	automatic := bandwidthSidecarLookup(node)
	var inventory *bandwidthSidecarInventory
	if automatic != nil {
		inventory = &bandwidthSidecarInventory{}
	}
	config, err := s.getXrayConfigWithBandwidthSidecars(automatic, inventory)
	if err != nil {
		return nil, err
	}
	if err := s.restartBandwidthXray(node, config, false, automatic, inventory); err != nil {
		return nil, err
	}
	if !bandwidthXrayPolicyLive(node) {
		return nil, errors.New("bandwidth Xray child is unavailable after policy activation")
	}
	accounts, err := node.liveBandwidthPolicyAccounts()
	if err != nil {
		return nil, err
	}
	node.xrayPolicyPending = false
	node.xrayPolicyReady = true
	return accounts, nil
}

func (node *managedBandwidthNode) liveBandwidthPolicyAccounts() (bandwidthruntime.XrayPolicyLiveAccounts, error) {
	accounts := make(bandwidthruntime.XrayPolicyLiveAccounts, len(node.xrayPolicyAccounts))
	for email, bindings := range node.xrayPolicyAccounts {
		accounts[email] = maps.Clone(bindings)
	}
	sidecars, err := liveBandwidthSidecarAccounts(currentXrayProcess(), node.xraySidecars)
	if err != nil {
		return nil, err
	}
	for email, bindings := range sidecars {
		for binding := range bindings {
			accounts.Add(email, binding)
		}
	}
	addLiveBandwidthMTProtoAccounts(accounts)
	for email, bindings := range amneziawgkern.GetManager().ReadyBandwidthBindings() {
		for _, binding := range bindings {
			accounts.Add(email, binding)
		}
	}
	return accounts, nil
}

func bandwidthXrayPolicyLive(node *managedBandwidthNode) bool {
	if node.xrayIdle.Load() {
		return true
	}
	process := currentXrayProcess()
	return process != nil && process.IsRunning()
}

// Owned by the Xray lifecycle lock, separate from the ready process snapshot.
var unpublishedBandwidthXray *xray.Process

func stopUnpublishedBandwidthXray() error {
	if unpublishedBandwidthXray != nil && unpublishedBandwidthXray.IsRunning() {
		if err := unpublishedBandwidthXray.Stop(); err != nil && !errors.Is(err, ErrXrayNotRunning) {
			return err
		}
	}
	unpublishedBandwidthXray = nil
	return nil
}
