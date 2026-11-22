package bandwidthruntime

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// BandwidthAttachment is the set of credential bindings on one physical node.
type BandwidthAttachment struct {
	Bindings    []bandwidthexchange.PolicyBinding
	Unsupported bool
}

// BandwidthAccount is the committed account, policy and physical membership.
type BandwidthAccount struct {
	ID          int
	Email       string
	Policy      ClientBandwidthPolicy
	Attachments map[string]BandwidthAttachment
}

func (attachment BandwidthAttachment) policyAccount(email string) bandwidthexchange.PolicyAccount {
	account := bandwidthexchange.PolicyAccount{Email: email}
	bindings := normalizedPolicyBindings(attachment.Bindings)
	counts := make(map[string]int)
	for _, binding := range bindings {
		counts[binding.Protocol]++
	}
	for _, binding := range bindings {
		// Keep the original wire fields when they can express the whole protocol.
		if counts[binding.Protocol] == 1 {
			switch binding.Protocol {
			case "vless":
				account.VLESSFingerprint = binding.Fingerprint
				continue
			case "hysteria":
				account.HysteriaFingerprint = binding.Fingerprint
				continue
			}
		}
		account.Bindings = append(account.Bindings, binding)
	}
	return account
}

type bandwidthInventoryReader interface {
	ReadBandwidthInventory(context.Context) ([]BandwidthAccount, error)
}

type enrolledAccount struct {
	account bandwidthexchange.PolicyAccount
	limits  bandwidthlease.Limits
}

func (e enrolledAccount) equal(other enrolledAccount) bool {
	return e.limits == other.limits &&
		e.account.Email == other.account.Email &&
		e.account.ClientID == other.account.ClientID &&
		e.account.RequestedBitsPerSecond == other.account.RequestedBitsPerSecond &&
		slices.Equal(normalizedPolicyBindings(e.account.EffectiveBindings()), normalizedPolicyBindings(other.account.EffectiveBindings()))
}

func normalizedPolicyBindings(bindings []bandwidthexchange.PolicyBinding) []bandwidthexchange.PolicyBinding {
	bindings = slices.Clone(bindings)
	slices.SortFunc(bindings, func(a, b bandwidthexchange.PolicyBinding) int {
		if protocol := strings.Compare(a.Protocol, b.Protocol); protocol != 0 {
			return protocol
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	return slices.Compact(bindings)
}

type automaticEnrollment struct {
	email     string
	peers     map[string]enrolledAccount
	available bool
}

type acknowledgedBandwidthPolicy struct {
	accounts        map[int]enrolledAccount
	emailIDs        map[string]int
	readyEmails     map[string]struct{}
	clientIDs       map[string]struct{}
	uncertain       map[int]struct{}
	uncertainEmails map[string]struct{}
	current         bool
}

type automaticAuthority struct {
	cfg       *PanelConfig
	reader    bandwidthInventoryReader
	legacy    PolicyReader
	client    *http.Client
	endpoints map[string]string
	staticIDs map[string]struct{}

	inventoryMu sync.Mutex
	mu          sync.RWMutex
	desired     map[int]automaticEnrollment
	ack         map[string]acknowledgedBandwidthPolicy
}

func startAutomaticAuthority(cfg *PanelConfig, reader PolicyReader, client *http.Client) (*automaticAuthority, error) {
	endpoints := make(map[string]string)
	staticIDs := make(map[string]struct{})
	for _, target := range cfg.targets {
		for id := range target.ClientIDs {
			staticIDs[id] = struct{}{}
		}
		if !cfg.limits[target.NodeID].automaticPolicy {
			continue
		}
		if err := target.Validate(); err != nil {
			return nil, err
		}
		endpoint, _ := url.Parse(target.URL)
		prefix, ok := strings.CutSuffix(endpoint.Path, "/exchange")
		if !ok {
			return nil, errors.New("automatic bandwidth requires an HTTPS exchange path ending in /exchange")
		}
		endpoint.Path = prefix + "/policy"
		if endpoint.RawPath != "" {
			rawPrefix, ok := strings.CutSuffix(endpoint.RawPath, "/exchange")
			if !ok {
				return nil, errors.New("automatic bandwidth requires an unescaped /exchange suffix")
			}
			endpoint.RawPath = rawPrefix + "/policy"
		}
		endpoints[target.NodeID] = endpoint.String()
	}
	if len(endpoints) == 0 {
		return nil, nil
	}
	inventory, ok := reader.(bandwidthInventoryReader)
	if !ok || client == nil {
		return nil, errors.New("automatic bandwidth requires a client inventory and HTTPS transport")
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	standard, ok := transport.(*http.Transport)
	if !ok || standard == nil || (standard.TLSClientConfig != nil && standard.TLSClientConfig.InsecureSkipVerify) ||
		standard.DialTLS != nil || standard.DialTLSContext != nil {
		return nil, errors.New("automatic bandwidth requires transport TLS verification")
	}
	return &automaticAuthority{
		cfg: cfg, reader: inventory, legacy: reader, endpoints: endpoints, staticIDs: staticIDs,
		ack: make(map[string]acknowledgedBandwidthPolicy, len(endpoints)),
		client: &http.Client{Transport: standard, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func (a *automaticAuthority) manages(nodeID string) bool {
	return a != nil && a.endpoints[nodeID] != ""
}

func (a *automaticAuthority) canonicalID(row BandwidthAccount) (string, error) {
	if id := a.cfg.panelCanonicalIDs[row.ID]; id != "" {
		return id, nil
	}
	// Database-managed IDs survive email and timestamp edits. Both supported
	// database schemas allocate the primary key from a non-reusing sequence.
	id := "panel-db:" + strconv.Itoa(row.ID)
	if _, collision := a.staticIDs[id]; collision {
		return "", errors.New("generated bandwidth identity conflicts with a configured account")
	}
	return id, nil
}

func (a *automaticAuthority) enrollment(row BandwidthAccount) (automaticEnrollment, error) {
	plan := automaticEnrollment{email: row.Email, peers: make(map[string]enrolledAccount), available: len(row.Attachments) > 0}
	if row.ID <= 0 || row.Policy.TotalBitsPerSecond < 0 || row.Policy.TotalBitsPerSecond > MaxPanelBitsPerSecond {
		return plan, errors.New("invalid committed bandwidth account or total")
	}
	canonical, err := a.canonicalID(row)
	if err != nil {
		return plan, err
	}
	legacyID := a.cfg.panelCanonicalIDs[row.ID]
	total := row.Policy.TotalBitsPerSecond
	if total == 0 && legacyID != "" {
		for _, peer := range a.cfg.limits {
			if fallback, ok := peer.clients[legacyID]; ok {
				total = fallback.TotalBitsPerSecond
				break
			}
		}
	}
	for key, attach := range row.Attachments {
		peerID := a.cfg.panelPeers[key]
		peer := a.cfg.limits[peerID]
		if a.manages(peerID) {
			plan.available = plan.available && len(attach.Bindings) > 0 && !attach.Unsupported
			continue
		}
		_, legacy := peer.clients[legacyID]
		plan.available = plan.available && legacy && (key != "local" || a.cfg.accounts[row.Email] == legacyID)
	}
	for key, attach := range row.Attachments {
		peerID := a.cfg.panelPeers[key]
		if !a.manages(peerID) || (total > 0 && !plan.available) {
			continue
		}
		if len(attach.Bindings) == 0 {
			continue
		}
		peer := a.cfg.limits[peerID]
		rate := peer.clients[legacyID].NodeBitsPerSecond
		if override, present := row.Policy.NodeBitsPerSecond[key]; present {
			if override < 0 || override > MaxPanelBitsPerSecond {
				return plan, errors.New("invalid committed bandwidth node limit")
			}
			rate = override
		}
		if rate > 0 && attach.Unsupported {
			continue
		}
		account := enrolledAccount{account: attach.policyAccount(row.Email)}
		if total > 0 || rate > 0 {
			grantTotal := total
			if grantTotal == 0 {
				// Only the per-node limit should bind; the allocator still needs
				// a positive total and must account for retained reservations.
				grantTotal = math.MaxInt64
			}
			rate = min(rate, grantTotal)
			account.limits = bandwidthlease.Limits{TotalBitsPerSecond: grantTotal, NodeBitsPerSecond: rate}
			account.account.ClientID = canonical
			account.account.RequestedBitsPerSecond = grantTotal
			if rate > 0 {
				account.account.RequestedBitsPerSecond = rate
			}
		}
		plan.peers[peerID] = account
	}
	return plan, nil
}

func (a *automaticAuthority) readDesired(ctx context.Context) (map[int]automaticEnrollment, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	a.inventoryMu.Lock()
	defer a.inventoryMu.Unlock()
	rows, err := a.reader.ReadBandwidthInventory(ctx)
	var desired map[int]automaticEnrollment
	if err == nil {
		desired = make(map[int]automaticEnrollment, len(rows))
		for _, row := range rows {
			if desired[row.ID].peers != nil {
				err = errors.New("duplicate committed bandwidth account")
				break
			}
			var plan automaticEnrollment
			plan, err = a.enrollment(row)
			if err != nil {
				break
			}
			desired[row.ID] = plan
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		desired = nil
	}
	a.mu.Lock()
	a.desired = desired
	a.mu.Unlock()
	return desired, err
}

func (a *automaticAuthority) prepare(ctx context.Context, target bandwidthexchange.Target) (map[string]struct{}, bool, error) {
	desired, err := a.readDesired(ctx)
	if err == nil {
		return a.publish(ctx, target, desired)
	}
	return a.unconfirmed(target.NodeID, errors.New("cannot read committed bandwidth inventory"))
}

func (a *automaticAuthority) publish(ctx context.Context, target bandwidthexchange.Target, desired map[int]automaticEnrollment) (map[string]struct{}, bool, error) {
	accounts := make(map[int]enrolledAccount)
	emailIDs := make(map[string]int)
	clientIDs := make(map[string]struct{}, len(target.ClientIDs))
	maps.Copy(clientIDs, target.ClientIDs)
	snapshot := bandwidthexchange.PolicySnapshot{
		NodeID: target.NodeID, Generation: target.Generation, Accounts: make([]bandwidthexchange.PolicyAccount, 0),
	}
	for id, plan := range desired {
		if account, attached := plan.peers[target.NodeID]; attached {
			accounts[id] = account
			emailIDs[account.account.Email] = id
			snapshot.Accounts = append(snapshot.Accounts, account.account)
			if account.account.ClientID != "" {
				clientIDs[account.account.ClientID] = struct{}{}
			}
		}
	}
	slices.SortFunc(snapshot.Accounts, func(x, y bandwidthexchange.PolicyAccount) int {
		return strings.Compare(x.Email, y.Email)
	})
	if len(clientIDs) > bandwidthexchange.MaxClients {
		return a.unconfirmed(target.NodeID, errors.New("automatic and static bandwidth account IDs exceed the exchange capacity"))
	}
	if err := snapshot.Validate(); err != nil {
		return a.unconfirmed(target.NodeID, err)
	}
	a.beginPublish(target.NodeID, accounts)
	ack, err := a.post(ctx, target, snapshot)
	if err != nil {
		return a.unconfirmed(target.NodeID, err)
	}
	ready := make(map[string]struct{}, len(ack.ReadyEmails))
	for _, email := range ack.ReadyEmails {
		if _, enrolled := emailIDs[email]; !enrolled {
			return a.unconfirmed(target.NodeID, errors.New("automatic bandwidth policy acknowledgement names an unknown account"))
		}
		ready[email] = struct{}{}
	}
	a.mu.Lock()
	a.ack[target.NodeID] = acknowledgedBandwidthPolicy{accounts: accounts, emailIDs: emailIDs, readyEmails: ready, clientIDs: clientIDs, current: true}
	a.mu.Unlock()
	return clientIDs, true, nil
}

func (a *automaticAuthority) beginPublish(nodeID string, accounts map[int]enrolledAccount) {
	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.ack[nodeID]
	if previous.uncertain == nil {
		previous.uncertain = make(map[int]struct{})
		previous.uncertainEmails = make(map[string]struct{})
	}
	for id, account := range accounts {
		if !previous.accounts[id].equal(account) {
			previous.uncertain[id] = struct{}{}
			previous.uncertainEmails[account.account.Email] = struct{}{}
		}
	}
	for id, account := range previous.accounts {
		if !accounts[id].equal(account) {
			previous.uncertain[id] = struct{}{}
			previous.uncertainEmails[account.account.Email] = struct{}{}
		}
	}
	a.ack[nodeID] = previous
}

func (a *automaticAuthority) unconfirmed(nodeID string, err error) (map[string]struct{}, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.ack[nodeID]
	previous.current = false
	a.ack[nodeID] = previous
	return previous.clientIDs, false, err
}

func (a *automaticAuthority) post(ctx context.Context, target bandwidthexchange.Target, snapshot bandwidthexchange.PolicySnapshot) (bandwidthexchange.PolicyAck, error) {
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > bandwidthexchange.MaxPolicyBody {
		return bandwidthexchange.PolicyAck{}, errors.New("cannot encode automatic bandwidth policy within the request size limit")
	}
	ctx, cancel := context.WithTimeout(ctx, bandwidthexchange.PolicyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoints[target.NodeID], bytes.NewReader(data))
	if err != nil {
		return bandwidthexchange.PolicyAck{}, errors.New("cannot build automatic bandwidth policy request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", target.Authorization)
	response, err := a.client.Do(req)
	if err != nil {
		return bandwidthexchange.PolicyAck{}, fmt.Errorf("automatic bandwidth policy request failed: %w", err)
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return bandwidthexchange.PolicyAck{}, errors.New("automatic bandwidth policy response lacks verified TLS identity")
	}
	if response.StatusCode != http.StatusOK {
		return bandwidthexchange.PolicyAck{}, fmt.Errorf("automatic bandwidth policy returned HTTP %d", response.StatusCode)
	}
	ack, err := bandwidthexchange.ReadPolicyAck(response.Body)
	if err != nil || ack.Digest != snapshot.Digest() {
		return bandwidthexchange.PolicyAck{}, errors.New("automatic bandwidth policy acknowledgement does not match the sent snapshot")
	}
	return ack, nil
}

// confirmed checks all related automatic peers, including any prior member
// whose last acknowledged policy still contains the account. Wait for an
// initial acknowledgement from every peer, since a prior authority process
// could have enrolled the account there before the membership changed.
// The caller holds a.mu for reading.
func (a *automaticAuthority) confirmed(id int, plan automaticEnrollment, requireLiveReady bool) bool {
	for nodeID := range a.endpoints {
		ack := a.ack[nodeID]
		if ack.clientIDs == nil {
			return false
		}
		wanted, attached := plan.peers[nodeID]
		applied, enrolled := ack.accounts[id]
		_, uncertain := ack.uncertain[id]
		_, uncertainEmail := ack.uncertainEmails[plan.email]
		if otherID, present := ack.emailIDs[plan.email]; uncertain || uncertainEmail || (present && otherID != id) {
			return false
		}
		if attached != enrolled || !applied.equal(wanted) {
			return false
		}
		if attached && requireLiveReady {
			if _, ready := ack.readyEmails[plan.email]; !ready || !ack.current {
				return false
			}
		}
	}
	return true
}

func (a *automaticAuthority) readyForLegacy(clientID string) bool {
	id, alias := a.cfg.panelClients[clientID]
	if !alias {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	plan, exists := a.desired[id]
	return exists && a.confirmed(id, plan, false)
}

func (a *automaticAuthority) resolveLimits(ctx context.Context, nodeID, generation, clientID string) (bandwidthlease.Limits, bool) {
	if ctx.Err() != nil || a.cfg.limits[nodeID].generation != generation {
		return bandwidthlease.Limits{}, false
	}
	a.mu.RLock()
	ack := a.ack[nodeID]
	if !ack.current {
		a.mu.RUnlock()
		return bandwidthlease.Limits{}, false
	}
	for id, account := range ack.accounts {
		if account.account.ClientID == clientID {
			plan, exists := a.desired[id]
			eligible := exists && a.confirmed(id, plan, false)
			a.mu.RUnlock()
			return account.limits, eligible
		}
	}
	a.mu.RUnlock()
	if !a.readyForLegacy(clientID) {
		return bandwidthlease.Limits{}, false
	}
	return a.cfg.resolveLimits(ctx, nodeID, generation, clientID, a.legacy)
}
