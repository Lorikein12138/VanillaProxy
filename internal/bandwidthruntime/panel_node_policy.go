package bandwidthruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
)

type nodePolicyFile struct {
	directory string
	name      string
}

func configureNodePolicyFile(dir *os.Root, path string) (*nodePolicyFile, error) {
	if !filepath.IsLocal(path) || filepath.Clean(path) == "." {
		return nil, errors.New("automaticPolicyFile must name a relative file")
	}
	path = filepath.Clean(path)
	parent, err := dir.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("cannot open automatic bandwidth policy directory")
	}
	defer parent.Close()
	directory, err := filepath.Abs(parent.Name())
	if err != nil {
		return nil, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	return &nodePolicyFile{directory: directory, name: filepath.Base(path)}, nil
}

type nodePolicyState struct {
	digest   string
	accounts map[string]nodePolicyAccount
	rates    map[string]int64
	managed  map[string]struct{}
}

type nodePolicyAccount struct {
	clientID string
	bindings map[bandwidthexchange.PolicyBinding]struct{}
}

type automaticNodePolicy struct {
	file      nodePolicyFile
	nodeID    string
	authorize bandwidthexchange.Authorize
	static    map[string]int64

	applyMu sync.Mutex
	// The immutable state pointer is protected by Node.mu.
	state *nodePolicyState
	// The durable digest is protected by applyMu.
	durableDigest string
}

func (n *Node) startAutomaticPolicy(config NodeConfig) error {
	policy := &automaticNodePolicy{
		file: *config.automaticPolicy, nodeID: config.NodeID,
		authorize: config.Authorize, static: maps.Clone(n.clientRates),
	}
	n.policy = policy
	snapshot, err := policy.file.load()
	if err != nil || snapshot == nil {
		return err
	}
	state, err := n.buildPolicyState(*snapshot)
	if err != nil {
		return err
	}
	n.installPolicyLocked(state)
	policy.durableDigest = state.digest
	return nil
}

// AutomaticAccountLookup freezes the current automatic account view for a
// generated Xray config build. An empty ID explicitly authorizes unrestricted
// service. An opted-in node requires the exact email and protocol credential.
func (panel *PanelRuntime) AutomaticAccountLookup() func(protocol, email, credential string) (string, bool) {
	n := panel.Node()
	if n == nil || n.policy == nil {
		return nil
	}
	n.mu.Lock()
	state := n.policy.state
	n.mu.Unlock()
	if state == nil {
		return func(string, string, string) (string, bool) { return "", false }
	}
	return func(protocol, email, credential string) (string, bool) {
		account, ok := state.accounts[email]
		if !ok {
			return "", false
		}
		binding := bandwidthexchange.PolicyBinding{
			Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, credential),
		}
		if _, allowed := account.bindings[binding]; !allowed {
			return "", false
		}
		return account.clientID, true
	}
}

func (panel *PanelRuntime) XrayAutomaticAccounts() func(protocol, email, credential string) (string, bool) {
	return panel.AutomaticAccountLookup()
}

// PolicyHandler serves the optional node-only endpoint. activate calls install
// while holding the child lifecycle lock, then activates the resulting config.
// install's bool reports whether the live policy changed, including when a
// failure happened after the policy file was atomically replaced.
func (panel *PanelRuntime) PolicyHandler(activate func(context.Context, func() (bool, error)) (XrayPolicyLiveAccounts, error)) http.Handler {
	n := panel.Node()
	if n == nil || n.policy == nil || activate == nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if authority, allowed := n.policy.authorize(r); !allowed || authority == "" {
			http.Error(w, "authority authorization required", http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), bandwidthexchange.PolicyTimeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		body := http.MaxBytesReader(w, r.Body, bandwidthexchange.MaxPolicyBody)
		snapshot, err := bandwidthexchange.ReadPolicySnapshot(body)
		if err != nil {
			status := http.StatusBadRequest
			if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "invalid bandwidth policy", status)
			return
		}
		if snapshot.NodeID != n.policy.nodeID || snapshot.Generation != n.generation {
			http.Error(w, "bandwidth policy node or generation mismatch", http.StatusConflict)
			return
		}
		state, err := n.buildPolicyState(snapshot)
		if err != nil {
			http.Error(w, "invalid bandwidth policy bindings", http.StatusBadRequest)
			return
		}
		if !n.policy.applyMu.TryLock() {
			http.Error(w, "bandwidth policy activation busy", http.StatusServiceUnavailable)
			return
		}
		defer n.policy.applyMu.Unlock()
		if ctx.Err() != nil {
			http.Error(w, "bandwidth policy activation unavailable", http.StatusServiceUnavailable)
			return
		}
		live, err := activate(ctx, func() (bool, error) { return n.applyPolicy(ctx, snapshot, state) })
		if err != nil || ctx.Err() != nil {
			http.Error(w, "bandwidth policy activation unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.MarshalWrite(w, bandwidthexchange.PolicyAck{Digest: state.digest, ReadyEmails: live.readyEmails(snapshot.Accounts)})
	})
}

// XrayPolicyLiveAccounts describes authorized generated accounts in the live child.
type XrayPolicyLiveAccounts map[string]map[bandwidthexchange.PolicyBinding]struct{}

func (live XrayPolicyLiveAccounts) Add(email string, binding bandwidthexchange.PolicyBinding) {
	bindings := live[email]
	if bindings == nil {
		bindings = make(map[bandwidthexchange.PolicyBinding]struct{})
		live[email] = bindings
	}
	bindings[binding] = struct{}{}
}

func (live XrayPolicyLiveAccounts) readyEmails(accounts []bandwidthexchange.PolicyAccount) []string {
	var ready []string
	for _, account := range accounts {
		bindings := live[account.Email]
		if !slices.ContainsFunc(account.EffectiveBindings(), func(binding bandwidthexchange.PolicyBinding) bool {
			_, exists := bindings[binding]
			return !exists
		}) {
			ready = append(ready, account.Email)
		}
	}
	slices.Sort(ready)
	return ready
}

func (n *Node) buildPolicyState(snapshot bandwidthexchange.PolicySnapshot) (*nodePolicyState, error) {
	if snapshot.NodeID != n.policy.nodeID || snapshot.Generation != n.generation {
		return nil, errors.New("stored bandwidth policy node or generation mismatch")
	}
	state := &nodePolicyState{
		digest: snapshot.Digest(), accounts: make(map[string]nodePolicyAccount, len(snapshot.Accounts)),
		rates: maps.Clone(n.policy.static), managed: make(map[string]struct{}),
	}
	for _, account := range snapshot.Accounts {
		bindings := account.EffectiveBindings()
		allowed := make(map[bandwidthexchange.PolicyBinding]struct{}, len(bindings))
		for _, binding := range bindings {
			allowed[binding] = struct{}{}
		}
		state.accounts[account.Email] = nodePolicyAccount{clientID: account.ClientID, bindings: allowed}
		if account.ClientID == "" {
			continue
		}
		state.managed[account.ClientID] = struct{}{}
		rate := account.RequestedBitsPerSecond
		if staticRate, exists := n.policy.static[account.ClientID]; exists {
			rate = min(staticRate, rate)
		}
		state.rates[account.ClientID] = rate
	}
	if state.digest == "" || len(state.rates) > bandwidthexchange.MaxClients {
		return nil, errors.New("invalid stored bandwidth policy bindings")
	}
	return state, nil
}

func (n *Node) applyPolicy(ctx context.Context, snapshot bandwidthexchange.PolicySnapshot, state *nodePolicyState) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false, errNodeClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var err error
	if n.policy.durableDigest != state.digest {
		var replaced bool
		replaced, err = n.policy.file.save(snapshot)
		if !replaced {
			return false, err
		}
		if err == nil {
			n.policy.durableDigest = state.digest
		} else {
			n.policy.durableDigest = ""
		}
	}
	if n.policy.state != nil && n.policy.state.digest == state.digest {
		return false, err
	}
	n.installPolicyLocked(state)
	return true, err
}

func (n *Node) installPolicyLocked(state *nodePolicyState) {
	for id, oldRate := range n.clientRates {
		wasAutomatic := n.policy.state == nil
		if n.policy.state != nil {
			_, wasAutomatic = n.policy.state.managed[id]
		}
		_, remainsAutomatic := state.managed[id]
		if rate := state.rates[id]; rate < oldRate || (wasAutomatic && !remainsAutomatic) {
			n.leases.Revoke(id)
			delete(n.demand, id)
		}
	}
	n.clientRates = state.rates
	n.clientIDs = slices.Sorted(maps.Keys(state.rates))
	n.policy.state = state
	close(n.changed)
	n.changed = make(chan struct{})
}

func (file nodePolicyFile) load() (*bandwidthexchange.PolicySnapshot, error) {
	dir, err := os.OpenRoot(file.directory)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	info, err := dir.Lstat(file.name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid automatic bandwidth policy file")
	}
	f, err := dir.Open(file.name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !isPrivatePanelTokenFile(f, opened) {
		return nil, errors.New("automatic bandwidth policy file requires private permissions")
	}
	snapshot, err := bandwidthexchange.ReadPolicySnapshot(f)
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func (file nodePolicyFile) save(snapshot bandwidthexchange.PolicySnapshot) (bool, error) {
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > bandwidthexchange.MaxPolicyBody {
		return false, errors.New("invalid automatic bandwidth policy size")
	}
	dir, err := os.OpenRoot(file.directory)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	tmp := ".bandwidth-policy-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	defer dir.Remove(tmp)
	if err := protectNodePolicyFile(f, filepath.Join(file.directory, tmp)); err != nil {
		_ = f.Close()
		return false, err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return false, err
	}
	if err := replaceNodePolicyFile(dir, tmp, file.name); err != nil {
		return false, err
	}
	return true, syncNodePolicyDirectory(dir)
}
