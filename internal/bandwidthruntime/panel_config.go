package bandwidthruntime

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// PanelConfigEnv specifies the path to the opt-in panel configuration file.
const PanelConfigEnv = "XUI_BANDWIDTH_CONFIG"

const (
	maxPanelConfigBytes = 4 << 20
	panelTokenLength    = 64
	bearerPrefix        = "Bearer "
)

type panelFile struct {
	Node      *panelNodeFile      `json:"node"`
	Authority *panelAuthorityFile `json:"authority"`
}

type panelNodeFile struct {
	ID                         string                      `json:"id"`
	Generation                 string                      `json:"generation"`
	AuthorityID                string                      `json:"authorityID"`
	TokenFile                  string                      `json:"tokenFile"`
	Accounts                   map[string]panelAccountFile `json:"accounts"`
	AllowUnmeteredXrayAccounts bool                        `json:"allowUnmeteredXrayAccounts"`
	AutomaticPolicyFile        string                      `json:"automaticPolicyFile"`
}

type panelAccountFile struct {
	ID                     string `json:"id"`
	RequestedBitsPerSecond int64  `json:"requestedBitsPerSecond"`
}

type panelAuthorityFile struct {
	Nodes        []panelPeerFile `json:"nodes"`
	PanelClients map[string]int  `json:"panelClients"`
}

type panelPeerFile struct {
	ID              string                     `json:"id"`
	Generation      string                     `json:"generation"`
	URL             string                     `json:"url"`
	TokenFile       string                     `json:"tokenFile"`
	Clients         map[string]panelLimitsFile `json:"clients"`
	PanelNodeKey    string                     `json:"panelNodeKey"`
	AutomaticPolicy bool                       `json:"automaticPolicy"`
}

type panelLimitsFile struct {
	TotalBitsPerSecond int64 `json:"totalBitsPerSecond"`
	NodeBitsPerSecond  int64 `json:"nodeBitsPerSecond"`
}

type panelPeerLimits struct {
	generation      string
	clients         map[string]bandwidthlease.Limits
	panelNodeKey    string
	automaticPolicy bool
}

// PanelConfig holds the validated startup settings for the configured roles.
type PanelConfig struct {
	allowUnmeteredXrayAccounts bool
	node                       *NodeConfig
	accounts                   map[string]string
	targets                    []bandwidthexchange.Target
	limits                     map[string]panelPeerLimits
	panelClients               map[string]int
	panelCanonicalIDs          map[int]string
	panelPeers                 map[string]string
}

// String and GoString keep credentials out of formatted startup diagnostics.
func (cfg PanelConfig) String() string   { return "bandwidth panel configuration" }
func (cfg PanelConfig) GoString() string { return cfg.String() }

// LoadPanelConfig validates both roles and reads their private token files.
// An empty path keeps distributed bandwidth disabled.
func LoadPanelConfig(path string) (*PanelConfig, error) {
	if path == "" {
		return nil, nil
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("cannot open bandwidth panel configuration directory")
	}
	defer root.Close()
	data, err := readPanelFile(root, filepath.Base(path), maxPanelConfigBytes, false)
	if err != nil {
		return nil, errors.New("cannot read bandwidth panel configuration file")
	}
	var spec panelFile
	if err := json.Unmarshal(data, &spec, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("invalid bandwidth panel configuration JSON")
	}
	if spec.Node == nil && spec.Authority == nil {
		return nil, errors.New("bandwidth panel configuration requires a node or authority role")
	}
	cfg := &PanelConfig{}
	if spec.Node != nil {
		if spec.Node.AutomaticPolicyFile != "" && (strings.EqualFold(filepath.Clean(spec.Node.AutomaticPolicyFile), filepath.Base(path)) ||
			strings.EqualFold(filepath.Clean(spec.Node.AutomaticPolicyFile), filepath.Clean(spec.Node.TokenFile))) {
			return nil, errors.New("automaticPolicyFile must be separate from the panel configuration and token")
		}
		if err := cfg.loadNode(root, spec.Node); err != nil {
			return nil, err
		}
	}
	if spec.Authority != nil {
		if err := cfg.loadAuthority(root, spec.Authority); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func (cfg *PanelConfig) loadNode(dir *os.Root, spec *panelNodeFile) error {
	if !bandwidthexchange.ValidIdentity(spec.ID) || !bandwidthexchange.ValidIdentity(spec.Generation) ||
		!bandwidthexchange.ValidIdentity(spec.AuthorityID) || (len(spec.Accounts) == 0 && spec.AutomaticPolicyFile == "") ||
		len(spec.Accounts) > bandwidthexchange.MaxClients {
		return errors.New("invalid bandwidth panel node configuration")
	}
	accounts := make(map[string]string, len(spec.Accounts))
	rates := make(map[string]int64, len(spec.Accounts))
	for email, account := range spec.Accounts {
		if email == "" || strings.IndexFunc(email, invalidPanelEmailChar) >= 0 ||
			!bandwidthexchange.ValidIdentity(account.ID) || account.RequestedBitsPerSecond <= 0 {
			return errors.New("invalid bandwidth panel node account")
		}
		if rate, exists := rates[account.ID]; exists && rate != account.RequestedBitsPerSecond {
			return errors.New("inconsistent requested bandwidth rate for a canonical account")
		}
		accounts[email] = account.ID
		rates[account.ID] = account.RequestedBitsPerSecond
	}
	token, err := loadPanelToken(dir, spec.TokenFile)
	if err != nil {
		return err
	}
	cfg.node = &NodeConfig{
		NodeID: spec.ID, Generation: spec.Generation, ClientRates: rates,
		Authorize: panelBearerAuth(spec.AuthorityID, token),
	}
	if spec.AutomaticPolicyFile != "" {
		file, err := configureNodePolicyFile(dir, spec.AutomaticPolicyFile)
		if err != nil {
			return err
		}
		cfg.node.automaticPolicy = file
	}
	cfg.accounts = accounts
	cfg.allowUnmeteredXrayAccounts = spec.AllowUnmeteredXrayAccounts
	return nil
}

func invalidPanelEmailChar(r rune) bool {
	return r == '/' || r == '\\' || unicode.IsControl(r) || unicode.IsSpace(r)
}

func (cfg *PanelConfig) loadAuthority(dir *os.Root, spec *panelAuthorityFile) error {
	if len(spec.Nodes) == 0 {
		return errors.New("bandwidth panel authority requires configured nodes")
	}
	totals := make(map[string]int64)
	cfg.targets = make([]bandwidthexchange.Target, 0, len(spec.Nodes))
	cfg.limits = make(map[string]panelPeerLimits, len(spec.Nodes))
	cfg.panelPeers = make(map[string]string, len(spec.Nodes))
	for _, peer := range spec.Nodes {
		target := bandwidthexchange.Target{URL: peer.URL, NodeID: peer.ID, Generation: peer.Generation}
		if err := target.Validate(); err != nil {
			return err
		}
		if _, found := cfg.limits[peer.ID]; found {
			return errors.New("duplicate bandwidth panel authority node")
		}
		if err := cfg.registerPanelPeer(peer); err != nil {
			return err
		}
		if peer.AutomaticPolicy {
			if peer.PanelNodeKey != "local" && !strings.HasPrefix(peer.PanelNodeKey, "node:") &&
				!strings.HasPrefix(peer.PanelNodeKey, "guid:") {
				return errors.New("automatic bandwidth policy requires a direct physical panel node key")
			}
			if peer.PanelNodeKey == "local" && cfg.node.automaticPolicy == nil {
				return errors.New("local automatic bandwidth policy requires automaticPolicyFile")
			}
		}
		if (len(peer.Clients) == 0 && !peer.AutomaticPolicy) || len(peer.Clients) > bandwidthexchange.MaxClients {
			return errors.New("invalid bandwidth panel authority client list")
		}
		limits := make(map[string]bandwidthlease.Limits, len(peer.Clients))
		target.ClientIDs = make(map[string]struct{}, len(peer.Clients))
		for id, client := range peer.Clients {
			if !bandwidthexchange.ValidIdentity(id) || client.TotalBitsPerSecond <= 0 ||
				client.NodeBitsPerSecond < 0 || client.NodeBitsPerSecond > client.TotalBitsPerSecond {
				return errors.New("invalid bandwidth panel authority client limits")
			}
			if total, exists := totals[id]; exists && total != client.TotalBitsPerSecond {
				return errors.New("inconsistent total bandwidth rate for a canonical account")
			}
			totals[id] = client.TotalBitsPerSecond
			limits[id] = bandwidthlease.Limits(client)
			target.ClientIDs[id] = struct{}{}
		}
		token, err := loadPanelToken(dir, peer.TokenFile)
		if err != nil {
			return err
		}
		target.Authorization = bearerPrefix + string(token[:])
		cfg.targets = append(cfg.targets, target)
		cfg.limits[peer.ID] = panelPeerLimits{generation: peer.Generation, clients: limits, panelNodeKey: peer.PanelNodeKey, automaticPolicy: peer.AutomaticPolicy}
	}
	cfg.panelClients = make(map[string]int, len(spec.PanelClients))
	cfg.panelCanonicalIDs = make(map[int]string, len(spec.PanelClients))
	for canonicalID, recordID := range spec.PanelClients {
		_, eligible := totals[canonicalID]
		if _, duplicate := cfg.panelCanonicalIDs[recordID]; recordID <= 0 || !eligible || duplicate {
			return errors.New("invalid bandwidth panel authority client binding")
		}
		cfg.panelClients[canonicalID] = recordID
		cfg.panelCanonicalIDs[recordID] = canonicalID
	}
	return nil
}

func readPanelFile(dir *os.Root, path string, limit int64, private bool) ([]byte, error) {
	info, err := dir.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid bandwidth configuration or token file")
	}
	file, err := dir.Open(path)
	if err != nil {
		return nil, errors.New("cannot open bandwidth configuration or token file")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || (private && !isPrivatePanelTokenFile(file, info)) {
		return nil, errors.New("invalid bandwidth configuration or token file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read bandwidth configuration or token file within its size limit")
	}
	return data, nil
}

func loadPanelToken(dir *os.Root, path string) ([panelTokenLength]byte, error) {
	var token [panelTokenLength]byte
	if !filepath.IsLocal(path) || filepath.Clean(path) == "." {
		return token, errors.New("bandwidth panel tokenFile must name a relative file")
	}
	data, err := readPanelFile(dir, filepath.Clean(path), panelTokenLength+2, true)
	if err != nil {
		return token, errors.New("cannot read private bandwidth panel tokenFile")
	}
	if withoutLF, ok := bytes.CutSuffix(data, []byte("\n")); ok {
		data = bytes.TrimSuffix(withoutLF, []byte("\r"))
	}
	var decoded [panelTokenLength / 2]byte
	if len(data) != len(token) {
		return token, errors.New("bandwidth panel tokenFile must contain 64 hexadecimal characters")
	}
	if _, err := hex.Decode(decoded[:], data); err != nil {
		return token, errors.New("bandwidth panel tokenFile must contain 64 hexadecimal characters")
	}
	copy(token[:], data)
	return token, nil
}

func panelBearerAuth(authorityID string, token [panelTokenLength]byte) bandwidthexchange.Authorize {
	return func(r *http.Request) (string, bool) {
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 {
			return "", false
		}
		value := headers[0]
		if len(value) != len(bearerPrefix)+len(token) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) ||
			subtle.ConstantTimeCompare([]byte(value[len(bearerPrefix):]), token[:]) != 1 {
			return "", false
		}
		return authorityID, true
	}
}

// PanelRuntime owns the configured local lease node and authority poller.
// Its account bindings and accessors remain safe to read concurrently with Close.
type PanelRuntime struct {
	allowUnmeteredXrayAccounts bool
	node                       *Node
	accounts                   map[string]string
	policyConfig               *PanelConfig
	automaticPolicy            *automaticAuthority
	transport                  *http.Transport
	cancel                     context.CancelFunc
	done                       chan struct{}
	close                      sync.Once
	closeErr                   error
}

// StartPanelRuntime starts the validated roles without mounting any HTTP routes.
func StartPanelRuntime(cfg *PanelConfig) (*PanelRuntime, error) {
	return StartPanelRuntimeWithPolicy(cfg, nil)
}

// StartPanelRuntimeWithPolicy connects database-backed limits to the same
// authority used for static limits.
func StartPanelRuntimeWithPolicy(cfg *PanelConfig, reader PolicyReader) (*PanelRuntime, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.node == nil && len(cfg.targets) == 0 {
		return nil, errors.New("bandwidth panel requires a configured role")
	}
	panel := &PanelRuntime{accounts: cfg.accounts, allowUnmeteredXrayAccounts: cfg.allowUnmeteredXrayAccounts}
	if reader != nil {
		panel.policyConfig = cfg
	}
	var poller *Poller
	if len(cfg.targets) != 0 {
		// A dedicated transport uses system certificate roots and verifies the
		// configured host before sending the credential.
		panel.transport = &http.Transport{ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second}
		client := &http.Client{Transport: panel.transport}
		automatic, err := startAutomaticAuthority(cfg, reader, client)
		if err != nil {
			_ = panel.Close()
			return nil, err
		}
		panel.automaticPolicy = automatic
		targets := make([]RootTarget, 0, len(cfg.targets))
		for _, target := range cfg.targets {
			peer := RootTarget{Target: target, Client: client}
			if automatic != nil && automatic.manages(target.NodeID) {
				peer.Prepare = automatic.prepare
			}
			targets = append(targets, peer)
		}
		poller, err = NewPoller(bandwidthlease.NewAuthority(nil), targets,
			func(ctx context.Context, nodeID, generation, clientID string) (bandwidthlease.Limits, bool) {
				if automatic != nil {
					if automatic.manages(nodeID) {
						return automatic.resolveLimits(ctx, nodeID, generation, clientID)
					}
					if !automatic.readyForLegacy(clientID) {
						return bandwidthlease.Limits{}, false
					}
				}
				return cfg.resolveLimits(ctx, nodeID, generation, clientID, reader)
			})
		if err != nil {
			return nil, errors.New("cannot configure bandwidth panel authority")
		}
	}
	if cfg.node != nil {
		node, err := StartNode(*cfg.node)
		if err != nil {
			_ = panel.Close()
			return nil, errors.New("cannot start bandwidth panel node")
		}
		panel.node = node
	}
	if poller != nil {
		var ctx context.Context
		ctx, panel.cancel = context.WithCancel(context.Background())
		panel.done = make(chan struct{})
		go func() {
			defer close(panel.done)
			_ = poller.Run(ctx, 0, nil)
		}()
	}
	return panel, nil
}

// Node returns the configured local lease node, if enabled.
func (panel *PanelRuntime) Node() *Node {
	if panel == nil {
		return nil
	}
	return panel.node
}

// ExchangeHandler returns the local HTTPS exchange handler, if enabled.
func (panel *PanelRuntime) ExchangeHandler() http.Handler {
	if node := panel.Node(); node != nil {
		return node.Handler()
	}
	return nil
}

// AccountID resolves an exact local email to its configured canonical ID.
func (panel *PanelRuntime) AccountID(email string) (string, bool) {
	if panel == nil {
		return "", false
	}
	id, configured := panel.accounts[email]
	return id, configured
}

// AllowsUnmeteredXrayAccounts reports the node's opt-in for generated Xray inbounds.
func (panel *PanelRuntime) AllowsUnmeteredXrayAccounts() bool {
	return panel != nil && panel.allowUnmeteredXrayAccounts
}

// Close stops authority polling and closes the local node once.
func (panel *PanelRuntime) Close() error {
	if panel == nil {
		return nil
	}
	panel.close.Do(func() {
		if panel.cancel != nil {
			panel.cancel()
			<-panel.done
		}
		if panel.transport != nil {
			panel.transport.CloseIdleConnections()
		}
		if panel.node != nil {
			panel.closeErr = panel.node.Close()
		}
	})
	return panel.closeErr
}
