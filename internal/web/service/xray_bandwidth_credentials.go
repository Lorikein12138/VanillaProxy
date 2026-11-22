package service

import (
	"bytes"
	stdjson "encoding/json"
	json "encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/xtls/xray-core/infra/conf"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"gorm.io/gorm"
)

type bandwidthProxyAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
	ClientID *int   `json:"bandwidthClientId,omitempty"`
}

type bandwidthProxyAccountLists struct {
	Users    []*bandwidthProxyAccount `json:"users"`
	Accounts []*bandwidthProxyAccount `json:"accounts"`
}

var errBandwidthProxyAccountsEmpty = errors.New("managed proxy requires configured username/password authentication")

func bandwidthProxyAccounts(protocol string, raw []byte) ([]*bandwidthProxyAccount, error) {
	var lists bandwidthProxyAccountLists
	switch protocol {
	case "http":
		var settings struct {
			bandwidthProxyAccountLists
			Transparent bool   `json:"allowTransparent"`
			UserLevel   uint32 `json:"userLevel"`
		}
		if json.Unmarshal(raw, &settings, json.RejectUnknownMembers(true)) != nil {
			return nil, errors.New("invalid managed HTTP proxy settings")
		}
		lists = settings.bandwidthProxyAccountLists
	case "mixed":
		var settings struct {
			bandwidthProxyAccountLists
			Auth      string        `json:"auth"`
			UDP       bool          `json:"udp"`
			IP        *conf.Address `json:"ip"`
			UserLevel uint32        `json:"userLevel"`
		}
		if json.Unmarshal(raw, &settings, json.RejectUnknownMembers(true)) != nil || settings.Auth != conf.AuthMethodUserPass {
			return nil, errors.New("managed Mixed requires password authentication")
		}
		lists = settings.bandwidthProxyAccountLists
	}
	accounts := preferredBandwidthAccounts(lists.Users, lists.Accounts)
	if len(accounts) == 0 {
		return nil, errBandwidthProxyAccountsEmpty
	}
	seen := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		if account == nil || account.Password == "" {
			return nil, errors.New("managed proxy requires username/password authentication")
		}
		if !validBandwidthXrayIdentity(account.Username) || seen[account.Username] {
			return nil, errors.New("managed proxy requires unique non-empty usernames")
		}
		if account.ClientID != nil && *account.ClientID <= 0 {
			return nil, errors.New("managed proxy requires a valid bandwidth client ID")
		}
		if account.ClientID != nil && (strings.Contains(account.Username, ":") ||
			(protocol == "mixed" && (len(account.Username) > 255 || len(account.Password) > 255))) {
			return nil, errors.New("invalid authenticated proxy credentials for a bandwidth client binding")
		}
		seen[account.Username] = true
	}
	return accounts, nil
}

func (account bandwidthProxyAccount) credential() string {
	return bandwidthexchange.CredentialParts(account.Username, account.Password)
}

func hasBandwidthProxyOwners(inbound *model.Inbound) bool {
	if inbound.Protocol != model.HTTP && inbound.Protocol != model.Mixed {
		return false
	}
	accounts, err := bandwidthProxyAccounts(string(inbound.Protocol), []byte(inbound.Settings))
	return err == nil && slices.ContainsFunc(accounts, func(account *bandwidthProxyAccount) bool {
		return account.ClientID != nil
	})
}

func pinBandwidthProxyOwners(db *gorm.DB, inbound *xray.InboundConfig) error {
	accounts, err := bandwidthProxyAccounts(inbound.Protocol, inbound.Settings)
	if err != nil {
		// Configuration preparation validates the proxy settings before it uses
		// the owner map. Leave compatibility errors to that step.
		return nil
	}
	ids, owners := make([]int, 0, len(accounts)), make(map[string]string)
	for _, account := range accounts {
		if account.ClientID != nil {
			ids = append(ids, *account.ClientID)
			owners[account.Username] = ""
		}
	}
	if len(ids) == 0 {
		return nil
	}
	emails := make(map[int]string, len(ids))
	for start := 0; start < len(ids); start += sqlInChunk {
		var clients []struct {
			ID    int
			Email string
		}
		if err := db.Model(&model.ClientRecord{}).Select("id, email").
			Where("id IN ? AND enable = ?", ids[start:min(start+sqlInChunk, len(ids))], true).
			Scan(&clients).Error; err != nil {
			return err
		}
		for _, client := range clients {
			emails[client.ID] = client.Email
		}
	}
	for _, account := range accounts {
		if account.ClientID != nil {
			owners[account.Username] = emails[*account.ClientID]
		}
	}
	inbound.BandwidthProxyOwners = owners
	return nil
}

// prepareBandwidthProxyAccounts strips panel metadata and filters only marked accounts.
func prepareBandwidthProxyAccounts(inbound *xray.InboundConfig, automatic func(string, string, string) (string, bool)) ([]string, map[string]string, error) {
	protocol := strings.ToLower(inbound.Protocol)
	accounts, err := bandwidthProxyAccounts(protocol, inbound.Settings)
	if err != nil {
		return nil, nil, err
	}
	usernames := make([]string, 0, len(accounts))
	retained := make([]bandwidthProxyAccount, 0, len(accounts))
	var bindings, owners map[string]string
	for _, account := range accounts {
		if account.ClientID != nil {
			if !inbound.PanelGenerated {
				return nil, nil, errors.New("bandwidth proxy account bindings require a panel inbound")
			}
			email := inbound.BandwidthProxyOwners[account.Username]
			if automatic == nil || !validBandwidthXrayIdentity(email) {
				continue
			}
			id, ok := automatic(protocol, email, account.credential())
			if !ok {
				continue
			}
			if bindings == nil {
				bindings, owners = make(map[string]string), make(map[string]string)
			}
			bindings[account.Username] = id
			owners[account.Username] = email
		}
		usernames = append(usernames, account.Username)
		retained = append(retained, bandwidthProxyAccount{Username: account.Username, Password: account.Password})
	}
	inbound.BandwidthProxyOwners = owners
	var settings map[string]stdjson.RawMessage
	if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
		return nil, nil, err
	}
	delete(settings, "users")
	settings["accounts"], err = json.Marshal(retained)
	if err == nil {
		inbound.Settings, err = json.Marshal(settings, json.Deterministic(true))
	}
	return usernames, bindings, err
}

type bandwidthXrayPolicyCredential struct {
	Protocol   string
	Email      string
	Credential string
	raw        stdjson.RawMessage
}

type bandwidthXrayNativePolicy struct {
	listKey       string
	omitWhenEmpty bool
	credentials   []bandwidthXrayPolicyCredential
}

// bandwidthXrayPolicyCredentials projects the actual authentication fields the
// native core will read. Top-level or static template accounts are configured
// separately and have no panel-generated client list to enroll automatically.
func bandwidthXrayPolicyCredentials(inbound xray.InboundConfig) (bandwidthXrayNativePolicy, error) {
	var policy bandwidthXrayNativePolicy
	protocol := strings.ToLower(inbound.Protocol)
	switch protocol {
	case "vless", "hysteria", "vmess", "trojan", "shadowsocks", "masque", "wireguard":
	default:
		return policy, nil
	}
	var settings struct {
		Clients  []stdjson.RawMessage `json:"clients"`
		Users    []stdjson.RawMessage `json:"users"`
		Peers    []stdjson.RawMessage `json:"peers"`
		Method   string               `json:"method"`
		Password string               `json:"password"`
	}
	if !jsonEmptyBandwidthXrayValue(inbound.Settings) && json.Unmarshal(inbound.Settings, &settings) != nil {
		return policy, errors.New("invalid native client settings")
	}
	users := preferredBandwidthAccounts(settings.Users, settings.Clients)
	if protocol == "wireguard" {
		policy.listKey = "peers"
		users = settings.Peers
	} else {
		policy.listKey = "clients"
		if protocol == "shadowsocks" {
			if users == nil {
				return bandwidthXrayNativePolicy{}, nil
			}
			// With zero users the native SS2022 builder turns the server
			// key into a single-user credential. Omit the listener instead.
			_, methodErr := ss2022.GetCipherMethod(settings.Method)
			policy.omitWhenEmpty = methodErr == nil
		}
	}
	for _, raw := range users {
		var user struct {
			Email        string `json:"email"`
			ID           string `json:"id"`
			Auth         string `json:"auth"`
			Password     string `json:"password"`
			Pass         string `json:"pass"`
			Method       string `json:"method"`
			PublicKey    string `json:"publicKey"`
			PreSharedKey string `json:"preSharedKey"`
		}
		// The pinned Xray builders decode account fields with encoding/json v1.
		if err := stdjson.Unmarshal(raw, &user); err != nil || !validBandwidthXrayIdentity(user.Email) {
			return policy, errors.New("invalid native client identity")
		}
		entry := bandwidthXrayPolicyCredential{Email: user.Email, Protocol: protocol, raw: raw}
		var err error
		switch protocol {
		case "vless", "vmess":
			entry.Credential = user.ID
		case "hysteria":
			entry.Credential = user.Auth
		case "trojan":
			entry.Credential = user.Password
		case "masque":
			entry.Credential = user.Pass
		case "wireguard":
			entry.Credential, err = bandwidthWireGuardCredential(user.PublicKey, user.PreSharedKey)
		case "shadowsocks":
			entry.Protocol, entry.Credential, err = bandwidthShadowsocksCredential(settings.Method, settings.Password, user.Method, user.Password)
		}
		if err != nil || entry.Credential == "" {
			return policy, errors.New("invalid native client credential")
		}
		policy.credentials = append(policy.credentials, entry)
	}
	return policy, nil
}

func bandwidthWireGuardCredential(publicKey, preSharedKey string) (string, error) {
	public, err := conf.ParseWireGuardKey(publicKey)
	if err != nil || len(public) != 64 || strings.Trim(public, "0") == "" {
		return "", errors.New("invalid WireGuard public key")
	}
	var shared string
	if preSharedKey != "" {
		shared, err = conf.ParseWireGuardKey(preSharedKey)
		if err != nil || len(shared) != 64 {
			return "", errors.New("invalid WireGuard preshared key")
		}
		if strings.Trim(shared, "0") == "" {
			shared = ""
		}
	}
	return bandwidthexchange.CredentialParts(strings.ToLower(public), strings.ToLower(shared)), nil
}

func bandwidthShadowsocksCredential(method, serverKey, userMethod, password string) (protocol, credential string, err error) {
	if _, err := ss2022.GetCipherMethod(method); err == nil {
		if userMethod != "" || !strings.Contains(strings.ToLower(method), "aes") {
			return "", "", errors.New("invalid Shadowsocks 2022 multi-user method")
		}
		master, masterErr := bandwidthSS2022Key(method, serverKey)
		key, keyErr := bandwidthSS2022Key(method, password)
		if masterErr != nil || keyErr != nil || bytes.Equal(master, key) {
			return "", "", errors.New("invalid Shadowsocks 2022 multi-user key")
		}
		return "shadowsocks-2022", bandwidthexchange.CredentialParts(strings.ToLower(method), string(master), string(key)), nil
	}
	if password == "" {
		return "", "", errors.New("missing Shadowsocks password")
	}
	var cipher string
	switch strings.ToLower(userMethod) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		cipher = "aes-128-gcm"
	case "aes-256-gcm", "aead_aes_256_gcm":
		cipher = "aes-256-gcm"
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		cipher = "chacha20-poly1305"
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		cipher = "xchacha20-poly1305"
	default:
		return "", "", errors.New("invalid Shadowsocks cipher")
	}
	return "shadowsocks", bandwidthexchange.CredentialParts(cipher, password), nil
}

func (policy bandwidthXrayNativePolicy) validateEffectiveUsers(clients []string) error {
	if len(clients) != len(policy.credentials) {
		return errors.New("automatic account inventory differs from the native configured users")
	}
	seen := make(map[string]bool, len(clients))
	for i, email := range clients {
		if email != policy.credentials[i].Email || seen[email] {
			return errors.New("automatic accounts require exact unique native emails")
		}
		seen[email] = true
	}
	return nil
}

func (policy bandwidthXrayNativePolicy) filter(inbound *xray.InboundConfig, allowed func(protocol, email, credential string) (string, bool)) (map[string]string, error) {
	authorized := make(map[string]string)
	retained := make([]stdjson.RawMessage, 0, len(policy.credentials))
	for _, entry := range policy.credentials {
		if id, ok := allowed(entry.Protocol, entry.Email, entry.Credential); ok {
			authorized[entry.Email] = id
			retained = append(retained, entry.raw)
		}
	}
	if len(retained) == len(policy.credentials) {
		return authorized, nil
	}
	var settings map[string]stdjson.RawMessage
	if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(retained)
	if err != nil {
		return nil, err
	}
	if policy.listKey == "clients" {
		delete(settings, "users")
	}
	settings[policy.listKey] = encoded
	inbound.Settings, err = json.Marshal(settings, json.Deterministic(true))
	return authorized, err
}
