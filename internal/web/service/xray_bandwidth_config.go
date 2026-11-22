package service

import (
	"bytes"
	"encoding/base64"
	stdjson "encoding/json"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport/internet/reality"
)

// prepareBandwidthXrayConfig checks the generated ingress inventory and freezes
// the exact native email or username bindings used by each metered inbound.
func prepareBandwidthXrayConfig(allowUnmetered bool, config *xray.Config, resolveAccount func(email string) (string, bool)) (*xray.Config, map[string]map[string]string, error) {
	return prepareBandwidthXrayConfigWithPolicy(allowUnmetered, config, resolveAccount, nil)
}

func prepareBandwidthXrayConfigWithPolicy(allowUnmetered bool, config *xray.Config, resolveAccount func(email string) (string, bool), automaticAccounts func(protocol, email, credential string) (string, bool)) (*xray.Config, map[string]map[string]string, error) {
	return prepareBandwidthXrayConfigForMode(allowUnmetered, config, resolveAccount, automaticAccounts, false)
}

func prepareBandwidthXrayConfigForRuntime(allowUnmetered bool, config *xray.Config, resolveAccount func(email string) (string, bool), automaticAccounts func(protocol, email, credential string) (string, bool)) (*xray.Config, map[string]map[string]string, error) {
	return prepareBandwidthXrayConfigForMode(allowUnmetered, config, resolveAccount, automaticAccounts, true)
}

func logBandwidthInboundIsolation(tag, protocol string) {
	logger.Warningf("Bandwidth-managed Xray skipped incompatible inbound %q using protocol %q", tag, protocol)
}

func prepareBandwidthXrayConfigForMode(allowUnmetered bool, config *xray.Config, resolveAccount func(email string) (string, bool), automaticAccounts func(protocol, email, credential string) (string, bool), isolateIncompatible bool) (*xray.Config, map[string]map[string]string, error) {
	if config == nil || resolveAccount == nil {
		return nil, nil, errors.New("managed Xray requires a configuration and account resolver")
	}
	api, err := prepareBandwidthXrayAPI(config)
	if err != nil {
		return nil, nil, err
	}
	if err := validateBandwidthXrayTemplate(config, api); err != nil {
		return nil, nil, err
	}
	clientsByTag := make(map[string]map[string]string)
	legacyAccountIDs := make(map[string]string)
	seenTags := make(map[string]bool)
	prepared := cloneBandwidthXrayConfig(config)
	retainedInbounds := prepared.InboundConfigs[:0]
	for _, inbound := range prepared.InboundConfigs {
		if !validBandwidthXrayIdentity(inbound.Tag) || seenTags[inbound.Tag] {
			return nil, nil, errors.New("managed Xray requires unique non-empty inbound tags")
		}
		seenTags[inbound.Tag] = true
		if inbound.Tag == api.Tag || inbound.Tag == "api" {
			if err := checkBandwidthXrayAPITunnel(config, inbound, api); err != nil {
				return nil, nil, err
			}
			retainedInbounds = append(retainedInbounds, inbound)
			continue
		}
		// Panel-generated loopback relays carry traffic already metered by their sidecars.
		if inbound.TuicRelay || inbound.AmneziaWGRelay {
			retainedInbounds = append(retainedInbounds, inbound)
			continue
		}
		bindings, err := prepareBandwidthXrayInbound(&inbound, allowUnmetered, resolveAccount, automaticAccounts, legacyAccountIDs)
		if err == nil && (bindings == nil || (isolateIncompatible && len(bindings) == 0)) {
			continue
		}
		if err == nil {
			err = validateNativeBandwidthXrayInbound(inbound, bindings, isolateIncompatible)
		}
		if err != nil {
			if isolateIncompatible {
				logBandwidthInboundIsolation(inbound.Tag, inbound.Protocol)
				continue
			}
			return nil, nil, fmt.Errorf("managed Xray inbound %q: %w", inbound.Tag, err)
		}
		clientsByTag[inbound.Tag] = bindings
		retainedInbounds = append(retainedInbounds, inbound)
	}
	prepared.InboundConfigs = retainedInbounds
	if api.Tag != "" && !seenTags[api.Tag] {
		return nil, nil, errors.New("managed Xray API requires its loopback tunnel")
	}
	if api.Tag != "" {
		prepared.API, err = json.Marshal(api)
		if err != nil {
			return nil, nil, errors.New("marshal managed Xray API configuration")
		}
	}
	return prepared, clientsByTag, nil
}

func validateNativeBandwidthXrayInbound(inbound xray.InboundConfig, bindings map[string]string, requireRuntimeCapabilities bool) (resultErr error) {
	invalidConfig := errors.New("invalid native inbound configuration")
	// Some native builders dereference invalid nested settings, such as a null
	// TLS certificate entry. Keep those panics within this inbound's preflight.
	defer func() {
		if recover() != nil {
			resultErr = invalidConfig
		}
	}()
	raw, err := stdjson.Marshal(inbound)
	if err != nil {
		return invalidConfig
	}
	built, err := xray.BuildInboundConfig(raw)
	if err != nil {
		return invalidConfig
	}
	if err := xraybandwidthchild.ValidateManagedInbound(built, bindings, inbound.PanelGenerated && inbound.BandwidthAutomatic, requireRuntimeCapabilities); err != nil {
		return errors.New("invalid native account bindings or transport")
	}
	return nil
}

// A nil binding map means the inbound must be omitted in either mode.
func prepareBandwidthXrayInbound(inbound *xray.InboundConfig, allowUnmetered bool, resolveAccount func(string) (string, bool), automaticAccounts func(string, string, string) (string, bool), legacyAccountIDs map[string]string) (map[string]string, error) {
	var policy bandwidthXrayNativePolicy
	var err error
	if inbound.PanelGenerated {
		policy, err = bandwidthXrayPolicyCredentials(*inbound)
		if err != nil {
			return nil, err
		}
	}
	generatedPolicyInbound := policy.listKey != ""
	inbound.BandwidthAutomatic = generatedPolicyInbound
	appliesAutomaticPolicy := generatedPolicyInbound && automaticAccounts != nil
	if policy.omitWhenEmpty && len(policy.credentials) == 0 {
		return nil, nil
	}
	var clients []string
	var proxyBindings map[string]string
	proxy := strings.EqualFold(inbound.Protocol, "http") || strings.EqualFold(inbound.Protocol, "mixed")
	if proxy {
		if _, err := validateBandwidthXrayReceiver(*inbound); err != nil {
			return nil, err
		}
		clients, proxyBindings, err = prepareBandwidthProxyAccounts(inbound, automaticAccounts)
		inbound.BandwidthAutomatic = len(proxyBindings) > 0
	} else {
		clients, err = bandwidthXrayClients(*inbound)
	}
	if err != nil {
		return nil, err
	}
	if proxy && len(clients) == 0 {
		// Empty HTTP account lists enable anonymous access in the core.
		return nil, nil
	}
	var authorizedAccounts map[string]string
	if appliesAutomaticPolicy {
		if err := policy.validateEffectiveUsers(clients); err != nil {
			return nil, err
		}
		authorizedAccounts, err = policy.filter(inbound, automaticAccounts)
		if err != nil {
			return nil, err
		}
		if policy.omitWhenEmpty && len(authorizedAccounts) == 0 {
			return nil, nil
		}
		clients = slices.DeleteFunc(clients, func(email string) bool {
			_, authorized := authorizedAccounts[email]
			return !authorized
		})
	}
	bindings := make(map[string]string, len(clients))
	for _, identity := range clients {
		if _, duplicate := bindings[identity]; duplicate || !validBandwidthXrayIdentity(identity) {
			return nil, errors.New("requires unique non-empty emails or usernames")
		}
		id, mappedProxy := proxyBindings[identity]
		ok := mappedProxy
		if appliesAutomaticPolicy {
			id, ok = authorizedAccounts[identity]
		} else if !mappedProxy {
			if id, ok = legacyAccountIDs[identity]; !ok {
				id, ok = resolveAccount(identity)
			}
		}
		if ((appliesAutomaticPolicy || mappedProxy) && ok && id == "") || (!ok && generatedPolicyInbound && allowUnmetered && !appliesAutomaticPolicy) {
			bindings[identity] = launch.UnmeteredXrayAccountID
			continue
		}
		if !ok || !validBandwidthXrayIdentity(id) {
			return nil, errors.New("has a client without a canonical account binding")
		}
		if !appliesAutomaticPolicy && !mappedProxy {
			legacyAccountIDs[identity] = id
		}
		bindings[identity] = id
	}
	return bindings, nil
}

func validBandwidthXrayIdentity(id string) bool {
	return len(id) > 0 && len(id) <= 256 && strings.TrimSpace(id) == id && strings.IndexFunc(id, unicode.IsControl) < 0
}

func cloneBandwidthXrayConfig(config *xray.Config) *xray.Config {
	result := *config
	result.InboundConfigs = slices.Clone(config.InboundConfigs)
	fields := []*json_util.RawMessage{
		&result.LogConfig, &result.RouterConfig, &result.DNSConfig, &result.OutboundConfigs,
		&result.Transport, &result.Policy, &result.API, &result.Stats, &result.Reverse,
		&result.FakeDNS, &result.Observatory, &result.BurstObservatory, &result.Metrics,
		&result.Geodata, &result.Env,
	}
	for _, field := range fields {
		*field = slices.Clone(*field)
	}
	for i := range result.InboundConfigs {
		inbound := &result.InboundConfigs[i]
		inbound.Listen = slices.Clone(inbound.Listen)
		inbound.Settings = slices.Clone(inbound.Settings)
		inbound.StreamSettings = slices.Clone(inbound.StreamSettings)
		inbound.Sniffing = slices.Clone(inbound.Sniffing)
	}
	return &result
}

func prepareBandwidthXrayAPI(config *xray.Config) (conf.APIConfig, error) {
	var api conf.APIConfig
	if jsonEmptyBandwidthXrayObject(config.API) {
		return api, nil
	}
	if json.Unmarshal(config.API, &api, json.RejectUnknownMembers(true)) != nil || api.Tag != "api" || api.Listen != "" {
		return conf.APIConfig{}, errors.New("managed Xray requires the default routed API endpoint")
	}
	services := api.Services[:0]
	seen := make(map[string]bool)
	for _, service := range api.Services {
		name := strings.ToLower(service)
		switch name {
		case "handlerservice", "routingservice":
			continue
		case "statsservice", "loggerservice", "reflectionservice", "observatoryservice":
			if !seen[name] {
				services = append(services, service)
				seen[name] = true
			}
		default:
			return conf.APIConfig{}, errors.New("unsupported managed Xray API service")
		}
	}
	api.Services = services
	return api, nil
}

func jsonEmptyBandwidthXrayValue(data []byte) bool {
	data = bytes.TrimSpace(data)
	return len(data) == 0 || bytes.Equal(data, []byte("null"))
}

func jsonEmptyBandwidthXrayObject(data []byte) bool {
	if jsonEmptyBandwidthXrayValue(data) {
		return true
	}
	var object map[string]jsontext.Value
	return json.Unmarshal(data, &object) == nil && len(object) == 0
}

func checkBandwidthXrayAPITunnel(config *xray.Config, inbound xray.InboundConfig, api conf.APIConfig) error {
	var listen string
	var settings struct {
		RewriteAddress string `json:"rewriteAddress"`
	}
	if api.Tag != "api" || inbound.Tag != "api" || inbound.Protocol != "tunnel" ||
		inbound.Port < 1 || inbound.Port > 65535 ||
		json.Unmarshal(inbound.Listen, &listen) != nil || listen != "127.0.0.1" ||
		json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil || settings.RewriteAddress != listen ||
		!jsonEmptyBandwidthXrayObject(inbound.StreamSettings) || !jsonEmptyBandwidthXrayObject(inbound.Sniffing) {
		return errors.New("managed Xray requires the default loopback API tunnel")
	}
	var routing conf.RouterConfig
	var route struct {
		Type        string   `json:"type"`
		InboundTags []string `json:"inboundTag"`
		OutboundTag string   `json:"outboundTag"`
	}
	if json.Unmarshal(config.RouterConfig, &routing, json.RejectUnknownMembers(true)) != nil || len(routing.RuleList) == 0 ||
		json.Unmarshal(routing.RuleList[0], &route, json.RejectUnknownMembers(true)) != nil ||
		route.Type != "field" || !slices.Equal(route.InboundTags, []string{inbound.Tag}) || route.OutboundTag != api.Tag {
		return errors.New("managed Xray API tunnel requires an unconditional first routing rule to the API service")
	}
	return nil
}

func validateBandwidthXrayTemplate(config *xray.Config, api conf.APIConfig) error {
	if !jsonEmptyBandwidthXrayObject(config.Reverse) || !jsonEmptyBandwidthXrayObject(config.Transport) || !jsonEmptyBandwidthXrayObject(config.Env) {
		return errors.New("managed Xray does not support reverse, global transport or environment configuration")
	}
	for _, section := range []json_util.RawMessage{config.RouterConfig, config.DNSConfig} {
		var options struct {
			Script string `json:"script"`
		}
		if !jsonEmptyBandwidthXrayValue(section) && (json.Unmarshal(section, &options, json.MatchCaseInsensitiveNames(true)) != nil || options.Script != "") {
			return errors.New("managed Xray does not support custom routing or DNS scripts")
		}
	}
	if !jsonEmptyBandwidthXrayValue(config.Metrics) {
		var metrics conf.MetricsConfig
		if json.Unmarshal(config.Metrics, &metrics, json.RejectUnknownMembers(true)) != nil || (api.Tag != "" && metrics.Tag == api.Tag) {
			return errors.New("invalid managed Xray metrics configuration")
		}
	}
	var outbounds []struct {
		Tag      string         `json:"tag"`
		Protocol string         `json:"protocol"`
		Settings jsontext.Value `json:"settings"`
	}
	if !jsonEmptyBandwidthXrayValue(config.OutboundConfigs) && json.Unmarshal(config.OutboundConfigs, &outbounds, json.MatchCaseInsensitiveNames(true)) != nil {
		return errors.New("invalid managed Xray outbounds")
	}
	for _, outbound := range outbounds {
		if api.Tag != "" && outbound.Tag == api.Tag {
			return errors.New("managed Xray API tag conflicts with an outbound")
		}
		if strings.EqualFold(outbound.Protocol, "vless") && !jsonEmptyBandwidthXrayValue(outbound.Settings) {
			var settings struct {
				Reverse jsontext.Value `json:"reverse"`
			}
			if json.Unmarshal(outbound.Settings, &settings, json.MatchCaseInsensitiveNames(true)) != nil || !jsonEmptyBandwidthXrayValue(settings.Reverse) {
				return errors.New("managed Xray does not support VLESS outbound reverse")
			}
		}
	}
	return nil
}

func bandwidthXrayClients(inbound xray.InboundConfig) ([]string, error) {
	stream, err := validateBandwidthXrayReceiver(inbound)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(inbound.Protocol) {
	case "vless":
		var settings conf.VLessInboundConfig
		if json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil ||
			settings.Decryption == "" || len(settings.Fallbacks) != 0 {
			return nil, errors.New("unsupported VLESS inbound settings")
		}
		vision := stream.visionTransport()
		if !allowedBandwidthVLESSFlow(settings.Flow, vision) {
			return nil, errors.New("VLESS Vision requires raw TCP with native TLS or REALITY")
		}
		emails, err := bandwidthXrayUserEmails(preferredBandwidthAccounts(settings.Users, settings.Clients), true, vision)
		if err != nil || settings.Decryption == "none" {
			return emails, err
		}
		return bandwidthEncryptedVLESSUsers(&settings, stream)
	case "vmess":
		var settings conf.VMessInboundConfig
		if !jsonEmptyBandwidthXrayValue(inbound.Settings) && json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil {
			return nil, errors.New("unsupported VMess inbound settings")
		}
		return bandwidthXrayUserEmails(preferredBandwidthAccounts(settings.Users, settings.Clients), false, false)
	case "hysteria":
		var settings conf.HysteriaServerConfig
		if json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil || settings.Version != 2 {
			return nil, errors.New("managed Hysteria requires version 2")
		}
		users := preferredBandwidthAccounts(settings.Users, settings.Clients)
		emails := make([]string, 0, len(users))
		for _, user := range users {
			// The native builder dereferences each user before the child
			// can run its typed credential checks.
			if user == nil || user.Auth == "" {
				return nil, errors.New("invalid managed Xray account")
			}
			emails = append(emails, user.Email)
		}
		return emails, nil
	case "trojan":
		var settings conf.TrojanServerConfig
		if json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil || len(settings.Fallbacks) != 0 {
			return nil, errors.New("managed Trojan does not support fallbacks or unknown settings")
		}
		users := preferredBandwidthAccounts(settings.Users, settings.Clients)
		emails := make([]string, 0, len(users))
		passwords := make(map[string]struct{}, len(users))
		for _, user := range users {
			if user == nil || user.Password == "" || user.Flow != "" {
				return nil, errors.New("managed Trojan requires password credentials without flow")
			}
			if _, duplicate := passwords[user.Password]; duplicate {
				return nil, errors.New("managed Trojan requires unique passwords")
			}
			passwords[user.Password] = struct{}{}
			emails = append(emails, user.Email)
		}
		return emails, nil
	case "shadowsocks":
		return bandwidthShadowsocksUsers(inbound.Settings, stream)
	case "http", "mixed":
		users, _, err := prepareBandwidthProxyAccounts(&inbound, nil)
		return users, err
	case "masque":
		var settings conf.MasqueServerConfig
		if json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil {
			return nil, errors.New("invalid managed MASQUE settings")
		}
		for _, user := range preferredBandwidthAccounts(settings.Users, settings.Clients) {
			if user == nil || user.Pass == "" {
				return nil, errors.New("managed MASQUE requires per-user credentials")
			}
		}
		built, err := settings.Build()
		if err != nil {
			return nil, errors.New("invalid managed MASQUE settings")
		}
		return nativeBandwidthEmails(built.(*masque.ServerConfig).Users), nil
	case "wireguard":
		var settings conf.WireGuardConfig
		if json.Unmarshal(inbound.Settings, &settings, json.RejectUnknownMembers(true)) != nil || settings.IsClient {
			return nil, errors.New("invalid managed WireGuard server settings")
		}
		for _, peer := range settings.Peers {
			if peer == nil {
				return nil, errors.New("managed WireGuard requires a public key for each peer")
			}
			key, err := conf.ParseWireGuardKey(peer.PublicKey)
			if err != nil || len(key) != 64 {
				return nil, errors.New("managed WireGuard requires a valid public key for each peer")
			}
		}
		built, err := settings.Build()
		if err != nil {
			return nil, errors.New("invalid managed WireGuard server settings")
		}
		return nativeBandwidthEmails(built.(*wireguard.DeviceConfig).Users), nil
	default:
		return nil, fmt.Errorf("unsupported traffic ingress protocol %q", inbound.Protocol)
	}
}

// Native builders prefer a non-nil override, including an empty list.
func preferredBandwidthAccounts[T any](accounts, override []T) []T {
	if override != nil {
		return override
	}
	return accounts
}

func nativeBandwidthEmails(users []*protocol.User) []string {
	emails := make([]string, 0, len(users))
	for _, user := range users {
		emails = append(emails, user.GetEmail())
	}
	return emails
}

func allowedBandwidthVLESSFlow(flow string, visionTLS bool) bool {
	return flow == "" || (flow == "xtls-rprx-vision" && visionTLS)
}

func bandwidthEncryptedVLESSUsers(settings *conf.VLessInboundConfig, stream *bandwidthXrayStream) ([]string, error) {
	if !strings.EqualFold(stream.Security, "reality") || !stream.rawTCPWithoutHeader() {
		return nil, errors.New("managed VLESS encryption requires REALITY over raw TCP")
	}
	// Use the pinned native.600s mode with one X25519 server key. Validate the
	// shape first because the native builder interprets short fields as padding.
	fields := strings.Split(settings.Decryption, ".")
	invalid := errors.New("invalid managed VLESS encryption configuration")
	if len(fields) != 4 || fields[0] != "mlkem768x25519plus" || fields[1] != "native" || fields[2] != "600s" ||
		len(fields[3]) != base64.RawURLEncoding.EncodedLen(32) {
		return nil, invalid
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(fields[3])
	if err != nil || len(key) != 32 {
		return nil, invalid
	}
	built, err := settings.Build()
	if err != nil {
		return nil, invalid
	}
	native := built.(*vlessinbound.Config)
	for _, user := range native.Users {
		message, err := user.GetAccount().GetInstance()
		account, ok := message.(*vless.Account)
		if err != nil || !ok || account.Reverse != nil {
			return nil, invalid
		}
		if account.Flow != vless.XRV {
			return nil, errors.New("managed VLESS encryption requires Vision flow for each account")
		}
	}
	return nativeBandwidthEmails(native.Users), nil
}

func bandwidthXrayUserEmails(users []stdjson.RawMessage, vless, visionTLS bool) ([]string, error) {
	emails := make([]string, 0, len(users))
	for _, raw := range users {
		var account struct {
			Email   string             `json:"email"`
			ID      string             `json:"id"`
			Flow    string             `json:"flow"`
			Reverse stdjson.RawMessage `json:"reverse"`
		}
		// Match the native builders' exact field resolution, which uses v1.
		if stdjson.Unmarshal(raw, &account) != nil ||
			account.ID == "" || (vless && (!allowedBandwidthVLESSFlow(account.Flow, visionTLS) || !jsonEmptyBandwidthXrayValue(account.Reverse))) {
			return nil, errors.New("unsupported or invalid managed Xray account")
		}
		// The child validates credential types and duplicate native account
		// identities before it creates or starts the core.
		emails = append(emails, account.Email)
	}
	return emails, nil
}

func bandwidthShadowsocksUsers(raw []byte, stream *bandwidthXrayStream) ([]string, error) {
	var settings conf.ShadowsocksServerConfig
	if json.Unmarshal(raw, &settings, json.RejectUnknownMembers(true)) != nil {
		return nil, errors.New("invalid managed Shadowsocks settings")
	}
	users := preferredBandwidthAccounts(settings.Users, settings.Clients)
	for _, user := range users {
		if user == nil || user.Password == "" {
			return nil, errors.New("managed Shadowsocks requires password credentials")
		}
		if user.Address != nil || user.Port != 0 {
			return nil, errors.New("managed Shadowsocks 2022 does not support relay destinations")
		}
	}
	built, err := settings.Build()
	if err != nil {
		return nil, errors.New("invalid managed Shadowsocks settings")
	}
	switch native := built.(type) {
	case *shadowsocks.ServerConfig:
		return nativeBandwidthEmails(native.Users), nil
	case *ss2022.ServerConfig:
		if stream.network() != "tcp" {
			return nil, errors.New("managed Shadowsocks 2022 requires raw transport")
		}
		if _, err := bandwidthSS2022Key(native.Method, native.Key); err != nil {
			return nil, err
		}
		return []string{native.Email}, nil
	case *ss2022.MultiUserServerConfig:
		if stream.network() != "tcp" || slices.ContainsFunc(native.Network, func(network xnet.Network) bool {
			return network != xnet.Network_TCP && network != xnet.Network_UDP
		}) {
			return nil, errors.New("managed multi-user Shadowsocks 2022 requires raw transport and TCP or UDP network")
		}
		master, err := bandwidthSS2022Key(native.Method, native.Key)
		if err != nil {
			return nil, err
		}
		for _, user := range users {
			key, err := bandwidthSS2022Key(native.Method, user.Password)
			if err != nil || bytes.Equal(key, master) {
				return nil, errors.New("managed Shadowsocks 2022 requires a valid user key distinct from the server key")
			}
		}
		return nativeBandwidthEmails(native.Users), nil
	default:
		return nil, errors.New("managed Shadowsocks 2022 does not support relay destinations")
	}
}

func bandwidthSS2022Key(methodName, key string) ([]byte, error) {
	method, err := ss2022.GetCipherMethod(methodName)
	if err != nil {
		return nil, errors.New("invalid managed Shadowsocks 2022 method")
	}
	decoded, err := ss2022.ParseKey(key, method.KeySaltLength)
	if err != nil {
		return nil, errors.New("invalid managed Shadowsocks 2022 key")
	}
	return decoded, nil
}

type bandwidthXrayStream struct {
	Method      *string                 `json:"method"`
	Network     *string                 `json:"network"`
	Security    string                  `json:"security"`
	TLS         *conf.TLSConfig         `json:"tlsSettings"`
	REALITY     jsontext.Value          `json:"realitySettings"`
	Raw         *conf.TCPConfig         `json:"rawSettings"`
	TCP         *conf.TCPConfig         `json:"tcpSettings"`
	WebSocket   *conf.WebSocketConfig   `json:"wsSettings"`
	GRPC        *conf.GRPCConfig        `json:"grpcSettings"`
	HTTPUpgrade *conf.HttpUpgradeConfig `json:"httpupgradeSettings"`
	Hysteria    *conf.HysteriaConfig    `json:"hysteriaSettings"`
	MASQUE      *conf.MasqueConfig      `json:"masqueSettings"`
	Socket      *conf.SocketConfig      `json:"sockopt"`
}

func (s *bandwidthXrayStream) network() string {
	network := s.Network
	if s.Method != nil {
		network = s.Method
	}
	if network == nil || strings.EqualFold(*network, "raw") {
		return "tcp"
	}
	return strings.ToLower(*network)
}

func (s *bandwidthXrayStream) visionTransport() bool {
	security := strings.ToLower(s.Security)
	return (security == "tls" || security == "reality") && s.rawTCPWithoutHeader()
}

func (s *bandwidthXrayStream) rawTCPWithoutHeader() bool {
	if s.network() != "tcp" {
		return false
	}
	tcp := s.TCP
	if s.Raw != nil {
		tcp = s.Raw
	}
	if tcp == nil || len(tcp.HeaderConfig) == 0 {
		return true
	}
	var header struct {
		Type string `json:"type"`
	}
	return stdjson.Unmarshal(tcp.HeaderConfig, &header) == nil && strings.EqualFold(header.Type, "none")
}

func validateBandwidthXrayReceiver(inbound xray.InboundConfig) (*bandwidthXrayStream, error) {
	if inbound.Port < 1 || inbound.Port > 65535 {
		return nil, errors.New("managed Xray requires a valid listen port")
	}
	if !jsonEmptyBandwidthXrayValue(inbound.Listen) {
		var listen string
		if json.Unmarshal(inbound.Listen, &listen) != nil {
			return nil, errors.New("invalid managed Xray listen address")
		}
		if _, err := netip.ParseAddr(listen); err != nil && listen != "" && listen != "localhost" {
			return nil, errors.New("managed Xray requires an IP listen address")
		}
	}
	var stream bandwidthXrayStream
	if !jsonEmptyBandwidthXrayValue(inbound.StreamSettings) && json.Unmarshal(inbound.StreamSettings, &stream, json.RejectUnknownMembers(true)) != nil {
		return nil, errors.New("unsupported managed Xray stream configuration")
	}
	security := strings.ToLower(stream.Security)
	switch security {
	case "", "none", "tls":
	case "reality":
		if !strings.EqualFold(inbound.Protocol, "vless") || !stream.rawTCPWithoutHeader() ||
			jsonEmptyBandwidthXrayValue(stream.REALITY) {
			return nil, errors.New("managed Xray REALITY requires VLESS over raw TCP with server settings")
		}
		// REALITY's native decoder accepts panel field casing such as maxTimediff
		// and limitFallbackUpload.afterBytes. Keep unknown fields rejected.
		var realitySettings conf.REALITYConfig
		if json.Unmarshal(stream.REALITY, &realitySettings, json.RejectUnknownMembers(true),
			json.MatchCaseInsensitiveNames(true), stdjson.MatchCaseSensitiveDelimiter(true)) != nil ||
			(realitySettings.Target == nil && realitySettings.Dest == nil) {
			return nil, errors.New("invalid managed Xray REALITY server settings")
		}
		settings, err := realitySettings.Build()
		config, ok := settings.(*reality.Config)
		if err != nil || !ok || !xraybandwidthcore.ValidManagedREALITYServer(config) {
			return nil, errors.New("invalid managed Xray REALITY server settings")
		}
	default:
		return nil, errors.New("unsupported managed Xray stream security")
	}
	if stream.Socket != nil {
		tproxy := strings.ToLower(stream.Socket.TProxy)
		if (tproxy != "" && tproxy != "off") || len(stream.Socket.CustomSockopt) != 0 {
			return nil, errors.New("managed Xray does not support transparent reception or custom socket options")
		}
	}
	network := stream.network()
	switch strings.ToLower(inbound.Protocol) {
	case "hysteria":
		h := stream.Hysteria
		if network != "hysteria" || security != "tls" || h == nil || h.Version != 2 ||
			h.Auth != "" || h.Masquerade.Type != "" || (h.UdpIdleTimeout != 0 && (h.UdpIdleTimeout < 2 || h.UdpIdleTimeout > 600)) {
			return nil, errors.New("managed Hysteria requires Hysteria v2 over TLS with per-user auth and no masquerade")
		}
	case "masque":
		m := stream.MASQUE
		if network != "masque" || security != "tls" || (m != nil && (m.User != "" || m.Pass != "" || m.Warp != nil)) {
			return nil, errors.New("managed MASQUE requires HTTP/3 over TLS with per-user auth")
		}
	case "wireguard":
		if network != "tcp" || (security != "" && security != "none") {
			return nil, errors.New("managed WireGuard requires its native UDP listener without a stream wrapper")
		}
	default:
		switch network {
		case "tcp", "ws", "websocket", "grpc", "httpupgrade":
		default:
			return nil, errors.New("unsupported managed Xray transport")
		}
	}
	return &stream, nil
}
