package xraybandwidthchild

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/proxyman"
	handlercommand "github.com/xtls/xray-core/app/proxyman/command"
	routingcommand "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/wireguard"
	grpctransport "github.com/xtls/xray-core/transport/internet/grpc"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"golang.org/x/text/cases"
)

const (
	protocolVLESS     = "vless"
	protocolHysteria  = "hysteria"
	protocolVMess     = "vmess"
	protocolTrojan    = "trojan"
	protocolSS        = "shadowsocks"
	protocolSS2022    = "shadowsocks-2022"
	protocolSSMulti   = "shadowsocks-2022-multi"
	protocolMASQUE    = "masque"
	protocolWireGuard = "wireguard"
)

type binding struct {
	protocol  string
	alternate string
	static    bool
	sidecar   bool
	clients   map[string]boundClient
}

type boundClient struct {
	id         string
	credential string
}

type bindings map[string]binding

func (b bindings) resolve(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return "", false, nil
	}
	bound, managed := b[inbound.Tag]
	if !managed {
		return "", false, nil
	}
	if bound.sidecar {
		if user != nil && inbound.Name == "socks" && inbound.Source.Address != nil &&
			inbound.Source.Address.Family().IsIP() && inbound.Source.Address.IP().IsLoopback() {
			if _, known := bound.clients[user.Email]; known {
				// The sidecar authenticated and metered this flow before sending
				// it to the private SOCKS handler.
				return "", false, nil
			}
		}
		return "", true, errors.New("sidecar relay requires a known authenticated loopback SOCKS account")
	}
	if user != nil && (inbound.Name == bound.protocol || (bound.alternate != "" && inbound.Name == bound.alternate)) {
		client, known := bound.clients[user.Email]
		if known {
			if bound.static && user.Account == nil {
				return client.id, true, nil
			}
			protocol, credential := accountIdentity(user.Account)
			if !bound.static && protocol == bound.protocol && credential == client.credential {
				if client.id == launch.UnmeteredXrayAccountID && bound.protocol != protocolWireGuard {
					return "", false, nil
				}
				return client.id, true, nil
			}
		}
	}
	return "", true, errors.New("managed Xray inbound requires a known authenticated account")
}

func accountIdentity(account protocol.Account) (string, string) {
	switch a := account.(type) {
	case *vless.MemoryAccount:
		if a != nil && a.ID != nil {
			id := vless.ProcessUUID(a.ID.UUID())
			return protocolVLESS, string(id[:])
		}
	case *hyaccount.MemoryAccount:
		if a != nil && a.Auth != "" {
			if id, err := uuid.Parse(a.Auth); err == nil {
				canonical := vless.ProcessUUID(id)
				return protocolHysteria, "uuid:" + string(canonical[:])
			}
			return protocolHysteria, "auth:" + a.Auth
		}
	case *masque.MemoryAccount:
		if a != nil && a.Password != "" {
			return protocolMASQUE, a.Password
		}
	case *wireguard.MemoryAccount:
		if a != nil && a.Pub != ([32]byte{}) {
			var shared [32]byte
			if a.PreSharedKey != "" {
				key, err := wireguard.ParseKey(a.PreSharedKey)
				if err != nil {
					return "", ""
				}
				shared = *key
			}
			return protocolWireGuard, string(a.Pub[:]) + string(shared[:])
		}
	default:
		return xraybandwidthcore.TypedAccountIdentity(account)
	}
	return "", ""
}

func bindClients(config *core.Config, clientsByTag map[string]map[string]string, generatedTags map[string]bool) (bindings, xraybandwidthcore.ManagedInboundTags, error) {
	return bindClientInventory(config, clientsByTag, generatedTags, true)
}

// ValidateManagedInbound applies the child's account binding checks to a single native inbound.
// Runtime callers also require the patched native capabilities used by the child.
func ValidateManagedInbound(inbound *core.InboundHandlerConfig, clients map[string]string, generated, requireRuntimeCapabilities bool) error {
	tag := inbound.GetTag()
	var generatedTags map[string]bool
	if generated {
		generatedTags = map[string]bool{tag: true}
	}
	config := &core.Config{Inbound: []*core.InboundHandlerConfig{inbound}}
	_, _, err := bindClientInventory(config, map[string]map[string]string{tag: clients}, generatedTags, requireRuntimeCapabilities)
	return err
}

func bindClientInventory(config *core.Config, clientsByTag map[string]map[string]string, generatedTags map[string]bool, requireRuntimeCapabilities bool) (bindings, xraybandwidthcore.ManagedInboundTags, error) {
	var guarded xraybandwidthcore.ManagedInboundTags
	if err := validateAPI(config); err != nil {
		return nil, guarded, err
	}
	for tag, generated := range generatedTags {
		if !generated || clientsByTag[tag] == nil {
			return nil, guarded, errors.New("invalid generated Xray account inventory")
		}
	}
	bound := make(bindings, len(clientsByTag))
	for _, inbound := range config.Inbound {
		tag := inbound.GetTag()
		clients, selected := clientsByTag[tag]
		if !selected {
			continue
		}
		if tag == "" || clients == nil {
			return nil, guarded, errors.New("invalid managed Xray inbound binding")
		}
		if _, exists := bound[tag]; exists {
			return nil, guarded, fmt.Errorf("duplicate managed Xray inbound tag %q", tag)
		}
		if err := validateGRPCTransport(inbound, requireRuntimeCapabilities); err != nil {
			return nil, guarded, fmt.Errorf("managed Xray inbound %q: %w", tag, err)
		}
		settings := inbound.GetProxySettings()
		if settings == nil {
			return nil, guarded, fmt.Errorf("managed Xray inbound %q is missing proxy settings", tag)
		}
		proxy, err := settings.GetInstance()
		if err != nil {
			return nil, guarded, fmt.Errorf("decode managed Xray inbound %q: %w", tag, err)
		}
		var selectedBinding binding
		var users []*protocol.User
		var staticAccounts map[string]string
		switch proxy := proxy.(type) {
		case *vlessinbound.Config:
			selectedBinding.protocol, users = protocolVLESS, proxy.Users
			guarded.VLESS = append(guarded.VLESS, tag)
		case *hysteria.ServerConfig:
			selectedBinding.protocol, users = protocolHysteria, proxy.Users
			if err := validateHysteriaTransport(inbound); err != nil {
				return nil, guarded, fmt.Errorf("managed Xray inbound %q: %w", tag, err)
			}
			guarded.Hysteria = append(guarded.Hysteria, tag)
		case *vmessinbound.Config:
			selectedBinding.protocol, users = protocolVMess, proxy.User
			guarded.VMess = append(guarded.VMess, tag)
		case *trojan.ServerConfig:
			selectedBinding.protocol, users = protocolTrojan, proxy.Users
			guarded.Trojan = append(guarded.Trojan, tag)
		case *shadowsocks.ServerConfig:
			selectedBinding.protocol, users = protocolSS, proxy.Users
			guarded.Shadowsocks = append(guarded.Shadowsocks, tag)
		case *httpproxy.ServerConfig:
			selectedBinding.protocol, selectedBinding.static, staticAccounts = "http", true, proxy.Accounts
			guarded.HTTP = append(guarded.HTTP, tag)
		case *socks.ServerConfig:
			selectedBinding.protocol, selectedBinding.alternate, selectedBinding.static = "socks", "http", true
			staticAccounts = proxy.Accounts
			guarded.Mixed = append(guarded.Mixed, tag)
		case *ss2022.ServerConfig:
			selectedBinding.protocol, selectedBinding.static = protocolSS2022, true
			staticAccounts = map[string]string{proxy.Email: ""}
			guarded.Shadowsocks2022 = append(guarded.Shadowsocks2022, tag)
		case *ss2022.MultiUserServerConfig:
			selectedBinding.protocol, users = protocolSSMulti, proxy.Users
			guarded.Shadowsocks2022Multi = append(guarded.Shadowsocks2022Multi, tag)
		case *masque.ServerConfig:
			if requireRuntimeCapabilities && !hasNativeMASQUEPacketGate() {
				return nil, guarded, fmt.Errorf("managed Xray inbound %q requires the patched native MASQUE packet gate", tag)
			}
			selectedBinding.protocol, users = protocolMASQUE, proxy.Users
		case *wireguard.DeviceConfig:
			if requireRuntimeCapabilities && !hasNativeWireGuardPacketGate() {
				return nil, guarded, fmt.Errorf("managed Xray inbound %q requires the patched native WireGuard packet gate", tag)
			}
			selectedBinding.protocol, users = protocolWireGuard, proxy.Users
		default:
			return nil, guarded, fmt.Errorf("unsupported managed Xray protocol for inbound %q", tag)
		}
		if selectedBinding.static {
			generated := generatedTags[tag]
			if generated && selectedBinding.protocol != "http" && selectedBinding.protocol != "socks" {
				return nil, guarded, errors.New("generated Xray bandwidth policy requires native client credentials")
			}
			accounts := make(map[string]string, len(staticAccounts))
			for username := range staticAccounts {
				if username != "" {
					accounts[username] = ""
				}
			}
			if generated && len(accounts) != len(clients) {
				return nil, guarded, errors.New("generated Xray accounts require complete native bindings")
			}
			selectedBinding.clients, err = bindKnownAccounts(accounts, clients, generated)
		} else {
			selectedBinding.clients, err = bindAccounts(selectedBinding.protocol, users, clients, generatedTags[tag])
		}
		if err != nil {
			return nil, guarded, fmt.Errorf("bind managed Xray inbound %q: %w", tag, err)
		}
		bound[tag] = selectedBinding
	}
	if len(bound) != len(clientsByTag) {
		return nil, guarded, errors.New("metered Xray handshake references an unknown inbound tag")
	}
	return bound, guarded, nil
}

func validateAPI(config *core.Config) error {
	commanderType := serial.GetMessageType(&commander.Config{})
	handlerType := serial.GetMessageType(&handlercommand.Config{})
	routingType := serial.GetMessageType(&routingcommand.Config{})
	for _, app := range config.App {
		if app.GetType() != commanderType {
			continue
		}
		settings, err := app.GetInstance()
		if err != nil {
			return fmt.Errorf("decode Xray API configuration: %w", err)
		}
		for _, service := range settings.(*commander.Config).Service {
			switch service.GetType() {
			case handlerType:
				return errors.New("metered Xray does not support HandlerService because it can replace managed inbounds")
			case routingType:
				return errors.New("metered Xray does not support RoutingService because it can replace the management tunnel route")
			}
		}
	}
	return nil
}

func hasNativeSynchronousGRPCListen() bool {
	_, ok := any(&grpctransport.Config{}).(interface{ VanillaProxySynchronousGRPCListenV1() })
	return ok
}

func validateGRPCTransport(inbound *core.InboundHandlerConfig, requireRuntimeCapabilities bool) error {
	settings := inbound.GetReceiverSettings()
	if settings.GetType() != serial.GetMessageType(&proxyman.ReceiverConfig{}) {
		return nil
	}
	receiver, err := settings.GetInstance()
	if err != nil {
		return fmt.Errorf("decode Xray receiver: %w", err)
	}
	stream := receiver.(*proxyman.ReceiverConfig).GetStreamSettings()
	if requireRuntimeCapabilities && stream.GetEffectiveProtocol() == "grpc" && !hasNativeSynchronousGRPCListen() {
		return errors.New("managed gRPC requires patched synchronous Xray listen")
	}
	return nil
}

func validateHysteriaTransport(inbound *core.InboundHandlerConfig) error {
	receiverType := serial.GetMessageType(&proxyman.ReceiverConfig{})
	settings := inbound.GetReceiverSettings()
	if settings.GetType() != receiverType {
		return errors.New("managed Hysteria requires a native Xray receiver")
	}
	receiver, err := settings.GetInstance()
	if err != nil {
		return fmt.Errorf("decode Hysteria receiver: %w", err)
	}
	stream := receiver.(*proxyman.ReceiverConfig).GetStreamSettings()
	if stream.GetEffectiveProtocol() != protocolHysteria {
		return errors.New("managed Hysteria requires Hysteria v2 transport")
	}
	transport, err := stream.GetEffectiveTransportSettings()
	if err != nil {
		return fmt.Errorf("decode Hysteria transport: %w", err)
	}
	native, ok := transport.(*hytransport.Config)
	if !ok || native.Auth != "" || strings.EqualFold(native.MasqType, "proxy") {
		return errors.New("managed Hysteria requires per-user auth and must not proxy masquerade requests")
	}
	return nil
}

func bindAccounts(protocolName string, users []*protocol.User, clients map[string]string, generated bool) (map[string]boundClient, error) {
	emailKeys := make(map[string]bool, len(users))
	credentials := make(map[string]bool, len(users))
	accounts := make(map[string]string, len(users))
	fold := cases.Fold()
	for _, user := range users {
		email := fold.String(user.GetEmail())
		switch protocolName {
		case protocolWireGuard:
			email = user.GetEmail()
		case protocolMASQUE:
			// MASQUE authenticates by case-normalized username and password.
			// The native user record preserves the configured email spelling.
			email = strings.ToLower(user.GetEmail())
			if strings.Contains(email, ":") {
				return nil, errors.New("configured MASQUE usernames cannot contain a colon")
			}
			if user.GetAccount().GetType() != serial.GetMessageType(&masque.Account{}) {
				return nil, errors.New("configured MASQUE users require native credentials")
			}
		}
		if email == "" || emailKeys[email] {
			return nil, errors.New("configured accounts must have unique non-empty emails")
		}
		memory, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("invalid configured credentials")
		}
		protocol, credential := accountIdentity(memory.Account)
		if protocol != protocolName {
			return nil, errors.New("invalid configured credentials")
		}
		if protocolName != protocolMASQUE {
			if credentials[credential] {
				return nil, errors.New("duplicate configured credentials")
			}
			credentials[credential] = true
		}
		emailKeys[email] = true
		accounts[user.Email] = credential
	}
	if generated && len(accounts) != len(clients) {
		return nil, errors.New("generated Xray accounts require complete native bindings")
	}
	return bindKnownAccounts(accounts, clients, generated)
}

func bindKnownAccounts(accounts, clients map[string]string, allowUnmetered bool) (map[string]boundClient, error) {
	bound := make(map[string]boundClient, len(clients))
	for email, id := range clients {
		credential, exists := accounts[email]
		if !exists {
			return nil, errors.New("handshake references an unknown authenticated email")
		}
		if !(allowUnmetered && id == launch.UnmeteredXrayAccountID) &&
			(len(id) == 0 || len(id) > 256 || strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0) {
			return nil, errors.New("invalid canonical client ID")
		}
		bound[email] = boundClient{id: id, credential: credential}
	}
	return bound, nil
}
