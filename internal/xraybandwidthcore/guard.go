package xraybandwidthcore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	stdnet "net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidth"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type managedInboundsKey struct{}
type managedInbound struct {
	proxy    proto.Message
	hysteria *hysteriaListenConfig
	vision   bool
}
type managedInboundConfigs map[string]managedInbound

func init() {
	// The pinned Xray distribution has no factory for BytesValue. The marker
	// carries the tag and can only resolve a config authorized by this constructor.
	common.Must(common.RegisterConfig((*wrapperspb.BytesValue)(nil), newGuardedInbound))
}

func newGuardedInbound(ctx context.Context, settings any) (any, error) {
	marker := settings.(*wrapperspb.BytesValue)
	tag := string(marker.GetValue())
	inbound := session.InboundFromContext(ctx)
	configs, _ := ctx.Value(managedInboundsKey{}).(managedInboundConfigs)
	config := configs[tag]
	if tag == "" || inbound == nil || inbound.Tag != tag || config.proxy == nil {
		return nil, errors.New("invalid internal managed inbound marker")
	}

	if config.hysteria != nil {
		return newGuardedHysteria(ctx, config)
	}
	native, err := common.CreateObject(ctx, config.proxy)
	if err != nil {
		return nil, err
	}
	if _, vless := config.proxy.(*vlessinbound.Config); vless {
		handler, ok := native.(*vlessinbound.Handler)
		if !ok {
			return nil, errors.New("Xray VLESS factory returned an unexpected type")
		}
		options, _ := ctx.Value(dispatcherOptionsKey{}).(dispatcherOptions)
		return &guardedVLESS{
			Handler:  handler,
			vision:   config.vision,
			allowMux: allowExemptVLESSMux(tag, options.resolve),
		}, nil
	}
	switch config.proxy.(type) {
	case *httpproxy.ServerConfig, *socks.ServerConfig, *ss2022.ServerConfig:
		return newGuardedStatic(native, config.proxy)
	default:
		return newGuardedLegacy(native, config.proxy)
	}
}

// guardInbounds replaces selected proxy settings on the constructor's
// private config copy. Keep stock handlers and settings for the other inbounds.
func guardInbounds(config *core.Config, tags ManagedInboundTags) (managedInboundConfigs, error) {
	markerType := serial.GetMessageType(&wrapperspb.BytesValue{})
	vlessType := serial.GetMessageType(&vlessinbound.Config{})
	hysteriaType := serial.GetMessageType(&hysteria.ServerConfig{})
	selected := make(map[string]string)
	for _, protocol := range []struct {
		proxyType string
		tags      []string
	}{
		{vlessType, tags.VLESS},
		{hysteriaType, tags.Hysteria},
		{serial.GetMessageType(&vmessinbound.Config{}), tags.VMess},
		{serial.GetMessageType(&trojan.ServerConfig{}), tags.Trojan},
		{serial.GetMessageType(&shadowsocks.ServerConfig{}), tags.Shadowsocks},
		{serial.GetMessageType(&httpproxy.ServerConfig{}), tags.HTTP},
		{serial.GetMessageType(&socks.ServerConfig{}), tags.Mixed},
		{serial.GetMessageType(&ss2022.ServerConfig{}), tags.Shadowsocks2022},
		{serial.GetMessageType(&ss2022.MultiUserServerConfig{}), tags.Shadowsocks2022Multi},
	} {
		for _, tag := range protocol.tags {
			if tag == "" {
				return nil, errors.New("managed inbound tag must not be empty")
			}
			if _, exists := selected[tag]; exists {
				return nil, fmt.Errorf("duplicate managed inbound tag %q", tag)
			}
			selected[tag] = protocol.proxyType
		}
	}

	configs := make(managedInboundConfigs, len(selected))
	for _, inbound := range config.Inbound {
		tag := inbound.GetTag()
		settings := inbound.GetProxySettings()
		if settings.GetType() == markerType {
			return nil, errors.New("Xray configuration contains the internal managed inbound marker")
		}
		proxyType, managed := selected[tag]
		if !managed {
			continue
		}
		if _, exists := configs[tag]; exists {
			return nil, fmt.Errorf("multiple Xray inbounds have managed tag %q", tag)
		}
		var guarded managedInbound
		var err error
		switch proxyType {
		case hysteriaType:
			guarded, err = parseManagedHysteria(inbound)
		case vlessType:
			guarded, err = parseManagedVLESS(inbound)
		default:
			guarded.proxy, err = parseManagedProxy(settings, proxyType)
		}
		if err != nil {
			return nil, fmt.Errorf("managed Xray inbound %q: %w", tag, err)
		}
		configs[tag] = guarded
		inbound.ProxySettings = serial.ToTypedMessage(wrapperspb.Bytes([]byte(tag)))
	}
	for tag := range selected {
		if _, exists := configs[tag]; !exists {
			return nil, fmt.Errorf("managed inbound %q was not found", tag)
		}
	}
	return configs, nil
}

func parseManagedVLESS(inbound *core.InboundHandlerConfig) (managedInbound, error) {
	settings := inbound.GetProxySettings()
	if settings.GetType() != serial.GetMessageType(&vlessinbound.Config{}) {
		return managedInbound{}, errors.New("requires VLESS proxy settings")
	}
	native := new(vlessinbound.Config)
	if err := proto.Unmarshal(settings.GetValue(), native); err != nil {
		return managedInbound{}, fmt.Errorf("decode managed VLESS inbound: %w", err)
	}
	if len(native.Fallbacks) != 0 {
		return managedInbound{}, errors.New("managed VLESS does not support fallbacks")
	}
	stream, err := managedVLESSStream(inbound.GetReceiverSettings())
	if err != nil {
		return managedInbound{}, err
	}
	vision := managedVLESSVisionTransport(stream)
	if native.Decryption != "" && native.Decryption != "none" {
		if stream.GetSecurityType() == serial.GetMessageType(&reality.Config{}) {
			// The pinned builder stores the decoded mode, duration, and padding
			// separately from the base64url authentication key.
			key, err := base64.RawURLEncoding.DecodeString(native.Decryption)
			if err != nil || len(key) != 32 || native.XorMode != 0 || native.SecondsFrom != 600 || native.SecondsTo != 0 || native.Padding != "" {
				return managedInbound{}, errors.New("managed VLESS REALITY requires native.600s encryption with one X25519 key and default padding")
			}
		} else {
			vision = false
		}
	}
	accountType := serial.GetMessageType(&vless.Account{})
	for index, user := range native.Users {
		settings := user.GetAccount()
		if settings.GetType() != accountType {
			return managedInbound{}, fmt.Errorf("user %d requires VLESS credentials", index)
		}
		var account vless.Account
		if err := proto.Unmarshal(settings.GetValue(), &account); err != nil {
			return managedInbound{}, fmt.Errorf("decode VLESS user %d: %w", index, err)
		}
		if err := validateManagedVLESSAccount(account.Flow, account.Reverse, vision); err != nil {
			return managedInbound{}, fmt.Errorf("VLESS user %d: %w", index, err)
		}
	}
	return managedInbound{proxy: native, vision: vision}, nil
}

func managedVLESSStream(settings *serial.TypedMessage) (*internet.StreamConfig, error) {
	if settings.GetType() != serial.GetMessageType(&proxyman.ReceiverConfig{}) {
		return nil, nil
	}
	var receiver proxyman.ReceiverConfig
	if proto.Unmarshal(settings.GetValue(), &receiver) != nil {
		return nil, errors.New("invalid managed VLESS receiver")
	}
	stream := receiver.GetStreamSettings()
	if stream.GetSecurityType() == serial.GetMessageType(&reality.Config{}) {
		security, err := managedVLESSSecurity(stream)
		config, ok := security.(*reality.Config)
		if err != nil || !ok || !validManagedVLESSRawTCP(stream) || !ValidManagedREALITYServer(config) {
			return nil, errors.New("managed VLESS REALITY requires raw TCP and valid server settings")
		}
	}
	return stream, nil
}

func managedVLESSSecurity(stream *internet.StreamConfig) (any, error) {
	for _, settings := range stream.GetSecuritySettings() {
		if settings.GetType() == stream.GetSecurityType() {
			return settings.GetInstance()
		}
	}
	return nil, errors.New("missing managed VLESS security settings")
}

// ValidManagedREALITYServer validates the server settings used by the panel and
// by the managed Xray receiver before the native listener uses them.
func ValidManagedREALITYServer(config *reality.Config) bool {
	if config == nil || config.Type != "tcp" || config.Xver > 2 ||
		len(config.PrivateKey) != 32 || len(config.ServerNames) == 0 || len(config.ShortIds) == 0 {
		return false
	}
	host, port, err := stdnet.SplitHostPort(config.Dest)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n") || portErr != nil || number == 0 {
		return false
	}
	for _, name := range config.ServerNames {
		if name == "" {
			return false
		}
	}
	for _, id := range config.ShortIds {
		if len(id) != 8 {
			return false
		}
	}
	return len(config.Mldsa65Seed) == 0 ||
		(len(config.Mldsa65Seed) == 32 && !bytes.Equal(config.Mldsa65Seed, config.PrivateKey))
}

func validManagedVLESSRawTCP(stream *internet.StreamConfig) bool {
	if stream.GetEffectiveProtocol() != "tcp" || len(stream.GetTcpmasks()) != 0 {
		return false
	}
	transport, err := stream.GetEffectiveTransportSettings()
	raw, ok := transport.(*tcp.Config)
	if err != nil || !ok {
		return false
	}
	if header := raw.GetHeaderSettings(); header != nil {
		if header.GetType() != serial.GetMessageType(&noop.ConnectionConfig{}) ||
			proto.Unmarshal(header.GetValue(), &noop.ConnectionConfig{}) != nil {
			return false
		}
	}
	return true
}

func managedVLESSVisionTransport(stream *internet.StreamConfig) bool {
	switch stream.GetSecurityType() {
	case serial.GetMessageType(&reality.Config{}):
		// managedVLESSStream already validates the effective REALITY receiver.
		return true
	case serial.GetMessageType(&tls.Config{}):
		security, err := managedVLESSSecurity(stream)
		_, ok := security.(*tls.Config)
		return err == nil && ok && validManagedVLESSRawTCP(stream)
	default:
		return false
	}
}

func validateManagedVLESSAccount(flow string, reverse *vless.Reverse, vision bool) error {
	if reverse != nil {
		return errors.New("reverse credentials are unsupported")
	}
	switch flow {
	case "":
		return nil
	case vless.XRV:
		if vision {
			return nil
		}
		return errors.New("VLESS Vision flow requires raw TCP with native TLS or REALITY. Managed Vision with VLESS encryption requires REALITY")
	default:
		return errors.New("unsupported VLESS flow")
	}
}

type guardedVLESS struct {
	*vlessinbound.Handler
	vision   bool
	allowMux func(context.Context) bool
}

var (
	_ proxy.Inbound     = (*guardedVLESS)(nil)
	_ proxy.UserManager = (*guardedVLESS)(nil)
	_ common.Closable   = (*guardedVLESS)(nil)
)

func (h *guardedVLESS) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if user == nil {
		return errors.New("managed VLESS requires a user")
	}
	account, ok := user.Account.(*vless.MemoryAccount)
	if !ok || account == nil || account.ID == nil {
		return errors.New("managed VLESS requires VLESS credentials")
	}
	if err := validateManagedVLESSAccount(account.Flow, account.Reverse, h.vision); err != nil {
		return err
	}
	return h.Handler.AddUser(ctx, user)
}

func (h *guardedVLESS) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatch routing.Dispatcher) error {
	return h.Handler.Process(ctx, network, conn, guardMuxDispatcher{Dispatcher: dispatch, allowMux: h.allowMux})
}

var errManagedVLESSMux = errors.New("Mux and XUDP are unsupported on managed inbounds")

type guardMuxDispatcher struct {
	routing.Dispatcher
	allowMux func(context.Context) bool
}

func allowExemptVLESSMux(tag string, resolve xraybandwidth.ResolveClient) func(context.Context) bool {
	if tag == "" || resolve == nil {
		return nil
	}
	return func(ctx context.Context) bool {
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || inbound.Tag != tag || inbound.Name != "vless" || inbound.User == nil {
			return false
		}
		clientID, managed, err := resolve(ctx, inbound.User)
		return err == nil && !managed && clientID == ""
	}
}

// Match Xray's inbound mux sentinel before it can reattach an existing XUDP link.
func isMuxDestination(dest net.Destination) bool {
	return dest.Address != nil && dest.Address.Family().IsDomain() && dest.Address.Domain() == "v1.mux.cool"
}

func (d guardMuxDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if isMuxDestination(dest) && (d.allowMux == nil || !d.allowMux(ctx)) {
		return nil, errManagedVLESSMux
	}
	return d.Dispatcher.Dispatch(ctx, dest)
}

func (d guardMuxDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if isMuxDestination(dest) && (d.allowMux == nil || !d.allowMux(ctx)) {
		return errManagedVLESSMux
	}
	return d.Dispatcher.DispatchLink(ctx, dest, link)
}
