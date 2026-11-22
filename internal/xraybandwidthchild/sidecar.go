package xraybandwidthchild

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/proto"
)

func validateInboundCoverage(config *core.Config, bound bindings) error {
	var api *core.InboundHandlerConfig
	for _, inbound := range config.Inbound {
		if inbound == nil {
			return errors.New("metered Xray contains a missing inbound")
		}
		if inbound.Tag == "api" && api == nil {
			api = inbound
			continue
		}
		if _, present := bound[inbound.Tag]; !present || inbound.Tag == "api" {
			return fmt.Errorf("metered Xray inbound %q has no authorized binding", inbound.Tag)
		}
	}
	if _, selected := bound["api"]; selected {
		return errors.New("metered Xray cannot select its management tunnel as a client inbound")
	}
	return validateManagementTunnel(config, api)
}

func validateManagementTunnel(config *core.Config, api *core.InboundHandlerConfig) error {
	var management *commander.Config
	var routing *router.Config
	for _, app := range config.App {
		switch app.GetType() {
		case serial.GetMessageType(&commander.Config{}):
			if management != nil {
				return errors.New("metered Xray contains multiple management services")
			}
			var settings commander.Config
			if proto.Unmarshal(app.Value, &settings) != nil || settings.GetTag() != "api" || settings.GetListen() != "" {
				return errors.New("metered Xray requires a routed management service")
			}
			management = &settings
		case serial.GetMessageType(&router.Config{}):
			if routing != nil {
				return errors.New("metered Xray contains multiple routers")
			}
			var settings router.Config
			if proto.Unmarshal(app.Value, &settings) != nil {
				return errors.New("invalid metered Xray router")
			}
			routing = &settings
		}
	}
	if management == nil && api == nil {
		return nil
	}
	invalid := errors.New("metered Xray requires an exclusive loopback management tunnel")
	if management == nil || api == nil || len(routing.GetRule()) == 0 {
		return invalid
	}
	loopbackIP := xnet.NewIPOrDomain(xnet.LocalHostIP)
	var receiver proxyman.ReceiverConfig
	var tunnel dokodemo.Config
	if api.GetReceiverSettings().GetType() != serial.GetMessageType(&receiver) ||
		proto.Unmarshal(api.ReceiverSettings.Value, &receiver) != nil ||
		api.GetProxySettings().GetType() != serial.GetMessageType(&tunnel) ||
		proto.Unmarshal(api.ProxySettings.Value, &tunnel) != nil {
		return invalid
	}
	ranges := receiver.GetPortList().GetRange()
	if len(ranges) != 1 || ranges[0].GetFrom() == 0 || ranges[0].GetFrom() > 65535 || ranges[0].GetFrom() != ranges[0].GetTo() ||
		!proto.Equal(&receiver, &proxyman.ReceiverConfig{Listen: loopbackIP, PortList: receiver.PortList}) ||
		!proto.Equal(&tunnel, &dokodemo.Config{RewriteAddress: loopbackIP, AllowedNetworks: []xnet.Network{xnet.Network_TCP}}) {
		return invalid
	}
	apiRoute := &router.RoutingRule{InboundTag: []string{"api"}, TargetTag: &router.RoutingRule_Tag{Tag: "api"}}
	if !proto.Equal(routing.Rule[0], apiRoute) || routing.Script != "" {
		return invalid
	}
	for _, rule := range routing.Rule[1:] {
		if rule.GetTag() == "api" {
			return invalid
		}
	}
	for _, balancer := range routing.BalancingRule {
		if balancer.GetFallbackTag() == "api" || slices.ContainsFunc(balancer.GetOutboundSelector(), func(selector string) bool {
			return strings.HasPrefix("api", selector)
		}) {
			return invalid
		}
	}
	for _, outbound := range config.Outbound {
		if outbound.GetTag() == "api" {
			return invalid
		}
		proxy := outbound.GetProxySettings()
		var settings loopback.Config
		if proxy.GetType() == serial.GetMessageType(&settings) {
			if proto.Unmarshal(proxy.GetValue(), &settings) != nil || settings.GetInboundTag() == "api" {
				return invalid
			}
		}
	}
	return nil
}

func bindSidecarRelays(config *core.Config, bound bindings, relays map[string]launch.SidecarRelay) error {
	ports := make(map[int]bool, len(relays))
	for _, tag := range slices.Sorted(maps.Keys(relays)) {
		relay := relays[tag]
		switch relay.Kind {
		case launch.TUICRelay:
			if relay.Port != tuic.SOCKSPortForInbound(relay.InboundID) {
				return errors.New("metered TUIC relay has an invalid port")
			}
		case launch.AmneziaWGRelay:
			if relay.Port != amneziawgnet.SOCKSPortForInbound(relay.InboundID) {
				return errors.New("metered AmneziaWG relay has an invalid port")
			}
		default:
			return errors.New("metered Xray has an unknown sidecar relay kind")
		}
		if _, duplicate := bound[tag]; duplicate || ports[relay.Port] || tag == "api" || !validSidecarIdentity(tag, 256) ||
			relay.InboundID <= 0 || len(relay.Accounts) == 0 ||
			!validSidecarIdentity(relay.Password, 255) || strings.Contains(relay.Password, "-fallback-") {
			return errors.New("invalid metered Xray sidecar relay specification")
		}
		ports[relay.Port] = true
		accounts := make(map[string]string, len(relay.Accounts))
		clients := make(map[string]boundClient, len(relay.Accounts))
		for email, id := range relay.Accounts {
			if !validSidecarIdentity(email, 255) || (!validSidecarIdentity(id, 256) && !(relay.Automatic && id == "")) {
				return errors.New("invalid metered Xray sidecar account")
			}
			accounts[email] = relay.Password
			clients[email] = boundClient{id: id}
		}
		loopbackIP := xnet.NewIPOrDomain(xnet.LocalHostIP)
		port := uint32(relay.Port)
		config.Inbound = append(config.Inbound, &core.InboundHandlerConfig{
			Tag: tag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   loopbackIP,
				PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: port, To: port}}},
				SniffingSettings: &proxyman.SniffingConfig{
					Enabled: true, RouteOnly: true, DestinationOverride: []string{"http", "tls", "quic", "fakedns"},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
				AuthType: socks.AuthType_PASSWORD, Accounts: accounts, Address: loopbackIP,
				UdpEnabled: true, UserLevel: relay.UserLevel,
			}),
		})
		bound[tag] = binding{sidecar: true, clients: clients}
	}
	return nil
}

func validSidecarIdentity(value string, maxBytes int) bool {
	return len(value) > 0 && len(value) <= maxBytes && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}
