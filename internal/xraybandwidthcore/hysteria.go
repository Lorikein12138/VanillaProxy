package xraybandwidthcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xcontext "github.com/xtls/xray-core/common/ctx"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

type hysteriaListenConfig struct {
	address net.Address
	port    net.Port
}

func parseManagedHysteria(inbound *core.InboundHandlerConfig) (managedInbound, error) {
	settings := inbound.GetProxySettings()
	if settings.GetType() != serial.GetMessageType(&hysteria.ServerConfig{}) {
		return managedInbound{}, errors.New("requires Hysteria proxy settings")
	}
	native := new(hysteria.ServerConfig)
	if err := proto.Unmarshal(settings.GetValue(), native); err != nil {
		return managedInbound{}, fmt.Errorf("decode Hysteria proxy settings: %w", err)
	}
	for i, user := range native.Users {
		account := user.GetAccount()
		if account.GetType() != serial.GetMessageType(&hyaccount.Account{}) {
			return managedInbound{}, fmt.Errorf("Hysteria user %d requires Hysteria credentials", i)
		}
		var credentials hyaccount.Account
		if err := proto.Unmarshal(account.GetValue(), &credentials); err != nil {
			return managedInbound{}, fmt.Errorf("decode Hysteria user %d: %w", i, err)
		}
		if credentials.Auth == "" || user.GetEmail() == "" {
			return managedInbound{}, fmt.Errorf("Hysteria user %d requires auth and email", i)
		}
	}
	receiver, err := parseHysteriaReceiver(inbound.GetReceiverSettings())
	if err != nil {
		return managedInbound{}, err
	}
	return managedInbound{proxy: native, hysteria: receiver}, nil
}

func parseHysteriaReceiver(settings *serial.TypedMessage) (*hysteriaListenConfig, error) {
	if settings.GetType() != serial.GetMessageType(&proxyman.ReceiverConfig{}) {
		return nil, errors.New("requires a native Xray receiver")
	}
	var receiver proxyman.ReceiverConfig
	if err := proto.Unmarshal(settings.GetValue(), &receiver); err != nil {
		return nil, fmt.Errorf("decode Hysteria receiver: %w", err)
	}

	ports := receiver.GetPortList().GetRange()
	if len(ports) != 1 || ports[0].GetFrom() == 0 || ports[0].GetFrom() > 65535 || ports[0].GetFrom() != ports[0].GetTo() {
		return nil, errors.New("managed Hysteria requires one UDP port from 1 to 65535")
	}
	address := net.AnyIP
	if listen := receiver.GetListen(); listen != nil {
		switch ip := listen.GetIp(); {
		case len(ip) == net.IPv4len || len(ip) == net.IPv6len:
			address = net.IPAddress(ip)
		case listen.GetDomain() == "localhost":
			address = net.DomainAddress("localhost")
		default:
			return nil, errors.New("managed Hysteria requires an IP listen address")
		}
	}
	stream := receiver.GetStreamSettings()
	socket := stream.GetSocketSettings()
	if receiver.GetReceiveOriginalDestination() || socket.GetReceiveOriginalDestAddress() || socket.GetTproxy() != internet.SocketConfig_Off {
		return nil, errors.New("managed Hysteria does not support transparent reception")
	}
	if stream.GetEffectiveProtocol() != "hysteria" {
		return nil, errors.New("managed Hysteria requires Hysteria v2 transport")
	}
	settingsValue, err := stream.GetEffectiveTransportSettings()
	if err != nil {
		return nil, fmt.Errorf("decode Hysteria transport: %w", err)
	}
	transport, ok := settingsValue.(*hytransport.Config)
	if !ok || transport.Auth != "" || strings.EqualFold(transport.MasqType, "proxy") {
		return nil, errors.New("managed Hysteria requires per-user auth and must not proxy masquerade requests")
	}
	return &hysteriaListenConfig{address: address, port: net.Port(ports[0].GetFrom())}, nil
}

func newGuardedHysteria(ctx context.Context, config managedInbound) (*guardedHysteria, error) {
	stream, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if !ok || tls.ConfigFromStreamSettings(stream) == nil {
		return nil, errors.New("managed Hysteria requires a TLS stream")
	}
	instance := core.MustFromContext(ctx)
	dispatch, ok := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	if !ok {
		return nil, errors.New("managed Hysteria requires an Xray dispatcher")
	}
	native, err := common.CreateObject(ctx, config.proxy)
	if err != nil {
		return nil, err
	}
	server, ok := native.(*hysteria.Server)
	if !ok {
		return nil, errors.New("Xray Hysteria factory returned an unexpected type")
	}

	tag := session.InboundFromContext(ctx).Tag
	h := &guardedHysteria{
		Server: server, ctx: ctx, tag: tag, stream: stream,
		listen: *config.hysteria, dispatch: guardMuxDispatcher{Dispatcher: dispatch},
		active: make(map[*activeHysteriaConn]struct{}),
	}
	if content := session.ContentFromContext(ctx); content != nil {
		h.sniff = content.SniffingRequest
	}
	policies := instance.GetFeature(policy.ManagerType()).(policy.Manager)
	counters := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	system := policies.ForSystem().Stats
	if system.InboundUplink {
		h.uplink, _ = counters.GetOrRegisterCounter("inbound>>>" + tag + ">>>traffic>>>uplink")
	}
	if system.InboundDownlink {
		h.downlink, _ = counters.GetOrRegisterCounter("inbound>>>" + tag + ">>>traffic>>>downlink")
	}
	return h, nil
}

type guardedHysteria struct {
	*hysteria.Server
	ctx      context.Context
	tag      string
	stream   *internet.MemoryStreamConfig
	listen   hysteriaListenConfig
	dispatch routing.Dispatcher
	sniff    session.SniffingRequest
	uplink   stats.Counter
	downlink stats.Counter

	mu       sync.Mutex
	listener internet.Listener
	cancel   context.CancelFunc
	active   map[*activeHysteriaConn]struct{}
}

type activeHysteriaConn struct {
	conn stat.Connection
	once sync.Once
}

func (c *activeHysteriaConn) close() {
	c.once.Do(func() { _ = c.conn.Close() })
}

var (
	_ proxy.Inbound     = (*guardedHysteria)(nil)
	_ proxy.UserManager = (*guardedHysteria)(nil)
	_ common.Runnable   = (*guardedHysteria)(nil)
)

// The stock TCP worker requires an exact *hysteria.Server for auth and
// otherwise injects a mux server. Use the native transport listener directly.
func (h *guardedHysteria) Network() []net.Network { return nil }

func (h *guardedHysteria) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if user == nil || user.Email == "" {
		return errors.New("managed Hysteria requires a user email")
	}
	account, ok := user.Account.(*hyaccount.MemoryAccount)
	if !ok || account == nil || account.Auth == "" {
		return errors.New("managed Hysteria requires per-user credentials")
	}
	return h.Server.AddUser(ctx, user)
}

func (h *guardedHysteria) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listener != nil {
		return nil
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(h.ctx)
	listenerCtx := hytransport.ContextWithValidator(ctx, h.HysteriaInboundValidator())
	listener, err := internet.ListenTCP(listenerCtx, h.listen.address, h.listen.port, h.stream, func(conn stat.Connection) {
		// The native UDP transport invokes this callback under its association lock.
		go h.serve(ctx, conn)
	})
	if err != nil {
		cancel()
		return err
	}
	h.listener, h.cancel = listener, cancel
	return nil
}

func (h *guardedHysteria) Process(ctx context.Context, network net.Network, conn stat.Connection, _ routing.Dispatcher) error {
	return h.Server.Process(ctx, network, conn, h.dispatch)
}

func (h *guardedHysteria) serve(ctx context.Context, conn stat.Connection) {
	active := &activeHysteriaConn{conn: conn}
	h.mu.Lock()
	if ctx.Err() != nil {
		h.mu.Unlock()
		active.close()
		return
	}
	h.active[active] = struct{}{}
	h.mu.Unlock()
	defer func() {
		active.close()
		h.mu.Lock()
		delete(h.active, active)
		h.mu.Unlock()
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = xcontext.ContextWithID(ctx, session.NewID())
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	if h.uplink != nil || h.downlink != nil {
		conn = &stat.CounterConnection{Connection: conn, ReadCounter: h.uplink, WriteCounter: h.downlink}
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: net.DestinationFromAddr(conn.RemoteAddr()), Local: net.DestinationFromAddr(conn.LocalAddr()),
		Gateway: net.TCPDestination(h.listen.address, h.listen.port), Tag: h.tag, Conn: conn,
	})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: h.sniff})
	if err := h.Process(ctx, net.Network_TCP, conn, nil); err != nil {
		xerrors.LogInfoInner(ctx, err, "connection ends")
	}
}

func (h *guardedHysteria) Close() error {
	h.mu.Lock()
	listener := h.listener
	if listener == nil {
		h.mu.Unlock()
		return nil
	}
	h.cancel()
	h.listener = nil
	active := make([]*activeHysteriaConn, 0, len(h.active))
	for conn := range h.active {
		active = append(active, conn)
	}
	h.mu.Unlock()

	for _, conn := range active {
		conn.close()
	}
	return listener.Close()
}
