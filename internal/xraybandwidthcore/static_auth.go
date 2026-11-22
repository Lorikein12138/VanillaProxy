package xraybandwidthcore

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/text/cases"
	"google.golang.org/protobuf/proto"
)

func validateStaticPasswords(accounts map[string]string) error {
	if len(accounts) == 0 {
		return errors.New("managed proxy requires configured username/password authentication")
	}
	for username, password := range accounts {
		if username == "" || password == "" {
			return errors.New("managed proxy requires non-empty usernames and passwords")
		}
	}
	return nil
}

func parseManagedSS2022Key(methodName, key string, multi bool) ([]byte, error) {
	method, err := ss2022.GetCipherMethod(methodName)
	if err != nil || (multi && method.IsChaCha) {
		return nil, errors.New("unsupported managed Shadowsocks 2022 method")
	}
	decoded, err := ss2022.ParseKey(key, method.KeySaltLength)
	if err != nil {
		return nil, errors.New("invalid managed Shadowsocks 2022 server key")
	}
	return decoded, nil
}

func validateManagedSS2022(config *ss2022.ServerConfig) error {
	if config.Email == "" {
		return errors.New("managed Shadowsocks 2022 requires a non-empty email")
	}
	_, err := parseManagedSS2022Key(config.Method, config.Key, false)
	return err
}

func validateManagedSS2022Multi(config *ss2022.MultiUserServerConfig) error {
	for _, network := range config.Network {
		if network != net.Network_TCP && network != net.Network_UDP {
			return errors.New("managed multi-user Shadowsocks 2022 requires TCP or UDP network")
		}
	}
	master, err := parseManagedSS2022Key(config.Method, config.Key, true)
	if err != nil {
		return err
	}
	emailKeys := make(map[string]bool, len(config.Users))
	keyHashes := make(map[[ss2022.AESBlockSize]byte]bool, len(config.Users))
	accountType := serial.GetMessageType(&ss2022.Account{})
	fold := cases.Fold()
	for i, user := range config.Users {
		email := fold.String(user.GetEmail())
		if email == "" || emailKeys[email] {
			return fmt.Errorf("Shadowsocks 2022 user %d requires a unique non-empty email", i)
		}
		if user.GetAccount().GetType() != accountType {
			return fmt.Errorf("user %d requires native Shadowsocks 2022 credentials", i)
		}
		memory, err := user.ToMemoryUser()
		if err != nil {
			return fmt.Errorf("invalid Shadowsocks 2022 user %d credentials", i)
		}
		_, key := TypedAccountIdentity(memory.Account)
		if err := validateSS2022UserKey(master, key); err != nil {
			return fmt.Errorf("user %d: %w", i, err)
		}
		hash := ss2022.DeriveUserPSKHash([]byte(key))
		if keyHashes[hash] {
			return fmt.Errorf("duplicate Shadowsocks 2022 user %d credentials", i)
		}
		emailKeys[email], keyHashes[hash] = true, true
	}
	return nil
}

func validateSS2022UserKey(master []byte, key string) error {
	if len(key) != len(master) || key == string(master) {
		return errors.New("managed Shadowsocks 2022 requires a valid user key distinct from the server key")
	}
	return nil
}

// The native handlers authenticate before dispatch and only report an email.
// Keep the allowed names and exact usernames local to each guarded handler.
type guardedStatic struct {
	proxy.Inbound
	name      string
	alternate string
	users     map[string]struct{}
}

func newGuardedStatic(native any, config proto.Message) (*guardedStatic, error) {
	h := &guardedStatic{users: make(map[string]struct{})}
	var accounts map[string]string
	switch config := config.(type) {
	case *httpproxy.ServerConfig:
		if server, ok := native.(*httpproxy.Server); ok {
			h.Inbound, h.name, accounts = server, "http", config.Accounts
		}
	case *socks.ServerConfig:
		if server, ok := native.(*socks.Server); ok {
			h.Inbound, h.name, h.alternate, accounts = server, "socks", "http", config.Accounts
		}
	case *ss2022.ServerConfig:
		if server, ok := native.(*ss2022.Inbound); ok {
			h.Inbound, h.name = server, "shadowsocks-2022"
			h.users[config.Email] = struct{}{}
		}
	}
	if h.Inbound == nil {
		return nil, errors.New("Xray factory returned an unexpected static inbound type")
	}
	for username := range accounts {
		h.users[username] = struct{}{}
	}
	return h, nil
}

func (h *guardedStatic) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatch routing.Dispatcher) error {
	return h.Inbound.Process(ctx, network, conn, guardStaticDispatcher{
		Dispatcher: guardMuxDispatcher{Dispatcher: dispatch}, handler: h,
	})
}

type guardStaticDispatcher struct {
	routing.Dispatcher
	handler *guardedStatic
}

func (d guardStaticDispatcher) authorize(ctx context.Context) (context.Context, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" || inbound.User.Account != nil {
		return nil, errors.New("managed inbound requires an authenticated username")
	}
	if _, known := d.handler.users[inbound.User.Email]; !known ||
		(inbound.Name != d.handler.name && (d.handler.alternate == "" || inbound.Name != d.handler.alternate)) {
		return nil, errors.New("managed inbound requires an authenticated username")
	}
	// HTTP keep-alive can authenticate the next request as another user.
	// Keep the previous request's identity and splice setting local to its link.
	user := *inbound.User
	snapshot := *inbound
	snapshot.User = &user
	snapshot.CanSpliceCopy = 3
	return session.ContextWithInbound(ctx, &snapshot), nil
}

func (d guardStaticDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	ctx, err := d.authorize(ctx)
	if err != nil {
		return nil, err
	}
	return d.Dispatcher.Dispatch(ctx, dest)
}

func (d guardStaticDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	ctx, err := d.authorize(ctx)
	if err != nil {
		return err
	}
	return d.Dispatcher.DispatchLink(ctx, dest, link)
}
