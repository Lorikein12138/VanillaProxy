package xraybandwidthcore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/text/cases"
	"google.golang.org/protobuf/proto"
)

// TypedAccountIdentity returns the native protocol name and authentication
// identity for VMess, Trojan and the supported typed Shadowsocks accounts.
func TypedAccountIdentity(account protocol.Account) (name, identity string) {
	switch account := account.(type) {
	case *vmess.MemoryAccount:
		if account != nil && account.ID != nil {
			return "vmess", string(account.ID.CmdKey())
		}
	case *trojan.MemoryAccount:
		if account != nil && account.Password != "" && len(account.Key) != 0 {
			return "trojan", string(account.Key)
		}
	case *shadowsocks.MemoryAccount:
		if account == nil || account.Password == "" {
			break
		}
		cipher, ok := account.Cipher.(*shadowsocks.AEADCipher)
		if !ok || cipher == nil || cipher.AEADAuthCreator == nil || len(account.Key) != int(cipher.KeySize()) {
			break
		}
		switch account.CipherType {
		case shadowsocks.CipherType_AES_128_GCM, shadowsocks.CipherType_AES_256_GCM,
			shadowsocks.CipherType_CHACHA20_POLY1305, shadowsocks.CipherType_XCHACHA20_POLY1305:
			return "shadowsocks", string([]byte{byte(account.CipherType)}) + string(account.Key)
		}
	case *ss2022.MemoryAccount:
		if account != nil && (len(account.Key) == 16 || len(account.Key) == 32) {
			return "shadowsocks-2022-multi", string(account.Key)
		}
	}
	return "", ""
}

func parseManagedProxy(settings *serial.TypedMessage, expected string) (proto.Message, error) {
	if settings.GetType() != expected {
		return nil, fmt.Errorf("requires native proxy settings of type %s", expected)
	}
	value, err := settings.GetInstance()
	if err != nil {
		return nil, fmt.Errorf("decode managed proxy settings: %w", err)
	}
	var users []*protocol.User
	var credentials proto.Message
	var name string
	switch config := value.(type) {
	case *httpproxy.ServerConfig:
		return value, validateStaticPasswords(config.Accounts)
	case *socks.ServerConfig:
		if config.AuthType != socks.AuthType_PASSWORD {
			return nil, errors.New("managed Mixed requires password authentication")
		}
		return value, validateStaticPasswords(config.Accounts)
	case *ss2022.ServerConfig:
		return value, validateManagedSS2022(config)
	case *ss2022.MultiUserServerConfig:
		return value, validateManagedSS2022Multi(config)
	case *vmessinbound.Config:
		// The pinned VMess handler never emits a detour command. Its default
		// only supplies a level to the unused GetOrGenerateUser method.
		if len(config.ProtoReflect().GetUnknown()) != 0 {
			return nil, errors.New("managed VMess does not support unknown configuration fields")
		}
		users, credentials, name = config.User, &vmess.Account{}, "vmess"
	case *trojan.ServerConfig:
		if len(config.Fallbacks) != 0 {
			return nil, errors.New("managed Trojan does not support fallbacks")
		}
		users, credentials, name = config.Users, &trojan.Account{}, "trojan"
	case *shadowsocks.ServerConfig:
		users, credentials, name = config.Users, &shadowsocks.Account{}, "shadowsocks"
	default:
		return nil, errors.New("unexpected managed proxy settings")
	}

	emailKeys := make(map[string]bool, len(users))
	accountKeys := make(map[string]bool, len(users))
	accountType := serial.GetMessageType(credentials)
	fold := cases.Fold()
	for i, user := range users {
		email := fold.String(user.GetEmail())
		if email == "" || emailKeys[email] {
			return nil, fmt.Errorf("user %d requires a unique non-empty email", i)
		}
		if user.GetAccount().GetType() != accountType {
			return nil, fmt.Errorf("user %d requires native %s credentials", i, name)
		}
		memory, err := user.ToMemoryUser()
		if err != nil {
			return nil, fmt.Errorf("user %d has invalid %s credentials", i, name)
		}
		protocol, key := TypedAccountIdentity(memory.Account)
		if protocol != name {
			return nil, fmt.Errorf("user %d has invalid %s credentials", i, name)
		}
		if accountKeys[key] {
			return nil, fmt.Errorf("user %d has duplicate %s credentials", i, name)
		}
		emailKeys[email], accountKeys[key] = true, true
	}
	return value, nil
}

type nativeLegacyInbound interface {
	proxy.Inbound
	proxy.UserManager
}

type guardedLegacy struct {
	nativeLegacyInbound
	name               string
	mu                 sync.Mutex
	validateCredential func(string) error
}

func newGuardedLegacy(native any, config proto.Message) (*guardedLegacy, error) {
	var inbound nativeLegacyInbound
	var name string
	switch config := config.(type) {
	case *vmessinbound.Config:
		handler, ok := native.(*vmessinbound.Handler)
		if ok {
			inbound, name = handler, "vmess"
		}
	case *trojan.ServerConfig:
		handler, ok := native.(*trojan.Server)
		if ok {
			inbound, name = handler, "trojan"
		}
	case *shadowsocks.ServerConfig:
		handler, ok := native.(*shadowsocks.Server)
		if ok {
			inbound, name = handler, "shadowsocks"
		}
	case *ss2022.MultiUserServerConfig:
		if handler, ok := native.(*ss2022.MultiUserInbound); ok {
			if slices.Contains(handler.Network(), net.Network_UDP) {
				managed, ok := any(handler).(interface{ EnableManagedUDP() })
				if !ok {
					return nil, errors.New("managed multi-user Shadowsocks 2022 UDP requires the patched Xray build")
				}
				managed.EnableManagedUDP()
			}
			master, err := parseManagedSS2022Key(config.Method, config.Key, true)
			if err != nil {
				return nil, err
			}
			return &guardedLegacy{
				nativeLegacyInbound: handler, name: "shadowsocks-2022-multi",
				validateCredential: func(key string) error { return validateSS2022UserKey(master, key) },
			}, nil
		}
	}
	if inbound == nil {
		return nil, errors.New("Xray factory returned an unexpected managed inbound type")
	}
	return &guardedLegacy{nativeLegacyInbound: inbound, name: name}, nil
}

func (h *guardedLegacy) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if user == nil || user.Email == "" {
		return errors.New("managed inbound requires a user email")
	}
	name, key := TypedAccountIdentity(user.Account)
	if name != h.name {
		return errors.New("invalid credentials for managed inbound")
	}
	if h.validateCredential != nil {
		if err := h.validateCredential(key); err != nil {
			return err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	fold := cases.Fold()
	email := fold.String(user.Email)
	for _, current := range h.GetUsers(ctx) {
		_, currentKey := TypedAccountIdentity(current.Account)
		if fold.String(current.Email) == email || currentKey == key {
			return errors.New("managed inbound requires unique emails and credentials")
		}
	}
	return h.nativeLegacyInbound.AddUser(ctx, user)
}

func (h *guardedLegacy) RemoveUser(ctx context.Context, email string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nativeLegacyInbound.RemoveUser(ctx, email)
}

func (h *guardedLegacy) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatch routing.Dispatcher) error {
	return h.nativeLegacyInbound.Process(ctx, network, conn, guardMuxDispatcher{Dispatcher: dispatch})
}

func (h *guardedLegacy) Close() error {
	return common.Close(h.nativeLegacyInbound)
}
