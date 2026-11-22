// Package xraybandwidthcore constructs a metered instance of the pinned Xray core.
package xraybandwidthcore

import (
	"context"
	"errors"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidth"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type dispatcherOptionsKey struct{}

type dispatcherOptions struct {
	config  *dispatcher.Config
	resolve xraybandwidth.ResolveClient
	wait    xraybandwidth.Gate
}

func init() {
	// Xray uses the serialized protobuf type to select an app factory. Its
	// pinned distribution does not register Empty as an app. This marker
	// exists only in the private in-memory copy of the core configuration.
	common.Must(common.RegisterConfig((*emptypb.Empty)(nil), func(ctx context.Context, _ any) (any, error) {
		options, ok := ctx.Value(dispatcherOptionsKey{}).(dispatcherOptions)
		if !ok {
			return nil, errors.New("Xray metered dispatcher requires constructor options")
		}
		// Let Xray register its own feature dependencies and preserve its
		// private state such as the optional FakeDNS engine.
		base, err := common.CreateObject(ctx, options.config)
		if err != nil {
			return nil, err
		}
		native, ok := base.(routing.Dispatcher)
		if !ok {
			return nil, errors.New("Xray dispatcher factory returned an unexpected type")
		}
		return xraybandwidth.Wrap(native, options.resolve, options.wait)
	}))
}

// New returns an unstarted Xray instance with the native dispatcher wrapped.
// The data paths that bypass Xray routing need their own enforcement before a
// caller can offer a client-wide guarantee.
func New(ctx context.Context, config *core.Config, resolve xraybandwidth.ResolveClient, wait xraybandwidth.Gate) (*core.Instance, error) {
	return NewWithManagedVLESS(ctx, config, resolve, wait, nil)
}

// NewWithManagedVLESS wraps the native dispatcher and guards the listed VLESS
// inbounds against reverse and fallback paths. Only exempt accounts may use mux.
// Accounts may use an empty flow or Vision on raw TCP with native TLS or
// REALITY. Managed Vision with VLESS encryption requires REALITY.
func NewWithManagedVLESS(ctx context.Context, config *core.Config, resolve xraybandwidth.ResolveClient, wait xraybandwidth.Gate, managedTags []string) (*core.Instance, error) {
	return NewWithManagedInbounds(ctx, config, resolve, wait, ManagedInboundTags{VLESS: managedTags})
}

// ManagedInboundTags lists the inbounds whose authenticated traffic needs a guard.
type ManagedInboundTags struct {
	VLESS                []string
	Hysteria             []string
	VMess                []string
	Trojan               []string
	Shadowsocks          []string
	HTTP                 []string
	Mixed                []string
	Shadowsocks2022      []string
	Shadowsocks2022Multi []string
}

// NewWithManagedInbounds installs protocol guards on the listed inbounds and
// wraps the native dispatcher.
func NewWithManagedInbounds(ctx context.Context, config *core.Config, resolve xraybandwidth.ResolveClient, wait xraybandwidth.Gate, tags ManagedInboundTags) (*core.Instance, error) {
	if ctx == nil || config == nil || resolve == nil || wait == nil {
		return nil, errors.New("metered Xray core requires a context, configuration, account resolver and gate")
	}

	stockType := serial.GetMessageType(&dispatcher.Config{})
	marker := serial.ToTypedMessage(&emptypb.Empty{})
	index := -1
	for i, app := range config.App {
		if app == nil {
			return nil, fmt.Errorf("Xray app configuration %d is missing", i)
		}
		switch app.Type {
		case marker.Type:
			return nil, errors.New("Xray configuration contains the internal metering marker")
		case stockType:
			if index >= 0 {
				return nil, errors.New("Xray configuration contains multiple dispatchers")
			}
			index = i
		}
	}
	if index < 0 {
		return nil, errors.New("Xray configuration is missing the native dispatcher")
	}

	var native dispatcher.Config
	if err := proto.Unmarshal(config.App[index].Value, &native); err != nil {
		return nil, fmt.Errorf("decode Xray dispatcher configuration: %w", err)
	}
	copy := proto.CloneOf(config)
	copy.App[index] = marker
	managed, err := guardInbounds(copy, tags)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, managedInboundsKey{}, managed)
	ctx = context.WithValue(ctx, dispatcherOptionsKey{}, dispatcherOptions{
		config: &native, resolve: resolve, wait: wait,
	})
	return core.NewWithContext(ctx, copy)
}
