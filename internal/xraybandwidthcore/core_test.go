package xraybandwidthcore

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewPreservesStockConfigAndReplacesOnlyDispatcher(t *testing.T) {
	ctx := context.Background()
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&appstats.Config{}),
	}}
	original := proto.CloneOf(config)
	blocked := errors.New("managed account denied")
	resolve := func(context.Context, *protocol.MemoryUser) (string, bool, error) {
		return "", false, blocked
	}
	wait := func(context.Context, string, int) error { return nil }

	instance, err := New(ctx, config, resolve, wait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if !proto.Equal(config, original) {
		t.Fatal("metered constructor changed the caller's config")
	}
	if instance.GetFeature(outbound.ManagerType()) == nil {
		t.Fatal("missing configured outbound manager")
	}
	if _, ok := instance.GetFeature(stats.ManagerType()).(*appstats.Manager); !ok {
		t.Fatal("missing configured stats service")
	}
	route, ok := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	if !ok {
		t.Fatal("missing dispatcher")
	}
	if _, err := route.Dispatch(ctx, net.Destination{}); !errors.Is(err, blocked) {
		t.Fatalf("dispatcher did not invoke the configured resolver, error = %v", err)
	}
	stock, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stock.Close() })
	if _, ok := stock.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher); !ok {
		t.Fatal("metered constructor altered stock dispatcher registration")
	}
}

func TestNewRejectsUnusableDispatcherConfigs(t *testing.T) {
	stock := serial.ToTypedMessage(&dispatcher.Config{})
	resolve := func(context.Context, *protocol.MemoryUser) (string, bool, error) {
		return "", false, nil
	}
	wait := func(context.Context, string, int) error { return nil }
	for _, test := range []struct {
		name string
		apps []*serial.TypedMessage
	}{
		{name: "missing"},
		{name: "duplicate", apps: []*serial.TypedMessage{stock, stock}},
		{name: "injected marker", apps: []*serial.TypedMessage{stock, serial.ToTypedMessage(&emptypb.Empty{})}},
		{name: "invalid payload", apps: []*serial.TypedMessage{{Type: stock.Type, Value: []byte{0xff}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if instance, err := New(context.Background(), &core.Config{App: test.apps}, resolve, wait); err == nil {
				_ = instance.Close()
				t.Fatal("accepted unusable dispatcher config")
			}
		})
	}
}
