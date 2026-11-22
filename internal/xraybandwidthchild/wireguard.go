package xraybandwidthchild

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/wireguard"
)

type wireGuardPacketGateVersion interface {
	VanillaProxyWireGuardPacketGateV1()
}

type wireGuardPacketGateStatus interface {
	wireGuardPacketGateVersion
	VanillaProxyWireGuardPacketGateEnabled() bool
}

func hasNativeWireGuardPacketGate() bool {
	_, ok := any((*wireguard.Server)(nil)).(wireGuardPacketGateVersion)
	return ok
}

func (b bindings) verifyWireGuardPacketGates(ctx context.Context, instance *core.Instance) error {
	for tag, bound := range b {
		if bound.protocol != protocolWireGuard {
			continue
		}
		manager, ok := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
		if !ok {
			return fmt.Errorf("managed WireGuard inbound %q has no Xray inbound manager", tag)
		}
		handler, err := manager.GetHandler(ctx, tag)
		if err != nil {
			return fmt.Errorf("find managed WireGuard inbound %q: %w", tag, err)
		}
		native, ok := handler.(proxy.GetInbound)
		if !ok {
			return fmt.Errorf("managed WireGuard inbound %q has no native proxy", tag)
		}
		server, ok := native.GetInbound().(*wireguard.Server)
		if !ok || server == nil {
			return fmt.Errorf("managed WireGuard inbound %q did not construct a native WireGuard server", tag)
		}
		gate, ok := any(server).(wireGuardPacketGateStatus)
		if !ok || !gate.VanillaProxyWireGuardPacketGateEnabled() {
			return fmt.Errorf("managed WireGuard inbound %q has no enabled native packet gate", tag)
		}
	}
	return nil
}
