package xraybandwidthchild

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/masque"
)

type masquePacketGateVersion interface {
	VanillaProxyPacketGateV1()
}

type masquePacketGateStatus interface {
	masquePacketGateVersion
	VanillaProxyPacketGateEnabled() bool
}

func hasNativeMASQUEPacketGate() bool {
	_, ok := any((*masque.Server)(nil)).(masquePacketGateVersion)
	return ok
}

func (b bindings) verifyMASQUEPacketGates(ctx context.Context, instance *core.Instance) error {
	for tag, bound := range b {
		if bound.protocol != protocolMASQUE {
			continue
		}
		manager, ok := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
		if !ok {
			return fmt.Errorf("managed MASQUE inbound %q has no Xray inbound manager", tag)
		}
		handler, err := manager.GetHandler(ctx, tag)
		if err != nil {
			return fmt.Errorf("find managed MASQUE inbound %q: %w", tag, err)
		}
		native, ok := handler.(proxy.GetInbound)
		if !ok {
			return fmt.Errorf("managed MASQUE inbound %q has no native proxy", tag)
		}
		server, ok := native.GetInbound().(*masque.Server)
		if !ok {
			return fmt.Errorf("managed MASQUE inbound %q did not construct a native MASQUE server", tag)
		}
		gate, ok := any(server).(masquePacketGateStatus)
		if !ok || !gate.VanillaProxyPacketGateEnabled() {
			return fmt.Errorf("managed MASQUE inbound %q has no enabled native packet gate", tag)
		}
	}
	return nil
}
