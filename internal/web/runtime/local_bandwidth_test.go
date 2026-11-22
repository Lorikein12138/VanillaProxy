package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestBandwidthLocalRuntimeGuardsImmediateMutations(t *testing.T) {
	ctx := context.Background()
	calls := 0
	local := NewLocal(LocalDeps{
		APIPort: func() int {
			t.Fatal("managed mutation attempted to use Xray HandlerService")
			return 0
		},
		RequestReconcile: func() { calls++ },
		BandwidthManaged: true,
	})
	vless := &model.Inbound{Enable: true, Protocol: model.VLESS}
	if err := local.AddInbound(ctx, vless); err != nil {
		t.Fatal(err)
	}
	if err := local.AddUser(ctx, vless, nil); err != nil {
		t.Fatal(err)
	}
	if err := local.DelInbound(ctx, vless); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("managed mutations requested %d reconciles, want 3", calls)
	}

	for _, inbound := range []*model.Inbound{
		{Enable: true, Protocol: model.TUIC},
		{Enable: true, Protocol: model.AmneziaWG, Settings: `{"kernelMode":true}`},
		{Enable: true, Protocol: model.AmneziaWG, Settings: `{"kernelMode":false}`},
		{Enable: true, Protocol: model.MTProto, Settings: `{"routeThroughXray":true}`},
		{Enable: true, Protocol: model.Tunnel},
	} {
		if err := local.AddInbound(ctx, inbound); err == nil {
			t.Fatalf("managed runtime accepted unsupported inbound %+v", inbound)
		}
		if err := local.UpdateInbound(ctx, vless, inbound); err == nil {
			t.Fatalf("managed runtime accepted unsupported update %+v", inbound)
		}
		if err := local.AddUser(ctx, inbound, nil); err == nil {
			t.Fatalf("managed runtime accepted unsupported user change %+v", inbound)
		}
	}
	if err := local.UpdateInbound(ctx, vless, &model.Inbound{Protocol: model.TUIC}); err != nil {
		t.Fatalf("managed runtime rejected disabled edit: %v", err)
	}
}

func TestBandwidthLocalKernelAmneziaWGAppliesCommittedChanges(t *testing.T) {
	const settings = `{"server":{"kernelMode":true},"clients":[]}`
	kernel := &model.Inbound{Id: 1, Enable: true, Protocol: model.AmneziaWG, Settings: settings}
	disabled := *kernel
	disabled.Enable = false
	embedded := *kernel
	embedded.Settings = `{"server":{"kernelMode":false},"clients":[]}`
	for _, op := range []struct {
		name string
		run  func(*Local) error
	}{
		{"add", func(r *Local) error { return r.AddInbound(t.Context(), kernel) }},
		{"edit", func(r *Local) error { return r.UpdateInbound(t.Context(), kernel, kernel) }},
		{"disable", func(r *Local) error { return r.UpdateInbound(t.Context(), kernel, &disabled) }},
		{"switch to embedded", func(r *Local) error { return r.UpdateInbound(t.Context(), kernel, &embedded) }},
		{"switch from embedded", func(r *Local) error { return r.UpdateInbound(t.Context(), &embedded, kernel) }},
		{"delete", func(r *Local) error { return r.DelInbound(t.Context(), kernel) }},
		{"remove peer", func(r *Local) error { return r.RemoveUser(t.Context(), kernel, "peer") }},
	} {
		t.Run(op.name, func(t *testing.T) {
			calls := 0
			want := errors.New("kernel reconcile refused the current config")
			rt := NewLocal(LocalDeps{BandwidthManaged: true, ReconcileKernelAmneziaWG: func() error {
				calls++
				return want
			}})
			if err := op.run(rt); !errors.Is(err, want) || calls != 1 {
				t.Fatalf("immediate kernel reconcile calls = %d, error = %v", calls, err)
			}
		})
	}
	bad := *kernel
	bad.Settings = `{"server":{"kernelMode":true,"routeThroughXray":true},"clients":[]}`
	calls := 0
	rt := NewLocal(LocalDeps{BandwidthManaged: true, ReconcileKernelAmneziaWG: func() error {
		calls++
		return nil
	}})
	if err := rt.UpdateInbound(t.Context(), kernel, &bad); err == nil || !strings.Contains(err.Error(), "routeThroughXray") || calls != 1 {
		t.Fatalf("invalid kernel update did not reconcile the committed inventory: calls = %d, error = %v", calls, err)
	}
}
