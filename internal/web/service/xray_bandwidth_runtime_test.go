package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestBandwidthKernelReconcileWorksDuringXrayLifecycleAndStopsOnShutdown(t *testing.T) {
	panel := setupBandwidthSaveNode(t)
	marker := errors.New("kernel apply result")
	lock.Lock()
	applied := make(chan error, 1)
	go func() {
		applied <- ApplyBandwidthKernelAmneziaWG(panel, func() ([]*xray.ClientTraffic, error) { return nil, marker })
	}()
	var err error
	select {
	case err = <-applied:
	case <-time.After(2 * time.Second):
		err = errors.New("kernel reconcile blocked on Xray lifecycle lock")
	}
	lock.Unlock()
	if !errors.Is(err, marker) {
		t.Fatal(err)
	}
	BeginBandwidthShutdown(panel)
	if err := ApplyBandwidthKernelAmneziaWG(panel, func() ([]*xray.ClientTraffic, error) {
		t.Fatal("closing node accepted new kernel work")
		return nil, nil
	}); err == nil {
		t.Fatal("expected the closing node to refuse kernel reconcile")
	}
}

func TestBandwidthKernelTrafficPersistsFromTrafficWriterCallback(t *testing.T) {
	setupConflictDB(t)
	panel := setupBandwidthSaveNode(t)
	StartTrafficWriter()
	t.Cleanup(StopTrafficWriter)
	db := database.GetDB()
	peer := xray.ClientTraffic{Email: "peer", Enable: true}
	if err := db.Create(&peer).Error; err != nil {
		t.Fatal(err)
	}
	applied := make(chan error, 1)
	go func() {
		applied <- submitTrafficWrite(func() error {
			return ApplyBandwidthKernelAmneziaWG(panel, func() ([]*xray.ClientTraffic, error) {
				return []*xray.ClientTraffic{{Email: peer.Email, Up: 40, Down: 60}}, nil
			})
		})
	}()
	select {
	case err := <-applied:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kernel reconcile attempted to reenter the traffic writer")
	}
	BeginBandwidthShutdown(panel)
	if err := FlushBandwidthKernelTraffic(panel, []*xray.ClientTraffic{{Email: peer.Email, Up: 20, Down: 30}}); err != nil {
		t.Fatal(err)
	}
	var got xray.ClientTraffic
	if err := db.First(&got, peer.Id).Error; err != nil {
		t.Fatal(err)
	}
	if got.Up != 60 || got.Down != 90 {
		t.Fatalf("kernel traffic up = %d, down = %d, want 60/90", got.Up, got.Down)
	}
}

func TestBandwidthKernelAmneziaWGSaveRequiresCanonicalPeerBinding(t *testing.T) {
	setupBandwidthSaveNode(t)
	const testKey = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	inbound := &model.Inbound{
		Tag: "kernel-amneziawg", Enable: true, Protocol: model.AmneziaWG, Port: 41418,
		Settings: `{"server":{"kernelMode":true,"subnetIp":"10.45.45.0","subnetCidr":24},
		"clients":[{"email":"no-account","enable":true,"publicKey":"` + testKey + `","allowedIPs":["10.45.45.2"]}]}`,
	}
	if err := validateSavedBandwidthInbound(inbound); err == nil || !strings.Contains(err.Error(), "canonical account") {
		t.Fatalf("unbound enabled kernel peer got %v, want canonical account rejection", err)
	}
	inbound.Enable = false
	if err := validateSavedBandwidthInbound(inbound); err != nil {
		t.Fatalf("unable to disable an invalid kernel inbound: %v", err)
	}
}

func TestBandwidthKernelTrafficUsesStableLedgerIDAfterEmailReuse(t *testing.T) {
	setupConflictDB(t)
	setupBandwidthSaveNode(t)
	db := database.GetDB()
	const oldEmail, newEmail = "old@example.test", "new@example.test"
	const sourceID, initialLedgerInbound = 11, 22
	peer := xray.ClientTraffic{Email: oldEmail, InboundId: initialLedgerInbound, Enable: true}
	removed := xray.ClientTraffic{Email: "removed@example.test", Enable: true}
	for _, row := range []*xray.ClientTraffic{&peer, &removed} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	inbound := &model.Inbound{Id: sourceID, Enable: true, Protocol: model.AmneziaWG, Settings: `{
		"server":{"kernelMode":true,"subnetIp":"10.1.1.0","subnetCidr":24},
		"clients":[{"email":"old@example.test","enable":true,"publicKey":"peer-key","allowedIPs":["10.1.1.2"]}]
	}`}
	desired, err := desiredAmneziaWGInstances([]*model.Inbound{inbound})
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 1 || len(desired[0].Peers) != 1 || desired[0].Peers[0].TrafficID != peer.Id {
		t.Fatalf("kernel peer did not bind its shared ledger row: %+v", desired)
	}
	sample := &xray.ClientTraffic{InboundId: sourceID, Email: oldEmail, AWGTrafficID: desired[0].Peers[0].TrafficID, Up: 40, Down: 60}
	if err := db.Model(&peer).Updates(map[string]any{"email": newEmail, "inbound_id": 33}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&removed).Error; err != nil {
		t.Fatal(err)
	}
	replacement := xray.ClientTraffic{Email: oldEmail, InboundId: initialLedgerInbound, Enable: true}
	if err := db.Create(&replacement).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&InboundService{}).AddTraffic(nil, []*xray.ClientTraffic{
		sample,
		{InboundId: sourceID, Email: oldEmail, AWGTrafficID: removed.Id, Up: 1000, Down: 1000},
		{InboundId: sourceID, Email: oldEmail, Up: 1, Down: 2}, // Stock sample remains email-keyed.
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []xray.ClientTraffic{
		{Id: peer.Id, Email: newEmail, Up: 40, Down: 60},
		{Id: replacement.Id, Email: oldEmail, Up: 1, Down: 2},
	} {
		var got xray.ClientTraffic
		if err := db.First(&got, want.Id).Error; err != nil {
			t.Fatal(err)
		}
		if got.Email != want.Email || got.Up != want.Up || got.Down != want.Down {
			t.Fatalf("ledger row %d for %q received %d/%d, want %d/%d", got.Id, got.Email, got.Up, got.Down, want.Up, want.Down)
		}
	}
}

func TestBandwidthManagedAPIRoutesRejectLoopbackManagementTag(t *testing.T) {
	for _, test := range []struct {
		name, outbound string
		wantError      bool
	}{
		{"management tag", `{"protocol":"loopback","settings":{"inboundTag":"api"}}`, true},
		{"data tag", `{"protocol":"loopback","settings":{"inboundTag":"api-data"}}`, false},
		{"freedom", `{"protocol":"freedom"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &xray.Config{
				API:             json_util.RawMessage(`{"tag":"api"}`),
				RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}`),
				OutboundConfigs: json_util.RawMessage("[" + test.outbound + "]"),
			}
			if err := validateBandwidthAPIRoutes(config); (err != nil) != test.wantError {
				t.Fatalf("API route validation error = %v, want error = %t", err, test.wantError)
			}
		})
	}
}

func TestBandwidthManagedStoredInbounds(t *testing.T) {
	setupConflictDB(t)
	inbound := &model.Inbound{Protocol: model.TUIC, Tag: "legacy-tuic", Settings: "{}"}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatal(err)
	}
	if err := validateSavedBandwidthInbound(&model.Inbound{Enable: true, Protocol: model.TUIC}); err != nil {
		t.Fatalf("default mode limited TUIC: %v", err)
	}
	restore := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(restore) })

	service := &InboundService{}
	if _, _, err := service.AddInbound(&model.Inbound{Enable: true, Protocol: model.TUIC}); err == nil {
		t.Fatal("managed node accepted new enabled legacy sidecar")
	}
	if _, err := service.SetInboundEnable(inbound.Id, true); err == nil {
		t.Fatal("managed node enabled legacy sidecar")
	}
	saved, err := service.GetInbound(inbound.Id)
	if err != nil || saved.Enable {
		t.Fatalf("legacy sidecar persisted enabled state: %v", err)
	}
	if err := database.GetDB().Model(inbound).Update("enable", true).Error; err != nil {
		t.Fatal(err)
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatalf("stored legacy sidecar blocked Xray configuration: %v", err)
	}
	for _, candidate := range config.InboundConfigs {
		if candidate.Tag == inbound.Tag || candidate.TuicRelay {
			t.Fatal("stored legacy sidecar generated an unsafe listener or relay")
		}
	}
	if saved, err := service.GetInbound(inbound.Id); err != nil || !saved.Enable || saved.Settings != inbound.Settings {
		t.Fatalf("runtime isolation changed the stored legacy sidecar: %v", err)
	}
}

func TestBandwidthManagedRuntimeIsolatesStoredInbounds(t *testing.T) {
	setupEnablePortTest(t)
	panel := setupBandwidthSaveNode(t)
	release, reserveTCP, _ := reserveBandwidthChildTestPorts(t)
	if err := (&XraySettingService{}).saveSetting("xrayTemplateConfig", `{}`); err != nil {
		t.Fatal(err)
	}
	service := &InboundService{}
	const vless = `{"decryption":"none","clients":[{"id":"00000000-0000-4000-8000-000000000001","email":"peer","enable":true}]}`
	valid := &model.Inbound{Tag: "valid-vless", Listen: "127.0.0.1", Port: reserveTCP(), Protocol: model.VLESS, Enable: true, Settings: vless}
	if _, _, err := service.AddInbound(valid); err != nil {
		t.Fatalf("save compatible VLESS inbound: %v", err)
	}
	legacyHTTP := &model.Inbound{Tag: "anonymous-http", Listen: "127.0.0.1", Port: reserveTCP(), Protocol: model.HTTP, Enable: true, Settings: `{"accounts":[]}`}
	if _, _, err := service.AddInbound(legacyHTTP); err == nil || !strings.Contains(err.Error(), "username/password authentication") {
		t.Fatalf("save must reject new anonymous HTTP inbound: %v", err)
	}
	legacyTransport := &model.Inbound{Tag: "legacy-transport", Listen: "127.0.0.1", Port: reserveTCP(), Protocol: model.VLESS, Enable: true,
		StreamSettings: `{"network":"kcp"}`, Settings: `{"decryption":"none","clients":[]}`}
	for _, inbound := range []*model.Inbound{legacyHTTP, legacyTransport} {
		if err := database.GetDB().Create(inbound).Error; err != nil {
			t.Fatal(err)
		}
	}

	generated, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	prepared, bindings, err := prepareBandwidthXrayConfigForRuntime(false, generated, panel.AccountID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.InboundConfigs) != 1 || prepared.InboundConfigs[0].Tag != valid.Tag || len(bindings) != 1 || bindings[valid.Tag]["peer"] != "shared-account" {
		t.Fatal("runtime candidate and handshake must retain only the compatible VLESS inbound")
	}
	for _, inbound := range []*model.Inbound{legacyHTTP, legacyTransport} {
		saved, err := service.GetInbound(inbound.Id)
		if err != nil || !saved.Enable || saved.Settings != inbound.Settings || saved.StreamSettings != inbound.StreamSettings {
			t.Fatalf("runtime isolation changed the stored inbound %q: %v", inbound.Tag, err)
		}
	}
	denied, deniedBindings, err := prepareBandwidthXrayConfigForRuntime(false, generated, panel.AccountID, func(string, string, string) (string, bool) {
		return "", false
	})
	if err != nil || len(denied.InboundConfigs) != 0 || len(deniedBindings) != 0 {
		t.Fatalf("runtime retained a listener or binding with no authorized accounts: %v", err)
	}
	generated.InboundConfigs = append(generated.InboundConfigs, generated.InboundConfigs[0])
	if _, _, err := prepareBandwidthXrayConfigForRuntime(false, generated, panel.AccountID, nil); err == nil || !strings.Contains(err.Error(), "unique non-empty inbound tags") {
		t.Fatalf("runtime failed to refuse duplicate tags: %v", err)
	}
	release()
	runGeneratedBandwidthChild(t, prepared, bindings, "", func(context.Context, string, int) error { return nil })
}

func TestBandwidthManagedRuntimeIsolatesNativeInboundErrors(t *testing.T) {
	setupConflictDB(t)
	panel := setupBandwidthSaveNode(t)
	release, reserveTCP, _ := reserveBandwidthChildTestPorts(t)
	valid := xray.InboundConfig{Tag: "valid-vless", Port: reserveTCP(), Listen: json_util.RawMessage(`"127.0.0.1"`), Protocol: "vless",
		Settings: json_util.RawMessage(`{"decryption":"none","clients":[{"id":"00000000-0000-4000-8000-000000000001","email":"peer"}]}`)}
	badSniffing := valid
	badSniffing.Tag, badSniffing.Port = "legacy-sniffing", reserveTCP()
	badSniffing.Sniffing = json_util.RawMessage(`{"enabled":true,"destOverride":["bogus-sniffing-protocol"]}`)
	badTLS := valid
	badTLS.Tag, badTLS.Port = "legacy-null-certificate", reserveTCP()
	badTLS.StreamSettings = json_util.RawMessage(`{"security":"tls","tlsSettings":{"certificates":[null]}}`)
	duplicate := valid
	duplicate.Tag, duplicate.Port = "legacy-duplicate-credentials", reserveTCP()
	duplicate.Settings = json_util.RawMessage(`{"decryption":"none","clients":[{"id":"abcdabcd-0000-4000-8000-000000000001","email":"peer"},{"id":"ABCDABCD-0000-4000-8000-000000000001","email":"wg-peer"}]}`)
	settings := &XraySettingService{}
	var template struct {
		Inbounds []xray.InboundConfig `json:"inbounds"`
	}
	for _, test := range []struct {
		inbound xray.InboundConfig
		want    string
	}{
		{badSniffing, "invalid native inbound configuration"},
		{badTLS, "invalid native inbound configuration"},
		{duplicate, "invalid native account bindings or transport"},
	} {
		template.Inbounds = []xray.InboundConfig{test.inbound}
		raw, err := json.Marshal(template)
		if err != nil {
			t.Fatal(err)
		}
		want := `managed Xray inbound "` + test.inbound.Tag + `": ` + test.want
		if err := settings.SaveXraySetting(string(raw)); err == nil || err.Error() != want {
			t.Fatalf("save returned %v, want %q", err, want)
		}
	}
	template.Inbounds = []xray.InboundConfig{badSniffing, valid, badTLS, duplicate}
	stored, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.saveSetting("xrayTemplateConfig", string(stored)); err != nil {
		t.Fatal(err)
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	prepared, bindings, err := prepareBandwidthXrayConfigForRuntime(false, config, panel.AccountID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.InboundConfigs) != 1 || prepared.InboundConfigs[0].Tag != valid.Tag || len(bindings) != 1 || bindings[valid.Tag]["peer"] != "shared-account" {
		t.Fatal("runtime candidate and handshake must retain only the valid native inbound")
	}
	if after, err := settings.GetXrayConfigTemplate(); err != nil || after != string(stored) {
		t.Fatalf("runtime isolation changed the stored template: %v", err)
	}
	release()
	runGeneratedBandwidthChild(t, prepared, bindings, "", func(context.Context, string, int) error { return nil })
}

func TestBandwidthManagedIdleFollowsDesiredInbounds(t *testing.T) {
	setupConflictDB(t)
	node := &managedBandwidthNode{}
	restore := activeBandwidthNode.Swap(node)
	manual := isManuallyStopped.Swap(false)
	restart := isNeedXrayRestart.Swap(false)
	reconcile := isNeedXrayReconcile.Swap(false)
	previousProcess, _ := xrayState.snapshot()
	t.Cleanup(func() {
		activeBandwidthNode.Store(restore)
		isManuallyStopped.Store(manual)
		isNeedXrayRestart.Store(restart)
		isNeedXrayReconcile.Store(reconcile)
		xrayState.replace(previousProcess)
	})

	xray := &XrayService{}
	if err := xray.RestartXray(true); err != nil {
		t.Fatalf("start node with no Xray traffic inbounds: %v", err)
	}
	if xray.IsXrayRunning() || xray.DidXrayCrash() || isManuallyStopped.Load() {
		t.Fatal("empty inventory must leave Xray intentionally idle, without marking it manually stopped")
	}

	settings := &XraySettingService{}
	const unbound = `{"inbounds":[{"tag":"unbound","listen":"127.0.0.1","port":44533,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"6e45abb0-c265-4add-97d9-2e6b9588a2a0","email":"user@test.invalid"}]}}]}`
	if err := settings.saveSetting("xrayTemplateConfig", unbound); err != nil {
		t.Fatal(err)
	}
	xray.SetToNeedReconcile()
	xray.ApplyPendingRestart()
	if xray.IsXrayRunning() || xray.DidXrayCrash() || xrayState.heldBackReason() != "" {
		t.Fatal("the stored unbound inbound must be isolated and leave Xray intentionally idle")
	}

	if err := settings.SaveXraySetting("{}"); err != nil {
		t.Fatal(err)
	}
	xray.ApplyPendingRestart()
	if xray.IsXrayRunning() || xray.DidXrayCrash() || xrayState.heldBackReason() != "" {
		t.Fatal("removing the last inbound must return Xray to idle and clear the error")
	}

	if err := settings.saveSetting("xrayTemplateConfig", "{"); err != nil {
		t.Fatal(err)
	}
	if err := xray.RestartXray(false); err == nil || !xray.DidXrayCrash() {
		t.Fatalf("invalid configuration was treated as idle: %v", err)
	}
}

func TestBandwidthManagedInboundEditUsesStoredEnable(t *testing.T) {
	setupEnablePortTest(t)
	restore := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(restore) })
	seedInboundConflict(t, "bandwidth-edit", "127.0.0.1", 44531, model.VLESS, `{"network":"tcp"}`, `{"clients":[]}`)
	stored := loadInboundByTag(t, "bandwidth-edit")
	form := *stored
	form.Protocol = model.MTProto
	form.Settings = `{"routeThroughXray":true,"clients":[]}`
	form.Enable = false
	_, _, err := (&InboundService{}).UpdateInbound(&form)
	if err == nil || !strings.Contains(err.Error(), "bandwidth-managed node") {
		t.Fatalf("allowed a stale disabled form to configure bridged MTProto on an enabled inbound: %v", err)
	}
	after := loadInboundByTag(t, "bandwidth-edit")
	if !after.Enable || after.Protocol != model.VLESS || after.Settings != stored.Settings {
		t.Fatalf("rejected edit modified the saved enabled inbound: %+v", after)
	}

	disableInboundRow(t, stored.Id)
	form = *stored
	form.Protocol = model.MTProto
	form.Settings = `{"routeThroughXray":true,"clients":[]}`
	form.Enable = true
	if _, _, err := (&InboundService{}).UpdateInbound(&form); err != nil {
		t.Fatalf("stale enabled form prevented editing a disabled inbound: %v", err)
	}
	after = loadInboundByTag(t, "bandwidth-edit")
	if after.Enable || after.Protocol != model.MTProto {
		t.Fatalf("disabled edit saved the wrong state: %+v", after)
	}
}

func TestBandwidthManagedEnableChecksAfterQueuedEdit(t *testing.T) {
	setupEnablePortTest(t)
	restore := activeBandwidthNode.Swap(&managedBandwidthNode{})
	t.Cleanup(func() { activeBandwidthNode.Store(restore) })
	seedInboundConflict(t, "bandwidth-enable", "127.0.0.1", 44532, model.VLESS, `{"network":"tcp"}`, `{"clients":[]}`)
	stored := loadInboundByTag(t, "bandwidth-enable")
	disableInboundRow(t, stored.Id)

	StartTrafficWriter()
	t.Cleanup(StopTrafficWriter)
	blocked, release := make(chan struct{}), make(chan struct{})
	releaseWriter := sync.OnceFunc(func() { close(release) })
	defer releaseWriter()
	go func() {
		_ = submitTrafficWrite(func() error {
			close(blocked)
			<-release
			return nil
		})
	}()
	<-blocked

	form := *stored
	form.Protocol = model.MTProto
	form.Settings = `{"routeThroughXray":true,"clients":[]}`
	svc := &InboundService{}
	edited := make(chan error, 1)
	go func() {
		_, _, err := svc.UpdateInbound(&form)
		edited <- err
	}()
	waitForQueuedBandwidthWrite(t, 1, edited)

	enabled := make(chan error, 1)
	go func() {
		_, err := svc.SetInboundEnable(stored.Id, true)
		enabled <- err
	}()
	waitForQueuedBandwidthWrite(t, 2, enabled)
	releaseWriter()
	if err := <-edited; err != nil {
		t.Fatalf("update disabled inbound before enable: %v", err)
	}
	if err := <-enabled; err == nil || !strings.Contains(err.Error(), "bandwidth-managed node") {
		t.Fatalf("enable did not reject the newly saved bridged MTProto configuration: %v", err)
	}
	after := loadInboundByTag(t, "bandwidth-enable")
	if after.Enable || after.Protocol != model.MTProto {
		t.Fatalf("concurrent edit/enable left the wrong saved state: %+v", after)
	}
}

func waitForQueuedBandwidthWrite(t *testing.T, want int, result <-chan error) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		twMu.Lock()
		count := len(twQueue)
		twMu.Unlock()
		if count == want {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("write returned before joining the queue: %v", err)
		case <-deadline.C:
			t.Fatalf("write queue length = %d, want %d", count, want)
		case <-tick.C:
		}
	}
}
