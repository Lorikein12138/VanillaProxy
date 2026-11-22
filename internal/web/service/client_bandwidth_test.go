package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wirecodec"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestRemoteBandwidthProxySnapshotBindsExactOwnerOnDirectPeer(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	const email = "owner@proxy.test"
	const peerGUID = "physical-proxy-guid"
	const peerOwnerID = 105
	const hubOwnerID = 117
	const vlessID = "22222222-2222-2222-2222-222222222222"
	peerOwner := model.ClientRecord{Id: peerOwnerID, Email: email}
	if err := db.Create(&peerOwner).Error; err != nil {
		t.Fatal(err)
	}
	marked := fmt.Sprintf(`{"user":"proxy-user","pass":"node-secret","bandwidthClientId":%d}`, peerOwnerID)
	rows, err := nodeSnapshotProxyBindings([]*model.Inbound{
		{Id: 21, Tag: "bound-http", Port: 31001, Protocol: model.HTTP, OriginNodeGuid: peerGUID, Enable: true,
			Settings: `{"users":[` + marked + `]}`},
		{Id: 22, Tag: "bound-mixed", Port: 31002, Protocol: model.Mixed, OriginNodeGuid: peerGUID, Enable: true,
			Settings: `{"auth":"password","users":[{"user":"shadowed","pass":"shadowed"}],"accounts":[` + marked + `,{"user":"legacy","pass":"unused"}]}`},
		{Id: 23, Tag: "bound-vless", Port: 31003, Protocol: model.VLESS, OriginNodeGuid: peerGUID, Enable: true,
			Settings: `{"clients":[{"email":"` + email + `","id":"` + vlessID + `","enable":true}]}`},
	}, peerGUID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[:2] {
		if strings.Contains(row.Settings, "bandwidthClientId") || row.BandwidthProxyBindings == nil || len(*row.BandwidthProxyBindings) != 1 {
			t.Fatal("a peer snapshot did not isolate the explicitly mapped effective account")
		}
	}
	leafA := (*rows[0].BandwidthProxyBindings)[0]
	if leafA.LeafOwnerKey == "" || leafA.LeafOwnerKey != (*rows[1].BandwidthProxyBindings)[0].LeafOwnerKey {
		t.Fatal("the leaf owner key must be stable across HTTP and Mixed inbounds")
	}
	if err := db.Model(&peerOwner).Update("enable", false).Error; err != nil {
		t.Fatal(err)
	}
	suspended, err := nodeSnapshotProxyBindings([]*model.Inbound{
		{Protocol: model.HTTP, OriginNodeGuid: peerGUID, Enable: true, Settings: `{"accounts":[` + marked + `]}`},
		{Protocol: model.HTTP, OriginNodeGuid: peerGUID, Enable: false, Settings: `{"accounts":[` + marked + `]}`},
		{Protocol: model.HTTP, OriginNodeGuid: peerGUID, Enable: true, Settings: `{"accounts":{},"users":[{"user":"valid","pass":"secret"}]}`},
	}, peerGUID)
	if err != nil || len(suspended) != 3 {
		t.Fatalf("leaf projection failed: %v", err)
	}
	for _, row := range suspended {
		if row.BandwidthProxyBindings != nil {
			t.Fatal("temporary leaf suspension or malformed settings were represented as an explicit unbind")
		}
	}
	// Switch from the simulated peer's local owner table to the hub's IDs.
	if err := db.Delete(&peerOwner).Error; err != nil {
		t.Fatal(err)
	}
	for _, client := range []model.ClientRecord{{Id: hubOwnerID, Email: email, UUID: vlessID}, {Id: peerOwnerID, Email: "legacy"}} {
		if err := db.Create(&client).Error; err != nil {
			t.Fatal(err)
		}
	}
	cloneHTTP := func(id int, tag string) runtime.NodeSnapshotInbound {
		row := *rows[0].Inbound
		row.Id, row.Tag, row.Port = id, tag, 31000+id
		return runtime.NodeSnapshotInbound{Inbound: &row, BandwidthProxyBindings: rows[0].BandwidthProxyBindings}
	}
	foreignOrigin := cloneHTTP(25, "foreign-origin")
	foreignOrigin.OriginNodeGuid = "other-physical-panel"
	nested := cloneHTTP(26, "nested")
	nested.NodeID = new(int)
	foreignID := cloneHTTP(27, "foreign-id")
	foreignID.Settings = `{"accounts":[` + marked + `]}`
	wrongCredential := cloneHTTP(28, "wrong-credential")
	wrongCredential.Settings = `{"accounts":[{"user":"proxy-user","pass":"different"}]}`
	rows = append(rows, foreignOrigin, nested, foreignID, wrongCredential)
	var response atomic.Value
	publish := func() {
		t.Helper()
		body, err := json.Marshal(map[string]any{"success": true, "obj": rows})
		if err != nil {
			t.Fatal(err)
		}
		response.Store(body)
	}
	publish()
	var requestedProxyBindings atomic.Bool
	var completePrivateInventory atomic.Bool
	completePrivateInventory.Store(true)
	var redirectList atomic.Bool
	var redirectedPrivateQuery atomic.Bool
	var reachedRedirectTarget atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panel/api/inbounds/list" {
			requestedProxyBindings.Store(r.URL.Query().Get(wirecodec.BandwidthProxyBindingsQuery) == "1")
			if redirectList.Load() {
				http.Redirect(w, r, "/redirected-list?"+r.URL.RawQuery, http.StatusFound)
				return
			}
			if completePrivateInventory.Load() && requestedProxyBindings.Load() {
				w.Header().Set(wirecodec.BandwidthProxyInventoryHeader, peerGUID)
			}
			_, _ = w.Write(response.Load().([]byte))
			return
		}
		if r.URL.Path == "/redirected-list" {
			reachedRedirectTarget.Store(true)
			if r.URL.Query().Get(wirecodec.BandwidthProxyBindingsQuery) == "1" {
				redirectedPrivateQuery.Store(true)
			}
			_, _ = w.Write(response.Load().([]byte))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"obj":null}`))
	})
	peer := httptest.NewTLSServer(handler)
	defer peer.Close()
	port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(peer.Certificate().Raw)
	node := model.Node{Name: "physical", Scheme: "https", Address: "127.0.0.1", Port: port, BasePath: "/",
		ApiToken: "test-token", Guid: peerGUID, Enable: true, AllowPrivateAddress: true, TlsVerifyMode: "pin", PinnedCertSha256: hex.EncodeToString(pin[:])}
	if err := db.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	fetch := func(node *model.Node) *runtime.TrafficSnapshot {
		t.Helper()
		snapshot, err := runtime.NewRemote(node, nil).FetchTrafficSnapshot(t.Context())
		if err != nil || len(snapshot.Inbounds) != len(rows) {
			t.Fatalf("snapshot failed: %v", err)
		}
		return snapshot
	}
	merge := func(snapshot *runtime.TrafficSnapshot) {
		t.Helper()
		if _, err := (&InboundService{}).setRemoteTrafficLocked(node.Id, snapshot, false, false); err != nil {
			t.Fatal(err)
		}
	}
	assertProtocols := func(want ...string) {
		t.Helper()
		inventory, err := readBandwidthInventory(db)
		if err != nil || len(inventory) != 2 || inventory[1].ID != hubOwnerID || len(inventory[0].Attachments) != 0 || len(inventory[1].Attachments) != 1 {
			t.Fatalf("unexpected node/owners: %+v, %v", inventory, err)
		}
		attachment := inventory[1].Attachments[synthNodeGuid(node.Id)]
		var got []string
		for _, binding := range attachment.Bindings {
			got = append(got, binding.Protocol)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) || attachment.Unsupported {
			t.Fatalf("direct peer protocols: %v; want %v", got, want)
		}
	}
	first := fetch(&node)
	if !requestedProxyBindings.Load() {
		t.Fatal("pinned HTTPS did not opt into private metadata")
	}
	merge(first)
	assertProtocols("http", "mixed", "vless")
	redirectList.Store(true)
	if fetch(&node).HasBandwidthProxyBindings() || !reachedRedirectTarget.Load() || redirectedPrivateQuery.Load() {
		t.Fatal("redirected snapshot did not fall back without forwarding private metadata opt-in")
	}
	redirectList.Store(false)
	nodes := &NodeService{}
	stale := fetch(&node)
	if err := nodes.MarkNodeDirty(node.Id); err != nil {
		t.Fatal(err)
	}
	_, _, _, dirtyAt, err := nodes.NodeSyncState(node.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodes.ClearNodeDirty(node.Id, dirtyAt); err != nil {
		t.Fatal(err)
	}
	assertProtocols("vless")
	merge(stale)
	assertProtocols("vless")
	time.Sleep(time.Millisecond)
	merge(fetch(&node))
	assertProtocols("http", "mixed", "vless")
	stale = fetch(&node)
	for _, enabled := range []bool{false, true} {
		if err := nodes.SetEnable(node.Id, enabled); err != nil {
			t.Fatal(err)
		}
	}
	merge(stale)
	assertProtocols("vless")
	time.Sleep(time.Millisecond)
	merge(fetch(&node))
	assertProtocols("http", "mixed", "vless")
	if err := db.Model(&model.Inbound{}).Where("node_id = ? AND protocol = ?", node.Id, model.Mixed).
		Update("settings", `{"auth":"password","accounts":[{"user":"proxy-user","pass":"rotated"}]}`).Error; err != nil {
		t.Fatal(err)
	}
	assertProtocols("http", "vless")
	merge(fetch(&node))
	assertProtocols("http", "mixed", "vless")
	rows[0].BandwidthProxyBindings = nil // older node
	empty := []runtime.BandwidthProxyBinding{}
	rows[1].BandwidthProxyBindings = &empty // newer node, explicitly unbound
	publish()
	unbound := fetch(&node)
	bindings := unbound.BandwidthProxyBindingsFor(&node)
	if _, legacyHasField := bindings[rows[0].Id]; legacyHasField || bindings[rows[1].Id] == nil || len(bindings[rows[1].Id]) != 0 {
		t.Fatal("old and explicitly empty snapshots were conflated")
	}
	merge(unbound)
	assertProtocols("vless")
	var count int64
	if err := db.Model(&model.RemoteBandwidthProxyBinding{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("an omitted projection must be preserved and an explicit empty removed: %d, %v", count, err)
	}
	rows[0].BandwidthProxyBindings = foreignOrigin.BandwidthProxyBindings
	publish()
	unverified := node
	unverified.TlsVerifyMode = "skip"
	if fetch(&unverified).HasBandwidthProxyBindings() || requestedProxyBindings.Load() {
		t.Fatal("unverified HTTPS received authority-eligible proxy metadata")
	}
	plain := httptest.NewServer(handler)
	defer plain.Close()
	unverified.Scheme = "http"
	unverified.Port, err = strconv.Atoi(strings.TrimPrefix(plain.URL, "http://127.0.0.1:"))
	if err != nil || fetch(&unverified).HasBandwidthProxyBindings() || requestedProxyBindings.Load() {
		t.Fatal("plaintext HTTP received authority-eligible proxy metadata")
	}

	// Keep a single physical HTTP inbound while the hub email is reused.
	rows = rows[:1]
	rows[0].BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{leafA}
	publish()
	merge(fetch(&node))
	leafEdited := peerOwner
	leafEdited.CreatedAt++
	if remoteProxyOwnerKey(peerGUID, leafEdited) != leafA.LeafOwnerKey {
		t.Fatal("mutable creation date changed an existing leaf owner identity")
	}
	if err := db.Delete(&model.ClientRecord{}, hubOwnerID).Error; err != nil {
		t.Fatal(err)
	}
	replacement := model.ClientRecord{Email: email}
	if err := db.Create(&replacement).Error; err != nil || replacement.Id == hubOwnerID {
		t.Fatalf("hub did not create a distinct replacement account: %v", err)
	}
	assertOwnerNode := func(owner string, want ...string) {
		t.Helper()
		settings, err := (ClientBandwidthService{}).Get(t.Context(), nil, owner)
		if err != nil || !slices.Equal(settings.AccountNodeKeys, want) {
			t.Fatalf("proxy owner %s resolved to %v; want %v (%v)", owner, settings.AccountNodeKeys, want, err)
		}
	}
	assertOwnerNode(email) // The earlier active binding also retains its original hub ID.
	for range 2 {
		merge(fetch(&node))
		assertOwnerNode(email)
	}
	leafA.CredentialFingerprint = bandwidthexchange.CredentialFingerprint("http", bandwidthexchange.CredentialParts("proxy-user", "new-password"))
	rows[0].Settings = `{"accounts":[{"user":"proxy-user","pass":"new-password"}]}`
	rows[0].BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{leafA}
	publish()
	merge(fetch(&node))
	assertOwnerNode(email)
	rows[0].Enable = false
	rows[0].BandwidthProxyBindings = &empty
	publish()
	merge(fetch(&node))
	rows[0].Enable = true
	rows[0].BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{leafA}
	publish()
	merge(fetch(&node))
	assertOwnerNode(email)

	leafB := leafA
	leafB.LeafOwnerKey = remoteProxyOwnerKey(peerGUID, model.ClientRecord{Id: peerOwnerID + 1})
	rows[0].BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{leafB}
	publish()
	merge(fetch(&node))
	assertOwnerNode(email, synthNodeGuid(node.Id))

	const lateEmail = "late@proxy.test"
	late := leafA
	late.OwnerEmail = lateEmail
	late.LeafOwnerKey = remoteProxyOwnerKey(peerGUID, model.ClientRecord{Id: peerOwnerID + 2})
	rows[0].BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{late}
	publish()
	merge(fetch(&node))
	if err := db.Model(&model.RemoteBandwidthProxyOwnerPin{}).Where("peer_guid = ? AND leaf_owner_key = ?", peerGUID, late.LeafOwnerKey).
		Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("absence of a local account incorrectly created a permanent pin: %d, %v", count, err)
	}
	lateOwner := model.ClientRecord{Email: lateEmail, SyncOrphanedAt: time.Now().Add(-time.Hour).UnixMilli()}
	if err := db.Create(&lateOwner).Error; err != nil {
		t.Fatal(err)
	}
	merge(fetch(&node))
	assertOwnerNode(lateEmail, synthNodeGuid(node.Id))
	rows[0].BandwidthProxyBindings = &empty
	publish()
	merge(fetch(&node))
	assertOrphanProtected := func(want bool) {
		t.Helper()
		linked, err := bandwidthProxyLinkedClients(db)
		if err != nil || linked[lateOwner.Id] != want {
			t.Fatalf("last confirmed orphan protection: got %v, want %v (%v)", linked[lateOwner.Id], want, err)
		}
	}
	assertOrphanProtected(false)

	confirmed := rows[0]
	confirmed.BandwidthProxyBindings = &[]runtime.BandwidthProxyBinding{late}
	other := runtime.NodeSnapshotInbound{Inbound: &model.Inbound{Id: 40, Tag: "other-still-present", Protocol: model.VLESS,
		Port: 31040, Enable: true, OriginNodeGuid: peerGUID, Settings: `{"clients":[]}`}}
	rows = []runtime.NodeSnapshotInbound{confirmed, other}
	publish()
	merge(fetch(&node))
	assertOrphanProtected(true)

	// An older TLS peer or a redirect fallback can still sweep the ordinary
	// mirror. Neither signifies absence from the authenticated private roster.
	rows = []runtime.NodeSnapshotInbound{other}
	completePrivateInventory.Store(false)
	publish()
	merge(fetch(&node))
	if err := db.Model(&model.Inbound{}).Where("node_id = ? AND tag = ?", node.Id, confirmed.Tag).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("legacy snapshot changed the ordinary mirror sweep: %d, %v", count, err)
	}
	assertOrphanProtected(true)
	completePrivateInventory.Store(true)
	redirectList.Store(true)
	merge(fetch(&node))
	assertOrphanProtected(true)
	redirectList.Store(false)

	malformed := *confirmed.Inbound
	malformed.Settings = `{"accounts":{}}`
	broken, err := nodeSnapshotProxyBindings([]*model.Inbound{&malformed}, peerGUID)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(broken, other)
	publish()
	merge(fetch(&node))
	assertOrphanProtected(true)
	rows = []runtime.NodeSnapshotInbound{other}
	publish()
	merge(fetch(&node))
	assertOrphanProtected(false)
	if removed, err := (&ClientService{}).ReapSyncOrphans(); err != nil || removed != 1 {
		t.Fatalf("confirmed remote inbound deletion did not release orphan protection: %d, %v", removed, err)
	}
}

func TestRemoteProxyOnlyBandwidthSettingsAndOrphanProtection(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	ctx := t.Context()
	owner := model.ClientRecord{Email: "remote-only@proxy.test", SyncOrphanedAt: time.Now().Add(-time.Hour).UnixMilli()}
	bystander := model.ClientRecord{Email: "unbound@proxy.test", SyncOrphanedAt: owner.SyncOrphanedAt}
	peer := model.Node{Name: "serving-peer", Guid: "serving-peer-guid"}
	other := model.Node{Name: "other-peer", Guid: "other-peer-guid"}
	for _, row := range []any{&owner, &bystander, &peer, &other} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	const proxySettings = `"accounts":[{"user":"proxy-user","pass":"proxy-secret"}]`
	for _, inbound := range []*model.Inbound{
		{Tag: "remote-only-http", Port: 32100, Protocol: model.HTTP, Settings: `{` + proxySettings + `}`},
		{Tag: "remote-only-mixed", Port: 32101, Protocol: model.Mixed, Settings: `{"auth":"password",` + proxySettings + `}`},
	} {
		inbound.NodeID, inbound.OriginNodeGuid, inbound.Enable = &peer.Id, peer.Guid, true
		if err := db.Create(inbound).Error; err != nil {
			t.Fatal(err)
		}
		bindings, err := json.Marshal([]storedRemoteProxyBinding{{
			BandwidthProxyBinding: runtime.BandwidthProxyBinding{
				OwnerEmail: owner.Email, LeafOwnerKey: remoteProxyOwnerKey(peer.Guid, owner),
				CredentialFingerprint: bandwidthexchange.CredentialFingerprint(string(inbound.Protocol),
					bandwidthexchange.CredentialParts("proxy-user", "proxy-secret")),
			},
			ClientID: owner.Id,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.RemoteBandwidthProxyBinding{InboundID: inbound.Id, RemoteInboundID: inbound.Id + 100, NodeID: peer.Id, OriginGUID: peer.Guid,
			Bindings: string(bindings), PolicyActive: true}).Error; err != nil {
			t.Fatal(err)
		}
	}
	var ordinaryLinks int64
	if err := db.Model(&model.ClientInbound{}).Where("client_id = ?", owner.Id).Count(&ordinaryLinks).Error; err != nil || ordinaryLinks != 0 {
		t.Fatalf("fixture already has ordinary inbound links: %d, %v", ordinaryLinks, err)
	}
	service := ClientBandwidthService{}
	peerKey, otherKey := synthNodeGuid(peer.Id), synthNodeGuid(other.Id)
	settings, err := service.Get(ctx, nil, owner.Email)
	if err != nil || !slices.Equal(settings.AccountNodeKeys, []string{peerKey}) {
		t.Fatalf("remote-only settings returned %+v (%v)", settings, err)
	}
	policy := bandwidthruntime.ClientBandwidthPolicy{TotalBitsPerSecond: 1000, NodeBitsPerSecond: map[string]int64{peerKey: 500}}
	settings, err = service.Save(ctx, nil, owner.Email, policy)
	if err != nil || !slices.Equal(settings.AccountNodeKeys, []string{peerKey}) || settings.NodeBitsPerSecond[peerKey] != 500 {
		t.Fatalf("remote-only save returned %+v (%v)", settings, err)
	}
	for _, key := range []string{"local", otherKey} {
		policy.NodeBitsPerSecond = map[string]int64{key: 250}
		if _, err := service.Save(ctx, nil, owner.Email, policy); err == nil {
			t.Errorf("save accepted unattached node %s", key)
		}
	}
	nodes := &NodeService{}
	if err := nodes.MarkNodeDirty(peer.Id); err != nil {
		t.Fatal(err)
	}
	_, _, _, dirtyAt, err := nodes.NodeSyncState(peer.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodes.ClearNodeDirty(peer.Id, dirtyAt); err != nil {
		t.Fatal(err)
	}
	if removed, err := (&ClientService{}).ReapSyncOrphans(); err != nil || removed != 1 {
		t.Fatalf("after dirty clear, sync orphan cleanup removed %d clients (%v)", removed, err)
	}
	if err := nodes.SetEnable(peer.Id, false); err != nil {
		t.Fatal(err)
	}
	if err := nodes.SetEnable(peer.Id, true); err != nil {
		t.Fatal(err)
	}
	settings, err = service.Get(ctx, nil, owner.Email)
	if err != nil || len(settings.AccountNodeKeys) != 0 {
		t.Fatalf("re-enabling the peer automatically restored an old policy: %+v, %v", settings, err)
	}
	if removed, err := (&ClientService{}).DeleteOrphans(); err != nil || removed != 0 {
		t.Fatalf("manual orphan cleanup removed %d clients (%v)", removed, err)
	}
	if err := db.Model(&model.RemoteBandwidthProxyBinding{}).Where("node_id = ?", peer.Id).Update("policy_active", true).Error; err != nil {
		t.Fatal(err)
	}
	standard := model.Inbound{Tag: "ordinary-vless", Port: 32102, Protocol: model.VLESS, NodeID: &other.Id, Enable: true, Settings: `{"clients":[]}`}
	if err := db.Create(&standard).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: owner.Id, InboundId: standard.Id}).Error; err != nil {
		t.Fatal(err)
	}
	policy.NodeBitsPerSecond = map[string]int64{peerKey: 500, otherKey: 300}
	settings, err = service.Save(ctx, nil, owner.Email, policy)
	if err != nil || !slices.Equal(settings.AccountNodeKeys, []string{peerKey, otherKey}) {
		t.Fatalf("ordinary and proxy node associations did not merge: %+v (%v)", settings, err)
	}
}

func TestRemoteProxyBindingsSurviveReusedMirrorID(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	peer := model.Node{Name: "physical-peer", Guid: "physical-peer-guid"}
	previous := model.ClientRecord{Email: "archived@proxy.test"}
	current := model.ClientRecord{Email: "current@proxy.test"}
	for _, row := range []any{&peer, &previous, &current} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	mirror := model.Inbound{Tag: "reused-mirror", Enable: true, NodeID: &peer.Id, OriginNodeGuid: peer.Guid, Port: 32320,
		Protocol: model.HTTP, Settings: `{"accounts":[{"user":"proxy-user","pass":"current-secret"}]}`}
	if err := db.Create(&mirror).Error; err != nil {
		t.Fatal(err)
	}
	projection := func(owner model.ClientRecord, remoteID int, password string, active bool) model.RemoteBandwidthProxyBinding {
		t.Helper()
		bindings, err := json.Marshal([]storedRemoteProxyBinding{{
			BandwidthProxyBinding: runtime.BandwidthProxyBinding{
				OwnerEmail: owner.Email, LeafOwnerKey: remoteProxyOwnerKey(peer.Guid, owner),
				CredentialFingerprint: bandwidthexchange.CredentialFingerprint("http", bandwidthexchange.CredentialParts("proxy-user", password)),
			},
			ClientID: owner.Id,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return model.RemoteBandwidthProxyBinding{
			NodeID: peer.Id, OriginGUID: peer.Guid, InboundID: mirror.Id, RemoteInboundID: remoteID, Bindings: string(bindings), PolicyActive: active,
		}
	}
	archived := projection(previous, 101, "old-secret", false)
	active := projection(current, 102, "current-secret", true)
	for _, record := range []model.RemoteBandwidthProxyBinding{archived, active, active} {
		if err := upsertRemoteBandwidthProxyBindings(db, []model.RemoteBandwidthProxyBinding{record}); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := db.Model(&model.RemoteBandwidthProxyBinding{}).Where("inbound_id = ?", mirror.Id).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("physical projections overwrote one another: %d, %v", count, err)
	}
	settings, err := (ClientBandwidthService{}).Get(t.Context(), nil, current.Email)
	if err != nil || !slices.Equal(settings.AccountNodeKeys, []string{synthNodeGuid(peer.Id)}) {
		t.Fatalf("active physical binding was not projected: %+v, %v", settings, err)
	}
	if _, err := (&InboundService{}).DelInbound(mirror.Id); err != nil {
		t.Fatal(err)
	}
	var copies []model.RemoteBandwidthProxyBinding
	if err := db.Find(&copies).Error; err != nil || !slices.Equal(copies, []model.RemoteBandwidthProxyBinding{archived}) {
		t.Fatalf("mirror delete lost the archived physical binding or kept the deleted one: %+v, %v", copies, err)
	}
	linked, err := bandwidthProxyLinkedClients(db)
	if err != nil || !linked[previous.Id] || linked[current.Id] {
		t.Fatalf("orphan protection followed the local ID instead of the physical inbound: %v, %v", linked, err)
	}
}

func TestBandwidthInventoryPinsEachRemoteMirrorCredential(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	const email = "shared@example.test"
	const ssMethod = "2022-blake3-aes-128-gcm"
	master := strings.Repeat("a", 16)
	masterKey := base64.StdEncoding.EncodeToString([]byte(master))
	client := model.ClientRecord{Email: email, UUID: "11111111-2222-3333-4444-555555555555", Auth: "hub-auth", Password: "hub-password"}
	if err := db.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	want := make(map[string][]bandwidthexchange.PolicyBinding)
	writeInbound := func(nodeID *int, protocol model.Protocol, wireProtocol, fields, serverFields, credential string) {
		t.Helper()
		key := "local"
		if nodeID != nil {
			key = synthNodeGuid(*nodeID)
		}
		inbound := model.Inbound{UserId: 1, Protocol: protocol, Enable: true, NodeID: nodeID,
			Tag: fmt.Sprintf("pin-%s-%d", key, len(want[key])), Port: 25000 + len(want[key]),
			Settings: fmt.Sprintf(`{%s"clients":[{"email":%q,"enable":true%s}]}`, serverFields, email, fields)}
		if err := db.Create(&inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
		want[key] = append(want[key], bandwidthexchange.PolicyBinding{
			Protocol: wireProtocol, Fingerprint: bandwidthexchange.CredentialFingerprint(wireProtocol, credential),
		})
	}
	for i := range 2 {
		node := model.Node{Name: fmt.Sprintf("pin-node-%d", i), Guid: fmt.Sprintf("pin-guid-%d", i)}
		if err := db.Create(&node).Error; err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("11111111-2222-3333-4444-%012d", i+1)
		auth, password := fmt.Sprintf("peer-auth-%d", i), fmt.Sprintf("peer-password-%d", i)
		ssKey := strings.Repeat(string(rune('b'+i)), 16)
		writeInbound(&node.Id, model.VLESS, "vless", fmt.Sprintf(`,"id":%q`, id), "", id)
		writeInbound(&node.Id, model.VMESS, "vmess", fmt.Sprintf(`,"id":%q`, id), "", id)
		writeInbound(&node.Id, model.Hysteria, "hysteria", fmt.Sprintf(`,"auth":%q`, auth), "", auth)
		writeInbound(&node.Id, model.Trojan, "trojan", fmt.Sprintf(`,"password":%q`, password), "", password)
		writeInbound(&node.Id, model.MASQUE, "masque", fmt.Sprintf(`,"pass":%q`, password), "", password)
		writeInbound(&node.Id, model.Shadowsocks, "shadowsocks", fmt.Sprintf(`,"password":%q`, password), `"method":"aes-256-gcm",`,
			bandwidthexchange.CredentialParts("aes-256-gcm", password))
		writeInbound(&node.Id, model.Shadowsocks, "shadowsocks-2022", fmt.Sprintf(`,"password":%q`, base64.StdEncoding.EncodeToString([]byte(ssKey))),
			fmt.Sprintf(`"method":%q,"password":%q,`, ssMethod, masterKey), bandwidthexchange.CredentialParts(ssMethod, master, ssKey))
		// A mirrored inbound without a stored legacy auth inherits the hub row.
		writeInbound(&node.Id, model.Hysteria, "hysteria", "", "", client.Auth)
	}
	writeInbound(nil, model.VLESS, "vless", `,"id":"stale-local-id"`, "", client.UUID)
	writeInbound(nil, model.Trojan, "trojan", `,"password":"stale-local-password"`, "", client.Password)
	accounts, err := readBandwidthInventory(db)
	if err != nil || len(accounts) != 1 || len(accounts[0].Attachments) != len(want) {
		t.Fatalf("inventory: %+v, %v", accounts, err)
	}
	for key, expected := range want {
		attachment := accounts[0].Attachments[key]
		if attachment.Unsupported || !slices.Equal(attachment.Bindings, expected) {
			t.Errorf("node %q: %+v, want %+v", key, attachment, expected)
		}
	}
}

func TestBandwidthProxyBindingsUseCommittedClientIDs(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	owner := model.ClientRecord{Email: "owner@panel.test", SyncOrphanedAt: time.Now().Add(-time.Hour).UnixMilli()}
	legacy := model.ClientRecord{Email: "authenticated-user", SyncOrphanedAt: owner.SyncOrphanedAt}
	for _, client := range []*model.ClientRecord{&owner, &legacy} {
		if err := db.Create(client).Error; err != nil {
			t.Fatal(err)
		}
	}
	const username = "authenticated-user"
	settings := func(protocol model.Protocol, password string) string {
		marked := fmt.Sprintf(`{"user":%q,"pass":%q,"bandwidthClientId":%d}`, username, password, owner.Id)
		if protocol == model.HTTP {
			return `{"users":[` + marked + `]}`
		}
		return `{"auth":"password","udp":true,"users":[{"user":"shadowed","pass":"unused"}],"accounts":[` + marked + `,{"user":"static-user","pass":"static-secret"}]}`
	}
	httpInbound := model.Inbound{Tag: "proxy-http", Port: 20001, Protocol: model.HTTP, Enable: true, Settings: settings(model.HTTP, "original")}
	mixedInbound := model.Inbound{Tag: "proxy-mixed", Port: 20002, Protocol: model.Mixed, Enable: true, Settings: settings(model.Mixed, "original")}
	for _, row := range []*model.Inbound{&httpInbound, &mixedInbound} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	remoteID := 101
	remote := model.Inbound{Tag: "proxy-mirror", Port: 20003, Protocol: model.HTTP, Enable: true, NodeID: &remoteID, Settings: settings(model.HTTP, "remote")}
	if err := db.Create(&remote).Error; err != nil {
		t.Fatal(err)
	}
	inventory, err := readBandwidthInventory(db)
	if err != nil || len(inventory) != 2 || inventory[0].ID != owner.Id || len(inventory[0].Attachments) != 1 || len(inventory[1].Attachments) != 0 {
		t.Fatalf("unexpected proxy associations: %+v (%v)", inventory, err)
	}
	allowed := make(map[bandwidthexchange.PolicyBinding]bool)
	for _, binding := range inventory[0].Attachments["local"].Bindings {
		allowed[binding] = true
	}
	for _, protocol := range []string{"http", "mixed"} {
		if !allowed[bandwidthexchange.PolicyBinding{Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, bandwidthexchange.CredentialParts(username, "original"))}] {
			t.Fatalf("missing exact %s credential", protocol)
		}
	}
	if len(allowed) != 2 {
		t.Fatalf("policy included an ineffective or remote proxy account: %v", allowed)
	}
	policy := bandwidthruntime.ClientBandwidthPolicy{TotalBitsPerSecond: 500, NodeBitsPerSecond: map[string]int64{"local": 200}}
	saved, err := (ClientBandwidthService{}).Save(t.Context(), nil, owner.Email, policy)
	if err != nil || !slices.Equal(saved.AccountNodeKeys, []string{"local"}) || saved.NodeBitsPerSecond["local"] != 200 {
		t.Fatalf("mapped-only client could not set a local cap: %+v (%v)", saved, err)
	}
	if _, err := (ClientBandwidthService{}).Save(t.Context(), nil, legacy.Email, policy); err == nil {
		t.Fatal("matching username guessed a panel association")
	}
	prepare := func() (*xray.Config, map[string]map[string]string) {
		t.Helper()
		config := &xray.Config{}
		for _, record := range []model.Inbound{httpInbound, mixedInbound} {
			generated, err := (&InboundService{}).buildGeneratedXrayInbound(db, &record, true)
			if err != nil {
				t.Fatal(err)
			}
			config.InboundConfigs = append(config.InboundConfigs, *generated)
		}
		prepared, bindings, err := prepareBandwidthXrayConfigWithPolicy(true, config, func(username string) (string, bool) {
			return "legacy-ID", username == "static-user"
		}, func(protocol, email, credential string) (string, bool) {
			return "owner-ID", email == owner.Email && allowed[bandwidthexchange.PolicyBinding{
				Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, credential),
			}]
		})
		if err != nil {
			t.Fatal(err)
		}
		return prepared, bindings
	}
	prepared, bindings := prepare()
	if len(prepared.InboundConfigs) != 2 || bindings[httpInbound.Tag][username] != "owner-ID" ||
		bindings[mixedInbound.Tag][username] != "owner-ID" || bindings[mixedInbound.Tag]["static-user"] != "legacy-ID" {
		t.Fatalf("incorrect managed native bindings: %v", bindings)
	}
	for _, inbound := range prepared.InboundConfigs {
		if strings.Contains(string(inbound.Settings), "bandwidthClientId") || strings.Contains(string(inbound.Settings), "shadowed") {
			t.Fatal("managed child received panel metadata or an ineffective account alias")
		}
	}
	live, err := liveBandwidthXrayPolicyAccounts(prepared, bindings)
	if err != nil || len(live) != 1 || len(live[owner.Email]) != 2 {
		t.Fatalf("acknowledgement used a native username or legacy account: %v (%v)", live, err)
	}
	for _, inbound := range []*model.Inbound{&httpInbound, &mixedInbound} {
		inbound.Settings = settings(inbound.Protocol, "rotated")
		if err := db.Model(inbound).UpdateColumn("settings", inbound.Settings).Error; err != nil {
			t.Fatal(err)
		}
	}
	prepared, bindings = prepare()
	if len(prepared.InboundConfigs) != 1 || prepared.InboundConfigs[0].Tag != mixedInbound.Tag ||
		!maps.Equal(bindings[mixedInbound.Tag], map[string]string{"static-user": "legacy-ID"}) {
		t.Fatalf("rotated credentials left an unsafe listener or binding: %v", bindings)
	}
	if removed, err := (&ClientService{}).ReapSyncOrphans(); err != nil || removed != 1 {
		t.Fatalf("orphan sweep deleted a mapped owner or kept a bystander: %d (%v)", removed, err)
	}
	if removed, err := (&ClientService{}).DeleteOrphans(); err != nil || removed != 0 {
		t.Fatalf("orphan cleanup deleted the mapped owner: %d (%v)", removed, err)
	}
	for _, protocol := range []string{"http", "mixed"} {
		allowed[bandwidthexchange.PolicyBinding{Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, bandwidthexchange.CredentialParts(username, "rotated"))}] = true
	}
	if _, current := prepare(); current[httpInbound.Tag][username] != "owner-ID" || current[mixedInbound.Tag][username] != "owner-ID" {
		t.Fatalf("new policy did not admit the rotated credentials: %v", current)
	}
	if _, err := (&ClientService{}).Delete(&InboundService{}, owner.Id, false); err != nil {
		t.Fatal(err)
	}
	prepared, bindings = prepare()
	if len(prepared.InboundConfigs) != 1 || !maps.Equal(bindings[mixedInbound.Tag], map[string]string{"static-user": "legacy-ID"}) {
		t.Fatalf("a removed panel owner still permits traffic: %v", bindings)
	}
}

func TestBandwidthPhysicalNodeKeys(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	first := model.Node{Name: "first clone", Guid: "shared"}
	second := model.Node{Name: "second clone", Guid: "shared"}
	unique := model.Node{Name: "unique", Guid: "unique-child"}
	client := model.ClientRecord{Email: "physical-nodes@example.test"}
	for _, row := range []any{&first, &second, &unique, &client} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	const childID = 1234
	synthetic := synthNodeGuid(childID)
	options := []struct {
		parent *int
		origin string
		want   string
	}{
		{nil, "current-panel-guid", "local"},
		{&first.Id, "shared", synthNodeGuid(first.Id)},
		{&second.Id, "shared", synthNodeGuid(second.Id)},
		{&first.Id, synthetic, fmt.Sprintf("via:%d:%d", first.Id, childID)},
		{&second.Id, synthetic, fmt.Sprintf("via:%d:%d", second.Id, childID)},
		{&first.Id, "unique-child", synthNodeGuid(unique.Id)},
		{&unique.Id, "unique-child", synthNodeGuid(unique.Id)},
		{&first.Id, "unknown-child", "guid:unknown-child"},
		{&second.Id, "unknown-child", "guid:unknown-child"},
	}
	wantKeys := make(map[string]struct{}, len(options))
	for index, option := range options {
		inbound := model.Inbound{
			UserId: 1, Tag: fmt.Sprintf("bandwidth-test-%d", index), Port: 20000 + index, Protocol: model.VLESS,
			NodeID: option.parent, OriginNodeGuid: option.origin,
		}
		if err := db.Create(&inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
		wantKeys[option.want] = struct{}{}
	}
	got, err := (&InboundService{}).GetInboundOptions(1)
	if err != nil || len(got) != len(options) {
		t.Fatalf("got %d options, err %v", len(got), err)
	}
	for index, option := range options {
		if got[index].BandwidthNodeKey != option.want {
			t.Errorf("option %d key = %s, want %s", index, got[index].BandwidthNodeKey, option.want)
		}
	}
	gotKeys, err := clientBandwidthNodes(db, client.Id)
	if err != nil || !maps.Equal(gotKeys, wantKeys) {
		t.Fatalf("associated keys = %v, %v, want %v", gotKeys, err, wantKeys)
	}
}

func TestReadBandwidthInventoryReflectsCommittedAssociationsAndRates(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	node := model.Node{Name: "direct bandwidth node", Guid: "direct-bandwidth"}
	existing := model.ClientRecord{Email: "existing@example.test", UUID: "vless-credential", Auth: "hy2-credential"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatal(err)
	}
	key := synthNodeGuid(node.Id)
	for i, protocol := range []model.Protocol{model.VLESS, model.Hysteria, model.Trojan} {
		inbound := model.Inbound{Tag: fmt.Sprintf("bandwidth-%d", i), Port: 20000 + i, Protocol: protocol, Enable: true, NodeID: &node.Id, OriginNodeGuid: node.Guid}
		if err := db.Create(&inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: existing.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
	}
	read := func() []bandwidthruntime.BandwidthAccount {
		t.Helper()
		accounts, err := (ClientBandwidthService{}).ReadBandwidthInventory(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return accounts
	}
	accounts := read()
	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %+v", accounts)
	}
	oldAttachment := accounts[0].Attachments[key]
	if accounts[0].ID != existing.Id || accounts[0].Email != existing.Email ||
		accounts[0].Policy.TotalBitsPerSecond != 0 || len(accounts[0].Attachments) != 1 ||
		!oldAttachment.Unsupported || !slices.Equal(oldAttachment.Bindings, []bandwidthexchange.PolicyBinding{
		{Protocol: "vless", Fingerprint: bandwidthexchange.CredentialFingerprint("vless", existing.UUID)},
		{Protocol: "hysteria", Fingerprint: bandwidthexchange.CredentialFingerprint("hysteria", existing.Auth)},
	}) {
		t.Fatalf("wrong old client inventory: %+v", accounts)
	}
	if err := db.Where("client_id = ?", existing.Id).Delete(&model.ClientInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := deleteClientRecords(db, []int{existing.Id}); err != nil {
		t.Fatal(err)
	}
	var next model.ClientRecord
	next.Email = "new@example.test"
	next.Auth = "new-hy2-credential"
	if err := db.Create(&next).Error; err != nil {
		t.Fatal(err)
	}
	if next.Id <= existing.Id {
		t.Fatalf("SQLite reused old account ID %d for %d", existing.Id, next.Id)
	}
	var inbound model.Inbound
	if err := db.Where("protocol = ?", model.Hysteria).First(&inbound).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: next.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatal(err)
	}
	settings := bandwidthruntime.ClientBandwidthPolicy{TotalBitsPerSecond: 500, NodeBitsPerSecond: map[string]int64{key: 200}}
	if _, err := (ClientBandwidthService{}).Save(t.Context(), nil, next.Email, settings); err != nil {
		t.Fatal(err)
	}
	accounts = read()
	if len(accounts) != 1 {
		t.Fatalf("expected one replacement account, got %+v", accounts)
	}
	nextAttachment := accounts[0].Attachments[key]
	if accounts[0].ID != next.Id || accounts[0].Policy.TotalBitsPerSecond != 500 ||
		accounts[0].Policy.NodeBitsPerSecond[key] != 200 || nextAttachment.Unsupported || !slices.Equal(nextAttachment.Bindings, []bandwidthexchange.PolicyBinding{
		{Protocol: "hysteria", Fingerprint: bandwidthexchange.CredentialFingerprint("hysteria", next.Auth)},
	}) {
		t.Fatalf("wrong new client inventory: %+v", accounts)
	}
	if err := db.Where("client_id = ? AND inbound_id = ?", next.Id, inbound.Id).Delete(&model.ClientInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	accounts = read()
	if len(accounts) != 1 || len(accounts[0].Attachments) != 0 || accounts[0].Policy.NodeBitsPerSecond[key] != 200 {
		t.Fatalf("detached policy should keep historical rates without active attachments: %+v", accounts)
	}
}

func TestBandwidthInventoryUsesEffectiveCredentialsOfEachEnabledInbound(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	const id = "11111111-2222-3333-4444-555555555555"
	const tuicID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const email = "effective@example.test"
	client := model.ClientRecord{Email: email, UUID: id, Password: "record password", PublicKey: strings.Repeat("11", 32)}
	other := model.ClientRecord{Email: "other@example.test", UUID: id, Password: "other password", PublicKey: strings.Repeat("99", 32)}
	for _, record := range []*model.ClientRecord{&client, &other} {
		if err := db.Create(record).Error; err != nil {
			t.Fatal(err)
		}
	}
	keyA, keyB, psk := strings.Repeat("22", 32), strings.Repeat("33", 32), strings.Repeat("44", 32)
	mtgKey := strings.Repeat("55", 16)
	settings := func(format string, args ...any) string { return fmt.Sprintf(format, args...) }
	bindings := []struct {
		protocol   model.Protocol
		settings   string
		credential string
		disabled   bool
	}{
		{model.VMESS, `{}`, id, false},
		{model.Trojan, `{}`, client.Password, false},
		{model.MASQUE, `{}`, client.Password, false},
		{model.Shadowsocks, `{"method":"aes-128-gcm"}`, bandwidthexchange.CredentialParts("aes-128-gcm", client.Password), false},
		{model.WireGuard, settings(`{"clients":[{"email":%q,"publicKey":%q,"preSharedKey":%q}]}`, strings.ToUpper(email), keyA, psk), bandwidthexchange.CredentialParts(keyA, psk), false},
		{model.WireGuard, settings(`{"clients":[{"email":%q,"publicKey":%q}]}`, email, keyB), bandwidthexchange.CredentialParts(keyB, ""), false},
		{model.AmneziaWG, settings(`{"server":{},"clients":[{"email":%q,"publicKey":%q,"preSharedKey":%q}]}`, email, keyB, psk), bandwidthexchange.CredentialParts(keyB, psk), false},
		{model.TUIC, settings(`{"clients":[{"email":%q,"id":%q,"password":"inbound password"}]}`, email, strings.ToUpper(tuicID)), bandwidthexchange.CredentialParts(tuicID, "inbound password"), false},
		{model.MTProto, settings(`{"clients":[{"email":%q,"secret":"ee%s6578616d706c652e74657374"}]}`, email, mtgKey), mtgKey, false},
		{model.Mixed, `{}`, "", true},
	}
	want := make(map[bandwidthexchange.PolicyBinding]bool)
	for i, binding := range bindings {
		inbound := model.Inbound{Tag: fmt.Sprintf("identity-%d", i), Port: 20000 + i, Enable: !binding.disabled,
			Protocol: binding.protocol, Settings: binding.settings}
		if err := db.Create(&inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
		if binding.protocol == model.Shadowsocks {
			if err := db.Create(&model.ClientInbound{ClientId: other.Id, InboundId: inbound.Id}).Error; err != nil {
				t.Fatal(err)
			}
		}
		if !binding.disabled {
			protocol := string(binding.protocol)
			want[bandwidthexchange.PolicyBinding{Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, binding.credential)}] = true
		}
	}
	accounts, err := readBandwidthInventory(db)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("inventory: %+v, %v", accounts, err)
	}
	first := accounts[0].Attachments["local"]
	got := make(map[bandwidthexchange.PolicyBinding]bool)
	for _, binding := range first.Bindings {
		got[binding] = true
	}
	if first.Unsupported || len(first.Bindings) != len(want) || !maps.Equal(got, want) {
		t.Fatalf("bindings = %+v, want %+v", first, want)
	}
	second := accounts[1].Attachments["local"]
	wantSecond := bandwidthexchange.CredentialFingerprint("shadowsocks", bandwidthexchange.CredentialParts("aes-128-gcm", other.Password))
	if second.Unsupported || len(second.Bindings) != 1 || second.Bindings[0].Fingerprint != wantSecond {
		t.Fatalf("shared inbound did not reuse the effective cipher for each separate account: %+v", second)
	}
	if err := db.Model(&client).UpdateColumn("enable", false).Error; err != nil {
		t.Fatal(err)
	}
	routed := model.Inbound{Tag: "routed-mtproto", Port: 20030, Enable: true, Protocol: model.MTProto,
		Settings: settings(`{"routeThroughXray":true,"clients":[{"email":%q,"secret":"ee%s6578616d706c652e74657374"}]}`, other.Email, mtgKey)}
	if err := db.Create(&routed).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: other.Id, InboundId: routed.Id}).Error; err != nil {
		t.Fatal(err)
	}
	accounts, err = readBandwidthInventory(db)
	if err != nil || len(accounts) != 2 || len(accounts[0].Attachments) != 0 {
		t.Fatalf("disabled canonical client still has active protocol bindings: %+v (%v)", accounts, err)
	}
	second = accounts[1].Attachments["local"]
	if !second.Unsupported || len(second.Bindings) != 1 || second.Bindings[0].Fingerprint != wantSecond {
		t.Fatalf("routed MTProto should mark the attachment unsupported: %+v", second)
	}
	keys, err := clientBandwidthNodes(db, client.Id)
	if _, local := keys["local"]; err != nil || !local {
		t.Fatalf("disabling must retain associated nodes for cap editing: %v (%v)", keys, err)
	}
}
