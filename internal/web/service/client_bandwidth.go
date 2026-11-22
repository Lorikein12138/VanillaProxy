package service

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/mtproto"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const bandwidthInboundNodeColumns = `inbounds.node_id, inbounds.origin_node_guid, nodes.guid AS bandwidth_node_guid,
	(SELECT CASE WHEN COUNT(*) = 1 THEN MIN(origin.id) END FROM nodes AS origin
	 WHERE origin.guid = inbounds.origin_node_guid AND origin.guid <> '') AS bandwidth_origin_node_id`

const bandwidthProxyInbounds = `FROM inbounds AS proxy
	LEFT JOIN remote_bandwidth_proxy_bindings AS rb ON rb.inbound_id = proxy.id AND rb.node_id = proxy.node_id
	LEFT JOIN nodes AS peer ON peer.id = proxy.node_id
	WHERE proxy.protocol IN ('http', 'mixed') AND (proxy.node_id IS NULL OR (
		proxy.enable AND peer.enable AND NOT peer.config_dirty AND rb.policy_active
		AND rb.origin_guid = proxy.origin_node_guid AND rb.origin_guid = peer.guid
		AND (SELECT COUNT(*) FROM nodes AS duplicate WHERE duplicate.guid = peer.guid) = 1
	))`

type bandwidthInboundNode struct {
	NodeId                *int
	OriginNodeGuid        string
	BandwidthNodeGuid     string
	BandwidthOriginNodeId *int
	Protocol              model.Protocol
}

func (node bandwidthInboundNode) bandwidthNodeKey() string {
	if node.NodeId == nil || *node.NodeId <= 0 {
		return "local"
	}
	// Direct nodes keep their panel-local key as snapshots populate GUIDs,
	// including when clones share a reported GUID or fall back to a synthetic one.
	direct := synthNodeGuid(*node.NodeId)
	origin := node.OriginNodeGuid
	if origin == "" || origin == node.BandwidthNodeGuid || origin == direct {
		return direct
	}
	if idText, synthetic := strings.CutPrefix(origin, "node:"); synthetic {
		if id, err := strconv.Atoi(idText); err == nil && id > 0 && synthNodeGuid(id) == origin {
			// The descendant's ID is local to the direct peer, not to this panel.
			return "via:" + strconv.Itoa(*node.NodeId) + ":" + idText
		}
	}
	if node.BandwidthOriginNodeId != nil {
		return synthNodeGuid(*node.BandwidthOriginNodeId)
	}
	return "guid:" + origin
}

type ClientBandwidthService struct{}

type ClientBandwidthSettings struct {
	Available       bool     `json:"available"`
	AccountNodeKeys []string `json:"accountNodeKeys,omitempty"`
	bandwidthruntime.ClientBandwidthPolicy
}

type bandwidthInventoryRow struct {
	model.ClientBandwidth `gorm:"embedded"`
	InboundNode           bandwidthInboundNode `gorm:"embedded"`
	Email                 string
	UUID                  string
	Auth                  string
	Password              string
	PublicKey             string
	PreSharedKey          string
	InboundID             *int
	InboundSettings       string
	InboundEnabled        bool
	ClientEnabled         bool
	ProxyInbounds         string
}

type bandwidthProxyInbound struct {
	Protocol string
	Settings string
	Enable   int
	NodeID   int
	Bindings string
}

func (proxy bandwidthProxyInbound) verifiedRemoteBindings() []storedRemoteProxyBinding {
	var bindings []storedRemoteProxyBinding
	if json.Unmarshal([]byte(proxy.Bindings), &bindings) != nil {
		return nil
	}
	return verifiedRemoteProxyBindings(proxy.Protocol, proxy.Settings, bindings)
}

func deleteConfirmedProxyBindingForInbound(tx *gorm.DB, inboundID int) error {
	var confirmed []struct {
		model.RemoteBandwidthProxyBinding
		Protocol string
		Settings string
	}
	if err := tx.Raw(`SELECT rb.*, proxy.protocol, proxy.settings `+bandwidthProxyInbounds+`
		AND proxy.id = ? AND proxy.node_id IS NOT NULL AND rb.remote_inbound_id > 0 LIMIT 2`, inboundID).Scan(&confirmed).Error; err != nil {
		return err
	}
	// The active projection proves which physical inbound the current mirror
	// represented. Archived projections may refer to a recycled local ID.
	if len(confirmed) != 1 {
		return nil
	}
	record := confirmed[0]
	proxy := bandwidthProxyInbound{Protocol: record.Protocol, Settings: record.Settings, Bindings: record.Bindings}
	if len(proxy.verifiedRemoteBindings()) == 0 {
		return nil
	}
	return tx.Where("node_id = ? AND origin_guid = ? AND remote_inbound_id = ?", record.NodeID, record.OriginGUID, record.RemoteInboundID).
		Delete(&model.RemoteBandwidthProxyBinding{}).Error
}

// ReadBandwidthInventory reads account identities, policies and links in a
// single statement so the authority never builds a policy from partial edits.
func (ClientBandwidthService) ReadBandwidthInventory(ctx context.Context) ([]bandwidthruntime.BandwidthAccount, error) {
	return readBandwidthInventory(database.GetDB().WithContext(ctx))
}

func readBandwidthInventory(db *gorm.DB) ([]bandwidthruntime.BandwidthAccount, error) {
	accounts, _, err := readBandwidthInventoryAndProxyLinks(db)
	return accounts, err
}

func readBandwidthInventoryAndProxyLinks(db *gorm.DB) ([]bandwidthruntime.BandwidthAccount, map[int]map[string]struct{}, error) {
	// Read the owner, its policy, and local/remote proxy settings together.
	const proxyFields = `'protocol', proxy.protocol, 'settings', proxy.settings, 'enable', CASE WHEN proxy.enable THEN 1 ELSE 0 END,
		'nodeID', COALESCE(proxy.node_id, 0), 'bindings', COALESCE(rb.bindings, '')`
	jsonAggregate := `json_group_array(json_object(` + proxyFields + `))`
	if db.Dialector.Name() == "postgres" {
		jsonAggregate = `CAST(json_agg(json_build_object(` + proxyFields + `)) AS TEXT)`
	}
	var rows []bandwidthInventoryRow
	err := db.Table("clients").
		Select(`clients.id AS client_id, clients.email, clients.uuid, clients.auth, clients.password,
			clients.enable AS client_enabled,
			clients.wg_public_key AS public_key, clients.wg_pre_shared_key AS pre_shared_key,
			COALESCE(client_bandwidth.total_bits_per_second, 0) AS total_bits_per_second, client_bandwidth.node_bits_per_second,
			inbounds.id AS inbound_id, inbounds.protocol,
			CASE WHEN ROW_NUMBER() OVER (PARTITION BY inbounds.id ORDER BY clients.id) = 1
				THEN inbounds.settings END AS inbound_settings,
			CASE WHEN ROW_NUMBER() OVER (ORDER BY clients.id, inbounds.id) = 1 THEN (
				SELECT ` + jsonAggregate + ` ` + bandwidthProxyInbounds + `
			) END AS proxy_inbounds,
			inbounds.enable AS inbound_enabled, ` + bandwidthInboundNodeColumns).
		Joins("LEFT JOIN client_bandwidth ON client_bandwidth.client_id = clients.id").
		Joins("LEFT JOIN client_inbounds ON client_inbounds.client_id = clients.id").
		Joins("LEFT JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
		Joins("LEFT JOIN nodes ON nodes.id = inbounds.node_id").
		Order("clients.id, inbounds.id").
		Scan(&rows).Error
	if err != nil {
		return nil, nil, err
	}
	accounts := make([]bandwidthruntime.BandwidthAccount, 0)
	accountIndexes := make(map[int]int)
	clientEnabled := make(map[int]bool)
	var proxyInbounds string
	// Only the first row of each inbound carries settings. Parsing once per
	// inbound also keeps inventories of many clients linear in the roster size.
	inbounds := make(map[int]bandwidthInboundCredentials)
	for _, row := range rows {
		if row.ProxyInbounds != "" {
			proxyInbounds = row.ProxyInbounds
		}
		if len(accounts) == 0 || accounts[len(accounts)-1].ID != row.ClientID {
			accountIndexes[row.ClientID] = len(accounts)
			clientEnabled[row.ClientID] = row.ClientEnabled
			accounts = append(accounts, bandwidthruntime.BandwidthAccount{
				ID: row.ClientID, Email: row.Email,
				Policy: bandwidthruntime.ClientBandwidthPolicy{
					TotalBitsPerSecond: row.TotalBitsPerSecond, NodeBitsPerSecond: row.NodeBitsPerSecond,
				},
				Attachments: make(map[string]bandwidthruntime.BandwidthAttachment),
			})
		}
		if row.InboundID != nil && row.InboundEnabled {
			inbound, cached := inbounds[*row.InboundID]
			if !cached {
				inbound = row.inboundCredentials()
				inbounds[*row.InboundID] = inbound
			}
			if row.ClientEnabled {
				row.addBandwidthAttachment(accounts[len(accounts)-1].Attachments, inbound)
			}
		}
	}
	var proxies []bandwidthProxyInbound
	if proxyInbounds != "" {
		if err := json.Unmarshal([]byte(proxyInbounds), &proxies); err != nil {
			return nil, nil, err
		}
	}
	linked := make(map[int]map[string]struct{})
	attachProxy := func(id int, key, protocol, fingerprint string, enabled bool) {
		index, exists := accountIndexes[id]
		if !exists {
			return
		}
		if linked[id] == nil {
			linked[id] = make(map[string]struct{})
		}
		linked[id][key] = struct{}{}
		if !enabled || !clientEnabled[id] {
			return
		}
		attachments := accounts[index].Attachments
		attachment := attachments[key]
		attachment.Bindings = append(attachment.Bindings, bandwidthexchange.PolicyBinding{Protocol: protocol, Fingerprint: fingerprint})
		attachments[key] = attachment
	}
	for _, proxy := range proxies {
		if proxy.NodeID > 0 {
			for _, binding := range proxy.verifiedRemoteBindings() {
				if index, exists := accountIndexes[binding.ClientID]; exists && accounts[index].Email == binding.OwnerEmail {
					attachProxy(binding.ClientID, synthNodeGuid(proxy.NodeID), proxy.Protocol, binding.CredentialFingerprint, true)
				}
			}
			continue
		}
		entries, err := bandwidthProxyAccounts(proxy.Protocol, []byte(proxy.Settings))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.ClientID != nil {
				attachProxy(*entry.ClientID, "local", proxy.Protocol,
					bandwidthexchange.CredentialFingerprint(proxy.Protocol, entry.credential()), proxy.Enable != 0)
			}
		}
	}
	return accounts, linked, nil
}

// Local native Xray users are projected from the normalized client records.
// Mirrored inbounds carry the credentials from their serving panel. Sidecars
// consume inbound settings, and WireGuard applies per-tunnel overrides.
type bandwidthInboundCredentials struct {
	publicKeys    map[string]model.Client
	remoteClients map[string]remoteBandwidthClient
	sidecar       map[string]string
	method        string
	serverKey     string
}

type remoteBandwidthClient struct {
	Email    string `json:"email"`
	ID       string `json:"id"`
	Auth     string `json:"auth"`
	Password string `json:"password"`
	Pass     string `json:"pass"`
}

func (row bandwidthInventoryRow) inboundCredentials() bandwidthInboundCredentials {
	var credentials bandwidthInboundCredentials
	if row.InboundNode.NodeId != nil && *row.InboundNode.NodeId > 0 {
		switch row.InboundNode.Protocol {
		case model.VLESS, model.VMESS, model.Hysteria, model.Trojan, model.Shadowsocks, model.MASQUE:
			var settings struct {
				Clients []remoteBandwidthClient `json:"clients"`
			}
			if json.Unmarshal([]byte(row.InboundSettings), &settings) == nil {
				credentials.remoteClients = make(map[string]remoteBandwidthClient, len(settings.Clients))
				for _, client := range settings.Clients {
					credentials.remoteClients[client.Email] = client
				}
			}
		}
	}
	switch row.InboundNode.Protocol {
	case model.Shadowsocks:
		var settings struct {
			Method   string `json:"method"`
			Password string `json:"password"`
		}
		if json.Unmarshal([]byte(row.InboundSettings), &settings) == nil {
			credentials.method, credentials.serverKey = settings.Method, settings.Password
			if replacement, removed := model.ReplaceRemovedShadowsocksCipher(settings.Method); removed {
				credentials.method = replacement
			}
		}
	case model.WireGuard, model.AmneziaWG, model.MTProto:
		if row.InboundNode.Protocol == model.MTProto {
			var settings struct {
				RouteThroughXray bool `json:"routeThroughXray"`
			}
			if json.Unmarshal([]byte(row.InboundSettings), &settings) != nil || settings.RouteThroughXray {
				return credentials
			}
		}
		clients, _ := ParseInboundSettingsClients(row.InboundSettings)
		credentials.publicKeys = make(map[string]model.Client, len(clients))
		credentials.sidecar = make(map[string]string, len(clients))
		for _, client := range clients {
			switch row.InboundNode.Protocol {
			case model.WireGuard:
				credentials.publicKeys[strings.ToLower(strings.TrimSpace(client.Email))] = client
			case model.AmneziaWG:
				credentials.sidecar[client.Email] = amneziawg.BandwidthCredential(client.PublicKey, client.PreSharedKey)
			case model.MTProto:
				credentials.sidecar[client.Email] = mtproto.BandwidthCredential(client.Secret)
			}
		}
	case model.TUIC:
		inbound := model.Inbound{Protocol: model.TUIC, Settings: row.InboundSettings}
		if configured, ok := tuic.ConfiguredInstanceFromInbound(&inbound); ok {
			credentials.sidecar = make(map[string]string, len(configured.Clients))
			for _, client := range configured.Clients {
				credentials.sidecar[client.Email] = tuic.BandwidthCredential(client.UUID, client.Password)
			}
		}
	}
	return credentials
}

func (row bandwidthInventoryRow) addBandwidthAttachment(attachments map[string]bandwidthruntime.BandwidthAttachment, inbound bandwidthInboundCredentials) {
	key := row.InboundNode.bandwidthNodeKey()
	attachment := attachments[key]
	protocol := string(row.InboundNode.Protocol)
	remote := inbound.remoteClients[row.Email]
	var credential string
	switch row.InboundNode.Protocol {
	case model.VLESS, model.VMESS:
		credential = firstBandwidthCredential(remote.ID, row.UUID)
	case model.Hysteria:
		credential = firstBandwidthCredential(remote.Auth, row.Auth)
	case model.Trojan:
		credential = firstBandwidthCredential(remote.Password, row.Password)
	case model.MASQUE:
		credential = firstBandwidthCredential(remote.Password, remote.Pass, row.Password)
	case model.Shadowsocks:
		userMethod := inbound.method
		if strings.HasPrefix(userMethod, "2022-blake3-") {
			userMethod = ""
		}
		protocol, credential, _ = bandwidthShadowsocksCredential(inbound.method, inbound.serverKey, userMethod, firstBandwidthCredential(remote.Password, row.Password))
	case model.WireGuard:
		public, psk := row.PublicKey, row.PreSharedKey
		if client, exists := inbound.publicKeys[strings.ToLower(strings.TrimSpace(row.Email))]; exists {
			public, psk = client.PublicKey, client.PreSharedKey
		}
		credential, _ = bandwidthWireGuardCredential(public, psk)
	case model.TUIC, model.AmneziaWG, model.MTProto:
		credential = inbound.sidecar[row.Email]
	}
	if credential == "" {
		attachment.Unsupported = true
	} else {
		attachment.Bindings = append(attachment.Bindings, bandwidthexchange.PolicyBinding{
			Protocol: protocol, Fingerprint: bandwidthexchange.CredentialFingerprint(protocol, credential),
		})
	}
	attachments[key] = attachment
}

func firstBandwidthCredential(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// ReadClientBandwidth implements the authority policy reader. Starting the
// query from clients makes a removed client distinguishable from a client
// with no overrides, even when both have no matching policy row.
func (ClientBandwidthService) ReadClientBandwidth(ctx context.Context, clientID int) (bandwidthruntime.ClientBandwidthPolicy, error) {
	return readClientBandwidth(database.GetDB().WithContext(ctx), clientID)
}

func readClientBandwidth(db *gorm.DB, clientID int) (bandwidthruntime.ClientBandwidthPolicy, error) {
	var row model.ClientBandwidth
	result := db.Table("clients").
		Select("clients.id AS client_id, COALESCE(client_bandwidth.total_bits_per_second, 0) AS total_bits_per_second, client_bandwidth.node_bits_per_second").
		Joins("LEFT JOIN client_bandwidth ON client_bandwidth.client_id = clients.id").
		Where("clients.id = ?", clientID).
		Scan(&row)
	if result.Error != nil {
		return bandwidthruntime.ClientBandwidthPolicy{}, result.Error
	}
	if result.RowsAffected != 1 {
		return bandwidthruntime.ClientBandwidthPolicy{}, gorm.ErrRecordNotFound
	}
	if row.NodeBitsPerSecond == nil {
		row.NodeBitsPerSecond = make(map[string]int64)
	}
	return bandwidthruntime.ClientBandwidthPolicy{TotalBitsPerSecond: row.TotalBitsPerSecond, NodeBitsPerSecond: row.NodeBitsPerSecond}, nil
}

func (ClientBandwidthService) Get(ctx context.Context, panel *bandwidthruntime.PanelRuntime, email string) (ClientBandwidthSettings, error) {
	db := database.GetDB().WithContext(ctx)
	account, linkedProxy, err := readClientBandwidthAccount(db.Where("clients.email = ?", email))
	if err != nil {
		return ClientBandwidthSettings{}, err
	}
	associated, err := clientBandwidthNodes(db, account.ID)
	if err != nil {
		return ClientBandwidthSettings{}, err
	}
	maps.Copy(associated, linkedProxy)
	return clientBandwidthSettings(panel, account, associated), nil
}

func clientBandwidthSettings(panel *bandwidthruntime.PanelRuntime, account bandwidthruntime.BandwidthAccount, associated map[string]struct{}) ClientBandwidthSettings {
	return ClientBandwidthSettings{
		Available: panel.ClientBandwidthPolicyAvailable(account), ClientBandwidthPolicy: account.Policy,
		AccountNodeKeys: slices.Sorted(maps.Keys(associated)),
	}
}

func (ClientBandwidthService) Save(ctx context.Context, panel *bandwidthruntime.PanelRuntime, email string, policy bandwidthruntime.ClientBandwidthPolicy) (ClientBandwidthSettings, error) {
	if err := validateClientBandwidth(policy); err != nil {
		return ClientBandwidthSettings{}, err
	}
	var settings ClientBandwidthSettings
	err := runSerializedTx(func(tx *gorm.DB) error {
		var client model.ClientRecord
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Where("email = ?", email).First(&client).Error; err != nil {
			return err
		}
		associated, err := clientBandwidthNodes(tx, client.Id)
		if err != nil {
			return err
		}
		account, linkedProxy, err := readClientBandwidthAccount(tx.Where("clients.id = ?", client.Id))
		if err != nil {
			return err
		}
		maps.Copy(associated, linkedProxy)
		for key := range policy.NodeBitsPerSecond {
			if _, ok := associated[key]; !ok {
				return errors.New("bandwidth node is not attached to this client")
			}
		}
		previous := account.Policy
		// A detached node may still serve until its next successful sync.
		// Retain its historical override in the authority's policy.
		for key := range associated {
			delete(previous.NodeBitsPerSecond, key)
		}
		for key, rate := range policy.NodeBitsPerSecond {
			previous.NodeBitsPerSecond[key] = rate
		}
		previous.TotalBitsPerSecond = policy.TotalBitsPerSecond
		row := model.ClientBandwidth{ClientID: client.Id, TotalBitsPerSecond: previous.TotalBitsPerSecond, NodeBitsPerSecond: previous.NodeBitsPerSecond}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "client_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"total_bits_per_second", "node_bits_per_second"}),
		}).Create(&row).Error; err != nil {
			return err
		}
		account.Policy = previous
		settings = clientBandwidthSettings(panel, account, associated)
		return nil
	})
	return settings, err
}

func validateClientBandwidth(policy bandwidthruntime.ClientBandwidthPolicy) error {
	if policy.TotalBitsPerSecond < 0 || policy.TotalBitsPerSecond > bandwidthruntime.MaxPanelBitsPerSecond || policy.NodeBitsPerSecond == nil {
		return errors.New("invalid client bandwidth policy")
	}
	for _, rate := range policy.NodeBitsPerSecond {
		if rate < 0 || rate > bandwidthruntime.MaxPanelBitsPerSecond || (policy.TotalBitsPerSecond > 0 && rate > policy.TotalBitsPerSecond) {
			return errors.New("invalid client bandwidth node limit")
		}
	}
	return nil
}

func readClientBandwidthAccount(db *gorm.DB) (bandwidthruntime.BandwidthAccount, map[string]struct{}, error) {
	accounts, linked, err := readBandwidthInventoryAndProxyLinks(db)
	if err != nil {
		return bandwidthruntime.BandwidthAccount{}, nil, err
	}
	if len(accounts) != 1 {
		return bandwidthruntime.BandwidthAccount{}, nil, gorm.ErrRecordNotFound
	}
	account := accounts[0]
	if account.Policy.NodeBitsPerSecond == nil {
		account.Policy.NodeBitsPerSecond = make(map[string]int64)
	}
	return account, linked[account.ID], nil
}

func clientBandwidthNodes(tx *gorm.DB, clientID int) (map[string]struct{}, error) {
	var rows []bandwidthInboundNode
	err := tx.Table("client_inbounds").
		Select(bandwidthInboundNodeColumns).
		Joins("JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
		Joins("LEFT JOIN nodes ON nodes.id = inbounds.node_id").
		Where("client_inbounds.client_id = ?", clientID).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		keys[row.bandwidthNodeKey()] = struct{}{}
	}
	return keys, nil
}

func bandwidthProxyLinkedClients(db *gorm.DB) (map[int]bool, error) {
	var proxies []bandwidthProxyInbound
	if err := db.Table("inbounds").Select("protocol, settings").
		Where("node_id IS NULL AND protocol IN ('http', 'mixed')").Scan(&proxies).Error; err != nil {
		return nil, err
	}
	linked := make(map[int]bool)
	for _, proxy := range proxies {
		accounts, err := bandwidthProxyAccounts(proxy.Protocol, []byte(proxy.Settings))
		if err != nil {
			continue
		}
		for _, account := range accounts {
			if account.ClientID != nil {
				linked[*account.ClientID] = true
			}
		}
	}
	// Suspended policy is not entitlement. The last confirmed association
	// still identifies the client the proxy serves once its node is available.
	var projections []string
	if err := db.Model(&model.RemoteBandwidthProxyBinding{}).Pluck("bindings", &projections).Error; err != nil {
		return nil, err
	}
	for _, projection := range projections {
		var bindings []storedRemoteProxyBinding
		if err := json.Unmarshal([]byte(projection), &bindings); err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if binding.ClientID > 0 {
				linked[binding.ClientID] = true
			}
		}
	}
	return linked, nil
}

func requestBandwidthProxyOwnerReconcile(ids ...int) {
	node := activeBandwidthNode.Load()
	if node == nil || node.panel.AutomaticAccountLookup() == nil {
		return
	}
	linked, err := bandwidthProxyLinkedClients(database.GetDB())
	for _, id := range ids {
		if err != nil || linked[id] {
			(&XrayService{}).SetToNeedReconcile()
			return
		}
	}
}

func deleteClientRecords(tx *gorm.DB, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	if err := tx.Where("id IN ?", ids).Delete(&model.ClientRecord{}).Error; err != nil {
		return err
	}
	return tx.Where("client_id IN ?", ids).Delete(&model.ClientBandwidth{}).Error
}
