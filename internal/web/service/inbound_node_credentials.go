package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type storedRemoteProxyBinding struct {
	runtime.BandwidthProxyBinding
	ClientID int `json:"clientId"`
}

func reconcileRemoteBandwidthProxyBindings(tx *gorm.DB, nodeID int, snapshot *runtime.TrafficSnapshot, matched map[int]*model.Inbound, frozen bool, selfKey string) error {
	var records []model.RemoteBandwidthProxyBinding
	var removed []int
	var inventoryOrigin string
	if !frozen && (len(matched) > 0 || snapshot.HasBandwidthProxyInventory()) {
		var peer model.Node
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&peer, nodeID).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && !peer.ConfigDirty && peer.Guid != "" && peer.Guid == selfKey && !strings.HasPrefix(peer.Guid, "node:") {
			decryptToken(&peer)
			bindings := snapshot.BandwidthProxyBindingsFor(&peer)
			inventory := snapshot.BandwidthProxyInventoryFor(&peer)
			verifiedByInbound := make(map[int][]storedRemoteProxyBinding)
			unbound := make(map[int]bool)
			for localID, remote := range matched {
				if remote == nil || remote.NodeID != nil || !remote.Enable || remote.OriginNodeGuid != peer.Guid {
					continue
				}
				claims, present := bindings[remote.Id]
				if !present {
					continue
				}
				if len(claims) == 0 {
					if inventory != nil {
						unbound[remote.Id] = true
					}
					continue
				}
				candidates := make([]storedRemoteProxyBinding, 0, len(claims))
				for _, binding := range claims {
					candidates = append(candidates, storedRemoteProxyBinding{BandwidthProxyBinding: binding})
				}
				if verified := verifiedRemoteProxyBindings(string(remote.Protocol), remote.Settings, candidates); len(verified) == len(claims) {
					verifiedByInbound[localID] = verified
				}
			}
			pins, err := pinRemoteProxyOwners(tx, peer.Guid, verifiedByInbound)
			if err != nil {
				return err
			}
			for localID, bindings := range verifiedByInbound {
				active := bindings[:0]
				for _, binding := range bindings {
					if pin, exists := pins[binding.LeafOwnerKey]; exists {
						binding.ClientID = pin.ClientID
						active = append(active, binding)
					}
				}
				if len(active) == 0 {
					continue
				}
				encoded, err := json.Marshal(active)
				if err != nil {
					return err
				}
				records = append(records, model.RemoteBandwidthProxyBinding{
					InboundID: localID, RemoteInboundID: matched[localID].Id, NodeID: nodeID,
					OriginGUID: peer.Guid, Bindings: string(encoded), PolicyActive: true,
				})
			}
			if inventory != nil {
				inventoryOrigin = peer.Guid
				var existing []int
				if err := tx.Model(&model.RemoteBandwidthProxyBinding{}).
					Where("node_id = ? AND origin_guid = ?", nodeID, peer.Guid).Pluck("remote_inbound_id", &existing).Error; err != nil {
					return err
				}
				for _, remoteID := range existing {
					if !inventory[remoteID] || unbound[remoteID] {
						removed = append(removed, remoteID)
					}
				}
			}
		}
	}
	if err := freezeRemoteBandwidthProxyBindings(tx, nodeID); err != nil {
		return err
	}
	for _, batch := range chunkInts(removed, sqlInChunk-2) {
		if err := tx.Where("node_id = ? AND origin_guid = ? AND remote_inbound_id IN ?", nodeID, inventoryOrigin, batch).
			Delete(&model.RemoteBandwidthProxyBinding{}).Error; err != nil {
			return err
		}
	}
	if len(records) != 0 {
		return upsertRemoteBandwidthProxyBindings(tx, records)
	}
	return nil
}

func upsertRemoteBandwidthProxyBindings(tx *gorm.DB, records []model.RemoteBandwidthProxyBinding) error {
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}, {Name: "origin_guid"}, {Name: "remote_inbound_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"inbound_id", "bindings", "policy_active"}),
	}).CreateInBatches(&records, sqlInChunk/6).Error
}

func freezeRemoteBandwidthProxyBindings(tx *gorm.DB, nodeID int) error {
	return tx.Model(&model.RemoteBandwidthProxyBinding{}).Where("node_id = ? AND policy_active", nodeID).
		Update("policy_active", false).Error
}

func pinRemoteProxyOwners(tx *gorm.DB, peerGUID string, inbounds map[int][]storedRemoteProxyBinding) (map[string]model.RemoteBandwidthProxyOwnerPin, error) {
	emailsByKey := make(map[string]string)
	for _, bindings := range inbounds {
		for _, binding := range bindings {
			if email, exists := emailsByKey[binding.LeafOwnerKey]; exists && email != binding.OwnerEmail {
				// Conflicting claims for one leaf identity cannot enroll it.
				emailsByKey[binding.LeafOwnerKey] = ""
			} else {
				emailsByKey[binding.LeafOwnerKey] = binding.OwnerEmail
			}
		}
	}
	keys := make([]string, 0, len(emailsByKey))
	emails := make(map[string]struct{})
	for key, email := range emailsByKey {
		if email != "" {
			keys = append(keys, key)
			emails[email] = struct{}{}
		}
	}
	clients := make(map[string]model.ClientRecord)
	for _, batch := range chunkStrings(slices.Collect(maps.Keys(emails)), sqlInChunk) {
		var rows []model.ClientRecord
		if err := tx.Select("id, email").Where("email IN ?", batch).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, client := range rows {
			clients[client.Email] = client
		}
	}
	pins := make(map[string]model.RemoteBandwidthProxyOwnerPin)
	for _, batch := range chunkStrings(keys, sqlInChunk-1) {
		var rows []model.RemoteBandwidthProxyOwnerPin
		query := tx.Where("peer_guid = ? AND leaf_owner_key IN ?", peerGUID, batch)
		if err := query.Find(&rows).Error; err != nil {
			return nil, err
		}
		known := make(map[string]bool, len(rows))
		for _, row := range rows {
			known[row.LeafOwnerKey] = true
		}
		var newPins []model.RemoteBandwidthProxyOwnerPin
		for _, key := range batch {
			if client := clients[emailsByKey[key]]; !known[key] && client.Id > 0 {
				newPins = append(newPins, model.RemoteBandwidthProxyOwnerPin{
					PeerGUID: peerGUID, LeafOwnerKey: key, ClientID: client.Id,
				})
			}
		}
		if len(newPins) > 0 {
			insert := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&newPins, sqlInChunk/3)
			if insert.Error != nil {
				return nil, insert.Error
			}
			if insert.RowsAffected == int64(len(newPins)) {
				rows = append(rows, newPins...)
			} else if err := query.Find(&rows).Error; err != nil {
				return nil, err
			}
		}
		for _, row := range rows {
			if client := clients[emailsByKey[row.LeafOwnerKey]]; client.Id == row.ClientID {
				pins[row.LeafOwnerKey] = row
			}
		}
	}
	return pins, nil
}

func deleteRemoteBandwidthProxyBindings(tx *gorm.DB, nodeID int) error {
	return tx.Where("node_id = ?", nodeID).Delete(&model.RemoteBandwidthProxyBinding{}).Error
}

// The node's explicit binding must still describe the committed effective
// accounts. An untrusted local-ID field cannot become an email binding.
func verifiedRemoteProxyBindings(protocol, settings string, bindings []storedRemoteProxyBinding) []storedRemoteProxyBinding {
	accounts, err := bandwidthProxyAccounts(protocol, []byte(settings))
	if err != nil {
		return nil
	}
	fingerprints := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		if account.ClientID != nil {
			return nil
		}
		if strings.Contains(account.Username, ":") || (protocol == "mixed" && (len(account.Username) > 255 || len(account.Password) > 255)) {
			continue
		}
		fingerprints[bandwidthexchange.CredentialFingerprint(protocol, account.credential())] = true
	}
	counts := make(map[string]int, len(bindings))
	for _, binding := range bindings {
		counts[binding.CredentialFingerprint]++
	}
	verified := make([]storedRemoteProxyBinding, 0, len(bindings))
	for _, binding := range bindings {
		key := binding.LeafOwnerKey
		if len(key) != sha256.Size*2 || strings.ToLower(key) != key {
			continue
		}
		if _, err := hex.DecodeString(key); err == nil && validBandwidthXrayIdentity(binding.OwnerEmail) &&
			fingerprints[binding.CredentialFingerprint] && counts[binding.CredentialFingerprint] == 1 {
			verified = append(verified, binding)
		}
	}
	return verified
}

// GetInboundsForNodeSync overlays the credentials used by local generated
// Xray inbounds on the normal node snapshot. Each mirror keeps the credentials
// of its own serving panel as it passes through another node.
func (s *InboundService) GetInboundsForNodeSync(userID int, includeProxyBindings bool) ([]runtime.NodeSnapshotInbound, string, error) {
	inbounds, err := s.GetInbounds(userID)
	if err != nil {
		return nil, "", err
	}
	direct := make(map[int]*model.Inbound)
	ids := make([]int, 0, len(inbounds))
	for _, inbound := range inbounds {
		if inbound.NodeID == nil && nodeSyncAuthField(inbound.Protocol) != "" {
			direct[inbound.Id] = inbound
			ids = append(ids, inbound.Id)
		}
	}
	for _, batch := range chunkInts(ids, sqlInChunk) {
		var clients []struct {
			InboundID            int
			Email                string
			UUID, Auth, Password string
		}
		err := database.GetDB().Table("clients").
			Select("client_inbounds.inbound_id, clients.email, clients.uuid, clients.auth, clients.password").
			Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
			Where("client_inbounds.inbound_id IN ?", batch).Scan(&clients).Error
		if err != nil {
			return nil, "", err
		}
		credentials := make(map[int]map[string]string, len(batch))
		for _, client := range clients {
			byEmail := credentials[client.InboundID]
			if byEmail == nil {
				byEmail = make(map[string]string)
				credentials[client.InboundID] = byEmail
			}
			switch nodeSyncAuthField(direct[client.InboundID].Protocol) {
			case "id":
				byEmail[client.Email] = client.UUID
			case "auth":
				byEmail[client.Email] = client.Auth
			case "password":
				byEmail[client.Email] = client.Password
			}
		}
		for inboundID, byEmail := range credentials {
			inbound := direct[inboundID]
			inbound.Settings = overlayNodeSyncAuth(inbound.Settings, inbound.Protocol, byEmail)
		}
	}
	guid := ""
	if includeProxyBindings {
		guid = s.panelGuid()
	}
	rows, err := nodeSnapshotProxyBindings(inbounds, guid)
	return rows, guid, err
}

func nodeSnapshotProxyBindings(inbounds []*model.Inbound, selfGUID string) ([]runtime.NodeSnapshotInbound, error) {
	rows := make([]runtime.NodeSnapshotInbound, 0, len(inbounds))
	marked := make(map[int][]*bandwidthProxyAccount)
	var ids []int
	for _, inbound := range inbounds {
		index := len(rows)
		rows = append(rows, runtime.NodeSnapshotInbound{Inbound: inbound})
		if inbound.Protocol != model.HTTP && inbound.Protocol != model.Mixed {
			continue
		}
		original := inbound.Settings
		inbound.Settings, _ = model.StripInboundProxyBandwidthBindings(inbound.Protocol, original)
		if inbound.NodeID != nil || selfGUID == "" || inbound.OriginNodeGuid != selfGUID {
			continue
		}
		if !inbound.Enable {
			continue
		}
		accounts, err := bandwidthProxyAccounts(string(inbound.Protocol), []byte(original))
		if err != nil {
			if errors.Is(err, errBandwidthProxyAccountsEmpty) {
				empty := []runtime.BandwidthProxyBinding{}
				rows[index].BandwidthProxyBindings = &empty
			}
			continue
		}
		empty := []runtime.BandwidthProxyBinding{}
		rows[index].BandwidthProxyBindings = &empty
		for _, account := range accounts {
			if account.ClientID != nil {
				ids = append(ids, *account.ClientID)
				marked[index] = append(marked[index], account)
			}
		}
	}
	owners := make(map[int]model.ClientRecord)
	for _, batch := range chunkInts(ids, sqlInChunk) {
		var clients []model.ClientRecord
		if err := database.GetDB().Select("id, email").
			Where("id IN ? AND enable = ?", batch, true).Find(&clients).Error; err != nil {
			return nil, err
		}
		for _, client := range clients {
			owners[client.Id] = client
		}
	}
	for index, accounts := range marked {
		row := &rows[index]
		for _, account := range accounts {
			if owner := owners[*account.ClientID]; validBandwidthXrayIdentity(owner.Email) {
				*row.BandwidthProxyBindings = append(*row.BandwidthProxyBindings, runtime.BandwidthProxyBinding{
					OwnerEmail:            owner.Email,
					LeafOwnerKey:          remoteProxyOwnerKey(selfGUID, owner),
					CredentialFingerprint: bandwidthexchange.CredentialFingerprint(string(row.Protocol), account.credential()),
				})
			}
		}
		if len(*row.BandwidthProxyBindings) != len(accounts) {
			// A locally marked owner can be temporarily suspended or missing.
			row.BandwidthProxyBindings = nil
		}
	}
	return rows, nil
}

func remoteProxyOwnerKey(guid string, owner model.ClientRecord) string {
	return bandwidthexchange.CredentialFingerprint("vanillaproxy-proxy-owner-v1",
		bandwidthexchange.CredentialParts(guid, strconv.Itoa(owner.Id)))
}

func nodeSyncAuthField(protocol model.Protocol) string {
	switch protocol {
	case model.VLESS, model.VMESS:
		return "id"
	case model.Hysteria:
		return "auth"
	case model.Trojan, model.Shadowsocks, model.MASQUE:
		return "password"
	default:
		return ""
	}
}

func overlayNodeSyncAuth(settings string, protocol model.Protocol, credentials map[string]string) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(settings), &fields) != nil {
		return settings
	}
	var clients []json.RawMessage
	if json.Unmarshal(fields["clients"], &clients) != nil {
		return settings
	}
	key := nodeSyncAuthField(protocol)
	changed := false
	for i, raw := range clients {
		var fields map[string]json.RawMessage
		var email string
		if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["email"], &email) != nil {
			continue
		}
		credential, linked := credentials[email]
		if !linked {
			continue
		}
		var existing string
		canonical := json.Unmarshal(fields[key], &existing) == nil && existing == credential
		_, hasPassAlias := fields["pass"]
		if canonical && (protocol != model.MASQUE || !hasPassAlias) {
			continue
		}
		fields[key], _ = json.Marshal(credential)
		if protocol == model.MASQUE {
			// The panel's password field maps to native pass. Keeping the old
			// alias would override the normalized password on conversion.
			delete(fields, "pass")
		}
		clients[i], _ = json.Marshal(fields)
		changed = true
	}
	if !changed {
		return settings
	}
	fields["clients"], _ = json.Marshal(clients)
	encoded, _ := json.Marshal(fields)
	return string(encoded)
}
