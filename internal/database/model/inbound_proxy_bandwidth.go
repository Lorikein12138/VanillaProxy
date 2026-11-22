package model

import (
	"encoding/json"
	"strings"
)

// RemoteBandwidthProxyBinding records the authenticated account projection for
// one mirrored inbound. It is separate from writable inbound settings.
type RemoteBandwidthProxyBinding struct {
	NodeID          int    `gorm:"primaryKey;autoIncrement:false"`
	OriginGUID      string `gorm:"primaryKey;column:origin_guid"`
	RemoteInboundID int    `gorm:"primaryKey;autoIncrement:false"`
	InboundID       int    `gorm:"not null;index"`
	Bindings        string `gorm:"not null"`
	PolicyActive    bool   `gorm:"not null;default:false"`
}

func (RemoteBandwidthProxyBinding) TableName() string { return "remote_bandwidth_proxy_bindings" }

// RemoteBandwidthProxyOwnerPin survives removal of the mirrored inbound or
// client. Reusing a hub email cannot change the identity originally enrolled.
type RemoteBandwidthProxyOwnerPin struct {
	PeerGUID     string `gorm:"primaryKey;column:peer_guid"`
	LeafOwnerKey string `gorm:"primaryKey;size:64"`
	ClientID     int    `gorm:"not null"`
}

func (RemoteBandwidthProxyOwnerPin) TableName() string { return "remote_bandwidth_proxy_owner_pins" }

// StripInboundProxyBandwidthBindings removes client IDs that only identify
// records in the database where the inbound was configured.
func StripInboundProxyBandwidthBindings(protocol Protocol, settings string) (string, bool) {
	switch strings.ToLower(string(protocol)) {
	case string(HTTP), string(Mixed):
	default:
		return settings, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(settings), &fields) != nil {
		return settings, false
	}
	changed := false
	for key, raw := range fields {
		if !strings.EqualFold(key, "accounts") && !strings.EqualFold(key, "users") {
			continue
		}
		var accounts []json.RawMessage
		if json.Unmarshal(raw, &accounts) != nil {
			continue
		}
		listChanged := false
		for i, raw := range accounts {
			var account map[string]json.RawMessage
			if json.Unmarshal(raw, &account) != nil {
				continue
			}
			accountChanged := false
			for field := range account {
				if strings.EqualFold(field, "bandwidthClientId") {
					delete(account, field)
					accountChanged = true
				}
			}
			if accountChanged {
				encoded, err := json.Marshal(account)
				if err != nil {
					return settings, false
				}
				accounts[i] = encoded
				listChanged = true
			}
		}
		if listChanged {
			encoded, err := json.Marshal(accounts)
			if err != nil {
				return settings, false
			}
			fields[key] = encoded
			changed = true
		}
	}
	if !changed {
		return settings, false
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return settings, false
	}
	return string(encoded), true
}
