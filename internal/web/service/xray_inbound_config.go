package service

import (
	"encoding/json"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/maskcompat"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"

	"gorm.io/gorm"
)

// buildGeneratedXrayInbound projects panel settings and linked client rows into Xray's native configuration.
func (s *InboundService) buildGeneratedXrayInbound(tx *gorm.DB, inbound *model.Inbound, bandwidthManaged bool) (*xray.InboundConfig, error) {
	settings := map[string]any{}
	_ = json.Unmarshal([]byte(inbound.Settings), &settings)
	flowAllowed := !inbound.DisableFlow &&
		inboundCanEnableTlsFlow(string(inbound.Protocol), inbound.StreamSettings, inbound.Settings)
	var wireguardClientsByEmail map[string]model.Client
	if inbound.Protocol == model.WireGuard {
		inboundClients, _ := ParseInboundSettingsClients(inbound.Settings)
		if len(inboundClients) > 0 {
			wireguardClientsByEmail = make(map[string]model.Client, len(inboundClients))
			for _, client := range inboundClients {
				wireguardClientsByEmail[strings.ToLower(strings.TrimSpace(client.Email))] = client
			}
		}
	}

	dbClients, listErr := s.clientService.ListForInbound(tx, inbound.Id)
	if listErr != nil {
		return nil, listErr
	}

	clientStats := inbound.ClientStats
	enableMap := make(map[string]bool, len(clientStats))
	for _, clientTraffic := range clientStats {
		enableMap[clientTraffic.Email] = clientTraffic.Enable
	}

	finalClients := make([]any, 0, len(dbClients))
	var wgPeers []any
	for i := range dbClients {
		c := dbClients[i]
		if enable, exists := enableMap[c.Email]; exists && !enable {
			logger.Infof("Remove Inbound User %s due to expiration or traffic limit", c.Email)
			continue
		}
		if !c.Enable {
			continue
		}
		flow := c.Flow
		if flow == "xtls-rprx-vision-udp443" {
			flow = "xtls-rprx-vision"
		}
		if !flowAllowed {
			flow = ""
		}
		entry := map[string]any{"email": c.Email}
		switch inbound.Protocol {
		case model.VLESS:
			if c.ID != "" {
				entry["id"] = c.ID
			}
			if flow != "" {
				entry["flow"] = flow
			}
			if c.Reverse != nil {
				entry["reverse"] = c.Reverse
			}
		case model.VMESS:
			if c.ID != "" {
				entry["id"] = c.ID
			}
			if c.Security != "" {
				entry["security"] = c.Security
			}
		case model.Trojan:
			if c.Password != "" {
				entry["password"] = c.Password
			}
			if flow != "" {
				entry["flow"] = flow
			}
		case model.Shadowsocks:
			if c.Password != "" {
				entry["password"] = c.Password
			}
		case model.Hysteria:
			if c.Auth != "" {
				entry["auth"] = c.Auth
			}
		case model.MASQUE:
			if c.Password != "" {
				entry["password"] = c.Password
			}
		case model.WireGuard:
			if inboundClient, ok := wireguardClientsByEmail[strings.ToLower(strings.TrimSpace(c.Email))]; ok {
				c.AllowedIPs = inboundClient.AllowedIPs
				c.PreSharedKey = inboundClient.PreSharedKey
				c.PublicKey = inboundClient.PublicKey
				// #6731: a nil settings keepalive must not keep the other tunnel's value.
				if inboundClient.KeepAlive == nil {
					c.KeepAlive = nil
				} else {
					keepalive := *inboundClient.KeepAlive
					c.KeepAlive = &keepalive
				}
			}
			wgPeers = append(wgPeers, model.WireguardPeerFromClient(c))
			continue
		}
		finalClients = append(finalClients, entry)
	}

	var mutated bool
	if inbound.Protocol == model.WireGuard {
		delete(settings, "clients")
		if wgPeers == nil {
			wgPeers = []any{}
		}
		settings["peers"] = wgPeers
		mutated = true
	} else {
		_, hadClients := settings["clients"]
		mutated = hadClients || len(finalClients) > 0
		if bandwidthManaged {
			switch inbound.Protocol {
			case model.VLESS, model.VMESS, model.Trojan, model.Hysteria, model.Shadowsocks, model.MASQUE:
				// A disabled or removed panel client must never expose an old
				// native users alias or a Shadowsocks server key as a fallback.
				_, hadUsers := settings["users"]
				mutated = mutated || hadUsers || len(dbClients) > 0
			}
		}
		if mutated {
			settings["clients"] = finalClients
		}
	}

	if bandwidthManaged {
		// These fields are stored by the panel and ignored by the pinned core.
		// WireGuard's native remoteDNS field remains part of its configuration.
		switch inbound.Protocol {
		case model.Shadowsocks:
			if _, exists := settings["ivCheck"]; exists {
				delete(settings, "ivCheck")
				mutated = true
			}
		case model.WireGuard:
			delete(settings, "subnetIp")
			delete(settings, "subnetCidr")
			delete(settings, "dns")
		}
	}

	if inboundCanHostFallbacks(inbound) {
		fallbacks, fbErr := s.fallbackService.BuildFallbacksJSON(tx, inbound.Id)
		if fbErr != nil {
			return nil, fbErr
		}
		if len(fallbacks) > 0 {
			generic := make([]any, 0, len(fallbacks))
			for _, f := range fallbacks {
				generic = append(generic, f)
			}
			settings["fallbacks"] = generic
			mutated = true
		}
	}

	if mutated {
		modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return nil, err
		}
		inbound.Settings = string(modifiedSettings)
	}

	if len(inbound.StreamSettings) > 0 {
		// Unmarshal stream JSON
		var stream map[string]any
		_ = json.Unmarshal([]byte(inbound.StreamSettings), &stream)

		// Remove the "settings" field under "tlsSettings" and "realitySettings"
		tlsSettings, ok1 := stream["tlsSettings"].(map[string]any)
		realitySettings, ok2 := stream["realitySettings"].(map[string]any)
		if ok1 || ok2 {
			if ok1 {
				delete(tlsSettings, "settings")
			} else if ok2 {
				delete(realitySettings, "settings")
			}
		}

		delete(stream, "externalProxy")

		// finalmask.tcp + REALITY panics Xray-core on the first connection
		// (XTLS/Xray-core#6453). AddInbound/UpdateInbound reject this
		// combination at save time, but a row saved before that guard
		// existed (upgrade, node sync, restored backup, direct DB edit)
		// would still crash Xray on the next restart without this — drop
		// it here too, the same way liftXhttpSessionIDKeys and
		// HealShadowsocksClientMethods heal other legacy data in place.
		if len(finalMaskRealityTcpMasks(stream)) > 0 {
			logger.Warningf("Inbound %q: dropping finalmask, incompatible with REALITY security (crashes Xray-core, see XTLS/Xray-core#6453)", inbound.Tag)
			delete(stream, "finalmask")
		}

		dropEmptyRandPackets(stream["finalmask"])

		if dropped := stripIncompleteXmcMasks(stream); dropped > 0 {
			logger.Warningf("Inbound %q: dropping %d XMC finalmask mask(s) without complete Minecraft profiles — reconfigure them to restore the obfuscation (see XTLS/Xray-core#6487)", inbound.Tag, dropped)
		}

		// A row that skipped the save path can still carry an xdns shape older than 26.10.10.
		maskcompat.UpgradeLegacyXdns(stream["finalmask"])

		// xray-core v26.6.22 (#6258) renamed the XHTTP session keys and
		// kept no fallback. Lift legacy sessionPlacement/sessionKey onto the
		// new names here so inbounds stored before the rename keep working
		// without the admin re-saving them.
		liftXhttpSessionIDKeys(stream)

		newStream, err := json.MarshalIndent(stream, "", "  ")
		if err != nil {
			return nil, err
		}
		inbound.StreamSettings = string(newStream)
	}

	if inbound.Protocol == model.Shadowsocks {
		if healed, ok := model.HealShadowsocksClientMethods(inbound.Settings); ok {
			inbound.Settings = healed
		}
	}

	generated := inbound.GenXrayInboundConfig()
	generated.PanelGenerated = bandwidthManaged
	if bandwidthManaged && (inbound.Protocol == model.HTTP || inbound.Protocol == model.Mixed) {
		if tx == nil {
			tx = database.GetDB()
		}
		if err := pinBandwidthProxyOwners(tx, generated); err != nil {
			return nil, err
		}
	}
	return generated, nil
}
