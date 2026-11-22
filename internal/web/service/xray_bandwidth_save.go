package service

import (
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func validateBandwidthTemplateInboundTags(db *gorm.DB, inbounds []xray.InboundConfig) error {
	if len(inbounds) == 0 {
		return nil
	}
	var localTags []string
	if err := db.Model(&model.Inbound{}).Where("node_id IS NULL AND enable = ?", true).Pluck("tag", &localTags).Error; err != nil {
		return err
	}
	used := make(map[string]struct{}, len(localTags))
	for _, tag := range localTags {
		used[tag] = struct{}{}
	}
	for _, inbound := range inbounds {
		if _, conflict := used[inbound.Tag]; conflict {
			return fmt.Errorf("managed Xray template inbound %q conflicts with an enabled local inbound tag", inbound.Tag)
		}
	}
	return nil
}

// validateSavedBandwidthXrayInbound checks the candidate before its transaction
// commits, when its normalized inbound, client links and counters are visible.
func (s *InboundService) validateSavedBandwidthXrayInbound(tx *gorm.DB, inbound *model.Inbound) error {
	node := activeBandwidthNode.Load()
	if node == nil || !inbound.Enable || inbound.NodeID != nil || servedOutsideXray(inbound.Protocol) {
		return nil
	}
	candidate := *inbound
	candidate.ClientStats = nil
	if err := tx.Where("inbound_id = ?", candidate.Id).Find(&candidate.ClientStats).Error; err != nil {
		return err
	}
	s.enrichClientStats(tx, []*model.Inbound{&candidate})
	if err := filterBandwidthDepletedClients(tx, &candidate); err != nil {
		return err
	}
	generated, err := s.buildGeneratedXrayInbound(tx, &candidate, true)
	if err != nil {
		return err
	}
	config := &xray.Config{InboundConfigs: []xray.InboundConfig{*generated}}
	_, _, err = prepareBandwidthXrayConfigWithPolicy(node.panel.AllowsUnmeteredXrayAccounts(), config, node.panel.AccountID, node.panel.AutomaticAccountLookup())
	return err
}

func filterBandwidthDepletedClients(tx *gorm.DB, candidate *model.Inbound) error {
	if len(candidate.ClientStats) == 0 {
		return nil
	}
	ids := make([]int, len(candidate.ClientStats))
	for i, stats := range candidate.ClientStats {
		ids[i] = stats.Id
	}
	// The generated config runs traffic maintenance before loading this row.
	// Account validation must likewise omit non-renewing depleted clients.
	condition, args := depletedCond(tx)
	disabled := make(map[int]bool)
	for start := 0; start < len(ids); start += sqlInChunk {
		var found []int
		if err := tx.Model(&xray.ClientTraffic{}).Where(condition, args...).
			Where("(reset = 0 AND reset_day = 0 AND reset_weekday = 0) OR (reset_max > 0 AND reset_count >= reset_max)").
			Where("id IN ?", ids[start:min(start+sqlInChunk, len(ids))]).Pluck("id", &found).Error; err != nil {
			return err
		}
		for _, id := range found {
			disabled[id] = true
		}
	}
	for i := range candidate.ClientStats {
		if disabled[candidate.ClientStats[i].Id] {
			candidate.ClientStats[i].Enable = false
		}
	}
	return nil
}

func validateSavedBandwidthXrayTemplate(candidate *xray.Config, resolveAccount func(string) (string, bool)) error {
	if err := rejectBandwidthAWGOutbounds(candidate); err != nil {
		return err
	}
	// Check the same API and routing settings the child would receive. The
	// stored template retains the administrator's API services and disabled rules.
	candidate.API = ensureAPIServices(candidate.API)
	candidate.RouterConfig = stripDisabledRules(candidate.RouterConfig)
	prepared, _, err := prepareBandwidthXrayConfig(false, candidate, resolveAccount)
	if err != nil {
		return err
	}
	return validateBandwidthAPIRoutes(prepared)
}
