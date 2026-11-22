package service

import (
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"

	"gorm.io/gorm"
)

// How long a client stays recoverable after a node merge concluded it is gone.
// Any merge that sees it attached again inside this window clears the mark.
const syncOrphanReapGrace = 15 * time.Minute

// A traffic row with no clients row behind it is drift the orphan sweep will
// never mark, so it stays on the old delete-immediately path.
func clientRecordExists(tx *gorm.DB, email string) bool {
	var n int64
	if err := tx.Model(&model.ClientRecord{}).Where("email = ?", email).Count(&n).Error; err != nil {
		return false
	}
	return n > 0
}

func markSyncOrphan(tx *gorm.DB, email string, nowMs int64) error {
	if email == "" {
		return nil
	}
	return tx.Model(&model.ClientRecord{}).
		Where("email = ? AND sync_orphaned_at = 0", email).
		Update("sync_orphaned_at", nowMs).Error
}

// A client that is attached again is not orphaned, whatever an earlier merge
// concluded — this is what makes a bad merge recoverable instead of fatal.
func clearSyncOrphanMarks(tx *gorm.DB) error {
	return tx.Model(&model.ClientRecord{}).
		Where("sync_orphaned_at > 0 AND EXISTS (SELECT 1 FROM client_inbounds WHERE client_inbounds.client_id = clients.id)").
		Update("sync_orphaned_at", 0).Error
}

// ReapSyncOrphans deletes the clients the node-snapshot sweep marked and no
// later merge reclaimed. It is the only path that hard-deletes for that sweep.
func (s *ClientService) ReapSyncOrphans() (int, error) {
	db := database.GetDB()
	cutoff := time.Now().Add(-syncOrphanReapGrace).UnixMilli()

	var emails []string
	if err := db.Model(&model.ClientRecord{}).
		Where("sync_orphaned_at > 0 AND sync_orphaned_at <= ?", cutoff).
		Where("NOT EXISTS (SELECT 1 FROM client_inbounds WHERE client_inbounds.client_id = clients.id)").
		Pluck("email", &emails).Error; err != nil {
		return 0, err
	}
	if len(emails) == 0 {
		return 0, nil
	}

	reaped := 0
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var removed int
		if err := runSerializedTx(func(tx *gorm.DB) error {
			var rows []model.ClientRecord
			if err := tx.Select("id, email").
				Where("email IN ? AND sync_orphaned_at > 0 AND sync_orphaned_at <= ?", batch, cutoff).
				Where("NOT EXISTS (SELECT 1 FROM client_inbounds WHERE client_inbounds.client_id = clients.id)").
				Find(&rows).Error; err != nil || len(rows) == 0 {
				return err
			}
			linked, err := bandwidthProxyLinkedClients(tx)
			if err != nil {
				return err
			}
			ids, orphanEmails := make([]int, 0, len(rows)), make([]string, 0, len(rows))
			for _, row := range rows {
				if !linked[row.Id] {
					ids = append(ids, row.Id)
					orphanEmails = append(orphanEmails, row.Email)
				}
			}
			if len(ids) == 0 {
				return nil
			}
			if err := adjustGroupBaselinesForRemovedTraffic(tx, orphanEmails); err != nil {
				return err
			}
			if err := deleteClientRecords(tx, ids); err != nil {
				return err
			}
			if err := tx.Where("email IN ?", orphanEmails).Delete(&xray.ClientTraffic{}).Error; err != nil {
				return err
			}
			if err := tx.Where("email IN ?", orphanEmails).Delete(&model.NodeClientTraffic{}).Error; err != nil {
				return err
			}
			removed = len(ids)
			return tx.Where("client_email IN ?", orphanEmails).Delete(&model.InboundClientIps{}).Error
		}); err != nil {
			return reaped, err
		}
		if removed > 0 {
			reaped += removed
			logger.Infof("reaped %d client(s) confirmed removed on their node", removed)
		}
	}
	return reaped, nil
}
