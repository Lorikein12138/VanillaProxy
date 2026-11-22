package database

import (
	"os"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMigrateData_CompositeKeyTableLargerThanBatch(t *testing.T) {
	dsn := os.Getenv("XUI_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set XUI_TEST_PG_DSN to a reachable Postgres to run this test")
	}

	// Seed a SQLite source with the full schema and >500 client_inbounds rows.
	srcPath := t.TempDir() + "/x-ui.db"
	src, err := gorm.Open(sqlite.Open(srcPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	for _, m := range migrationModels() {
		if err := src.AutoMigrate(m); err != nil {
			t.Fatalf("automigrate %T: %v", m, err)
		}
	}
	const n = 600 // > batchSize (500) so the between-batches path is exercised
	links := make([]model.ClientInbound, 0, n)
	for i := 1; i <= n; i++ {
		links = append(links, model.ClientInbound{ClientId: i, InboundId: 1})
	}
	if err := src.CreateInBatches(links, 200).Error; err != nil {
		t.Fatalf("seed client_inbounds: %v", err)
	}
	if sqlDB, err := src.DB(); err == nil {
		sqlDB.Close() // flush before MigrateData reopens the file
	}

	// Make the test re-runnable: drop any tables from a previous run.
	dst, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := dst.Migrator().DropTable(migrationModels()...); err != nil {
		t.Fatalf("drop tables: %v", err)
	}

	if err := MigrateData(srcPath, dsn); err != nil {
		t.Fatalf("MigrateData: %v", err) // fails here before the fix
	}

	var got int64
	if err := dst.Model(&model.ClientInbound{}).Count(&got).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != n {
		t.Fatalf("client_inbounds rows = %d, want %d", got, n)
	}
}

func TestMigrateData_PreservesFalseDefaultedColumnsAndClientIDSequence(t *testing.T) {
	dsn := os.Getenv("XUI_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set XUI_TEST_PG_DSN to a reachable Postgres to run this test")
	}

	srcPath := t.TempDir() + "/x-ui.db"
	src, err := gorm.Open(sqlite.Open(srcPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	for _, m := range migrationModels() {
		if err := src.AutoMigrate(m); err != nil {
			t.Fatalf("automigrate %T: %v", m, err)
		}
	}

	if err := src.Create([]*model.ClientRecord{
		{Email: "on@example.com"},
		{Email: "off@example.com"},
	}).Error; err != nil {
		t.Fatalf("seed clients: %v", err)
	}
	const deletedID = 1000
	deleted := &model.ClientRecord{Id: deletedID, Email: "deleted@example.com"}
	if err := src.Create(deleted).Error; err != nil {
		t.Fatalf("seed high client ID: %v", err)
	}
	if err := src.Delete(deleted).Error; err != nil {
		t.Fatalf("delete high client ID: %v", err)
	}
	if err := src.Model(&model.ClientRecord{}).Where("email = ?", "off@example.com").
		Update("enable", false).Error; err != nil {
		t.Fatalf("disable client: %v", err)
	}
	if err := src.Create(&model.Node{Name: "n-off", Address: "1.2.3.4", Port: 1, ApiToken: "tok"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := src.Model(&model.Node{}).Where("name = ?", "n-off").
		Update("enable", false).Error; err != nil {
		t.Fatalf("disable node: %v", err)
	}
	if sqlDB, err := src.DB(); err == nil {
		sqlDB.Close()
	}

	dst, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := dst.Migrator().DropTable(migrationModels()...); err != nil {
		t.Fatalf("drop tables: %v", err)
	}

	if err := MigrateData(srcPath, dsn); err != nil {
		t.Fatalf("MigrateData: %v", err)
	}

	var off model.ClientRecord
	if err := dst.Where("email = ?", "off@example.com").First(&off).Error; err != nil {
		t.Fatalf("load disabled client: %v", err)
	}
	if off.Enable {
		t.Fatalf("disabled client re-enabled after migration (enable=%v)", off.Enable)
	}

	var on model.ClientRecord
	if err := dst.Where("email = ?", "on@example.com").First(&on).Error; err != nil {
		t.Fatalf("load enabled client: %v", err)
	}
	if !on.Enable {
		t.Fatalf("enabled client wrongly disabled after migration")
	}

	var node model.Node
	if err := dst.Where("name = ?", "n-off").First(&node).Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.Enable {
		t.Fatalf("disabled node re-enabled after migration")
	}

	checkNextID := func(db *gorm.DB, want int) {
		t.Helper()
		client := &model.ClientRecord{Email: "generated@example.com"}
		if err := db.Create(client).Error; err != nil {
			t.Fatalf("create generated client: %v", err)
		}
		if client.Id != want {
			t.Fatalf("generated client ID = %d, want %d", client.Id, want)
		}
		if err := db.Delete(client).Error; err != nil {
			t.Fatalf("delete generated client: %v", err)
		}
	}
	checkNextID(dst, deletedID+1)
	if err := resyncPostgresSequences(dst, []any{&model.ClientRecord{}}); err != nil {
		t.Fatalf("resync on startup: %v", err)
	}
	checkNextID(dst, deletedID+2)
	if err := MigrateData(srcPath, dsn); err != nil {
		t.Fatalf("repeat MigrateData: %v", err)
	}
	checkNextID(dst, deletedID+3)

	exportPath := t.TempDir() + "/export.db"
	if err := ExportPostgresToSQLite(dsn, exportPath); err != nil {
		t.Fatalf("ExportPostgresToSQLite: %v", err)
	}
	exported, err := gorm.Open(sqlite.Open(exportPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open exported SQLite: %v", err)
	}
	defer closeGorm(exported)
	checkNextID(exported, deletedID+4)
}

func TestSQLiteClientSequencePreservesDeletedIDs(t *testing.T) {
	src, err := gorm.Open(sqlite.Open(t.TempDir()+"/source.db"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer closeGorm(src)
	if seq, err := sqliteClientSequence(src); err != nil || seq != 0 {
		t.Fatalf("missing sqlite_sequence = %d, %v, want 0", seq, err)
	}
	if err := src.AutoMigrate(&model.ClientRecord{}); err != nil {
		t.Fatalf("create source clients: %v", err)
	}
	if seq, err := sqliteClientSequence(src); err != nil || seq != 0 {
		t.Fatalf("unused client sequence = %d, %v, want 0", seq, err)
	}
	const deletedID = 1000
	client := &model.ClientRecord{Id: deletedID, Email: "deleted@example.com"}
	if err := src.Create(client).Error; err != nil {
		t.Fatalf("seed high client ID: %v", err)
	}
	if err := src.Delete(client).Error; err != nil {
		t.Fatalf("delete high client ID: %v", err)
	}
	sequence, err := sqliteClientSequence(src)
	if err != nil || sequence != deletedID {
		t.Fatalf("sequence after delete = %d, %v, want %d", sequence, err, deletedID)
	}

	dst, err := gorm.Open(sqlite.Open(t.TempDir()+"/destination.db"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open destination: %v", err)
	}
	defer closeGorm(dst)
	if err := dst.AutoMigrate(&model.ClientRecord{}); err != nil {
		t.Fatalf("create destination clients: %v", err)
	}
	if err := advanceSQLiteClientSequence(dst, sequence); err != nil {
		t.Fatalf("initialize destination sequence: %v", err)
	}
	first := &model.ClientRecord{Email: "first@example.com"}
	if err := dst.Create(first).Error; err != nil || first.Id != deletedID+1 {
		t.Fatalf("first generated client ID = %d, %v, want %d", first.Id, err, deletedID+1)
	}
	if err := dst.Delete(first).Error; err != nil {
		t.Fatalf("delete first generated client: %v", err)
	}
	if err := advanceSQLiteClientSequence(dst, sequence); err != nil {
		t.Fatalf("clamp destination sequence: %v", err)
	}
	second := &model.ClientRecord{Email: "second@example.com"}
	if err := dst.Create(second).Error; err != nil || second.Id != deletedID+2 {
		t.Fatalf("second generated client ID = %d, %v, want %d", second.Id, err, deletedID+2)
	}
}

func TestPrepareSQLiteForMigrationPreservesClientSequence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		blockLater bool
	}{
		{name: "successful upgrade"},
		{name: "later model failed", blockLater: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srcPath := t.TempDir() + "/source.db"
			src, err := gorm.Open(sqlite.Open(srcPath), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				t.Fatalf("open source: %v", err)
			}
			defer closeGorm(src)
			if err := src.AutoMigrate(&model.User{}, &model.Setting{}, &model.Inbound{}); err != nil {
				t.Fatalf("create old panel tables: %v", err)
			}
			if err := src.Exec("CREATE TABLE clients (id integer PRIMARY KEY AUTOINCREMENT, email varchar NOT NULL)").Error; err != nil {
				t.Fatalf("create legacy clients: %v", err)
			}
			const deletedID = 1000
			if err := src.Exec("INSERT INTO clients (id, email) VALUES (?, 'deleted@example.com')", deletedID).Error; err != nil {
				t.Fatalf("seed legacy client: %v", err)
			}
			if err := src.Exec("DELETE FROM clients WHERE id = ?", deletedID).Error; err != nil {
				t.Fatalf("delete legacy client: %v", err)
			}
			if tc.blockLater {
				if err := src.Exec("CREATE VIEW outbound_subscriptions AS SELECT 1 AS id").Error; err != nil {
					t.Fatalf("block a later schema migration: %v", err)
				}
			}
			err = PrepareSQLiteForMigration(srcPath)
			if tc.blockLater {
				if err == nil || !strings.Contains(err.Error(), "upgrade panel schema for *model.OutboundSubscription") {
					t.Fatalf("prepare migration error = %v, want outbound subscriptions error", err)
				}
			} else if err != nil {
				t.Fatalf("prepare migration: %v", err)
			}
			client := &model.ClientRecord{Email: "prepared@example.com"}
			if err := src.Create(client).Error; err != nil || client.Id != deletedID+1 {
				t.Fatalf("next client ID after schema upgrade = %d, %v, want %d", client.Id, err, deletedID+1)
			}
		})
	}
}

func TestMigrateData_FailedCopyLeavesDestinationUntouched(t *testing.T) {
	dsn := os.Getenv("XUI_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set XUI_TEST_PG_DSN to a reachable Postgres to run this test")
	}

	seedSource := func(username string) string {
		t.Helper()
		srcPath := t.TempDir() + "/x-ui.db"
		src, err := gorm.Open(sqlite.Open(srcPath), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		for _, m := range migrationModels() {
			if err := src.AutoMigrate(m); err != nil {
				t.Fatalf("automigrate %T: %v", m, err)
			}
		}
		if err := src.Create(&model.User{Username: username, Password: "pw"}).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if sqlDB, err := src.DB(); err == nil {
			sqlDB.Close()
		}
		return srcPath
	}

	dst, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := dst.Migrator().DropTable(migrationModels()...); err != nil {
		t.Fatalf("drop tables: %v", err)
	}

	if err := MigrateData(seedSource("keep-me"), dsn); err != nil {
		t.Fatalf("seed destination via MigrateData: %v", err)
	}

	brokenSrc := seedSource("evil")
	breaker, err := gorm.Open(sqlite.Open(brokenSrc), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("reopen broken source: %v", err)
	}
	if err := breaker.Exec("DROP TABLE outbound_subscriptions").Error; err != nil {
		t.Fatalf("drop table from broken source: %v", err)
	}
	if sqlDB, err := breaker.DB(); err == nil {
		sqlDB.Close()
	}

	if err := MigrateData(brokenSrc, dsn); err == nil {
		t.Fatal("MigrateData succeeded on a source missing outbound_subscriptions, want error")
	}

	var keepMe, evil int64
	if err := dst.Model(&model.User{}).Where("username = ?", "keep-me").Count(&keepMe).Error; err != nil {
		t.Fatalf("count keep-me: %v", err)
	}
	if err := dst.Model(&model.User{}).Where("username = ?", "evil").Count(&evil).Error; err != nil {
		t.Fatalf("count evil: %v", err)
	}
	if keepMe != 1 {
		t.Fatalf("previous destination data lost after failed migration: keep-me count = %d, want 1", keepMe)
	}
	if evil != 0 {
		t.Fatalf("failed migration leaked partial rows: evil count = %d, want 0", evil)
	}
}
