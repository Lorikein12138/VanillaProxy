package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestBandwidthClientMutationRollsBackUnknownAccount(t *testing.T) {
	setupEnablePortTest(t)
	setupBandwidthSaveNode(t)
	inbounds := &InboundService{}
	clients := &ClientService{}
	inbound := &model.Inbound{Tag: "client-mutation", Port: 40493, Enable: true, Protocol: model.VLESS,
		Settings: `{"decryption":"none","clients":[]}`}
	if _, _, err := inbounds.AddInbound(inbound); err != nil {
		t.Fatal(err)
	}
	data := func(client model.Client) *model.Inbound {
		return &model.Inbound{Id: inbound.Id, Settings: clientsSettings(t, []model.Client{client})}
	}
	known := model.Client{Email: "peer", ID: "6e45abb0-c265-4add-97d9-2e6b9588a2a0", Enable: true}
	if _, err := clients.AddInboundClient(inbounds, data(known)); err != nil {
		t.Fatalf("add known account: %v", err)
	}
	assertRejected := func(mutate func() error) {
		t.Helper()
		before, err := inbounds.GetInbound(inbound.Id)
		if err != nil {
			t.Fatal(err)
		}
		beforeLinks, err := clients.ListForInbound(nil, inbound.Id)
		if err != nil {
			t.Fatal(err)
		}
		if err := mutate(); err == nil || !strings.Contains(err.Error(), "canonical account binding") {
			t.Fatalf("mutation error = %v, want missing account binding", err)
		}
		after, err := inbounds.GetInbound(inbound.Id)
		if err != nil {
			t.Fatal(err)
		}
		afterLinks, err := clients.ListForInbound(nil, inbound.Id)
		if err != nil {
			t.Fatal(err)
		}
		if after.Settings != before.Settings || !reflect.DeepEqual(after.ClientStats, before.ClientStats) ||
			!reflect.DeepEqual(afterLinks, beforeLinks) {
			t.Fatal("rejected mutation changed the inbound settings, links or traffic rows")
		}
	}

	unknown := model.Client{Email: "unknown", ID: "6e45abb0-c265-4add-97d9-2e6b9588a2a1", Enable: true}
	assertRejected(func() error {
		_, err := clients.AddInboundClient(inbounds, data(unknown))
		return err
	})
	renamed := known
	renamed.Email = "unknown-rename"
	assertRejected(func() error {
		_, err := clients.UpdateInboundClient(inbounds, data(renamed), known.Email)
		return err
	})

	unknown.Enable = false
	if _, err := clients.AddInboundClient(inbounds, data(unknown)); err != nil {
		t.Fatalf("add disabled account for later editing: %v", err)
	}
	assertRejected(func() error {
		_, _, err := clients.SetClientEnableByEmail(inbounds, unknown.Email, true)
		return err
	})
	// Bulk enable does not update the counter flag. Start with an enabled
	// counter so this tests a bulk change that would really serve traffic.
	if err := database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", unknown.Email).Update("enable", true).Error; err != nil {
		t.Fatal(err)
	}
	assertRejected(func() error {
		result := clients.bulkSetEnableInboundClients(inbounds, inbound.Id, []string{unknown.Email}, true)
		if message := result.perEmailSkipped[unknown.Email]; message != "" {
			return errors.New(message)
		}
		return nil
	})
}

func TestSaveBandwidthXrayTemplateRejectsEnabledLocalTagCollision(t *testing.T) {
	setupConflictDB(t)
	setupBandwidthSaveNode(t)
	svc := &XraySettingService{}
	if err := svc.SaveXraySetting("{}"); err != nil {
		t.Fatal(err)
	}
	before, err := svc.GetXrayConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	seedInboundConflict(t, "same-tag", "127.0.0.1", 40494, model.VLESS, `{}`, `{"decryption":"none","clients":[]}`)
	const template = `{"inbounds":[{"tag":"same-tag","port":40495,"protocol":"http","settings":{"accounts":[{"user":"peer","pass":"secret"}]}}]}`
	if err := svc.SaveXraySetting(template); err == nil || !strings.Contains(err.Error(), "conflicts with an enabled local inbound tag") {
		t.Fatalf("setting save error = %v, want enabled local tag collision", err)
	}
	after, err := svc.GetXrayConfigTemplate()
	if err != nil || after != before {
		t.Fatalf("rejected template changed stored settings: %v", err)
	}
	disableInboundRow(t, loadInboundByTag(t, "same-tag").Id)
	if err := svc.SaveXraySetting(template); err != nil {
		t.Fatalf("disabled inbound blocked saving the template: %v", err)
	}
}
