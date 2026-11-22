package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wirecodec"
)

func TestNodeSyncSnapshotUsesEffectiveNativeCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	dbtest.InitDB(t, filepath.Join(dbDir, "x-ui.db"))
	db := database.GetDB()
	for token, scope := range map[string]string{"node-token": model.ApiScopeNodeSync, "admin-token": model.ApiScopeAdmin} {
		if err := db.Create(&model.ApiToken{Name: token, Token: crypto.HashTokenSHA256(token), Enabled: true, Scope: scope}).Error; err != nil {
			t.Fatal(err)
		}
	}
	const (
		email       = "multi@example.test"
		previousID  = "11111111-1111-1111-1111-111111111111"
		currentID   = "22222222-2222-2222-2222-222222222222"
		staleVMess  = `{"clients":[{"email":"` + email + `","id":"` + previousID + `","enable":false,"expiryTime":42}],"disableInsecureEncryption":true}`
		newVLESS    = `{"clients":[{"email":"` + email + `","id":"` + currentID + `","enable":true}],"decryption":"none"}`
		staleMasque = `{"clients":[{"email":"` + email + `","pass":"old","enable":true}]}`
	)
	client := model.ClientRecord{Email: email, UUID: currentID, Password: "current-password"}
	node := model.Node{Name: "descendant", Guid: "descendant-guid"}
	for _, row := range []any{&client, &node} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, inbound := range []*model.Inbound{
		{UserId: 1, Tag: "local-vmess", Protocol: model.VMESS, Port: 23500, Enable: true, Settings: staleVMess},
		{UserId: 1, Tag: "local-vless", Protocol: model.VLESS, Port: 23501, Enable: true, Settings: newVLESS},
		{UserId: 1, Tag: "mirror-vmess", Protocol: model.VMESS, Port: 23502, Enable: true, NodeID: &node.Id, Settings: staleVMess},
		{UserId: 1, Tag: "local-masque", Protocol: model.MASQUE, Port: 23503, Enable: true, Settings: staleMasque},
	} {
		if err := db.Create(inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
	}
	proxy := model.Inbound{UserId: 1, Tag: "bound-http", Protocol: model.HTTP, Port: 23504, Enable: true,
		Settings: fmt.Sprintf(`{"accounts":[{"user":"proxy-user","pass":"password","bandwidthClientId":%d}]}`, client.Id)}
	if err := db.Create(&proxy).Error; err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	a := &APIController{}
	api := engine.Group("/panel/api")
	api.Use(a.checkAPIAuth, a.enforceTokenScope)
	NewInboundController(api.Group("/inbounds"))
	list := func(token string, requested, optedIn, master bool) map[string]string {
		t.Helper()
		path := "/panel/api/inbounds/list"
		if requested {
			path += "?" + wirecodec.EffectiveNativeAuthQuery + "=1"
		}
		if optedIn {
			join := "?"
			if requested {
				join = "&"
			}
			path += join + wirecodec.BandwidthProxyBindingsQuery + "=1"
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if master {
			req.Header.Set(wirecodec.MasterPushHeader, "1")
		}
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		var response struct {
			Success bool
			Obj     []*model.Inbound
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || !response.Success || len(response.Obj) != 5 {
			t.Fatalf("snapshot status %d, response %s, decode error %v", w.Code, w.Body.String(), err)
		}
		settings := make(map[string]string)
		for _, inbound := range response.Obj {
			settings[inbound.Tag] = inbound.Settings
		}
		trustedRequest := requested && (token == "node-token" || master)
		wantProjection := trustedRequest && optedIn
		if strings.Contains(settings[proxy.Tag], "bandwidthClientId") == trustedRequest ||
			strings.Contains(w.Body.String(), "\"bandwidthProxyBindings\"") != wantProjection ||
			(w.Header().Get("Cache-Control") == "no-store") != wantProjection ||
			(w.Header().Get(wirecodec.BandwidthProxyInventoryHeader) != "") != wantProjection {
			t.Fatalf("proxy projection/cache mismatched scoped opt-in; request %s, response %s", path, w.Body.String())
		}
		return settings
	}
	assertProjected := func(settings map[string]string) {
		t.Helper()
		if settings["local-vless"] != newVLESS || settings["mirror-vmess"] != staleVMess {
			t.Fatal("the snapshot changed a current local row or descendant row")
		}
		var vmess struct {
			Clients                   []model.Client `json:"clients"`
			DisableInsecureEncryption bool           `json:"disableInsecureEncryption"`
		}
		if err := json.Unmarshal([]byte(settings["local-vmess"]), &vmess); err != nil ||
			len(vmess.Clients) != 1 || vmess.Clients[0].ID != currentID || vmess.Clients[0].Enable || vmess.Clients[0].ExpiryTime != 42 || !vmess.DisableInsecureEncryption {
			t.Fatalf("unexpected VMess projection: %+v, %v", vmess, err)
		}
		var masque struct {
			Clients []struct{ Password, Pass string } `json:"clients"`
		}
		if err := json.Unmarshal([]byte(settings["local-masque"]), &masque); err != nil ||
			len(masque.Clients) != 1 || masque.Clients[0].Password != client.Password || masque.Clients[0].Pass != "" {
			t.Fatalf("unexpected MASQUE projection: %+v, %v", masque, err)
		}
	}
	assertProjected(list("node-token", true, false, false))
	assertProjected(list("node-token", true, true, false))
	assertProjected(list("admin-token", true, true, true))
	for _, settings := range []map[string]string{list("node-token", false, true, true), list("admin-token", true, true, false)} {
		if settings["local-vmess"] != staleVMess || settings["local-masque"] != staleMasque {
			t.Fatal("the stock snapshot changed or the projected credentials were persisted")
		}
	}
}
