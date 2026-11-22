package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	xuilogger "github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
	"github.com/mhsanaei/3x-ui/v3/internal/web/global"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/op/go-logging"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type bandwidthTestWebServer struct {
	global.WebServer
	scheduler *cron.Cron
}

func (server bandwidthTestWebServer) GetCron() *cron.Cron { return server.scheduler }

func TestClientBandwidthAPI(t *testing.T) {
	xuilogger.InitLogger(logging.ERROR)
	router, _ := newAPIAuthTestEngine(t)
	previous := global.GetWebServer()
	global.SetWebServer(bandwidthTestWebServer{scheduler: cron.New()})
	t.Cleanup(func() { global.SetWebServer(previous) })
	NewAPIController(router.Group("/base"))
	db := database.GetDB()
	client := model.ClientRecord{Email: "limited@example.test"}
	upstream := model.Node{Name: "upstream", Guid: "upstream-guid"}
	legacy := model.Node{Name: "legacy"}
	for _, row := range []any{&client, &upstream, &legacy} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	inbounds := []model.Inbound{
		{UserId: 1, Tag: "bandwidth-local", Port: 1443, Protocol: model.VLESS},
		{UserId: 1, Tag: "bandwidth-origin", Port: 2443, Protocol: model.VLESS, NodeID: &upstream.Id, OriginNodeGuid: "physical-origin"},
		{UserId: 1, Tag: "bandwidth-upstream", Port: 3443, Protocol: model.VLESS, NodeID: &upstream.Id},
		{UserId: 1, Tag: "bandwidth-legacy", Port: 4443, Protocol: model.VLESS, NodeID: &legacy.Id},
	}
	for index := range inbounds {
		inbound := &inbounds[index]
		if err := db.Create(inbound).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Model(&inbounds[1]).UpdateColumn("enable", false).Error; err != nil {
		t.Fatal(err)
	}
	options, err := (&service.InboundService{}).GetInboundOptions(1)
	if err != nil || len(options) != len(inbounds) {
		t.Fatalf("got %d inbound options, err %v", len(options), err)
	}
	legacyKey := fmt.Sprintf("node:%d", legacy.Id)
	if options[0].BandwidthNodeKey != "local" || options[1].Enable || options[1].BandwidthNodeKey != "guid:physical-origin" ||
		options[2].BandwidthNodeKey != fmt.Sprintf("node:%d", upstream.Id) || options[3].BandwidthNodeKey != legacyKey {
		t.Fatalf("unexpected physical node identities in options: %+v", options)
	}
	const endpoint = "/base/panel/api/clients/"
	valid := fmt.Sprintf(`{"totalBitsPerSecond":7000000,"nodeBitsPerSecond":{"local":0,"guid:physical-origin":3000000,%q:2000000}}`, legacyKey)
	for _, scope := range []string{model.ApiScopeAdmin, model.ApiScopeMonitor, model.ApiScopeNodeSync, model.ApiScopeNodeAdmin} {
		if err := db.Create(&model.ApiToken{Name: scope, Token: crypto.HashTokenSHA256(scope), Enabled: true, Scope: scope}).Error; err != nil {
			t.Fatal(err)
		}
	}
	call := func(method, email, body, token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, endpoint+email+"/bandwidth", strings.NewReader(body))
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	assertPolicy := func(w *httptest.ResponseRecorder, total int64, nodeRates map[string]int64) {
		t.Helper()
		var payload struct {
			Success bool
			Obj     service.ClientBandwidthSettings
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != http.StatusOK || !payload.Success || payload.Obj.Available ||
			payload.Obj.TotalBitsPerSecond != total || payload.Obj.NodeBitsPerSecond == nil || !maps.Equal(payload.Obj.NodeBitsPerSecond, nodeRates) {
			t.Fatalf("unexpected policy response (%d): %s, %v", w.Code, w.Body, err)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if got := call(method, client.Email, valid, "").Code; got != http.StatusUnauthorized {
			t.Errorf("anonymous %s returned %d", method, got)
		}
		for _, scope := range []string{model.ApiScopeMonitor, model.ApiScopeNodeSync, model.ApiScopeNodeAdmin} {
			if got := call(method, client.Email, valid, scope).Code; got != http.StatusForbidden {
				t.Errorf("%s %s returned %d", scope, method, got)
			}
		}
	}
	assertPolicy(call(http.MethodGet, client.Email, "", model.ApiScopeAdmin), 0, nil)
	wanted := map[string]int64{"local": 0, "guid:physical-origin": 3000000, legacyKey: 2000000}
	assertPolicy(call(http.MethodPost, client.Email, valid, model.ApiScopeAdmin), 7000000, wanted)
	// A legacy snapshot first backfills the synthetic GUID. A later heartbeat
	// gives the same node a real GUID. The saved limit stays on the same node.
	if err := db.Model(&inbounds[3]).Update("origin_node_guid", legacyKey).Error; err != nil {
		t.Fatal(err)
	}
	assertPolicy(call(http.MethodGet, client.Email, "", model.ApiScopeAdmin), 7000000, wanted)
	if err := db.Model(&legacy).Update("guid", "learned-guid").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&inbounds[3]).Update("origin_node_guid", "learned-guid").Error; err != nil {
		t.Fatal(err)
	}
	assertPolicy(call(http.MethodGet, client.Email, "", model.ApiScopeAdmin), 7000000, wanted)
	for _, body := range []string{
		`{"totalBitsPerSecond":3}`,
		`{"totalBitsPerSecond":null,"nodeBitsPerSecond":{}}`,
		`{"totalBitsPerSecond":1.5,"nodeBitsPerSecond":{}}`,
		`{"totalBitsPerSecond":-1,"nodeBitsPerSecond":{}}`,
		`{"totalBitsPerSecond":9007199254740992,"nodeBitsPerSecond":{}}`,
		`{"totalBitsPerSecond":0,"nodeBitsPerSecond":null}`,
		`{"totalBitsPerSecond":5,"nodeBitsPerSecond":{"local":6}}`,
		`{"totalBitsPerSecond":0,"nodeBitsPerSecond":{"local":9007199254740992}}`,
		`{"totalBitsPerSecond":0,"nodeBitsPerSecond":{"local":null}}`,
		`{"totalBitsPerSecond":0,"nodeBitsPerSecond":{"guid:unattached":3}}`,
	} {
		w := call(http.MethodPost, client.Email, body, model.ApiScopeAdmin)
		var payload struct{ Success bool }
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != http.StatusOK || payload.Success {
			t.Errorf("invalid request %s returned (%d): %s, %v", body, w.Code, w.Body, err)
		}
	}
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/test-login", nil))
	if login.Code != http.StatusOK || len(login.Result().Cookies()) == 0 {
		t.Fatalf("no authenticated session: %d %s", login.Code, login.Body)
	}
	assertPolicy(call(http.MethodGet, client.Email, "", "", login.Result().Cookies()...), 7000000, wanted)

	if err := db.Where("client_id = ? AND inbound_id = ?", client.Id, inbounds[1].Id).Delete(&model.ClientInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	client.Email = "renamed@example.test"
	if err := db.Save(&client).Error; err != nil {
		t.Fatal(err)
	}
	assertPolicy(call(http.MethodGet, client.Email, "", model.ApiScopeAdmin), 7000000, wanted)
	retained := map[string]int64{"guid:physical-origin": 3000000}
	assertPolicy(call(http.MethodPost, client.Email, `{"totalBitsPerSecond":0,"nodeBitsPerSecond":{}}`, model.ApiScopeAdmin), 0, retained)
	policy, err := (service.ClientBandwidthService{}).ReadClientBandwidth(t.Context(), client.Id)
	if err != nil || policy.TotalBitsPerSecond != 0 || !maps.Equal(policy.NodeBitsPerSecond, retained) {
		t.Fatalf("authority policy lost the detached node limit: %+v, %v", policy, err)
	}
	restored := model.ClientInbound{ClientId: client.Id, InboundId: inbounds[1].Id}
	if err := db.Create(&restored).Error; err != nil {
		t.Fatal(err)
	}
	assertPolicy(call(http.MethodPost, client.Email, `{"totalBitsPerSecond":5000000,"nodeBitsPerSecond":{"guid:physical-origin":3000000}}`, model.ApiScopeAdmin), 5000000, retained)
	if err := db.Where("client_id = ?", client.Id).Delete(&model.ClientInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := (&service.ClientService{}).Delete(&service.InboundService{}, client.Id, false); err != nil {
		t.Fatal(err)
	}
	var policyRows int64
	if err := db.Model(&model.ClientBandwidth{}).Where("client_id = ?", client.Id).Count(&policyRows).Error; err != nil || policyRows != 0 {
		t.Fatalf("removed client has %d stored policy rows: %v", policyRows, err)
	}
	if _, err := (service.ClientBandwidthService{}).ReadClientBandwidth(t.Context(), client.Id); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("removed client must fail policy resolution, got %v", err)
	}
}
