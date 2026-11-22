package xraybandwidthchild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/infra/conf/serial"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vmess"
)

const (
	vlessID  = "6e45abb0-c265-4add-97d9-2e6b9588a2a0"
	vlessTag = "limited-vless"
	hy2Tag   = "limited-hy2"
	email    = "client-email"
	clientID = "canonical-client"
)

func TestReadHandshakeRejectsMalformedInput(t *testing.T) {
	const secret = "private-test-marker"
	const ipc = `"ipc":{"Address":"127.0.0.1:1234","Token":"` + secret + `"}`
	const valid = "{" + ipc + `,"clients":{"tag":{"email":"id"}}}`
	for _, tc := range []struct{ name, input string }{
		{"missing", ""},
		{"null", "null"},
		{"incomplete", "{" + ipc + "}"},
		{"empty managed inbounds", "{" + ipc + `,"clients":{}}`},
		{"unknown member", valid[:len(valid)-1] + `,"unexpected":"` + secret + `"}`},
		{"duplicate tag", "{" + ipc + `,"clients":{"tag":{},"tag":{}}}`},
		{"duplicate email", "{" + ipc + `,"clients":{"tag":{"email":"a","email":"b"}}}`},
		{"duplicate capability", "{" + ipc + `,"clients":{"tag":{}},` + ipc + "}"},
		{"trailing data", valid + "{}"},
		{"oversized", strings.Repeat(" ", launch.MaxHandshakeSize) + valid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readHandshake(strings.NewReader(tc.input))
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("got error %v, expected rejection without private values", err)
			}
		})
	}
	if _, err := readHandshake(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
}

func TestRunCancelsBlockedHandshake(t *testing.T) {
	stdin, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []string{"unused.json"}, stdin) }()
	if _, err := io.WriteString(writer, "{"); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run waited for EOF after cancellation")
	}
}

func TestReadyRequiresUnchangedNativeConfig(t *testing.T) {
	data := []byte(fmt.Sprintf(`{"inbounds":[%s]}`, vlessInbound(20000)))
	digest := sha256.Sum256(data)
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path, digest[:]); err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(vlessID), []byte("fcd78466-6d89-4f01-a72c-0b4adb15be62"), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path, digest[:]); err == nil || !strings.Contains(err.Error(), "changed before startup") {
		t.Fatalf("changed native configuration accepted: %v", err)
	}
}

func TestBindClientsUsesTagProtocolAndExactEmail(t *testing.T) {
	config := fmt.Sprintf(`{"api":{"tag":"api","services":["StatsService","LoggerService"]},"inbounds":[%s,%s]}`,
		vlessInbound(20000), hysteriaInbound(`"version":2`))
	cfg, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	bound, guarded, err := bindClients(cfg, map[string]map[string]string{
		vlessTag: {email: clientID}, hy2Tag: {email: clientID},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(guarded.VLESS) != 1 || guarded.VLESS[0] != vlessTag || len(guarded.Hysteria) != 1 || guarded.Hysteria[0] != hy2Tag {
		t.Fatalf("managed inbound tags = %+v", guarded)
	}
	vlessAccount, err := (&vless.Account{Id: vlessID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	hyUser := &protocol.MemoryUser{Email: email, Account: &hyaccount.MemoryAccount{Auth: "test-password"}}
	vlessUser := &protocol.MemoryUser{Email: email, Account: vlessAccount}
	for _, tc := range []struct {
		tag, name string
		user      *protocol.MemoryUser
		allowed   bool
	}{
		{vlessTag, protocolVLESS, vlessUser, true},
		{hy2Tag, protocolHysteria, hyUser, true},
		{vlessTag, protocolVLESS, nil, false},
		{vlessTag, protocolVLESS, hyUser, false},
		{vlessTag, protocolHysteria, vlessUser, false},
		{hy2Tag, protocolHysteria, &protocol.MemoryUser{Email: strings.ToUpper(email), Account: hyUser.Account}, false},
	} {
		ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: tc.tag, Name: tc.name})
		id, managed, err := bound.resolve(ctx, tc.user)
		if !managed || (err == nil) != tc.allowed || (id == clientID) != tc.allowed {
			t.Fatalf("resolve %q/%q for %v = %q, %v, %v", tc.tag, tc.name, tc.user, id, managed, err)
		}
	}
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: "ordinary", Name: protocolVLESS})
	if id, managed, err := bound.resolve(ctx, vlessUser); id != "" || managed || err != nil {
		t.Fatalf("ordinary inbound = %q, %v, %v", id, managed, err)
	}
}

func TestBindClientsUnmeteredXrayAccountsRequireExactCredentials(t *testing.T) {
	const unmeteredEmail = "unmetered"
	const unmeteredUUID = "6e45abb0-c265-4add-97d9-2e6b9588a2a1"
	proxyConfig := fmt.Sprintf(`{"inbounds":[
		{"tag":%q,"port":20000,"protocol":"vless","settings":{"decryption":"none","clients":[{"email":%q,"id":%q},{"email":%q,"id":%q}]}},
		{"tag":%q,"port":20001,"protocol":"hysteria","settings":{"version":2,"clients":[{"email":%q,"auth":"limited-auth"},{"email":%q,"auth":"unmetered-auth"}]},
		 "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2}}}
	]}`, vlessTag, email, vlessID, unmeteredEmail, unmeteredUUID, hy2Tag, email, unmeteredEmail)
	cfg, err := serial.LoadJSONConfig(strings.NewReader(proxyConfig))
	if err != nil {
		t.Fatal(err)
	}
	bound, _, err := bindClients(cfg, map[string]map[string]string{
		vlessTag: {email: clientID, unmeteredEmail: launch.UnmeteredXrayAccountID},
		hy2Tag:   {email: clientID, unmeteredEmail: launch.UnmeteredXrayAccountID},
	}, map[string]bool{vlessTag: true, hy2Tag: true})
	if err != nil {
		t.Fatal(err)
	}
	strict, _, err := bindClients(cfg, map[string]map[string]string{
		vlessTag: {email: clientID}, hy2Tag: {email: clientID},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		tag, name       string
		limited, exempt protocol.AsAccount
	}{
		{vlessTag, protocolVLESS, &vless.Account{Id: vlessID}, &vless.Account{Id: unmeteredUUID}},
		{hy2Tag, protocolHysteria, &hyaccount.Account{Auth: "limited-auth"}, &hyaccount.Account{Auth: "unmetered-auth"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			limited, err := test.limited.AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			exempt, err := test.exempt.AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: test.tag, Name: test.name})
			for _, tc := range []struct {
				label, accountEmail string
				account             protocol.Account
				wantID              string
				managed, rejected   bool
			}{
				{"limited", email, limited, clientID, true, false},
				{"exempt", unmeteredEmail, exempt, "", false, false},
				{"unknown", "unknown", exempt, "", true, true},
				{"wrong case", strings.ToUpper(unmeteredEmail), exempt, "", true, true},
				{"wrong credential", unmeteredEmail, limited, "", true, true},
				{"missing credential", unmeteredEmail, nil, "", true, true},
			} {
				id, managed, err := bound.resolve(ctx, &protocol.MemoryUser{Email: tc.accountEmail, Account: tc.account})
				if id != tc.wantID || managed != tc.managed || (err != nil) != tc.rejected {
					t.Errorf("%s resolved to %q, managed=%v, error=%v", tc.label, id, managed, err)
				}
			}
			if id, managed, err := strict.resolve(ctx, &protocol.MemoryUser{Email: unmeteredEmail, Account: exempt}); id != "" || !managed || err == nil {
				t.Errorf("missing strict binding resolved to %q, managed=%v, error=%v", id, managed, err)
			}
			for _, invalid := range []map[string]string{{"unknown": launch.UnmeteredXrayAccountID}, {unmeteredEmail: ""}} {
				if _, _, err := bindClients(cfg, map[string]map[string]string{test.tag: invalid}, map[string]bool{test.tag: true}); err == nil {
					t.Errorf("accepted invalid handshake binding %q", invalid)
				}
			}
		})
	}
}

func TestBindClientsRejectsIrrelevantOrUnsafeConfig(t *testing.T) {
	const unsupported = `{"tag":"other","port":20001,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":80}}`
	vless := vlessInbound(20000)
	for _, tc := range []struct {
		name, inbounds, api, tag, email, want string
	}{
		{"unknown tag", vless, "", "missing", email, "unknown inbound tag"},
		{"unknown email", vless, "", vlessTag, "missing", "unknown authenticated email"},
		{"duplicate inbound", vless + "," + vless, "", vlessTag, email, "duplicate managed"},
		{"unsupported protocol", unsupported, "", "other", email, "unsupported managed Xray protocol"},
		{"mutation API", vless, `,"api":{"tag":"api","services":["hAndlerService"]}`, vlessTag, email, "HandlerService"},
		{"routing API", vless, `,"api":{"tag":"api","services":["rOutingService"]}`, vlessTag, email, "RoutingService"},
		{"shared Hysteria auth", hysteriaInbound(`"version":2,"auth":"shared"`), "", hy2Tag, email, "per-user auth"},
		{"Hysteria masquerade proxy", hysteriaInbound(`"version":2,"masquerade":{"type":"proxy","url":"http://127.0.0.1"}`), "", hy2Tag, email, "must not proxy"},
		{"unsupported Shadowsocks 2022 relay", `{"tag":"ss2022","port":20002,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"test","clients":[{"address":"127.0.0.1","port":80,"password":"user-key"}]}}`, "", "ss2022", email, "unsupported managed Xray protocol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := serial.LoadJSONConfig(strings.NewReader(`{"inbounds":[` + tc.inbounds + "]" + tc.api + "}"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := bindClients(config, map[string]map[string]string{tc.tag: {tc.email: clientID}}, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bind error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBindClientsUsesExactLegacyCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, settings string
		good, other    protocol.AsAccount
	}{
		{
			protocolVMess, fmt.Sprintf(`{"clients":[{"email":%q,"id":%q}]}`, email, vlessID),
			&vmess.Account{Id: vlessID}, &vmess.Account{Id: "88f16dc8-1412-4fed-8d80-bf90ab816437"},
		},
		{
			protocolTrojan, fmt.Sprintf(`{"clients":[{"email":%q,"password":"test-password"}]}`, email),
			&trojan.Account{Password: "test-password"}, &trojan.Account{Password: "different-password"},
		},
		{
			protocolSS, fmt.Sprintf(`{"clients":[{"email":%q,"method":"aes-128-gcm","password":"test-password"}]}`, email),
			&shadowsocks.Account{Password: "test-password", CipherType: shadowsocks.CipherType_AES_128_GCM},
			&shadowsocks.Account{Password: "test-password", CipherType: shadowsocks.CipherType_AES_256_GCM},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const tag = "managed"
			cfg, err := serial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(
				`{"inbounds":[{"tag":%q,"port":20000,"protocol":%q,"settings":%s}]}`, tag, tc.name, tc.settings,
			)))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := bindClients(cfg, map[string]map[string]string{tag: {email: launch.UnmeteredXrayAccountID}}, nil); err == nil {
				t.Fatal("accepted an unmetered account on a legacy protocol")
			}
			bound, tags, err := bindClients(cfg, map[string]map[string]string{tag: {email: clientID}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			selected := map[string][]string{protocolVMess: tags.VMess, protocolTrojan: tags.Trojan, protocolSS: tags.Shadowsocks}
			if values := selected[tc.name]; len(values) != 1 || values[0] != tag {
				t.Fatalf("managed tags = %+v", tags)
			}
			unmetered, _, err := bindClients(cfg, map[string]map[string]string{tag: {email: launch.UnmeteredXrayAccountID}}, map[string]bool{tag: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: tag, Name: tc.name})
			for _, test := range []struct {
				account protocol.AsAccount
				want    string
			}{
				{tc.good, clientID},
				{tc.other, ""},
			} {
				account, err := test.account.AsAccount()
				if err != nil {
					t.Fatal(err)
				}
				id, managed, err := bound.resolve(ctx, &protocol.MemoryUser{Email: email, Account: account})
				if id != test.want || !managed || (err == nil) != (test.want != "") {
					t.Fatalf("resolve = %q, %v, %v, want ID %q", id, managed, err, test.want)
				}
				id, managed, err = unmetered.resolve(ctx, &protocol.MemoryUser{Email: email, Account: account})
				if id != "" || managed != (test.want == "") || (err != nil) != (test.want == "") {
					t.Fatalf("generated exemption with native credential = %q, %v, %v", id, managed, err)
				}
			}
		})
	}
}

func TestBindClientsUsesStaticUsernameAndSS2022Key(t *testing.T) {
	const config = `{"inbounds":[
		{"tag":"http","port":20001,"protocol":"http","settings":{"accounts":[{"user":"client-email","pass":"http-test"}]}},
		{"tag":"mixed","port":20002,"protocol":"mixed","settings":{"auth":"password","accounts":[{"user":"client-email","pass":"mixed-test"}]}},
		{"tag":"single","port":20003,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","email":"client-email","password":"YWFhYWFhYWFhYWFhYWFhYQ=="}},
		{"tag":"multi","port":20004,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"YWFhYWFhYWFhYWFhYWFhYQ==","clients":[{"email":"client-email","password":"YmJiYmJiYmJiYmJiYmJiYg=="}]}}
	]}`
	cfg, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	bound, tags, err := bindClients(cfg, map[string]map[string]string{
		"http": {email: clientID}, "mixed": {email: clientID}, "single": {email: clientID}, "multi": {email: clientID},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for tag, selected := range map[string][]string{
		"http": tags.HTTP, "mixed": tags.Mixed, "single": tags.Shadowsocks2022, "multi": tags.Shadowsocks2022Multi,
	} {
		if len(selected) != 1 || selected[0] != tag {
			t.Fatalf("managed tags = %+v", tags)
		}
	}
	static := &protocol.MemoryUser{Email: email}
	multi := &protocol.MemoryUser{Email: email, Account: &ss2022.MemoryAccount{Key: []byte("bbbbbbbbbbbbbbbb")}}
	wrong := &protocol.MemoryUser{Email: email, Account: &ss2022.MemoryAccount{Key: []byte("cccccccccccccccc")}}
	generated, _, err := bindClients(cfg, map[string]map[string]string{"multi": {email: launch.UnmeteredXrayAccountID}}, map[string]bool{"multi": true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: "multi", Name: protocolSSMulti})
	if _, managed, err := generated.resolve(ctx, multi); managed || err != nil {
		t.Fatalf("valid generated SS2022 exemption: managed=%v, error=%v", managed, err)
	}
	if _, managed, err := generated.resolve(ctx, wrong); !managed || err == nil {
		t.Fatalf("invalid SS2022 key escaped generated account verification: managed=%v, error=%v", managed, err)
	}
	for _, tc := range []struct {
		tag, protocol string
		user          *protocol.MemoryUser
		want          bool
	}{
		{"http", "http", static, true},
		{"http", "socks", static, false},
		{"mixed", "http", static, true},
		{"mixed", "socks", static, true},
		{"mixed", "socks", &protocol.MemoryUser{}, false},
		{"single", protocolSS2022, static, true},
		{"single", protocolSS2022, multi, false},
		{"multi", protocolSSMulti, multi, true},
		{"multi", protocolSSMulti, static, false},
		{"multi", protocolSSMulti, wrong, false},
	} {
		ctx := session.ContextWithInbound(t.Context(), &session.Inbound{Tag: tc.tag, Name: tc.protocol})
		id, managed, err := bound.resolve(ctx, tc.user)
		if !managed || (err == nil) != tc.want || (id == clientID) != tc.want {
			t.Fatalf("resolve %q/%q = %q, %v, %v", tc.tag, tc.protocol, id, managed, err)
		}
	}
}

func TestRunMetersVLESSOverIPC(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	target := listenTCP(t)

	reservation := listenTCP(t)
	addr := reservation.Addr().(*net.TCPAddr)
	_ = reservation.Close()
	t.Setenv("XRAY_LOCATION_ASSET", t.TempDir())
	configPath := filepath.Join(t.TempDir(), "config.json")
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[%s],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"ip":["127.0.0.1/32"],"action":"allow"}]}}]}`, vlessInbound(addr.Port))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	const upload, download = "test upload", "test download"
	permits := make(chan int, 8)
	gate, err := bandwidthipc.Listen(func(_ context.Context, id string, size int) error {
		if id != clientID {
			return errors.New("unexpected client ID")
		}
		permits <- size
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	handshake, err := json.Marshal(Handshake{
		IPC: gate.Info(), Clients: map[string]map[string]string{vlessTag: {email: clientID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []string{configPath}, io.NopCloser(bytes.NewReader(handshake))) }()
	var conn net.Conn
	startup := time.NewTimer(5 * time.Second)
	defer startup.Stop()
	for conn == nil {
		conn, _ = net.DialTimeout("tcp4", addr.String(), 50*time.Millisecond)
		if conn != nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run exited before listening: %v", err)
		case <-startup.C:
			t.Fatal("Run failed to listen")
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	account, err := (&vless.Account{Id: vlessID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Command: protocol.RequestCommandTCP,
		User:    &protocol.MemoryUser{Account: account},
		Address: xnet.LocalHostIP,
		Port:    xnet.Port(target.Addr().(*net.TCPAddr).Port),
	}
	if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
		t.Fatalf("send VLESS request header: %v", err)
	}
	backend, err := target.AcceptTCP()
	if err != nil {
		t.Fatalf("accept proxied connection: %v", err)
	}
	defer backend.Close()
	if err := backend.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, upload); err != nil {
		t.Fatalf("send upload: %v", err)
	}
	received := make([]byte, len(upload))
	if _, err := io.ReadFull(backend, received); err != nil || string(received) != upload {
		t.Fatalf("proxied upload = %q, %v", received, err)
	}
	if _, err := io.WriteString(backend, download); err != nil {
		t.Fatalf("send download: %v", err)
	}
	if _, err := encoding.DecodeResponseHeader(conn, request); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(download))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != download {
		t.Fatalf("proxied download = %q, %v", buf, err)
	}
	var granted int
	for len(permits) != 0 {
		granted += <-permits
	}
	if granted != len(upload)+len(download) {
		t.Fatalf("granted %d bytes, want %d for both directions", granted, len(upload)+len(download))
	}
	_ = conn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down")
	}
	if conn, err := net.DialTimeout("tcp4", addr.String(), 50*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("metered listener remained open after cancellation")
	}
}

func vlessInbound(port int) string {
	return fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q,"email":%q}]}}`,
		vlessTag, port, vlessID, email)
}

func hysteriaInbound(transport string) string {
	return fmt.Sprintf(`{"tag":%q,"port":20001,"protocol":"hysteria","settings":{"version":2,"clients":[{"auth":"test-password","email":%q}]},"streamSettings":{"network":"hysteria","hysteriaSettings":{%s}}}`,
		hy2Tag, email, transport)
}

func listenTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
