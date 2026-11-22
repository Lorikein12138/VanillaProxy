package web

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
)

func TestBandwidthKernelInterfaceRecoveryRequiresOwnership(t *testing.T) {
	interfaces := []net.Interface{{Name: "eth0"}, {Name: "xui-awg17"}}
	probed := make([]string, 0, 1)
	if err := checkBandwidthKernelInterfaces(interfaces, nil, func(name string) (bool, error) {
		probed = append(probed, name)
		return true, nil
	}); err != nil || len(probed) != 1 || probed[0] != "xui-awg17" {
		t.Fatalf("owned cold recovery = %v, probes = %v", err, probed)
	}
	if err := checkBandwidthKernelInterfaces(interfaces, nil, func(string) (bool, error) { return false, nil }); err == nil ||
		!strings.Contains(err.Error(), "remove existing kernel AmneziaWG interface") {
		t.Fatalf("unverified cold recovery = %v", err)
	}
	keyMismatch := errors.New("live key does not match")
	if err := checkBandwidthKernelInterfaces(interfaces, nil, func(string) (bool, error) { return false, keyMismatch }); !errors.Is(err, keyMismatch) {
		t.Fatalf("cold recovery discarded a failed verification: %v", err)
	}
	if err := checkBandwidthKernelInterfaces(interfaces, map[string]bool{"xui-awg17": true}, nil); err != nil {
		t.Fatalf("existing managed interface rejected on hot reload: %v", err)
	}
	if err := checkBandwidthKernelInterfaces(interfaces, nil, nil); err == nil {
		t.Fatal("hot reload accepted an interface outside its manager's inventory")
	}
}

func TestBandwidthExchangeRoute(t *testing.T) {
	const path = "/node" + bandwidthExchangePath
	for _, tc := range []struct {
		name, method, path string
		handler, tls       bool
		want               int
	}{
		{"disabled", http.MethodPost, path, false, true, http.StatusNotFound},
		{"plaintext", http.MethodPost, path, true, false, http.StatusNotFound},
		{"wrong method", http.MethodGet, path, true, true, http.StatusNotFound},
		{"wrong base path", http.MethodPost, bandwidthExchangePath, true, true, http.StatusNotFound},
		{"direct HTTPS", http.MethodPost, path, true, true, http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := gin.New()
			var handler http.Handler
			if tc.handler {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusAccepted)
				})
			}
			mountBandwidthExchange(engine.Group("/node/"), handler)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestBandwidthPolicyRouteRequiresDirectTLSAndExactPath(t *testing.T) {
	engine := gin.New()
	group := engine.Group("/node/")
	const exact = "/node" + bandwidthexchange.PolicyPath
	mountBandwidthPolicy(group, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	for _, tc := range []struct {
		url  string
		want int
	}{
		{"https://example.test" + exact, http.StatusAccepted},
		{"http://example.test" + exact, http.StatusNotFound},
		{"https://example.test" + exact + "/", http.StatusNotFound},
		{"https://example.test" + bandwidthexchange.PolicyPath, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.url, nil)
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, req)
		if response.Code != tc.want || response.Header().Get("Location") != "" {
			t.Fatalf("%s returned %d and Location %q, want status %d without redirect", tc.url, response.Code, response.Header().Get("Location"), tc.want)
		}
	}
}

func TestBandwidthNodeRequiresValidDirectTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certificate.pem")
	keyPath := filepath.Join(dir, "key.pem")
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	key, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	validTime := server.Certificate().NotBefore.Add(time.Second)
	for _, tc := range []struct {
		name, cert, key string
		now             time.Time
		valid           bool
	}{
		{"missing", certPath, "", validTime, false},
		{"unreadable", certPath, keyPath + ".missing", validTime, false},
		{"malformed", certPath, certPath, validTime, false},
		{"expired", certPath, keyPath, server.Certificate().NotAfter, false},
		{"valid", certPath, keyPath, validTime, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := bandwidthTLSCertificate(tc.cert, tc.key, tc.now)
			if tc.valid && (cert == nil || err != nil) || !tc.valid && (cert != nil || err == nil) {
				t.Fatalf("valid certificate = %v, err = %v, want valid %v", cert != nil, err, tc.valid)
			}
		})
	}
}
