package xraybandwidthchild

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestManagedChildAllowsOnlyExplicitDataInboundsAndExclusiveAPI(t *testing.T) {
	const valid = `{
		"api":{"tag":"api","services":["StatsService"]},
		"inbounds":[{"tag":"api","listen":"127.0.0.1","port":62789,"protocol":"tunnel","settings":{"rewriteAddress":"127.0.0.1"}}],
		"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}
	}`
	tests := []struct {
		name   string
		config string
		valid  bool
	}{
		{"exclusive API", valid, true},
		{"public API", strings.Replace(valid, `"listen":"127.0.0.1"`, `"listen":"0.0.0.0"`, 1), false},
		{"unexpected proxy", strings.Replace(valid, `"protocol":"tunnel"`, `"protocol":"socks"`, 1), false},
		{"nonexclusive route", strings.Replace(valid, `"inboundTag":["api"]`, `"inboundTag":["api","public"]`, 1), false},
		{"loopback uses management tag", strings.Replace(valid, `"routing":`, `"outbounds":[{"tag":"loop","protocol":"loopback","settings":{"inboundTag":"api"}}],"routing":`, 1), false},
		{"loopback uses data tag", strings.Replace(valid, `"routing":`, `"outbounds":[{"tag":"loop","protocol":"loopback","settings":{"inboundTag":"api-data"}}],"routing":`, 1), true},
		{"unexpected data inbound", `{"inbounds":[{"tag":"public","listen":"127.0.0.1","port":42829,"protocol":"socks"}]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := serial.LoadJSONConfig(strings.NewReader(tt.config))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateInboundCoverage(cfg, nil); (err == nil) != tt.valid {
				t.Fatalf("coverage error = %v, want accepted = %t", err, tt.valid)
			}
		})
	}
}
