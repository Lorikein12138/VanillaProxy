package xraybandwidthchild

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	grpctransport "github.com/xtls/xray-core/transport/internet/grpc"
)

func TestBindClientsChecksNativeGRPCListenCapability(t *testing.T) {
	clients := map[string]map[string]string{vlessTag: {email: clientID}}
	cfg := loadGRPCTestConfig(t, 20000, "grpc")
	bound, tags, err := bindClients(cfg, clients, nil)
	if hasNativeSynchronousGRPCListen() {
		if err != nil || len(tags.VLESS) != 1 || tags.VLESS[0] != vlessTag || bound[vlessTag].clients[email].id != clientID {
			t.Fatalf("patched gRPC binding = %+v, %+v, %v", bound, tags, err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "managed gRPC requires patched synchronous Xray listen") {
		t.Fatalf("stock gRPC binding error = %v", err)
	}
	if _, _, err := bindClients(cfg, nil, nil); err != nil {
		t.Fatalf("unmanaged gRPC binding: %v", err)
	}
	tcp := loadGRPCTestConfig(t, 20000, "tcp")
	if _, _, err := bindClients(tcp, clients, nil); err != nil {
		t.Fatalf("managed TCP with inactive gRPC settings: %v", err)
	}
}

func TestNativeGRPCStartReturnsBindErrorAndCloseReleasesPort(t *testing.T) {
	if !hasNativeSynchronousGRPCListen() {
		t.Skip("requires patched synchronous Xray gRPC listen")
	}
	reserved := listenTCP(t)
	addr := reserved.Addr().(*net.TCPAddr)

	blocked, err := core.New(loadGRPCTestConfig(t, addr.Port, "grpc"))
	if err != nil {
		t.Fatal(err)
	}
	startErr := blocked.Start()
	_ = blocked.Close()
	if startErr == nil || !strings.Contains(startErr.Error(), "failed to listen on") {
		t.Fatalf("native gRPC Start with occupied port = %v", startErr)
	}
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}

	live, err := core.New(loadGRPCTestConfig(t, addr.Port, "grpc"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if live != nil {
			_ = live.Close()
		}
	}()
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	if conflict, err := net.ListenTCP("tcp4", addr); err == nil {
		_ = conflict.Close()
		t.Fatal("native gRPC Start returned before binding its port")
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	live = nil
	rebound, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		t.Fatalf("cannot rebind after native gRPC Close: %v", err)
	}
	_ = rebound.Close()
}

func TestNativeGRPCUnix(t *testing.T) {
	if !hasNativeSynchronousGRPCListen() {
		t.Skip("requires patched synchronous Xray gRPC listen")
	}
	addr := &net.UnixAddr{Name: filepath.Join(t.TempDir(), "grpc.sock"), Net: "unix"}
	reserved, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()

	settings := &internet.MemoryStreamConfig{
		ProtocolSettings: &grpctransport.Config{ServiceName: "test-service"},
		FinalMask: finalmask.NewFinalMask(nil, nil, nil, func(ctx context.Context, addr xnet.Addr) (xnet.Listener, error) {
			return internet.ListenSystem(ctx, addr, nil)
		}, nil, nil),
	}
	listen := func() (internet.Listener, error) {
		return grpctransport.Listen(t.Context(), xnet.DomainAddress(addr.Name), 0, settings, nil)
	}
	blocked, err := listen()
	if blocked != nil {
		_ = blocked.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "failed to listen on") {
		t.Fatalf("gRPC listen on occupied Unix socket = %v", err)
	}
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}

	live, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("cannot rebind Unix socket after gRPC Close: %v", err)
	}
	_ = rebound.Close()
}

func loadGRPCTestConfig(t *testing.T, port int, network string) *core.Config {
	t.Helper()
	inbound := strings.TrimSuffix(vlessInbound(port), "}") + fmt.Sprintf(
		`,"streamSettings":{"network":%q,"grpcSettings":{"serviceName":"test-service"}}}`, network)
	config, err := serial.LoadJSONConfig(strings.NewReader(`{"inbounds":[` + inbound + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return config
}
