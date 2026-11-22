package bandwidthipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startGate(t *testing.T, gate Gate) (*Server, *Client) {
	t.Helper()
	return startGateWithWindow(t, gate, permitWindow)
}

func startGateWithWindow(t *testing.T, gate Gate, window time.Duration) (*Server, *Client) {
	t.Helper()
	server, err := listen(gate, window)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := Dial(server.Info())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func TestAcquireRetriesPendingUntilGranted(t *testing.T) {
	var calls, grants atomic.Int32
	server, client := startGateWithWindow(t, func(ctx context.Context, id string, size int) error {
		if id != "slow-client" || size != 8_192 {
			t.Errorf("got permit for %q with %d bytes", id, size)
		}
		if calls.Add(1) <= 2 {
			<-ctx.Done()
			return ctx.Err()
		}
		grants.Add(1)
		return nil
	}, 15*time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := client.Acquire(ctx, "slow-client", 8_192); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("gate called %d times, want 3", got)
	}
	if got := grants.Load(); got != 1 {
		t.Fatalf("gate granted %d permits, want 1", got)
	}
	server.replayMu.Lock()
	defer server.replayMu.Unlock()
	if got := len(server.seen); got != 3 {
		t.Fatalf("server accepted %d request IDs, want 3", got)
	}
}

func TestGateResultAtPermitDeadline(t *testing.T) {
	noLease := errors.New("no allocation")
	for _, test := range []struct {
		name       string
		awaitTimer bool
		gateErr    error
	}{
		{"completed grant", true, nil},
		{"lease denied after timer", true, noLease},
		{"unrelated deadline", false, context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			window := permitWindow
			if test.awaitTimer {
				window = 15 * time.Millisecond
			}
			var calls atomic.Int32
			_, client := startGateWithWindow(t, func(ctx context.Context, _ string, _ int) error {
				if calls.Add(1) > 1 {
					return noLease
				}
				if test.awaitTimer {
					<-ctx.Done()
				}
				return test.gateErr
			}, window)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err := client.Acquire(ctx, "client", 1)
			if (err == nil) != (test.gateErr == nil) {
				t.Fatalf("Acquire returned %v after gate returned %v", err, test.gateErr)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("gate called %d times, want 1", got)
			}
		})
	}
}

func TestAcquire(t *testing.T) {
	var calls atomic.Int32
	server, client := startGate(t, func(_ context.Context, id string, size int) error {
		calls.Add(1)
		if id == "client-with-额度" && size == MaxPermitBytes {
			return nil
		}
		return errors.New("no allocation")
	})
	if err := client.Acquire(t.Context(), "client-with-额度", MaxPermitBytes); err != nil {
		t.Fatalf("valid permit failed: %v", err)
	}
	if err := client.Acquire(t.Context(), "denied", 1); err == nil {
		t.Fatal("failed gate returned a permit")
	}
	for _, request := range []struct {
		id   string
		size int
	}{
		{"", 1},
		{"client", -1},
		{"client", 0},
		{"client", MaxPermitBytes + 1},
		{strings.Repeat("a", maxClientID+1), 1},
		{"client\x00", 1},
		{"client\xff", 1},
	} {
		if err := client.Acquire(t.Context(), request.id, request.size); err == nil {
			t.Errorf("invalid request with ID %q and size %d was authorized", request.id, request.size)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("gate called %d times, want 2", calls.Load())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Acquire(t.Context(), "client-with-额度", MaxPermitBytes); err == nil {
		t.Fatal("unavailable server returned a permit")
	}
}

func TestDialRejectsInvalidEndpointOrToken(t *testing.T) {
	server, _ := startGate(t, func(context.Context, string, int) error { return nil })
	info := server.Info()
	for _, address := range []string{"localhost:1234", "127.0.0.1:0", "198.51.100.1:444", "127.0.0.1:1234/path", "http://127.0.0.1:1234"} {
		if _, err := Dial(Info{Address: address, Token: info.Token}); err == nil {
			t.Errorf("accepted endpoint %q", address)
		}
	}
	for _, token := range []string{"", "short", info.Token + "\n"} {
		if _, err := Dial(Info{Address: info.Address, Token: token}); err == nil {
			t.Error("accepted a malformed capability")
		}
	}
}

func TestRejectsUnauthorizedMalformedAndDuplicateRequest(t *testing.T) {
	var calls atomic.Int32
	server, _ := startGate(t, func(context.Context, string, int) error {
		calls.Add(1)
		return nil
	})
	info := server.Info()
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	body := make([]byte, headerBytes+len("client"))
	binary.BigEndian.PutUint64(body, uint64(time.Now().UnixMilli()))
	binary.BigEndian.PutUint32(body[requestIDBytes:headerBytes], 1)
	copy(body[headerBytes:], "client")
	validBearer := "Bearer " + authenticate(server.secret, "request", body)
	for _, test := range []struct {
		path   string
		bearer []string
		body   []byte
		want   int
	}{
		{"/other", []string{validBearer}, body, http.StatusNotFound},
		{permitPath + "?q=1", []string{validBearer}, body, http.StatusNotFound},
		{permitPath, nil, body, http.StatusUnauthorized},
		{permitPath, []string{"Bearer wrong"}, body, http.StatusUnauthorized},
		{permitPath, []string{"Bearer " + info.Token}, body, http.StatusUnauthorized},
		{permitPath, []string{validBearer, validBearer}, body, http.StatusUnauthorized},
		{permitPath, []string{validBearer}, make([]byte, maxBodyBytes+1), http.StatusBadRequest},
		{permitPath, []string{validBearer}, body[:headerBytes], http.StatusBadRequest},
		{permitPath, []string{validBearer}, body, http.StatusNoContent},
		{permitPath, []string{validBearer}, body, http.StatusConflict},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+info.Address+test.path, bytes.NewReader(test.body))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", contentType)
		for _, bearer := range test.bearer {
			request.Header.Add("Authorization", bearer)
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = response.Body.Close()
		cancel()
		if response.StatusCode != test.want {
			t.Errorf("request to %q returned %d, want %d", test.path, response.StatusCode, test.want)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("gate called %d times, want 1", calls.Load())
	}
}

func TestAcquireRequiresServerProof(t *testing.T) {
	server, _ := startGate(t, func(context.Context, string, int) error { return nil })
	info := server.Info()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+info.Token {
			t.Error("client disclosed the long-lived capability to a different server")
		}
		w.Header().Set(permitProof, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(fake.Close)
	info.Address = fake.Listener.Addr().String()
	client, err := Dial(info)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Acquire(t.Context(), "client", 1); err == nil {
		t.Fatal("unauthenticated server returned a permit")
	}
}

func TestAcquireRejectsMismatchedResponseProof(t *testing.T) {
	original, _ := startGate(t, func(context.Context, string, int) error { return nil })
	for _, test := range []struct {
		name    string
		status  int
		purpose string
	}{
		{"request proof on pending", http.StatusAccepted, "request"},
		{"permit proof on pending", http.StatusAccepted, "permit"},
		{"pending proof on permit", http.StatusNoContent, "pending"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) > 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set(permitProof, authenticate(original.secret, test.purpose, body))
				w.WriteHeader(test.status)
			}))
			t.Cleanup(fake.Close)
			info := original.Info()
			info.Address = fake.Listener.Addr().String()
			client, err := Dial(info)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.Acquire(t.Context(), "client", 1); err == nil {
				t.Fatal("mismatched response proof was accepted")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("fake server received %d requests, want 1", got)
			}
		})
	}
}

func TestCancelAfterPendingRetry(t *testing.T) {
	for _, shutdown := range []string{"context", "client"} {
		t.Run(shutdown, func(t *testing.T) {
			var calls atomic.Int32
			retried := make(chan struct{})
			_, client := startGateWithWindow(t, func(ctx context.Context, _ string, _ int) error {
				if calls.Add(1) == 2 {
					close(retried)
				}
				<-ctx.Done()
				return ctx.Err()
			}, 15*time.Millisecond)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- client.Acquire(ctx, "client", 1) }()
			select {
			case <-retried:
			case <-ctx.Done():
				t.Fatal("pending response was not retried")
			}
			if shutdown == "client" {
				_ = client.Close()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Acquire returned %v, want cancellation", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Acquire continued after cancellation")
			}
		})
	}
}

func TestCancellationReachesGate(t *testing.T) {
	for _, shutdown := range []string{"context", "client", "server"} {
		t.Run(shutdown, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			server, client := startGate(t, func(ctx context.Context, _ string, _ int) error {
				close(started)
				<-ctx.Done()
				close(canceled)
				return ctx.Err()
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- client.Acquire(ctx, "client", 1) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("gate never started")
			}
			switch shutdown {
			case "context":
				cancel()
			case "client":
				_ = client.Close()
			case "server":
				_ = server.Close()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled request received a permit")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("client did not finish after cancellation")
			}
			select {
			case <-canceled:
			case <-time.After(3 * time.Second):
				t.Fatal("gate did not receive cancellation")
			}
		})
	}
}

func TestExpiredRequestCannotReappearAfterClockMovesBack(t *testing.T) {
	server := &Server{seen: make(map[[requestIDBytes]byte]int64)}
	var id [requestIDBytes]byte
	const issued = 5_001
	binary.BigEndian.PutUint64(id[:], issued)
	if !server.useRequestID(id, issued) {
		t.Fatal("initial request rejected")
	}
	if server.useRequestID(id, issued+replayAge.Milliseconds()+1) {
		t.Fatal("stale request allowed")
	}
	if server.useRequestID(id, issued) {
		t.Fatal("stale request allowed after clock moved back")
	}
}
