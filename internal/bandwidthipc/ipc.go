// Package bandwidthipc shares a node's byte-permission gate with local child processes.
package bandwidthipc

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxPermitBytes = 65_536
	maxClientID    = 256
	tokenBytes     = 32
	timestampBytes = 8
	requestIDBytes = timestampBytes + 16
	headerBytes    = requestIDBytes + 4
	maxBodyBytes   = headerBytes + maxClientID
	maxReplayIDs   = 65_536
	maxPending     = 1_024
	permitWindow   = 10 * time.Second
	requestTimeout = permitWindow + 5*time.Second
	replayAge      = 5 * time.Second
	clockAllowance = time.Second
	permitPath     = "/v1/permit"
	contentType    = "application/octet-stream"
	permitProof    = "X-Bandwidth-Permit"
)

var errPermitWindowElapsed = errors.New("bandwidth ipc: permit wait window elapsed")

// Gate grants bytes for one client. Implementations should honor cancellation.
type Gate func(context.Context, string, int) error

// Info is a capability intended only for the local child process.
type Info struct {
	Address string
	Token   string
}

type Server struct {
	info     Info
	secret   [tokenBytes]byte
	gate     Gate
	window   time.Duration
	listener net.Listener
	http     *http.Server
	cancel   context.CancelFunc
	pending  chan struct{}

	replayMu   sync.Mutex
	seen       map[[requestIDBytes]byte]int64
	lastNow    int64
	pruneAfter int64
}

// Listen serves the gate on an ephemeral IPv4 loopback port.
func Listen(gate Gate) (*Server, error) {
	return listen(gate, permitWindow)
}

func listen(gate Gate, window time.Duration) (*Server, error) {
	if gate == nil {
		return nil, errors.New("bandwidth ipc: gate is required")
	}
	var secret [tokenBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("bandwidth ipc: create capability: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bandwidth ipc: listen: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		info:     Info{Address: listener.Addr().String(), Token: base64.RawURLEncoding.EncodeToString(secret[:])},
		secret:   secret,
		gate:     gate,
		window:   window,
		listener: listener,
		cancel:   cancel,
		pending:  make(chan struct{}, maxPending),
		seen:     make(map[[requestIDBytes]byte]int64),
	}
	server.http = &http.Server{
		Handler:           http.HandlerFunc(server.servePermit),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      window + 3*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    2_048,
	}
	go func() {
		defer cancel()
		_ = server.http.Serve(listener)
	}()
	return server, nil
}

func (s *Server) Info() Info { return s.info }

// Close stops accepting requests and cancels outstanding gate calls.
func (s *Server) Close() error {
	s.cancel()
	err := s.http.Close()
	// Cover Close being called before Serve registers the listener.
	_ = s.listener.Close()
	return err
}

func (s *Server) servePermit(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI != permitPath || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	authorization := r.Header.Values("Authorization")
	if len(authorization) != 1 || !strings.HasPrefix(authorization[0], "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	media := r.Header.Values("Content-Type")
	if len(media) != 1 || media[0] != contentType || r.ContentLength < headerBytes+1 || r.ContentLength > maxBodyBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	select {
	case s.pending <- struct{}{}:
		defer func() { <-s.pending }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil || int64(len(body)) != r.ContentLength {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !hmac.Equal([]byte(authorization[0]), []byte("Bearer "+authenticate(s.secret, "request", body))) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	clientID := string(body[headerBytes:])
	size := int(binary.BigEndian.Uint32(body[requestIDBytes:headerBytes]))
	if !validPermit(clientID, size) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !s.useRequestID([requestIDBytes]byte(body[:requestIDBytes]), time.Now().UnixMilli()) {
		w.WriteHeader(http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeoutCause(r.Context(), s.window, errPermitWindowElapsed)
	defer cancel()
	if r.Context().Err() != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	err = s.gate(ctx, clientID, size)
	switch {
	case r.Context().Err() != nil:
		w.WriteHeader(http.StatusServiceUnavailable)
	case err == nil:
		// The gate already charged the bytes, even if the local timer just fired.
		w.Header().Set(permitProof, authenticate(s.secret, "permit", body))
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, context.DeadlineExceeded) && context.Cause(ctx) == errPermitWindowElapsed:
		w.Header().Set(permitProof, authenticate(s.secret, "pending", body))
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (s *Server) useRequestID(id [requestIDBytes]byte, now int64) bool {
	issued := int64(binary.BigEndian.Uint64(id[:timestampBytes]))
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	// A system clock adjustment must not make an expired request valid again.
	now = max(now, s.lastNow)
	s.lastNow = now
	oldest := now - replayAge.Milliseconds()
	if issued < oldest || issued > now+clockAllowance.Milliseconds() {
		return false
	}
	if now >= s.pruneAfter {
		for usedID, usedAt := range s.seen {
			if usedAt < oldest {
				delete(s.seen, usedID)
			}
		}
		s.pruneAfter = now + time.Second.Milliseconds()
	}
	if _, duplicate := s.seen[id]; duplicate || len(s.seen) >= maxReplayIDs {
		return false
	}
	s.seen[id] = issued
	return true
}

type Client struct {
	address   string
	secret    [tokenBytes]byte
	transport *http.Transport
	ctx       context.Context
	cancel    context.CancelFunc
}

// Dial validates a local capability and prepares a reusable client. It does
// not consume a permit or open a connection until Acquire is called.
func Dial(info Info) (*Client, error) {
	addr, err := netip.ParseAddrPort(info.Address)
	if err != nil || !addr.Addr().IsLoopback() || addr.Addr().Zone() != "" || addr.Port() == 0 {
		return nil, errors.New("bandwidth ipc: endpoint must be a literal loopback address and port")
	}
	if len(info.Token) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return nil, errors.New("bandwidth ipc: invalid capability")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(info.Token)
	if err != nil || len(secret) != tokenBytes {
		return nil, errors.New("bandwidth ipc: invalid capability")
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &Client{
		address: info.Address,
		secret:  [tokenBytes]byte(secret),
		transport: &http.Transport{
			DialContext:         dialer.DialContext,
			MaxConnsPerHost:     512,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     30 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Acquire returns nil only when the server grants the requested bytes.
func (c *Client) Acquire(ctx context.Context, clientID string, size int) error {
	if !validPermit(clientID, size) {
		return errors.New("bandwidth ipc: invalid permit request")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pending, err := c.requestPermit(ctx, clientID, size)
		if err != nil {
			return err
		}
		if !pending {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			return ctx.Err()
		}
	}
}

func (c *Client) requestPermit(ctx context.Context, clientID string, size int) (pending bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	body := make([]byte, headerBytes+len(clientID))
	binary.BigEndian.PutUint64(body, uint64(time.Now().UnixMilli()))
	if _, err := rand.Read(body[timestampBytes:requestIDBytes]); err != nil {
		return false, fmt.Errorf("bandwidth ipc: create request ID: %w", err)
	}
	binary.BigEndian.PutUint32(body[requestIDBytes:headerBytes], uint32(size))
	copy(body[headerBytes:], clientID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+c.address+permitPath, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+authenticate(c.secret, "request", body))
	request.Header.Set("Content-Type", contentType)
	response, err := c.transport.RoundTrip(request)
	if err != nil {
		return false, fmt.Errorf("bandwidth ipc: request permit: %w", err)
	}
	defer response.Body.Close()
	var purpose string
	switch response.StatusCode {
	case http.StatusNoContent:
		purpose = "permit"
	case http.StatusAccepted:
		purpose = "pending"
	default:
		return false, fmt.Errorf("bandwidth ipc: permit denied (HTTP %d)", response.StatusCode)
	}
	proof := response.Header.Values(permitProof)
	if len(proof) != 1 || !hmac.Equal([]byte(proof[0]), []byte(authenticate(c.secret, purpose, body))) {
		return false, fmt.Errorf("bandwidth ipc: server did not authenticate the %s response", purpose)
	}
	return response.StatusCode == http.StatusAccepted, nil
}

// Close cancels outstanding requests and discards the client's idle connections.
func (c *Client) Close() error {
	c.cancel()
	c.transport.CloseIdleConnections()
	return nil
}

func validPermit(clientID string, size int) bool {
	return size > 0 && size <= MaxPermitBytes && len(clientID) > 0 && len(clientID) <= maxClientID &&
		utf8.ValidString(clientID) && strings.TrimSpace(clientID) == clientID && strings.IndexFunc(clientID, unicode.IsControl) == -1
}

// A process that binds a stale endpoint can see the request proof. Only the
// peer with the original capability can authenticate a grant or pending response.
func authenticate(secret [tokenBytes]byte, purpose string, body []byte) string {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(purpose))
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
