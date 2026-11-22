package mtproto

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
)

const (
	bandwidthFlag             = "--vanilla-bandwidth"
	maxBandwidthHandshakeSize = 1 << 20
	maxBandwidthClientIDBytes = 256
	fakeTLSKeyBytes           = 16
)

// BandwidthOptions opts into the patched mtg-multi binary's shared gate.
// ClientIDs binds each configured secret name to the gate's canonical client ID.
// Two secret names may share an ID to use the same bandwidth budget.
type BandwidthOptions struct {
	IPC       bandwidthipc.Info `json:"ipc"`
	ClientIDs map[string]string `json:"clients"`
	// PolicyBindings pins automatic authorization to a name and its decoded
	// authentication key. An empty ClientID is valid only with this pin.
	PolicyBindings map[string]string `json:"policy_bindings,omitempty"`
}

type bandwidthBootstrap struct {
	BandwidthOptions
	Ready launch.Ready `json:"ready"`
}

func newBandwidthReadiness() (*net.TCPListener, launch.Ready, error) {
	nonce := make([]byte, launch.ReadyNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, launch.Ready{}, fmt.Errorf("mtproto: generate readiness challenge: %w", err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, launch.Ready{}, fmt.Errorf("mtproto: listen for readiness: %w", err)
	}
	return listener, launch.Ready{Address: listener.Addr().String(), Nonce: nonce}, nil
}

func waitBandwidthReady(listener *net.TCPListener, ready launch.Ready, done <-chan struct{}, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	proofDone := make(chan struct{})
	var proofErr error
	go func() {
		defer close(proofDone)
		proofErr = receiveBandwidthReady(ctx, listener, ready.Nonce)
	}()
	defer func() {
		cancel()
		_ = listener.Close()
		<-proofDone
	}()

	exited := errors.New("mtproto: child exited before reporting readiness")
	timedOut := errors.New("mtproto: timed out waiting for child readiness")
	select {
	case <-done:
		return exited
	case <-ctx.Done():
		return timedOut
	case <-proofDone:
		select {
		case <-done:
			return exited
		default:
		}
		if ctx.Err() != nil {
			return timedOut
		}
		return proofErr
	}
}

func receiveBandwidthReady(ctx context.Context, listener *net.TCPListener, nonce []byte) error {
	for ctx.Err() == nil {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return errors.New("mtproto: could not receive child readiness signal")
		}
		// An incomplete or wrong local proof must not block the actual child.
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		var data [launch.ReadyNonceSize + 1]byte
		n, err := io.ReadFull(conn, data[:])
		stop()
		_ = conn.Close()
		if err == io.ErrUnexpectedEOF && n == len(nonce) && subtle.ConstantTimeCompare(data[:n], nonce) == 1 {
			return nil
		}
	}
	return ctx.Err()
}

func (m *Manager) prepareBandwidthHandshake(inst *Instance) ([]byte, error) {
	if inst.RouteThroughXray && (m.prepareBandwidth != nil || inst.Bandwidth != nil) {
		return nil, errors.New("mtproto: bandwidth-managed MTProto requires direct egress")
	}
	if m.prepareBandwidth != nil {
		desired := *inst
		desired.Bandwidth = nil
		desired.Secrets = slices.Clone(inst.Secrets)
		options, err := m.prepareBandwidth(desired)
		if err != nil {
			return nil, fmt.Errorf("mtproto: prepare bandwidth: %w", err)
		}
		if options == nil {
			return nil, errors.New("mtproto: bandwidth preparation returned no policy")
		}
		inst.Bandwidth = options
	}
	if inst.Bandwidth != nil && inst.Bandwidth.PolicyBindings != nil {
		if err := validateBandwidthSecrets(inst.Secrets); err != nil {
			return nil, err
		}
		inst.Secrets = slices.DeleteFunc(slices.Clone(inst.Secrets), func(secret SecretEntry) bool {
			_, allowed := inst.Bandwidth.PolicyBindings[secret.Name]
			return !allowed
		})
		if len(inst.Secrets) == 0 && len(inst.Bandwidth.PolicyBindings) == 0 && len(inst.Bandwidth.ClientIDs) == 0 {
			return nil, nil
		}
	}
	return inst.bandwidthHandshake()
}

// bandwidthHandshake validates and snapshots the launch configuration. The
// child reads the resulting JSON document from stdin, followed by EOF.
func (inst Instance) bandwidthHandshake() ([]byte, error) {
	options := inst.Bandwidth
	if options == nil {
		return nil, nil
	}
	if len(inst.Secrets) == 0 || len(inst.Secrets) != len(options.ClientIDs) {
		return nil, errors.New("mtproto: bandwidth bindings must match the configured secret names")
	}
	if options.PolicyBindings != nil && len(inst.Secrets) != len(options.PolicyBindings) {
		return nil, errors.New("mtproto: bandwidth policy must match the configured secret names")
	}
	if err := validateBandwidthSecrets(inst.Secrets); err != nil {
		return nil, err
	}
	for _, secret := range inst.Secrets {
		name := secret.Name
		id, bound := options.ClientIDs[name]
		if !bound {
			return nil, errors.New("mtproto: bandwidth bindings must match the configured secret names")
		}
		if options.PolicyBindings != nil {
			fingerprint := bandwidthexchange.CredentialFingerprint("mtproto", BandwidthCredential(secret.Secret))
			if options.PolicyBindings[name] != fingerprint {
				return nil, errors.New("mtproto: bandwidth policy does not match the configured authentication key")
			}
		} else if id == "" {
			return nil, errors.New("mtproto: invalid bandwidth client ID")
		}
		if len(id) > maxBandwidthClientIDBytes || !utf8.ValidString(id) ||
			strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return nil, errors.New("mtproto: invalid bandwidth client ID")
		}
	}

	client, err := bandwidthipc.Dial(options.IPC)
	if err != nil {
		return nil, fmt.Errorf("mtproto: invalid bandwidth IPC: %w", err)
	}
	_ = client.Close()

	payload, err := json.Marshal(options)
	if err != nil {
		return nil, errors.New("mtproto: invalid bandwidth handshake")
	}
	if len(payload) > maxBandwidthHandshakeSize {
		return nil, errors.New("mtproto: bandwidth handshake exceeds size limit")
	}
	return payload, nil
}

func validateBandwidthSecrets(secrets []SecretEntry) error {
	seenNames := make(map[string]struct{}, len(secrets))
	seenKeys := make(map[[fakeTLSKeyBytes]byte]struct{}, len(secrets))
	for _, secret := range secrets {
		name := secret.Name
		if name == "" || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return errors.New("mtproto: invalid bandwidth secret name")
		}
		if _, duplicate := seenNames[name]; duplicate {
			return errors.New("mtproto: duplicate bandwidth secret name")
		}
		seenNames[name] = struct{}{}
		key, valid := fakeTLSKey(secret.Secret)
		if !valid {
			return errors.New("mtproto: malformed FakeTLS secret in bandwidth configuration")
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return errors.New("mtproto: duplicate FakeTLS authentication key in bandwidth configuration")
		}
		seenKeys[key] = struct{}{}
	}
	return nil
}

// BandwidthCredential returns the hex representation of mtg's authentication key.
func BandwidthCredential(secret string) string {
	key, valid := fakeTLSKey(secret)
	if !valid {
		return ""
	}
	return hex.EncodeToString(key[:])
}

// fakeTLSKey follows mtg's hex-first decoding of the marker, key and hostname.
// Authentication uses the decoded key without the hostname.
func fakeTLSKey(secret string) ([fakeTLSKeyBytes]byte, bool) {
	raw, err := hex.DecodeString(secret)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(secret)
	}
	var empty [fakeTLSKeyBytes]byte
	if err != nil || len(raw) <= 1+fakeTLSKeyBytes || raw[0] != 0xee {
		return empty, false
	}
	key := [fakeTLSKeyBytes]byte(raw[1:])
	return key, key != empty
}
