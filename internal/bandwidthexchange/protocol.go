// Package bandwidthexchange exchanges bandwidth lease demands and grants over
// an explicitly enabled, root-initiated HTTPS connection.
package bandwidthexchange

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

const (
	// MaxClients bounds the clients and outstanding challenges in one exchange.
	MaxClients = 256
	maxBody    = 512 << 10
	maxLabel   = 128
	timeout    = 5 * time.Second
)

type request struct {
	NodeID     string      `json:"node_id"`
	Generation string      `json:"generation"`
	Grants     []wireEntry `json:"grants"`
}

type response struct {
	NodeID     string      `json:"node_id"`
	Generation string      `json:"generation"`
	Demands    []wireEntry `json:"demands"`
	Applied    []wireEntry `json:"applied"`
}

// Demand is an authenticated node's request for a rate for an eligible client.
type Demand struct {
	Challenge              bandwidthlease.Challenge
	RequestedBitsPerSecond int64
}

type wireEntry struct {
	ClientID      string `json:"client_id"`
	IncarnationID string `json:"incarnation_id"`
	Nonce         string `json:"nonce"`
	Sequence      uint64 `json:"sequence"`
	BitsPerSecond *int64 `json:"bits_per_second"`
}

func toWire(challenge bandwidthlease.Challenge, rate int64) wireEntry {
	return wireEntry{challenge.ClientID, challenge.IncarnationID, challenge.Nonce, challenge.Sequence, &rate}
}

func (entry wireEntry) challenge(nodeID string) bandwidthlease.Challenge {
	return bandwidthlease.Challenge{
		ClientID: entry.ClientID, NodeID: nodeID, IncarnationID: entry.IncarnationID, Nonce: entry.Nonce, Sequence: entry.Sequence,
	}
}

func (entry wireEntry) grant(nodeID string) bandwidthlease.Grant {
	return bandwidthlease.Grant{Challenge: entry.challenge(nodeID), BitsPerSecond: *entry.BitsPerSecond}
}

// ValidIdentity reports whether a configured node ID, client ID or generation
// can be used in the exchange protocol.
func ValidIdentity(value string) bool {
	return value != "" && len(value) <= maxLabel && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validToken(value string) bool {
	if len(value) != 32 || strings.ToLower(value) != value {
		return false
	}
	var token [16]byte
	_, err := hex.Decode(token[:], []byte(value))
	return err == nil
}

func validEntries(entries []wireEntry) bool {
	if entries == nil || len(entries) > MaxClients {
		return false
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !ValidIdentity(entry.ClientID) || !validToken(entry.IncarnationID) || !validToken(entry.Nonce) ||
			entry.Sequence == 0 || entry.BitsPerSecond == nil || *entry.BitsPerSecond < 0 {
			return false
		}
		if _, duplicate := seen[entry.ClientID]; duplicate {
			return false
		}
		seen[entry.ClientID] = struct{}{}
	}
	return true
}

var errBodyTooLarge = errors.New("bandwidth exchange body exceeds limit")

func readJSON(body io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(body, maxBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxBody {
		return errBodyTooLarge
	}
	return json.Unmarshal(data, dst, json.RejectUnknownMembers(true))
}
