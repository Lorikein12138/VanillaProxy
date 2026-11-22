package bandwidthexchange

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	PolicyPath        = "/bandwidth/v1/policy"
	MaxPolicyBody     = maxBody
	MaxPolicyAccounts = 1024
	PolicyTimeout     = 25 * time.Second
)

type PolicyAccount struct {
	Email                  string          `json:"email"`
	ClientID               string          `json:"client_id"`
	RequestedBitsPerSecond int64           `json:"requested_bits_per_second"`
	VLESSFingerprint       string          `json:"vless_fingerprint,omitempty"`
	HysteriaFingerprint    string          `json:"hysteria_fingerprint,omitempty"`
	Bindings               []PolicyBinding `json:"bindings,omitempty"`
}

// PolicyBinding pins a credential to its protocol for an exact account email.
type PolicyBinding struct {
	Protocol    string `json:"protocol"`
	Fingerprint string `json:"fingerprint"`
}

// EffectiveBindings returns the account's bindings across both wire formats.
func (account PolicyAccount) EffectiveBindings() []PolicyBinding {
	if account.VLESSFingerprint == "" && account.HysteriaFingerprint == "" {
		return account.Bindings
	}
	bindings := make([]PolicyBinding, 0, len(account.Bindings)+2)
	bindings = append(bindings, account.Bindings...)
	if account.VLESSFingerprint != "" {
		bindings = append(bindings, PolicyBinding{Protocol: "vless", Fingerprint: account.VLESSFingerprint})
	}
	if account.HysteriaFingerprint != "" {
		bindings = append(bindings, PolicyBinding{Protocol: "hysteria", Fingerprint: account.HysteriaFingerprint})
	}
	return bindings
}

func (account *PolicyAccount) UnmarshalJSON(data []byte) error {
	var wire struct {
		Email                  *string         `json:"email"`
		ClientID               *string         `json:"client_id"`
		RequestedBitsPerSecond *int64          `json:"requested_bits_per_second"`
		VLESSFingerprint       string          `json:"vless_fingerprint,omitempty"`
		HysteriaFingerprint    string          `json:"hysteria_fingerprint,omitempty"`
		Bindings               []PolicyBinding `json:"bindings,omitempty"`
	}
	if err := json.Unmarshal(data, &wire, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if wire.Email == nil || wire.ClientID == nil || wire.RequestedBitsPerSecond == nil {
		return errors.New("incomplete bandwidth policy account")
	}
	*account = PolicyAccount{
		Email: *wire.Email, ClientID: *wire.ClientID, RequestedBitsPerSecond: *wire.RequestedBitsPerSecond,
		VLESSFingerprint: wire.VLESSFingerprint, HysteriaFingerprint: wire.HysteriaFingerprint, Bindings: wire.Bindings,
	}
	return nil
}

// PolicySnapshot is the complete allowlist of generated accounts on a node.
// An empty ClientID explicitly authorizes service without bandwidth metering.
type PolicySnapshot struct {
	NodeID     string          `json:"node_id"`
	Generation string          `json:"generation"`
	Accounts   []PolicyAccount `json:"accounts"`
}

type PolicyAck struct {
	Digest      string   `json:"digest"`
	ReadyEmails []string `json:"ready_emails,omitempty"`
}

func (p PolicySnapshot) Validate() error {
	if !ValidIdentity(p.NodeID) || !ValidIdentity(p.Generation) || p.Accounts == nil || len(p.Accounts) > MaxPolicyAccounts {
		return errors.New("invalid bandwidth policy snapshot")
	}
	seen := make(map[string]struct{}, len(p.Accounts))
	rates := make(map[string]int64)
	for _, account := range p.Accounts {
		if !validPolicyEmail(account.Email) {
			return errors.New("invalid bandwidth policy email")
		}
		if err := account.validateBindings(); err != nil {
			return err
		}
		if _, exists := seen[account.Email]; exists {
			return errors.New("duplicate bandwidth policy email")
		}
		seen[account.Email] = struct{}{}
		if account.ClientID == "" && account.RequestedBitsPerSecond == 0 {
			continue
		}
		if !ValidIdentity(account.ClientID) || account.RequestedBitsPerSecond <= 0 || account.RequestedBitsPerSecond > 1<<53-1 {
			return errors.New("invalid bandwidth policy rate or client ID")
		}
		if prior, exists := rates[account.ClientID]; exists && prior != account.RequestedBitsPerSecond {
			return errors.New("inconsistent bandwidth policy rate for one client ID")
		}
		rates[account.ClientID] = account.RequestedBitsPerSecond
	}
	if len(rates) > MaxClients {
		return errors.New("too many managed bandwidth policy client IDs")
	}
	return nil
}

func (account PolicyAccount) validateBindings() error {
	bindings := account.EffectiveBindings()
	if len(bindings) == 0 {
		return errors.New("missing bandwidth policy credential binding")
	}
	seen := make(map[PolicyBinding]struct{}, len(bindings))
	for _, binding := range bindings {
		if !validPolicyProtocol(binding.Protocol) || !validSHA256Hex(binding.Fingerprint) {
			return errors.New("invalid bandwidth policy credential binding")
		}
		if _, exists := seen[binding]; exists {
			return errors.New("duplicate bandwidth policy credential binding")
		}
		seen[binding] = struct{}{}
	}
	return nil
}

func validPolicyProtocol(protocol string) bool {
	if len(protocol) == 0 || len(protocol) > 32 || protocol[0] < 'a' || protocol[0] > 'z' {
		return false
	}
	for _, r := range protocol[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// CredentialParts encodes a compound credential as concatenated byte-length-prefixed parts.
func CredentialParts(parts ...string) string {
	var credential strings.Builder
	for _, part := range parts {
		credential.WriteString(strconv.Itoa(len(part)))
		credential.WriteByte(':')
		credential.WriteString(part)
	}
	return credential.String()
}

// CredentialFingerprint binds an exact configured credential to its protocol.
func CredentialFingerprint(protocol, credential string) string {
	if credential == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(protocol + "\x00" + credential))
	return hex.EncodeToString(digest[:])
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	var digest [sha256.Size]byte
	_, err := hex.Decode(digest[:], []byte(value))
	return err == nil
}

func validPolicyEmail(email string) bool {
	return email != "" && len(email) <= 256 && utf8.ValidString(email) && strings.IndexFunc(email, func(r rune) bool {
		return r == '/' || r == '\\' || unicode.IsControl(r) || unicode.IsSpace(r)
	}) < 0
}

// Digest identifies validated policy content independently of account and binding order.
func (p PolicySnapshot) Digest() string {
	p.Accounts = slices.Clone(p.Accounts)
	slices.SortFunc(p.Accounts, func(a, b PolicyAccount) int { return strings.Compare(a.Email, b.Email) })
	for index := range p.Accounts {
		bindings := slices.Clone(p.Accounts[index].Bindings)
		slices.SortFunc(bindings, func(a, b PolicyBinding) int {
			if order := strings.Compare(a.Protocol, b.Protocol); order != 0 {
				return order
			}
			return strings.Compare(a.Fingerprint, b.Fingerprint)
		})
		p.Accounts[index].Bindings = bindings
	}
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func ReadPolicySnapshot(body io.Reader) (PolicySnapshot, error) {
	var p PolicySnapshot
	if err := readJSON(body, &p); err != nil {
		return PolicySnapshot{}, err
	}
	return p, p.Validate()
}

func ReadPolicyAck(body io.Reader) (PolicyAck, error) {
	var ack PolicyAck
	if err := readJSON(body, &ack); err != nil {
		return PolicyAck{}, err
	}
	if !validSHA256Hex(ack.Digest) || len(ack.ReadyEmails) > MaxPolicyAccounts {
		return PolicyAck{}, errors.New("invalid bandwidth policy acknowledgment")
	}
	prior := ""
	for _, email := range ack.ReadyEmails {
		if email <= prior || !validPolicyEmail(email) {
			return PolicyAck{}, errors.New("invalid ready email in bandwidth policy acknowledgment")
		}
		prior = email
	}
	return ack, nil
}
