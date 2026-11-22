// Package launch defines the private protocol between the panel and metered child.
package launch

import "github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"

// Command is the private child entry point of the panel binary.
const Command = "xray-bandwidth-child"

// MaxHandshakeSize bounds the JSON document passed to the child.
const MaxHandshakeSize = 8 << 20

// UnmeteredXrayAccountID explicitly selects a trusted generated native account
// that may route without acquiring a distributed bandwidth lease.
const UnmeteredXrayAccountID = "\x00"

const (
	TUICRelay      = "tuic"
	AmneziaWGRelay = "amneziawg"
)

// SidecarRelay identifies a generated loopback relay. The sidecar, rather
// than the Xray dispatcher, already charges traffic for every account.
type SidecarRelay struct {
	Kind      string            `json:"kind"`
	InboundID int               `json:"inboundId"`
	Port      int               `json:"port"`
	Password  string            `json:"password"`
	UserLevel uint32            `json:"userLevel"`
	Automatic bool              `json:"automatic,omitempty"`
	Accounts  map[string]string `json:"accounts"`
}

// Handshake is sent as a single JSON document over child stdin, followed by
// EOF. Clients maps inbound tags and authenticated emails to canonical IDs
// or UnmeteredXrayAccountID.
type Handshake struct {
	IPC          bandwidthipc.Info            `json:"ipc"`
	Clients      map[string]map[string]string `json:"clients"`
	Relays       map[string]SidecarRelay      `json:"relays,omitempty"`
	Generated    map[string]bool              `json:"generated,omitempty"`
	ConfigSHA256 []byte                       `json:"configSHA256,omitempty"`
	Ready        *Ready                       `json:"ready,omitempty"`
}
