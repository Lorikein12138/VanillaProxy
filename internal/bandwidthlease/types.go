// Package bandwidthlease coordinates temporary per-client bandwidth across nodes.
package bandwidthlease

import "time"

const (
	// Lifetime starts at the node before it sends the challenge.
	Lifetime = 30 * time.Second
	// Retention runs at the authority after receipt, with a clock-drift margin.
	Retention = 35 * time.Second
)

// Challenge identifies one lease request from an authenticated node.
type Challenge struct {
	ClientID      string
	NodeID        string
	IncarnationID string
	Nonce         string
	Sequence      uint64
}

// Grant authorizes the node to enforce this client's rate until the previously
// recorded challenge expires. Receipt of a grant never starts a new deadline.
type Grant struct {
	Challenge     Challenge
	BitsPerSecond int64
}
