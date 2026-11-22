package xray

import (
	"bytes"
	"maps"

	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
)

// InboundConfig represents an Xray inbound configuration.
// It defines how Xray accepts incoming connections including protocol, port, and settings.
type InboundConfig struct {
	// PanelGenerated marks inbounds projected from local database rows for a managed node.
	PanelGenerated bool `json:"-"`
	// BandwidthAutomatic marks a native client list selected by the panel's policy preparation.
	BandwidthAutomatic bool `json:"-"`
	// BandwidthProxyOwners records explicit native username to panel email bindings.
	BandwidthProxyOwners map[string]string `json:"-"`
	// TuicRelay owns client revocation outside Xray; its user edits must not restart the core.
	TuicRelay          bool                 `json:"-"`
	TuicInboundID      int                  `json:"-"`
	AmneziaWGRelay     bool                 `json:"-"`
	AmneziaWGInboundID int                  `json:"-"`
	Listen             json_util.RawMessage `json:"listen"` // listen cannot be an empty string
	Port               int                  `json:"port"`
	Protocol           string               `json:"protocol"`
	Settings           json_util.RawMessage `json:"settings"`
	StreamSettings     json_util.RawMessage `json:"streamSettings,omitempty"`
	Tag                string               `json:"tag"`
	Sniffing           json_util.RawMessage `json:"sniffing,omitempty"`
}

// IsSidecarRelay is set only by the panel's two relay generators.
func (c InboundConfig) IsSidecarRelay() bool {
	return c.TuicRelay || c.AmneziaWGRelay
}

// Equals compares two InboundConfig instances for deep equality.
func (c *InboundConfig) Equals(other *InboundConfig) bool {
	if c.PanelGenerated != other.PanelGenerated || c.BandwidthAutomatic != other.BandwidthAutomatic ||
		!maps.Equal(c.BandwidthProxyOwners, other.BandwidthProxyOwners) ||
		c.TuicRelay != other.TuicRelay || c.TuicInboundID != other.TuicInboundID ||
		c.AmneziaWGRelay != other.AmneziaWGRelay || c.AmneziaWGInboundID != other.AmneziaWGInboundID {
		return false
	}
	if !bytes.Equal(c.Listen, other.Listen) {
		return false
	}
	if c.Port != other.Port {
		return false
	}
	if c.Protocol != other.Protocol {
		return false
	}
	if !bytes.Equal(c.Settings, other.Settings) {
		return false
	}
	if !bytes.Equal(c.StreamSettings, other.StreamSettings) {
		return false
	}
	if c.Tag != other.Tag {
		return false
	}
	if !bytes.Equal(c.Sniffing, other.Sniffing) {
		return false
	}
	return true
}
