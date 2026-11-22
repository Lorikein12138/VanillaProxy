package amneziawg

import (
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// BandwidthCredential represents a peer's authentication key and optional PSK.
func BandwidthCredential(publicKey, presharedKey string) string {
	public, err := wireguard.KeyToHex(publicKey)
	if err != nil || public == "" || public == strings.Repeat("0", 64) {
		return ""
	}
	psk, err := wireguard.KeyToHex(presharedKey)
	if err != nil {
		return ""
	}
	if psk == strings.Repeat("0", 64) {
		psk = ""
	}
	return bandwidthexchange.CredentialParts(public, psk)
}
