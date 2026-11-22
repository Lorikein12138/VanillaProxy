//go:build !windows

package bandwidthruntime

import "os"

func isPrivatePanelTokenFile(_ *os.File, info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}
