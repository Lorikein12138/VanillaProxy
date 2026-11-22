//go:build !linux && !windows

package bandwidthlease

import (
	"fmt"
	"runtime"
	"time"
)

func bootTimeNow() (time.Time, error) {
	return time.Time{}, fmt.Errorf("no suspend-aware clock for %s", runtime.GOOS)
}
