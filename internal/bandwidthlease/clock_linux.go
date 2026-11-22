package bandwidthlease

import (
	"time"

	"golang.org/x/sys/unix"
)

func bootTimeNow() (time.Time, error) {
	var elapsed unix.Timespec
	// CLOCK_BOOTTIME continues through suspend and is independent of wall time.
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed); err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(elapsed.Sec), int64(elapsed.Nsec)), nil
}
