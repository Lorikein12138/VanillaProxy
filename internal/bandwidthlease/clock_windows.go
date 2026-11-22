package bandwidthlease

import (
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

var getTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func bootTimeNow() (time.Time, error) {
	if err := getTickCount64.Find(); err != nil {
		return time.Time{}, err
	}
	// GetTickCount64 includes time spent suspended. Its 64-bit value uses
	// both return registers on 32-bit Windows.
	low, high, _ := getTickCount64.Call()
	elapsed := uint64(low)
	if strconv.IntSize == 32 {
		elapsed |= uint64(high) << 32
	}
	return time.Unix(int64(elapsed/1000), int64(elapsed%1000)*int64(time.Millisecond)), nil
}
