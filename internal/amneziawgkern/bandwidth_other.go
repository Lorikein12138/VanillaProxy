//go:build !linux

package amneziawgkern

import (
	"context"
	"errors"
)

var errKernelBandwidthUnavailable = errors.New("amneziawgkern: bandwidth gate requires Linux NFQUEUE")

type BandwidthGate struct{}

func OpenBandwidthGate(string, int, []BandwidthRoute, func(context.Context, string, int) error) (*BandwidthGate, error) {
	return nil, errKernelBandwidthUnavailable
}

func openBandwidthGate(string, int, string, []BandwidthRoute, func(context.Context, string, int) error) (*BandwidthGate, error) {
	return nil, errKernelBandwidthUnavailable
}

func (*BandwidthGate) Healthy() bool { return false }

func (*BandwidthGate) Block() {}

func (*BandwidthGate) Close() error { return errKernelBandwidthUnavailable }

func RemoveStaleBandwidthGate(string) error { return errKernelBandwidthUnavailable }

func removeStaleBandwidthGate(string, string) error { return errKernelBandwidthUnavailable }
