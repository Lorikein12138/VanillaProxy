package launch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ReadyNonceSize is the size of the one-time readiness challenge.
const ReadyNonceSize = 32

// Ready tells the child where to send the raw nonce and EOF after core startup.
type Ready struct {
	Address string `json:"addr"`
	Nonce   []byte `json:"nonce"`
}

// Valid verifies that the destination is a literal IPv4 loopback endpoint.
func (r Ready) Valid() bool {
	addr, err := netip.ParseAddrPort(r.Address)
	return err == nil && addr.Port() != 0 && addr.Addr().Is4() && addr.Addr().IsLoopback() && len(r.Nonce) == ReadyNonceSize
}

// Notify delivers the readiness nonce to the parent's local listener.
func (r Ready) Notify(ctx context.Context) error {
	if !r.Valid() {
		return errors.New("invalid metered Xray readiness destination")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", r.Address)
	if err != nil {
		return errors.New("could not reach metered Xray readiness listener")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if n, err := conn.Write(r.Nonce); err != nil || n != ReadyNonceSize {
		return errors.New("could not send metered Xray readiness signal")
	}
	return ctx.Err()
}
