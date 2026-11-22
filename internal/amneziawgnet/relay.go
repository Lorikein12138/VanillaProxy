// Phase 2: relaying a recovered tunnel connection into Xray's own,
// completely stock SOCKS5 inbound -- authenticating as the owning peer's
// email -- is what gives every embedded AmneziaWG connection real, native
// Xray stats/routing/sniffing with no Xray-core fork at all (Finding 3 of
// the migration plan: a stock SOCKS5 inbound sets its per-connection stats
// identity directly from the SOCKS5 auth username).
package amneziawgnet

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// SocksRelay describes the loopback SOCKS5 inbound decapsulated AmneziaWG
// traffic gets relayed into.
type SocksRelay struct {
	// Addr is the SOCKS5 inbound's own address, e.g. "127.0.0.1:11500".
	Addr string
	// Password is shared across every account. This traffic never leaves
	// loopback, so the password is not a real secrecy boundary -- it only
	// needs to satisfy Xray's SOCKS5 inbound requiring *some* username/
	// password auth before it will accept a connection and use the
	// username as the stats identity. Document this reasoning wherever a
	// caller generates or displays it, so it's never mistaken later for a
	// real credential.
	Password string
	// RequireBoundUDP forces password authentication for TCP and UDP, and
	// binds a UDP association to the loopback socket declared to Xray.
	RequireBoundUDP bool
}

// SocksInboundSettings builds the JSON `settings` block for a stock Xray
// SOCKS5 inbound with one username/password account per email, all sharing
// password (see SocksRelay's doc comment). udp:true is required: RelayUDP
// depends on the inbound accepting UDP ASSOCIATE, not just CONNECT.
func SocksInboundSettings(emails []string, password string) ([]byte, error) {
	type account struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	settings := struct {
		Auth     string    `json:"auth"`
		UDP      bool      `json:"udp"`
		Accounts []account `json:"accounts"`
	}{Auth: "password", UDP: true}
	for _, email := range emails {
		settings.Accounts = append(settings.Accounts, account{User: email, Pass: password})
	}
	return json.Marshal(settings)
}

// RelayTCP dials r.Addr, authenticates as email, issues a SOCKS5 CONNECT to
// dest, and pipes bytes both ways until both directions end.
// Blocks until the relay ends; meant to be called from (or as) an
// AttachTCPForwarder handler, which already runs each connection on its own
// goroutine.
func (r SocksRelay) RelayTCP(conn *gonet.TCPConn, email string, dest netip.AddrPort) {
	defer conn.Close()

	upstream, err := r.dialTCP(email, dest)
	if err != nil {
		logger.Warningf("amneziawgnet: RelayTCP: SOCKS5 CONNECT to %s as %q: %v", dest, email, err)
		return
	}
	defer upstream.Close()

	pipeBothWays(conn, upstream)
}

func (r SocksRelay) dialTCP(email string, dest netip.AddrPort) (net.Conn, error) {
	if r.RequireBoundUDP {
		if !dest.IsValid() || dest.Addr().Zone() != "" {
			return nil, fmt.Errorf("amneziawgnet: invalid SOCKS5 CONNECT destination %s", dest)
		}
		conn, err := r.dialAuthenticated(email)
		if err != nil {
			return nil, err
		}
		if err := socks5Request(conn, 0x01, dest); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := readSocks5Reply(conn, true); err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
	auth := &proxy.Auth{User: email, Password: r.Password}
	dialer, err := proxy.SOCKS5("tcp", r.Addr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", dest.String())
}

// halfCloseIdle bounds how long the surviving direction of a half-closed pair
// may sit idle, so a peer that vanished mid-transfer cannot pin it forever.
const halfCloseIdle = 2 * time.Minute

// closeWriter is the half-close half of *net.TCPConn and *gonet.TCPConn.
type closeWriter interface{ CloseWrite() error }

// guardedReader reads one side of a relayed pair, re-arming its read deadline
// on every read once armed, so the bound is an idle window, not a total one.
type guardedReader struct {
	conn  net.Conn
	armed atomic.Bool
}

func (r *guardedReader) Read(p []byte) (int, error) {
	if r.armed.Load() {
		_ = r.conn.SetReadDeadline(time.Now().Add(halfCloseIdle))
	}
	return r.conn.Read(p)
}

// arm bounds this side's remaining reads, including one already in flight.
func (r *guardedReader) arm() {
	r.armed.Store(true)
	_ = r.conn.SetReadDeadline(time.Now().Add(halfCloseIdle))
}

// pipeBothWays copies a and b into each other until BOTH directions end,
// half-closing each far side in turn so a half-closed peer still gets its reply.
func pipeBothWays(a, b net.Conn) {
	ga, gb := &guardedReader{conn: a}, &guardedReader{conn: b}
	var wg sync.WaitGroup
	wg.Add(2)
	// Arming dst bounds the direction still reading from it -- the one this
	// copy just signalled EOF to.
	pipe := func(dst, src *guardedReader) {
		defer wg.Done()
		_, _ = io.Copy(dst.conn, src)
		if cw, ok := dst.conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.conn.Close()
		}
		dst.arm()
	}
	go pipe(gb, ga)
	go pipe(ga, gb)
	wg.Wait()
}

// socks5UDPSession is one established SOCKS5 UDP ASSOCIATE session: udpConn
// is the actual socket packets are sent to (and replies read from); ctrl is
// the TCP control connection that must stay open for the session's
// lifetime -- per RFC 1928, closing it tears the association down.
type socks5UDPSession struct {
	ctrl       net.Conn
	udpConn    *net.UDPConn
	boundRelay netip.AddrPort
	closed     atomic.Bool
}

// Bounds dial plus the greeting/auth/associate reads: an accepted-but-silent
// server otherwise parks Handle, and with it the tunnel's delivery path.
var socks5AssociateTimeout = 5 * time.Second

// newUDPSession performs the SOCKS5 greeting, username/password auth,
// and UDP ASSOCIATE request/reply by hand: golang.org/x/net/proxy's SOCKS5
// client (used by RelayTCP above) only implements CONNECT, and xray-core's
// own proxy/socks/client.go is written against its internal transport
// types, not reusable as a standalone dialer -- so this is a small, direct,
// from-the-RFC implementation rather than an existing library call.
func (r SocksRelay) newUDPSession(user string) (*socks5UDPSession, error) {
	ctrl, err := r.dialAuthenticated(user)
	if err != nil {
		return nil, err
	}
	sess := &socks5UDPSession{ctrl: ctrl}
	ready := false
	defer func() {
		if !ready {
			sess.Close()
		}
	}()

	// Stock SOCKS5 uses 0.0.0.0:0, allowing Xray to learn the source port.
	// Strict mode announces the actual socket from the authenticated TCP
	// connection, allowing Xray to require that exact source endpoint.
	source := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if r.RequireBoundUDP {
		localIP := ctrl.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		sess.udpConn, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP, 0)))
		if err != nil {
			return nil, fmt.Errorf("amneziawgnet: bind UDP association socket: %w", err)
		}
		source = sess.udpConn.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	if err := socks5Request(ctrl, 0x03, source); err != nil {
		return nil, err
	}
	bind, err := readSocks5Reply(ctrl, r.RequireBoundUDP)
	if err != nil {
		return nil, err
	}
	if r.RequireBoundUDP {
		relayIP := ctrl.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		if bind.Addr().Unmap() != relayIP || bind.Port() == 0 {
			return nil, fmt.Errorf("amneziawgnet: unexpected bound UDP relay endpoint %s", bind)
		}
		sess.boundRelay = netip.AddrPortFrom(relayIP, bind.Port())
	} else {
		sess.udpConn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bind))
		if err != nil {
			return nil, fmt.Errorf("amneziawgnet: dial SOCKS5 UDP relay endpoint %s: %w", bind, err)
		}
	}
	_ = ctrl.SetDeadline(time.Time{})
	ready = true
	if r.RequireBoundUDP {
		go sess.watchControl()
	}
	return sess, nil
}

func (r SocksRelay) dialAuthenticated(user string) (net.Conn, error) {
	if r.RequireBoundUDP {
		if err := r.validateBoundRelay(); err != nil {
			return nil, err
		}
		if !validRelayEmail(user) {
			return nil, fmt.Errorf("amneziawgnet: SOCKS5 username must contain 1 to 255 bytes")
		}
	}
	deadline := time.Now().Add(socks5AssociateTimeout)
	dialer := net.Dialer{Deadline: deadline}
	ctrl, err := dialer.DialContext(context.Background(), "tcp", r.Addr)
	if err != nil {
		return nil, fmt.Errorf("amneziawgnet: dial SOCKS5 control connection: %w", err)
	}
	_ = ctrl.SetDeadline(deadline)
	if err := socks5Handshake(ctrl, user, r.Password, r.RequireBoundUDP); err != nil {
		ctrl.Close()
		return nil, err
	}
	return ctrl, nil
}

func (r SocksRelay) validateBoundRelay() error {
	endpoint, err := netip.ParseAddrPort(r.Addr)
	if err != nil || endpoint.Addr().Zone() != "" || !endpoint.Addr().Unmap().IsLoopback() || endpoint.Port() == 0 {
		return fmt.Errorf("amneziawgnet: bound relay requires a loopback IP and port")
	}
	if len(r.Password) == 0 || len(r.Password) > 255 || strings.HasPrefix(r.Password, "amneziawgnet-fallback-") {
		return fmt.Errorf("amneziawgnet: secure SOCKS relay password unavailable")
	}
	return nil
}

func validRelayEmail(email string) bool {
	return len(email) > 0 && len(email) <= 255
}

func socks5Request(conn net.Conn, command byte, address netip.AddrPort) error {
	var req [22]byte
	req[0], req[1], req[3] = 0x05, command, 0x01
	ip := address.Addr().Unmap()
	if ip.Is6() {
		req[3] = 0x04
	}
	n := 4 + copy(req[4:], ip.AsSlice())
	binary.BigEndian.PutUint16(req[n:], address.Port())
	if _, err := conn.Write(req[:n+2]); err != nil {
		return fmt.Errorf("amneziawgnet: send SOCKS5 command %d: %w", command, err)
	}
	return nil
}

// socks5Handshake performs the version greeting and (if the server
// requires it) username/password auth. Xray's SOCKS5 inbound with
// auth:"password" always requires it; the no-auth branch exists so this
// helper isn't silently wrong against a differently-configured server.
func socks5Handshake(conn net.Conn, user, password string, requirePassword bool) error {
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	if requirePassword {
		greeting = []byte{0x05, 0x01, 0x02}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("amneziawgnet: send SOCKS5 greeting: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("amneziawgnet: read SOCKS5 greeting reply: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("amneziawgnet: unexpected SOCKS5 version %d", resp[0])
	}
	if requirePassword && resp[1] != 0x02 {
		return fmt.Errorf("amneziawgnet: SOCKS5 password authentication required, selected method %d", resp[1])
	}
	switch resp[1] {
	case 0x00: // no auth required
		return nil
	case 0x02: // username/password
		req := make([]byte, 0, 3+len(user)+len(password))
		req = append(req, 0x01, byte(len(user)))
		req = append(req, user...)
		req = append(req, byte(len(password)))
		req = append(req, password...)
		if _, err := conn.Write(req); err != nil {
			return fmt.Errorf("amneziawgnet: send SOCKS5 auth: %w", err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fmt.Errorf("amneziawgnet: read SOCKS5 auth reply: %w", err)
		}
		if requirePassword && authResp[0] != 0x01 {
			return fmt.Errorf("amneziawgnet: unexpected SOCKS5 auth version %d", authResp[0])
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("amneziawgnet: SOCKS5 auth rejected (status %d)", authResp[1])
		}
		return nil
	default:
		return fmt.Errorf("amneziawgnet: SOCKS5 server offered unsupported auth method %d", resp[1])
	}
}

// readSocks5Reply reads a SOCKS5 reply (the common format shared by CONNECT
// and UDP ASSOCIATE replies) and returns its bound address.
func readSocks5Reply(r io.Reader, requireIP bool) (netip.AddrPort, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("amneziawgnet: read SOCKS5 reply header: %w", err)
	}
	if hdr[0] != 0x05 {
		return netip.AddrPort{}, fmt.Errorf("amneziawgnet: unexpected SOCKS5 reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return netip.AddrPort{}, fmt.Errorf("amneziawgnet: SOCKS5 request failed (reply code %d)", hdr[1])
	}
	if requireIP && (hdr[2] != 0 || (hdr[3] != 0x01 && hdr[3] != 0x04)) {
		return netip.AddrPort{}, fmt.Errorf("amneziawgnet: invalid SOCKS5 relay reply for bound connection")
	}
	addr, err := readSocks5Addr(r, hdr[3])
	if err != nil {
		return netip.AddrPort{}, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("amneziawgnet: read SOCKS5 reply port: %w", err)
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(portBytes[:])), nil
}

// readSocks5Addr reads the address portion of a SOCKS5 reply for the given
// address type (IPv4, IPv6, or domain -- resolved locally since a loopback
// Xray inbound is not expected to reply with one, but it's cheap to handle
// correctly rather than fail oddly if it ever does).
func readSocks5Addr(r io.Reader, atyp byte) (netip.Addr, error) {
	switch atyp {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom4(b), nil
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom16(b), nil
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return netip.Addr{}, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return netip.Addr{}, err
		}
		resolved, err := net.ResolveIPAddr("ip", string(name))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("amneziawgnet: resolve SOCKS5 domain reply %q: %w", name, err)
		}
		addr, ok := netip.AddrFromSlice(resolved.IP)
		if !ok {
			return netip.Addr{}, fmt.Errorf("amneziawgnet: unparseable resolved SOCKS5 domain reply address")
		}
		return addr, nil
	default:
		return netip.Addr{}, fmt.Errorf("amneziawgnet: unsupported SOCKS5 address type %d", atyp)
	}
}

// Close ends the UDP ASSOCIATE session: closing ctrl tells the SOCKS5
// server to tear down its relay side too (RFC 1928).
func (s *socks5UDPSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	return s.ctrl.Close()
}

func (s *socks5UDPSession) watchControl() {
	// SOCKS5 sends no control data after UDP ASSOCIATE succeeds.
	var buf [1]byte
	_, _ = s.ctrl.Read(buf[:])
	_ = s.Close()
}

// sendTo wraps payload in a SOCKS5 UDP request header addressed to dest and
// sends it to the session's relay endpoint.
func (s *socks5UDPSession) sendTo(dest netip.AddrPort, payload []byte) error {
	hdr := make([]byte, 0, 3+1+16+2+len(payload))
	hdr = append(hdr, 0x00, 0x00, 0x00) // RSV RSV FRAG(=0, no fragmentation)
	if dest.Addr().Is4() {
		b := dest.Addr().As4()
		hdr = append(hdr, 0x01)
		hdr = append(hdr, b[:]...)
	} else {
		b := dest.Addr().As16()
		hdr = append(hdr, 0x04)
		hdr = append(hdr, b[:]...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], dest.Port())
	hdr = append(hdr, portBytes[:]...)
	hdr = append(hdr, payload...)
	if s.boundRelay.IsValid() {
		_, err := s.udpConn.WriteToUDPAddrPort(hdr, s.boundRelay)
		return err
	}
	_, err := s.udpConn.Write(hdr)
	return err
}

// receive reads one reply datagram into buf, returning the address the
// SOCKS5 server says it came from and the actual payload (a sub-slice of
// buf -- valid only until the next receive call).
func (s *socks5UDPSession) receive(buf []byte) (netip.AddrPort, []byte, error) {
	n, err := s.readUDP(buf)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	data := buf[:n]
	if len(data) < 4 {
		return netip.AddrPort{}, nil, fmt.Errorf("amneziawgnet: short SOCKS5 UDP reply (%d bytes)", n)
	}
	if s.boundRelay.IsValid() && (data[0] != 0 || data[1] != 0 || data[2] != 0) {
		return netip.AddrPort{}, nil, fmt.Errorf("amneziawgnet: invalid SOCKS5 UDP relay header")
	}
	addr, rest, err := splitSocks5Addr(data[4:], data[3])
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	if len(rest) < 2 {
		return netip.AddrPort{}, nil, fmt.Errorf("amneziawgnet: truncated SOCKS5 UDP reply port")
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(rest[:2])), rest[2:], nil
}

func (s *socks5UDPSession) readUDP(buf []byte) (int, error) {
	if !s.boundRelay.IsValid() {
		return s.udpConn.Read(buf)
	}
	for {
		n, source, err := s.udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return n, err
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		if source == s.boundRelay {
			return n, nil
		}
	}
}

// splitSocks5Addr decodes the address at the head of b for address type atyp
// and returns it with whatever follows, length-checked at every step.
func splitSocks5Addr(b []byte, atyp byte) (netip.Addr, []byte, error) {
	switch atyp {
	case 0x01:
		if len(b) < 4 {
			return netip.Addr{}, nil, fmt.Errorf("amneziawgnet: truncated SOCKS5 IPv4 reply address")
		}
		return netip.AddrFrom4([4]byte(b[:4])), b[4:], nil
	case 0x04:
		if len(b) < 16 {
			return netip.Addr{}, nil, fmt.Errorf("amneziawgnet: truncated SOCKS5 IPv6 reply address")
		}
		return netip.AddrFrom16([16]byte(b[:16])), b[16:], nil
	case 0x03:
		// Resolving here would block the receive loop on DNS, and a datagram's
		// own source is an address already -- so only a literal is accepted.
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return netip.Addr{}, nil, fmt.Errorf("amneziawgnet: truncated SOCKS5 domain reply address")
		}
		name := string(b[1 : 1+int(b[0])])
		addr, err := netip.ParseAddr(name)
		if err != nil {
			return netip.Addr{}, nil, fmt.Errorf("amneziawgnet: SOCKS5 UDP reply from non-literal address %q", name)
		}
		return addr, b[1+int(b[0]):], nil
	default:
		return netip.Addr{}, nil, fmt.Errorf("amneziawgnet: unsupported SOCKS5 address type %d", atyp)
	}
}

// UDPRelay tracks one SOCKS5 UDP ASSOCIATE session per source (tunnel-
// internal client) flow, relaying each into r's SOCKS5 inbound and writing
// replies back through gstack -- the UDP counterpart of RelayTCP, meant to
// be driven by an AttachUDPHandler callback (see udp.go).
type UDPRelay struct {
	relay  SocksRelay
	gstack *stack.Stack

	// Keyed by the comparable netip.AddrPort, like udpForwardListener's own
	// session map: src.String() would allocate on every relayed datagram.
	mu       sync.Mutex
	sessions map[netip.AddrPort]*socks5UDPSession
	closed   bool
}

// NewUDPRelay creates a UDPRelay for one embedded AmneziaWG Device's stack.
func NewUDPRelay(relay SocksRelay, gstack *stack.Stack) *UDPRelay {
	return &UDPRelay{relay: relay, gstack: gstack, sessions: map[netip.AddrPort]*socks5UDPSession{}}
}

// Handle relays one packet from src (the peer's tunnel-internal source) to
// dst (its real, recovered destination), opening a fresh SOCKS5 UDP
// ASSOCIATE session for src the first time it's seen (authenticating as
// email, so Xray attributes the whole flow's stats to the right peer) and
// reusing it for subsequent packets from the same src.
func (u *UDPRelay) Handle(src, dst netip.AddrPort, email string, payload []byte) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	sess, ok := u.sessions[src]
	u.mu.Unlock()

	if !ok {
		fresh, err := u.relay.newUDPSession(email)
		if err != nil {
			logger.Warningf("amneziawgnet: UDPRelay: SOCKS5 associate for %q: %v", email, err)
			return
		}
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			fresh.Close()
			return
		}
		// Associating happens off-lock, so a concurrent Handle for the same src
		// may already have published one; keep it, so the key has a single pump.
		if existing, dup := u.sessions[src]; dup {
			u.mu.Unlock()
			fresh.Close()
			sess = existing
		} else {
			u.sessions[src] = fresh
			u.mu.Unlock()
			sess = fresh
			go u.pump(src, fresh)
		}
	}
	if err := sess.sendTo(dst, payload); err != nil {
		logger.Warningf("amneziawgnet: UDPRelay: send to %s: %v", dst, err)
	}
}

// pump reads replies from sess and writes them back into the tunnel toward
// src until the session errors out or goes idle for 2 minutes, then tears
// it down -- both the map entry and the underlying SOCKS5 association.
func (u *UDPRelay) pump(src netip.AddrPort, sess *socks5UDPSession) {
	defer func() {
		u.mu.Lock()
		// Only retire our own entry: a delete by key alone would evict whichever
		// session currently holds src, orphaning a live one.
		if u.sessions[src] == sess {
			delete(u.sessions, src)
		}
		u.mu.Unlock()
		sess.Close()
	}()
	buf := make([]byte, 65536)
	for {
		_ = sess.udpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		from, payload, err := sess.receive(buf)
		if err != nil {
			return
		}
		if err := WriteUDPReply(u.gstack, from, src, payload); err != nil {
			logger.Warningf("amneziawgnet: UDPRelay: reply write: %v", err)
		}
	}
}

// Close tears down every open session. Call when the owning Device is
// closed.
func (u *UDPRelay) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	for k, s := range u.sessions {
		s.Close()
		delete(u.sessions, k)
	}
}
