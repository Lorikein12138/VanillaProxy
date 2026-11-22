package amneziawgnet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

const boundRelayTestUser = "Peer.A@example.test"
const boundRelayTestPassword = "local-test-password"

func startBoundRelayTestServer(t *testing.T, serve func(net.Conn) error) (SocksRelay, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			err = serve(conn)
		}
		done <- err
	}()
	return SocksRelay{Addr: ln.Addr().String(), Password: boundRelayTestPassword, RequireBoundUDP: true}, done
}

func readBoundRelayTestBytes(conn net.Conn, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("read bytes %x, want %x", got, want)
	}
	return nil
}

func authenticateBoundRelayTestClient(conn net.Conn) error {
	if err := readBoundRelayTestBytes(conn, []byte{5, 1, 2}); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}
	auth := append([]byte{1, byte(len(boundRelayTestUser))}, boundRelayTestUser...)
	auth = append(auth, byte(len(boundRelayTestPassword)))
	auth = append(auth, boundRelayTestPassword...)
	if err := readBoundRelayTestBytes(conn, auth); err != nil {
		return err
	}
	_, err := conn.Write([]byte{1, 0})
	return err
}

func TestBoundSocksRelayRejectsNoAuth(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			relay, done := startBoundRelayTestServer(t, func(conn net.Conn) error {
				if err := readBoundRelayTestBytes(conn, []byte{5, 1, 2}); err != nil {
					return err
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return err
				}
				var next [1]byte
				n, err := conn.Read(next[:])
				if n != 0 || !errors.Is(err, io.EOF) {
					return fmt.Errorf("connection remained open after downgrade: read %d bytes, %v", n, err)
				}
				return nil
			})
			if protocol == "tcp" {
				conn, err := relay.dialTCP(boundRelayTestUser, netip.MustParseAddrPort("192.0.2.5:443"))
				if err == nil {
					conn.Close()
					t.Fatal("TCP accepted authentication downgrade")
				}
			} else {
				sess, err := relay.newUDPSession(boundRelayTestUser)
				if err == nil {
					sess.Close()
					t.Fatal("UDP accepted authentication downgrade")
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoundSocksTCPAuthenticatesAndConnects(t *testing.T) {
	target := netip.MustParseAddrPort("[2001:db8::41]:443")
	payload := []byte("tcp relay")
	relay, done := startBoundRelayTestServer(t, func(conn net.Conn) error {
		if err := authenticateBoundRelayTestClient(conn); err != nil {
			return err
		}
		request := append([]byte{5, 1, 0, 4}, target.Addr().AsSlice()...)
		request = append(request, 1, 187)
		if err := readBoundRelayTestBytes(conn, request); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return err
		}
		if err := readBoundRelayTestBytes(conn, payload); err != nil {
			return err
		}
		_, err := conn.Write(payload)
		return err
	})
	conn, err := relay.dialTCP(boundRelayTestUser, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := readBoundRelayTestBytes(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBoundSocksUDPRejectsInvalidAssociateReply(t *testing.T) {
	for _, tt := range []struct {
		name  string
		reply []byte
	}{
		{"zero port", []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}},
		{"different IP", []byte{5, 0, 0, 1, 127, 0, 0, 2, 0, 53}},
		{"domain", []byte{5, 0, 0, 3, 1, 'x', 0, 53}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			relay, done := startBoundRelayTestServer(t, func(conn net.Conn) error {
				if err := authenticateBoundRelayTestClient(conn); err != nil {
					return err
				}
				var request [10]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil {
					return err
				}
				_, err := conn.Write(tt.reply)
				return err
			})
			if sess, err := relay.newUDPSession(boundRelayTestUser); err == nil {
				sess.Close()
				t.Fatal("accepted invalid bound endpoint")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoundSocksUDPDropsOtherEndpointsAndClosesWithControl(t *testing.T) {
	listenUDP := func() *net.UDPConn {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = udp.Close() })
		return udp
	}
	udp, wrongPort := listenUDP(), listenUDP()
	udpEndpoint := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	association := make(chan netip.AddrPort, 1)
	stopControl := make(chan struct{})
	relay, done := startBoundRelayTestServer(t, func(conn net.Conn) error {
		if err := authenticateBoundRelayTestClient(conn); err != nil {
			return err
		}
		if err := readBoundRelayTestBytes(conn, []byte{5, 3, 0, 1, 127, 0, 0, 1}); err != nil {
			return err
		}
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return err
		}
		source := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port[0])<<8|uint16(port[1]))
		association <- source
		reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(udpEndpoint.Port() >> 8), byte(udpEndpoint.Port())}
		if _, err := conn.Write(reply); err != nil {
			return err
		}
		<-stopControl
		return nil
	})
	defer close(stopControl)
	session, err := relay.newUDPSession(boundRelayTestUser)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	source := <-association
	if source.Port() == 0 || session.udpConn.LocalAddr().(*net.UDPAddr).AddrPort() != source {
		t.Fatalf("announced %s, actual UDP socket %s", source, session.udpConn.LocalAddr())
	}
	target := netip.MustParseAddrPort("192.0.2.5:53")
	payload := []byte("udp relay")
	if err := session.sendTo(target, payload); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, actualSource, err := udp.ReadFromUDPAddrPort(buf)
	if err != nil || actualSource != source {
		t.Fatalf("received UDP source = %s, err = %v, want %s", actualSource, err, source)
	}
	packet := append([]byte{0, 0, 0, 1, 192, 0, 2, 5, 0, 53}, payload...)
	if !bytes.Equal(buf[:n], packet) {
		t.Fatalf("unexpected UDP packet %x", buf[:n])
	}
	if _, err := wrongPort.WriteToUDPAddrPort(packet, source); err != nil {
		t.Fatal(err)
	}
	_ = session.udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := session.receive(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("wrong source endpoint: err = %v, want read deadline", err)
	}
	if _, err := udp.WriteToUDPAddrPort(packet, source); err != nil {
		t.Fatal(err)
	}
	_ = session.udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	from, got, err := session.receive(buf)
	if err != nil || from != target || !bytes.Equal(got, payload) {
		t.Fatalf("exact source endpoint: from = %s, payload = %q, err = %v", from, got, err)
	}
	stopControl <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.receive(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("reading after TCP control closure: err = %v, want closed socket", err)
	}
}
