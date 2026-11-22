package tuic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

func TestServerBandwidthGateAuthenticatedTCPAndUDP(t *testing.T) {
	const email = "bandwidth@example.test"
	const relayPassword = "lifecycle-socks-password"
	const clientID = "canonical-client"
	relayAddr, cleanup := startMockSocks5Server(t, email, relayPassword)
	defer cleanup()

	var mu sync.Mutex
	var charges []int
	var deny bool
	gate := func(_ context.Context, id string, n int) error {
		mu.Lock()
		defer mu.Unlock()
		if id != clientID || n > 64*1024 {
			t.Errorf("unexpected bandwidth charge: id=%q bytes=%d", id, n)
		}
		charges = append(charges, n)
		if deny {
			return errors.New("lease inactive")
		}
		return nil
	}
	newServer := func(inst Instance, relay *SocksRelay) (*Server, error) {
		expected := uuid.MustParse(inst.Clients[0].UUID)
		password := inst.Clients[0].Password
		return NewServerWithBandwidth(inst, relay, gate, func(id [16]byte, credential string) (string, bool) {
			return clientID, id == expected && credential == password
		})
	}
	server, client, _, _ := startLifecycleTestServerWithConstructor(t, &SocksRelay{
		Addr: relayAddr, Password: relayPassword,
	}, email, newServer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := &Address{Type: AddrTypeIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	tcpPayload := bytes.Repeat([]byte{'t'}, 80*1024)
	connect := bytes.NewBuffer([]byte{ProtocolVersion, CmdConnect})
	if err := WriteAddress(connect, target); err != nil {
		t.Fatal(err)
	}
	connect.Write(tcpPayload)
	if _, err := stream.Write(connect.Bytes()); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(stream, reply); err != nil || !bytes.Equal(reply, tcpPayload) {
		t.Fatalf("TCP echo failed: %v", err)
	}
	mu.Lock()
	var tcpCharged int
	for _, n := range charges {
		tcpCharged += n
	}
	charges = nil
	mu.Unlock()
	if tcpCharged != 2*len(tcpPayload) {
		t.Fatalf("TCP charged %d bytes, want %d", tcpCharged, 2*len(tcpPayload))
	}

	udpPayload := bytes.Repeat([]byte{'u'}, 1300)
	for i := range 2 {
		var frame bytes.Buffer
		var addr *Address
		if i == 0 {
			addr = target
		}
		if err := WritePacket(&frame, 100, 1, 2, uint8(i), addr, udpPayload[i*650:(i+1)*650]); err != nil {
			t.Fatal(err)
		}
		if err := client.SendDatagram(frame.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	reassembler := newPacketReassembler(1500)
	for {
		datagram, err := client.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		reader := bytes.NewReader(datagram)
		if _, cmd, err := ReadCommand(reader); err != nil || cmd != CmdPacket {
			t.Fatalf("invalid UDP reply command: %d, %v", cmd, err)
		}
		header, err := ReadPacketHeader(reader)
		if err != nil {
			t.Fatal(err)
		}
		fragment, err := readPacketPayload(reader, header)
		if err != nil {
			t.Fatal(err)
		}
		if _, full, complete := reassembler.feed(packetTransportDatagram, header, fragment); complete {
			if !bytes.Equal(full, udpPayload) {
				t.Fatal("UDP echo payload differs")
			}
			break
		}
	}
	mu.Lock()
	udpCharges := charges
	charges = nil
	deny = true
	mu.Unlock()
	if len(udpCharges) != 2 || udpCharges[0] != len(udpPayload) || udpCharges[1] != len(udpPayload) {
		t.Fatalf("UDP charges = %v, want one full payload per direction", udpCharges)
	}

	if _, err := stream.Write([]byte("no active lease")); err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Read(reply); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("TCP lease denial should end the stream, got %d bytes and %v", n, err)
	}
	waitForClientTraffic(t, server, email, int64(len(tcpPayload)+len(udpPayload)))
}

func TestServerBandwidthUnboundClientDoesNotDialRelay(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	resolutions := make(chan struct{}, 2)
	newServer := func(inst Instance, relay *SocksRelay) (*Server, error) {
		return NewServerWithBandwidth(inst, relay, func(context.Context, string, int) error {
			t.Error("unbound client reached bandwidth gate")
			return nil
		}, func([16]byte, string) (string, bool) {
			resolutions <- struct{}{}
			return "", false
		})
	}
	_, client, _, _ := startLifecycleTestServerWithConstructor(t, &SocksRelay{
		Addr: listener.Addr().String(),
	}, "unbound@example.test", newServer)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	connect := bytes.NewBuffer([]byte{ProtocolVersion, CmdConnect})
	if err := WriteAddress(connect, &Address{Type: AddrTypeIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 80}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(connect.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatalf("unbound TCP stream failed to close: %v", err)
	}
	sendBandwidthTestDatagram(t, client, 42, 1, "unbound UDP")
	for range 2 {
		select {
		case <-resolutions:
		case <-ctx.Done():
			t.Fatal("server did not check both TCP and UDP bindings")
		}
	}
	if err := listener.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.AcceptTCP()
	if err == nil {
		_ = connection.Close()
		t.Fatal("unbound client caused a SOCKS connection")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected SOCKS listener error: %v", err)
	}
}

func TestServerBandwidthUnrestrictedAuthenticatedTCP(t *testing.T) {
	const email, relayPassword = "unrestricted@example.test", "lifecycle-socks-password"
	relayAddr, cleanup := startMockSocks5Server(t, email, relayPassword)
	defer cleanup()
	newServer := func(inst Instance, relay *SocksRelay) (*Server, error) {
		client := inst.Clients[0]
		id := uuid.MustParse(client.UUID)
		return NewServerWithBandwidth(inst, relay, func(context.Context, string, int) error {
			t.Error("an unrestricted authenticated client reached the bandwidth gate")
			return errors.New("unexpected lease")
		}, func(candidate [16]byte, credential string) (string, bool) {
			return "", candidate == id && credential == client.Password
		})
	}
	_, client, _, _ := startLifecycleTestServerWithConstructor(t, &SocksRelay{Addr: relayAddr, Password: relayPassword}, email, newServer)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	connect := bytes.NewBuffer([]byte{ProtocolVersion, CmdConnect})
	if err := WriteAddress(connect, &Address{Type: AddrTypeIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 80}); err != nil {
		t.Fatal(err)
	}
	connect.WriteString("ping")
	if _, err := stream.Write(connect.Bytes()); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "ping" {
		t.Fatalf("unrestricted TCP echo = %q, %v", reply, err)
	}
}

func TestServerBandwidthDissociationCancelsUDPWait(t *testing.T) {
	for _, tc := range []struct {
		name        string
		blockCharge int32
	}{{"uplink", 1}, {"downlink", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			const email = "udp-bandwidth@example.test"
			const relayPassword = "lifecycle-socks-password"
			const blockedPayload = "blocked payload"
			relayAddr, cleanup := startMockSocks5Server(t, email, relayPassword)
			defer cleanup()
			waiting, canceled := make(chan struct{}), make(chan struct{})
			var charges atomic.Int32
			newServer := func(inst Instance, relay *SocksRelay) (*Server, error) {
				return NewServerWithBandwidth(inst, relay, func(ctx context.Context, _ string, n int) error {
					if n == len(blockedPayload) && charges.Add(1) == tc.blockCharge {
						close(waiting)
						<-ctx.Done()
						close(canceled)
						return ctx.Err()
					}
					return nil
				}, func([16]byte, string) (string, bool) { return "canonical-client", true })
			}
			_, client, _, _ := startLifecycleTestServerWithConstructor(t, &SocksRelay{
				Addr: relayAddr, Password: relayPassword,
			}, email, newServer)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			sendBandwidthTestDatagram(t, client, 42, 1, "warmup")
			readBandwidthTestDatagram(t, ctx, client, 42, "warmup")
			sendBandwidthTestDatagram(t, client, 42, 2, blockedPayload)
			select {
			case <-waiting:
			case <-ctx.Done():
				t.Fatal("packet never entered a bandwidth wait")
			}
			sendBandwidthTestDatagram(t, client, 43, 1, "independent association")
			readBandwidthTestDatagram(t, ctx, client, 43, "independent association")
			if err := client.SendDatagram([]byte{ProtocolVersion, CmdDissociate, 0, 42}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-canceled:
			case <-ctx.Done():
				t.Fatal("dissociation did not cancel the bandwidth wait")
			}
		})
	}
}

func sendBandwidthTestDatagram(t *testing.T, client *quic.Conn, assocID, packetID uint16, payload string) {
	t.Helper()
	var frame bytes.Buffer
	addr := &Address{Type: AddrTypeIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 53}
	if err := WritePacket(&frame, assocID, packetID, 1, 0, addr, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(frame.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func readBandwidthTestDatagram(t *testing.T, ctx context.Context, client *quic.Conn, assocID uint16, payload string) {
	t.Helper()
	datagram, err := client.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(datagram)
	if _, cmd, err := ReadCommand(reader); err != nil || cmd != CmdPacket {
		t.Fatalf("invalid UDP reply command: %d, %v", cmd, err)
	}
	header, err := ReadPacketHeader(reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readPacketPayload(reader, header)
	if err != nil || header.AssocID != assocID || string(got) != payload {
		t.Fatalf("unexpected UDP reply: association=%d payload=%q error=%v", header.AssocID, got, err)
	}
}
