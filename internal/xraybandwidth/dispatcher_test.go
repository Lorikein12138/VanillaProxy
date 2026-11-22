package xraybandwidth

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type testDispatcher struct {
	routing.Dispatcher
	dispatch     func(context.Context, net.Destination) (*transport.Link, error)
	dispatchLink func(context.Context, net.Destination, *transport.Link) error
}

func (d testDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.dispatch(ctx, dest)
}

func (d testDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return d.dispatchLink(ctx, dest, link)
}

type writerFunc func(buf.MultiBuffer) error

func (f writerFunc) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return f(mb)
}

type readerFunc func() (buf.MultiBuffer, error)

func (f readerFunc) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return f()
}

func testBuffer(n int) *buf.Buffer {
	b := buf.NewWithSize(int32(n))
	b.Extend(int32(n))
	return b
}

func TestManagedDispatchUsesOneGateInBothDirections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	inbound := &session.Inbound{
		User:          &protocol.MemoryUser{Email: "credential"},
		CanSpliceCopy: 2,
	}
	ctx = session.ContextWithInbound(ctx, inbound)
	dest := net.TCPDestination(net.DomainAddress("example.test"), 443)
	done := make(chan error, 1)
	base := testDispatcher{
		dispatchLink: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
			mb, err := link.Reader.ReadMultiBuffer()
			if err == nil {
				buf.ReleaseMulti(mb)
				err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{testBuffer(3)})
			}
			done <- err
			_ = common.Close(link.Writer)
			return err
		},
	}
	var mu sync.Mutex
	var charges []int
	wrapped, err := Wrap(base, func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user != inbound.User {
			t.Fatal("resolver did not receive the authenticated user")
		}
		return "account", true, nil
	}, func(ctx context.Context, client string, n int) error {
		if client != "account" {
			return errors.New("incorrect account key")
		}
		mu.Lock()
		charges = append(charges, n)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	link, err := wrapped.Dispatch(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := link.Reader.(*pipe.Reader)
	if !ok {
		t.Fatalf("reader type is %T", link.Reader)
	}
	if inbound.CanSpliceCopy != 3 {
		t.Fatal("managed session could splice around the gate")
	}
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{testBuffer(5)}); err != nil {
		t.Fatal(err)
	}
	_ = common.Close(link.Writer)
	mb, err := reader.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(charges) != 2 || charges[0] != 5 || charges[1] != 3 {
		t.Fatalf("charges %v, want [5 3]", charges)
	}
}

func TestManagedDispatchLinkPreservesDatagramsAndSharedAccount(t *testing.T) {
	dest := net.UDPDestination(net.DomainAddress("example.test"), 443)
	base := testDispatcher{
		dispatchLink: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
			for i := 0; i < 2; i++ {
				mb, err := link.Reader.ReadMultiBuffer()
				if err != nil {
					return err
				}
				if err := link.Writer.WriteMultiBuffer(mb); err != nil {
					return err
				}
			}
			return nil
		},
	}
	var charges []int
	wrapped, err := Wrap(base, func(ctx context.Context, user *protocol.MemoryUser) (string, bool, error) {
		if user == nil || user.Email == "" {
			return "", false, errors.New("missing credential")
		}
		return "account", true, nil
	}, func(ctx context.Context, client string, n int) error {
		if client != "account" {
			return errors.New("incorrect account key")
		}
		charges = append(charges, n)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"credential-a", "credential-b"} {
		first, second := testBuffer(7), testBuffer(11)
		first.UDP, second.UDP = &dest, &dest
		var index int
		link := &transport.Link{
			Reader: readerFunc(func() (buf.MultiBuffer, error) {
				return buf.MultiBuffer{first, second}, nil
			}),
			Writer: writerFunc(func(mb buf.MultiBuffer) error {
				defer buf.ReleaseMulti(mb)
				if len(mb) != 1 || mb[0] != []*buf.Buffer{first, second}[index] || mb[0].UDP != &dest {
					t.Fatalf("unexpected packet %d", index)
				}
				index++
				return nil
			}),
		}
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: credential}})
		if err := wrapped.DispatchLink(ctx, dest, link); err != nil {
			t.Fatal(err)
		}
		if index != 2 {
			t.Fatalf("forwarded %d packets, want 2", index)
		}
	}
	want := []int{7, 7, 11, 11, 7, 7, 11, 11}
	if len(charges) != len(want) {
		t.Fatalf("charges %v, want %v", charges, want)
	}
	for i := range charges {
		if charges[i] != want[i] {
			t.Fatalf("charges %v, want %v", charges, want)
		}
	}
}

func TestUnmanagedDispatchIsUnchanged(t *testing.T) {
	baseLink := new(transport.Link)
	called := false
	base := testDispatcher{
		dispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			called = true
			return baseLink, nil
		},
	}
	wrapped, err := Wrap(base, func(context.Context, *protocol.MemoryUser) (string, bool, error) {
		return "", false, nil
	}, func(context.Context, string, int) error {
		t.Fatal("unmanaged route used the gate")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapped.Dispatch(context.Background(), net.Destination{})
	if err != nil || got != baseLink || !called {
		t.Fatalf("unmanaged route did not delegate: %v %v", got, err)
	}
}

func TestChunkLimitAndCancelledWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var charges, writes []int
	writer := newWriter(ctx, writerFunc(func(mb buf.MultiBuffer) error {
		writes = append(writes, int(mb.Len()))
		buf.ReleaseMulti(mb)
		return nil
	}), func(ctx context.Context, client string, n int) error {
		charges = append(charges, n)
		return nil
	}, "account", false)
	defer writer.Close()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{testBuffer(maxChunkBytes + 13)}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{testBuffer(1)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write error %v, want context.Canceled", err)
	}
	if len(charges) != 2 || charges[0] != maxChunkBytes || charges[1] != 13 ||
		len(writes) != 2 || writes[0] != maxChunkBytes || writes[1] != 13 {
		t.Fatalf("charges %v, writes %v", charges, writes)
	}
}

func TestReaderReturnsFinalDataAndError(t *testing.T) {
	reader := newReader(context.Background(), readerFunc(func() (buf.MultiBuffer, error) {
		return buf.MultiBuffer{testBuffer(maxChunkBytes + 5)}, io.EOF
	}), func(context.Context, string, int) error { return nil }, "account", false)
	defer reader.release()
	for _, expected := range []struct {
		size int
		err  error
	}{{maxChunkBytes, nil}, {5, io.EOF}} {
		mb, err := reader.ReadMultiBuffer()
		size := int(mb.Len())
		buf.ReleaseMulti(mb)
		if size != expected.size || err != expected.err {
			t.Fatalf("got size %d and error %v, want %d and %v", size, err, expected.size, expected.err)
		}
	}
}
