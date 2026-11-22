package xraybandwidth

import (
	"context"
	"errors"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// A complete datagram fits in a 64 KiB grant. Large stream buffers must be
// delivered incrementally so each admission corresponds to a bounded write.
const maxChunkBytes = 64 * 1024

type gateWriter struct {
	ctx    context.Context
	cancel context.CancelFunc
	writer buf.Writer
	wait   Gate
	client string
	packet bool
}

func newWriter(ctx context.Context, writer buf.Writer, wait Gate, client string, packet bool) *gateWriter {
	ctx, cancel := context.WithCancel(ctx)
	return &gateWriter{ctx: ctx, cancel: cancel, writer: writer, wait: wait, client: client, packet: packet}
}

func (w *gateWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for len(mb) > 0 {
		chunk, rest, size, err := nextChunk(mb, w.packet)
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if err := admit(w.ctx, w.wait, w.client, size); err != nil {
			buf.ReleaseMulti(chunk)
			buf.ReleaseMulti(rest)
			return err
		}
		if err := w.writer.WriteMultiBuffer(chunk); err != nil {
			buf.ReleaseMulti(rest)
			return err
		}
		mb = rest
	}
	return nil
}

func (w *gateWriter) Close() error {
	w.cancel()
	return common.Close(w.writer)
}

func (w *gateWriter) Interrupt() {
	w.cancel()
	_ = common.Interrupt(w.writer)
}

type gateReader struct {
	ctx    context.Context
	cancel context.CancelFunc
	reader buf.Reader
	wait   Gate
	client string
	packet bool

	mu      sync.Mutex
	pending buf.MultiBuffer
	readErr error
}

func newReader(ctx context.Context, reader buf.Reader, wait Gate, client string, packet bool) *gateReader {
	ctx, cancel := context.WithCancel(ctx)
	return &gateReader{ctx: ctx, cancel: cancel, reader: reader, wait: wait, client: client, packet: packet}
}

func (r *gateReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	mb, readErr := r.pending, r.readErr
	r.pending, r.readErr = nil, nil
	r.mu.Unlock()
	if len(mb) == 0 {
		if err := r.ctx.Err(); err != nil {
			return nil, err
		}
		mb, readErr = r.reader.ReadMultiBuffer()
		if len(mb) == 0 {
			return mb, readErr
		}
	}

	chunk, rest, size, err := nextChunk(mb, r.packet)
	if err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	if err := admit(r.ctx, r.wait, r.client, size); err != nil {
		buf.ReleaseMulti(chunk)
		buf.ReleaseMulti(rest)
		return nil, err
	}
	if len(rest) != 0 {
		r.mu.Lock()
		if err := r.ctx.Err(); err != nil {
			r.mu.Unlock()
			buf.ReleaseMulti(chunk)
			buf.ReleaseMulti(rest)
			return nil, err
		}
		r.pending, r.readErr = rest, readErr
		r.mu.Unlock()
		readErr = nil
	}
	return chunk, readErr
}

func (r *gateReader) release() {
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	buf.ReleaseMulti(r.pending)
	r.pending, r.readErr = nil, nil
}

func (r *gateReader) Interrupt() {
	r.release()
	_ = common.Interrupt(r.reader)
}

func admit(ctx context.Context, wait Gate, client string, size int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if size != 0 {
		if err := wait(ctx, client, size); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// nextChunk transfers ownership of the leading buffers and returns the rest.
// The returned slices cannot append into each other's backing storage.
func nextChunk(mb buf.MultiBuffer, packet bool) (chunk, rest buf.MultiBuffer, size int, err error) {
	for i, current := range mb {
		n := int(current.Len())
		isPacket := packet || current != nil && current.UDP != nil
		if isPacket && i == 0 {
			if n > maxChunkBytes {
				return nil, mb, 0, errors.New("Xray datagram exceeds bandwidth grant size")
			}
			return mb[:1:1], mb[1:], n, nil
		}
		if isPacket || size+n > maxChunkBytes {
			if i != 0 {
				return mb[:i:i], mb[i:], size, nil
			}
			first := buf.NewWithSize(maxChunkBytes)
			_, _ = first.Write(current.BytesTo(maxChunkBytes))
			current.Advance(maxChunkBytes)
			return buf.MultiBuffer{first}, mb, maxChunkBytes, nil
		}
		size += n
	}
	return mb, nil, size, nil
}
