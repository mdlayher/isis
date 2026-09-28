package isis_test

import (
	"bytes"
	"net"
	"sync"

	"github.com/mdlayher/isis"
)

// memLinkFrames is how many frames each direction of an in-memory link
// buffers before a write is dropped.
const memLinkFrames = 64

// A memFrame is one PDU in flight over an in-memory link.
type memFrame struct {
	src isis.SNPA
	pdu []byte
}

// A memTransport is one end of an in-memory link. failRead injects the
// terminal fault of a real socket, failWrites a transient one, and drop
// silences the end, which is how a test runs a holding time out.
type memTransport struct {
	local   isis.SNPA
	in, out chan memFrame
	maxPDU  int
	errC    chan error
	done    chan struct{}
	once    sync.Once

	mu       sync.Mutex
	dropped  bool
	writeErr error
}

var _ isis.Transport = (*memTransport)(nil)

// memLink returns the two ends of an in-memory point to point link for
// synctest bubbles. Writes buffer generously and never block, as a packet
// socket effectively does not at test sizes, and a write beyond the buffer
// is dropped as a saturated link would drop it. Reads block on a channel,
// so a bubble sees them as durably blocked and fake time advances across
// them.
func memLink(a, b isis.SNPA, maxPDU int) (*memTransport, *memTransport) {
	ab := make(chan memFrame, memLinkFrames)
	ba := make(chan memFrame, memLinkFrames)

	return &memTransport{
			local:  a,
			in:     ba,
			out:    ab,
			maxPDU: maxPDU,
			errC:   make(chan error, 1),
			done:   make(chan struct{}),
		}, &memTransport{
			local:  b,
			in:     ab,
			out:    ba,
			maxPDU: maxPDU,
			errC:   make(chan error, 1),
			done:   make(chan struct{}),
		}
}

// reopen returns a fresh end on the same link, which is how a test
// restarts a Circuit over a Transport its predecessor closed.
func (t *memTransport) reopen() *memTransport {
	return &memTransport{
		local:  t.local,
		in:     t.in,
		out:    t.out,
		maxPDU: t.maxPDU,
		errC:   make(chan error, 1),
		done:   make(chan struct{}),
	}
}

func (t *memTransport) ReadPDU(b []byte) (int, isis.SNPA, error) {
	// A closed end reports it before any queued frame, as a closed socket
	// would. The second select can only find done ready if Close races it.
	select {
	case <-t.done:
		return 0, isis.SNPA{}, net.ErrClosed
	default:
	}

	select {
	case f := <-t.in:
		return copy(b, f.pdu), f.src, nil
	case err := <-t.errC:
		return 0, isis.SNPA{}, err
	case <-t.done:
		return 0, isis.SNPA{}, net.ErrClosed
	}
}

func (t *memTransport) WritePDU(_ isis.SNPA, b []byte) error { return t.writeFrom(t.local, b) }

// writeFrom sends b as though src had sent it, which is how a test
// reproduces the outgoing multicast a packet socket delivers back to
// itself.
func (t *memTransport) writeFrom(src isis.SNPA, b []byte) error {
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}

	t.mu.Lock()
	dropped, err := t.dropped, t.writeErr
	t.mu.Unlock()

	if err != nil {
		return err
	}

	if dropped {
		return nil
	}

	select {
	case t.out <- memFrame{src: src, pdu: bytes.Clone(b)}:
	default:
	}

	return nil
}

func (t *memTransport) MaxPDULen() int       { return t.maxPDU }
func (t *memTransport) LocalSNPA() isis.SNPA { return t.local }

// drop silences this end's transmissions.
func (t *memTransport) drop(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropped = v
}

// failWrites makes every later write return err, or succeed again when
// err is nil.
func (t *memTransport) failWrites(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeErr = err
}

// failRead makes a pending or future read return err.
func (t *memTransport) failRead(err error) { t.errC <- err }

func (t *memTransport) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}
