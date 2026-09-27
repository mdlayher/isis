package isis_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/mdlayher/isis"
	"golang.org/x/sync/errgroup"
)

// linkPDULength is the maximum PDU length of an in-memory link: a 1500
// octet Ethernet MTU less the 3 octet LLC header.
const linkPDULength = 1497

// The two ends of an in-memory link: locally administered SNPAs.
var (
	snpaA = isis.SNPA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	snpaB = isis.SNPA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}
)

// A PDU written on either end arrives whole at the other end's ReadPDU,
// reported with the writer's SNPA.
func TestTransportWriteReachesPeer(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		ab := memFrame{
			src: snpaA,
			pdu: []byte{0x83, 1, 2, 3},
		}
		if err := a.WritePDU(isis.AllISs(), ab.pdu); err != nil {
			t.Fatalf("failed to write from a: %v", err)
		}

		wantRead(t, b, ab)

		ba := memFrame{
			src: snpaB,
			pdu: []byte{0x83, 4, 5},
		}
		if err := b.WritePDU(isis.AllISs(), ba.pdu); err != nil {
			t.Fatalf("failed to write from b: %v", err)
		}

		wantRead(t, a, ba)
	})
}

// WritePDU copies b before returning, so a caller reusing its buffer for
// the next PDU never changes one already written.
func TestTransportWriteDoesNotRetain(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		buf := []byte{0x83, 1, 2, 3}
		if err := a.WritePDU(isis.AllISs(), buf); err != nil {
			t.Fatalf("failed to write from a: %v", err)
		}

		copy(buf, []byte{0x83, 4, 5, 6})

		want := memFrame{
			src: snpaA,
			pdu: []byte{0x83, 1, 2, 3},
		}
		wantRead(t, b, want)
	})
}

// Several goroutines write on both ends at once while each end reads,
// and every PDU arrives exactly once with its writer's SNPA. Run under
// the race detector, this proves the in-memory link is safe for
// concurrent use, as the Transport contract requires.
func TestTransportConcurrentUse(t *testing.T) {
	t.Parallel()

	// writers times frames stays within the link's buffer, so no write is
	// dropped however the goroutines are scheduled.
	const (
		writers = 4
		frames  = 8
	)

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		var (
			g        errgroup.Group
			atA, atB [][]byte
		)

		for _, tr := range []*memTransport{a, b} {
			for w := range writers {
				g.Go(func() error {
					for i := range frames {
						if err := tr.WritePDU(isis.AllISs(), []byte{0x83, byte(w), byte(i)}); err != nil {
							return err
						}
					}

					return nil
				})
			}
		}

		g.Go(func() (err error) {
			atA, err = readPDUs(a, snpaB, writers*frames)
			return err
		})

		g.Go(func() (err error) {
			atB, err = readPDUs(b, snpaA, writers*frames)
			return err
		})

		if err := g.Wait(); err != nil {
			t.Fatalf("failed to use the link concurrently: %v", err)
		}

		var want [][]byte
		for w := range writers {
			for i := range frames {
				want = append(want, []byte{0x83, byte(w), byte(i)})
			}
		}

		// Writers interleave, so compare in sorted order.
		slices.SortFunc(atA, bytes.Compare)
		slices.SortFunc(atB, bytes.Compare)

		if d := diff(t, want, atA); d != "" {
			t.Fatalf("unexpected PDUs at a (-want +got):\n%s", d)
		}

		if d := diff(t, want, atB); d != "" {
			t.Fatalf("unexpected PDUs at b (-want +got):\n%s", d)
		}
	})
}

// A ReadPDU durably blocked on an empty link returns once the end is
// closed or fails, with an error matching the cause.
func TestTransportPendingReadEnds(t *testing.T) {
	t.Parallel()

	errInjected := errors.New("injected read failure")

	tests := []struct {
		name string
		end  func(tr *memTransport)
		err  error
	}{
		{
			name: "Close",
			end:  func(tr *memTransport) { _ = tr.Close() },
			err:  net.ErrClosed,
		},
		{
			name: "failRead",
			end:  func(tr *memTransport) { tr.failRead(errInjected) },
			err:  errInjected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				a, _ := memLink(snpaA, snpaB, linkPDULength)

				var (
					g        errgroup.Group
					returned atomic.Bool
				)

				g.Go(func() error {
					defer returned.Store(true)
					_, _, err := a.ReadPDU(make([]byte, a.MaxPDULen()))
					return err
				})

				synctest.Wait()
				if returned.Load() {
					t.Fatal("read returned before the end was closed")
				}

				tt.end(a)

				if err := g.Wait(); !errors.Is(err, tt.err) {
					t.Fatalf("unexpected read error: %v", err)
				}
			})
		})
	}
}

// A closed end reports net.ErrClosed from ReadPDU even with a PDU
// queued for it, and from WritePDU, rather than carrying on as though
// open.
func TestTransportClosedEnd(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		if err := b.WritePDU(isis.AllISs(), []byte{0x83, 1}); err != nil {
			t.Fatalf("failed to write from b: %v", err)
		}

		if err := a.Close(); err != nil {
			t.Fatalf("failed to close a: %v", err)
		}

		if _, _, err := a.ReadPDU(make([]byte, a.MaxPDULen())); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected read error: %v", err)
		}

		if err := a.WritePDU(isis.AllISs(), []byte{0x83, 2}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected write error: %v", err)
		}
	})
}

// A silenced end's writes never arrive, while the other direction still
// carries, which is how a test runs one side's holding time out.
func TestTransportDropSilencesWrites(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		a.drop(true)
		if err := a.WritePDU(isis.AllISs(), []byte{0x83, 1}); err != nil {
			t.Fatalf("failed to write from a silenced end: %v", err)
		}

		ba := memFrame{
			src: snpaB,
			pdu: []byte{0x83, 2},
		}
		if err := b.WritePDU(isis.AllISs(), ba.pdu); err != nil {
			t.Fatalf("failed to write from b: %v", err)
		}

		wantRead(t, a, ba)

		// Once a speaks again, the next PDU b reads is the one written
		// after, so the silenced one was never queued.
		a.drop(false)
		ab := memFrame{
			src: snpaA,
			pdu: []byte{0x83, 3},
		}
		if err := a.WritePDU(isis.AllISs(), ab.pdu); err != nil {
			t.Fatalf("failed to write from a: %v", err)
		}

		wantRead(t, b, ab)
	})
}

// writeFrom delivers a frame carrying another SNPA, such as the reader's
// own, which is how a packet socket echoing outgoing multicast looks.
func TestTransportWriteFromEchoesOwnSNPA(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		echo := memFrame{
			src: a.LocalSNPA(),
			pdu: []byte{0x83, 1},
		}
		if err := b.writeFrom(echo.src, echo.pdu); err != nil {
			t.Fatalf("failed to write from b: %v", err)
		}

		wantRead(t, a, echo)
	})
}

// A reopened end replaces a closed one on the same link: it keeps the
// closed end's identity and receives what that end would have.
func TestTransportReopen(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)
		if err := b.Close(); err != nil {
			t.Fatalf("failed to close b: %v", err)
		}

		b2 := b.reopen()
		if got := b2.LocalSNPA(); got != snpaB {
			t.Fatalf("unexpected reopened SNPA: %v", got)
		}

		if got := b2.MaxPDULen(); got != linkPDULength {
			t.Fatalf("unexpected reopened maximum PDU length: %d", got)
		}

		ab := memFrame{
			src: snpaA,
			pdu: []byte{0x83, 1},
		}
		if err := a.WritePDU(isis.AllISs(), ab.pdu); err != nil {
			t.Fatalf("failed to write from a: %v", err)
		}

		wantRead(t, b2, ab)

		ba := memFrame{
			src: snpaB,
			pdu: []byte{0x83, 2},
		}
		if err := b2.WritePDU(isis.AllISs(), ba.pdu); err != nil {
			t.Fatalf("failed to write from the reopened end: %v", err)
		}

		wantRead(t, a, ba)
	})
}

// Each end reports the SNPA and maximum PDU length memLink was given.
func TestTransportReportsLink(t *testing.T) {
	t.Parallel()

	a, b := memLink(snpaA, snpaB, 1492)

	tests := []struct {
		name string
		tr   *memTransport
		snpa isis.SNPA
	}{
		{
			name: "a",
			tr:   a,
			snpa: snpaA,
		},
		{
			name: "b",
			tr:   b,
			snpa: snpaB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.tr.LocalSNPA(); got != tt.snpa {
				t.Fatalf("unexpected SNPA: %v", got)
			}

			if got := tt.tr.MaxPDULen(); got != 1492 {
				t.Fatalf("unexpected maximum PDU length: %d", got)
			}
		})
	}
}

// A write past the link's buffer is dropped rather than blocking the
// writer: in a bubble, a blocked write would fail the test as a deadlock.
func TestTransportWriteBeyondBufferDropped(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := memLink(snpaA, snpaB, linkPDULength)

		for i := range memLinkFrames + 1 {
			if err := a.WritePDU(isis.AllISs(), []byte{0x83, byte(i)}); err != nil {
				t.Fatalf("failed to write frame %d: %v", i, err)
			}
		}

		for i := range memLinkFrames {
			want := memFrame{
				src: snpaA,
				pdu: []byte{0x83, byte(i)},
			}
			wantRead(t, b, want)
		}

		// The link has drained, so the next PDU b reads is one written
		// now, never the one written past the buffer.
		after := memFrame{
			src: snpaA,
			pdu: []byte{0x83, 0xff},
		}
		if err := a.WritePDU(isis.AllISs(), after.pdu); err != nil {
			t.Fatalf("failed to write after draining: %v", err)
		}

		wantRead(t, b, after)
	})
}

// wantRead reads one PDU from tr and fails the test unless it came from
// want.src and carries exactly want.pdu. In a synctest bubble, a read with
// nothing queued fails the test as a deadlock rather than hanging it.
func wantRead(t *testing.T, tr *memTransport, want memFrame) {
	t.Helper()

	b := make([]byte, tr.MaxPDULen())
	n, got, err := tr.ReadPDU(b)
	if err != nil {
		t.Fatalf("failed to read PDU: %v", err)
	}

	if got != want.src {
		t.Fatalf("unexpected source SNPA: %v", got)
	}

	if d := diff(t, want.pdu, b[:n]); d != "" {
		t.Fatalf("unexpected PDU (-want +got):\n%s", d)
	}
}

// readPDUs reads n PDUs from tr and returns their octets, reporting an
// error if any came from an SNPA other than src.
func readPDUs(tr *memTransport, src isis.SNPA, n int) ([][]byte, error) {
	pdus := make([][]byte, 0, n)
	for range n {
		b := make([]byte, tr.MaxPDULen())
		m, got, err := tr.ReadPDU(b)
		if err != nil {
			return nil, err
		}

		if got != src {
			return nil, fmt.Errorf("unexpected source SNPA: %v", got)
		}

		pdus = append(pdus, b[:m])
	}

	return pdus, nil
}
