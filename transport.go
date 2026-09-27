package isis

import "errors"

// A Transport carries IS-IS PDUs between one Circuit and the link it
// attaches to. This package implements one for Ethernet with a Linux
// AF_PACKET socket.
//
// Framing belongs to the implementation: the LLC header, the 802.3 length
// field, multicast memberships, and filtering a Circuit's own
// transmissions out of its reads.
//
// A Transport must be safe for concurrent use by multiple goroutines.
type Transport interface {
	// ReadPDU blocks until a PDU arrives, then fills b with exactly one
	// whole PDU and reports the neighbor's SNPA. An Instance learns of
	// transport death only through ReadPDU: any error not wrapping
	// ErrDropped is terminal. ReadPDU must not retain b after returning.
	ReadPDU(b []byte) (n int, src SNPA, err error)

	// WritePDU sends one PDU to dst, best effort: an error is never
	// terminal, since IS-IS recovers through the next hello. WritePDU must
	// not retain b after returning.
	WritePDU(dst SNPA, b []byte) error

	// MaxPDULen reports how many PDU octets the link carries, which is
	// the interface MTU less any framing the Transport adds. A Circuit
	// sizes its receive buffer and pads its hellos from it, so it must
	// account for the largest PDU the link can deliver. A link which will
	// carry link state PDUs must report at least 1492, ISO 10589's
	// ReceiveLSPBufferSize.
	MaxPDULen() int

	// LocalSNPA reports this end's own link layer address, which a
	// Circuit uses to drop its own transmissions delivered back to it.
	LocalSNPA() SNPA

	// Close unblocks a pending ReadPDU, which then returns an error. It is
	// called concurrently with a pending ReadPDU so an Instance can always
	// tear down.
	Close() error
}

// ErrDropped reports a frame a Transport received and discarded, such as
// one which failed its filtering. A ReadPDU error wrapping ErrDropped is
// not terminal: the caller reads again. ReadPDU still blocks for a frame
// before reporting a drop, never returning ErrDropped for an empty read,
// and the count returned beside it is ignored. Wrap ErrDropped with the
// reason, as in fmt.Errorf("%w: LLC header 0xaaaa03", ErrDropped).
var ErrDropped = errors.New("isis: frame dropped")
