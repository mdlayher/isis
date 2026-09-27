package isis

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// A PointToPointHello is the point to point hello PDU, type 17, described
// in ISO 10589 clause 9.7. A point to point Circuit sends one every hello
// interval and every adjacency on it lives or dies by their arrival. RFC
// 5309 allows an Ethernet link to carry them.
type PointToPointHello struct {
	// Levels is the set of levels the sending Circuit runs: the wire's
	// circuit type field. It must name at least one level.
	Levels LevelSet

	// SourceID is the sending Instance's system identifier.
	SourceID SystemID

	// HoldingTime is how long a receiver keeps the adjacency alive
	// without a further hello. The wire carries whole seconds in 16 bits,
	// so it must be a whole number of seconds from 1 to 65535.
	HoldingTime time.Duration

	// LocalCircuitID is the sender's one octet identifier for the sending
	// Circuit. The extended local circuit ID of the three way adjacency
	// TLV supersedes it (RFC 5303 section 3.1).
	LocalCircuitID uint8

	// TLVs is the hello's variable length part, in wire order. Padding
	// TLVs a sender emitted appear here like any other; use PadTo to
	// generate them instead of building them by hand.
	TLVs []TLV

	// PadTo, when nonzero, pads the encoded hello to that many octets
	// with padding TLVs. ISO 10589 clause 8.2.3 pads so an adjacency
	// forms only between systems able to exchange PDUs of the link's full
	// size. A PadTo the two octet TLV header cannot reach exactly leaves
	// the hello one octet short of it.
	PadTo int
}

// AppendBinary implements encoding.BinaryAppender. Call it with a nil
// buffer for a standalone encoding; with a longer buffer, the PDU length
// field counts only the octets AppendBinary added.
func (h *PointToPointHello) AppendBinary(b []byte) ([]byte, error) {
	if h.Levels == 0 || h.Levels > Level1And2 {
		return nil, fmt.Errorf("isis: hello circuit type %d names no level", uint8(h.Levels))
	}

	if h.SourceID == (SystemID{}) {
		return nil, fmt.Errorf("isis: hello source system ID must be nonzero")
	}

	if h.HoldingTime <= 0 || h.HoldingTime%time.Second != 0 || h.HoldingTime/time.Second > math.MaxUint16 {
		return nil, fmt.Errorf("isis: holding time must be 1 to %d whole seconds: %s", math.MaxUint16, h.HoldingTime)
	}

	start := len(b)

	b, err := Header{Type: PDUPointToPointHello}.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	b = append(b, uint8(h.Levels))
	b = append(b, h.SourceID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(h.HoldingTime/time.Second))

	// The PDU length is not known until the TLVs and any padding are
	// encoded, so its two octets are reserved and filled in below.
	lengthOff := len(b)
	b = append(b, 0, 0, h.LocalCircuitID)

	for _, t := range h.TLVs {
		if b, err = t.AppendBinary(b); err != nil {
			return nil, err
		}
	}

	if h.PadTo > 0 {
		b = appendPadding(b, start+h.PadTo)
	}

	n := len(b) - start
	if n > math.MaxUint16 {
		return nil, fmt.Errorf("isis: hello is %d octets, over the wire's %d", n, math.MaxUint16)
	}

	binary.BigEndian.PutUint16(b[lengthOff:], uint16(n))
	return b, nil
}

// ParsePointToPointHello parses a point to point hello from b, which must
// begin with exactly one whole PDU, as received from the link. Octets past
// the PDU length field are ignored: an Ethernet frame below the medium's
// minimum size arrives padded, and the padding is not part of the PDU.
//
// Every octet of the variable length part must belong to a TLV, and their
// values alias b. A TLV this package does not model is returned like any
// other, since RFC 8918 section 3.1 requires it be ignored rather than
// reject the hello.
func ParsePointToPointHello(b []byte) (*PointToPointHello, error) {
	hdr, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}

	if hdr.Type != PDUPointToPointHello {
		return nil, fmt.Errorf("isis: PDU is a %s, not a %s", hdr.Type, PDUPointToPointHello)
	}

	n, err := pduLength(hdr.Type, b)
	if err != nil {
		return nil, err
	}

	h := &PointToPointHello{
		Levels:         LevelSet(b[8] & 0x03),
		SourceID:       SystemID(b[9:15]),
		HoldingTime:    time.Duration(binary.BigEndian.Uint16(b[15:17])) * time.Second,
		LocalCircuitID: b[19],
	}

	if h.Levels == 0 {
		return nil, fmt.Errorf("isis: hello circuit type %d names no level", b[8])
	}

	if h.SourceID == (SystemID{}) {
		return nil, fmt.Errorf("isis: hello source system ID must be nonzero")
	}

	if h.HoldingTime == 0 {
		return nil, fmt.Errorf("isis: hello holding time must be nonzero")
	}

	// The first walk validates and counts, so the slice is allocated once.
	// A hello without TLVs leaves it nil.
	tlvs := b[hdr.Type.fixedHeaderLen():n]

	var count int
	for _, err := range TLVs(tlvs) {
		if err != nil {
			return nil, err
		}

		count++
	}

	if count > 0 {
		h.TLVs = make([]TLV, 0, count)
		for tlv := range TLVs(tlvs) {
			h.TLVs = append(h.TLVs, tlv)
		}
	}

	return h, nil
}
