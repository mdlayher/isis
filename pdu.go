package isis

import (
	"encoding/binary"
	"fmt"
)

const (
	// discriminator is the intradomain routeing protocol discriminator,
	// the first octet of every IS-IS PDU. IANA assigns 0x83 to IS-IS in
	// its NLPID registry.
	discriminator = 0x83

	// headerLen is the length of the common fixed header every IS-IS PDU
	// begins with (ISO 10589 clause 9.5).
	headerLen = 8

	// protocolIDExtension and protocolVersion are the two version octets
	// of the common header. ISO 10589 fixes both at 1.
	protocolIDExtension = 1
	protocolVersion     = 1

	// idLength is the ID length octet a Header encodes. Zero means six,
	// the only system identifier length ISO 10589 deployments use.
	idLength = 0

	// maxAreaAddresses is how many area addresses an area may hold at
	// once, fixed at the ISO 10589 default. The octet carrying it is sent
	// as zero, which means three.
	maxAreaAddresses = 3
)

// A PDUType is the type of an IS-IS PDU, as assigned in ISO 10589 clause
// 9.4.
type PDUType uint8

// The PDU types.
const (
	PDUL1LANHello         PDUType = 15
	PDUL2LANHello         PDUType = 16
	PDUPointToPointHello  PDUType = 17
	PDUL1LinkState        PDUType = 18
	PDUL2LinkState        PDUType = 20
	PDUL1CompleteSequence PDUType = 24
	PDUL2CompleteSequence PDUType = 25
	PDUL1PartialSequence  PDUType = 26
	PDUL2PartialSequence  PDUType = 27
)

// String returns the name of a PDUType.
func (t PDUType) String() string {
	switch t {
	case PDUL1LANHello:
		return "Level 1 LAN hello"
	case PDUL2LANHello:
		return "Level 2 LAN hello"
	case PDUPointToPointHello:
		return "point to point hello"
	case PDUL1LinkState:
		return "Level 1 link state"
	case PDUL2LinkState:
		return "Level 2 link state"
	case PDUL1CompleteSequence:
		return "Level 1 complete sequence numbers"
	case PDUL2CompleteSequence:
		return "Level 2 complete sequence numbers"
	case PDUL1PartialSequence:
		return "Level 1 partial sequence numbers"
	case PDUL2PartialSequence:
		return "Level 2 partial sequence numbers"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}

// fixedHeaderLen returns the length of a PDU of this type's whole fixed
// header, the common part of ISO 10589 clause 9.5 and the type specific
// part together, or zero when the type does not exist.
func (t PDUType) fixedHeaderLen() int {
	switch t {
	case PDUL1LANHello, PDUL2LANHello:
		return 27
	case PDUPointToPointHello:
		return 20
	case PDUL1LinkState, PDUL2LinkState:
		return 27
	case PDUL1CompleteSequence, PDUL2CompleteSequence:
		return 33
	case PDUL1PartialSequence, PDUL2PartialSequence:
		return 17
	default:
		return 0
	}
}

// pduLength returns the PDU length field of b, one PDU of type t whose
// header has parsed, checked against its fixed header and the octets
// received. The field sits after the source ID in a hello and straight
// after the common header in every other PDU (ISO 10589 clauses 9.6 to
// 9.12).
func pduLength(t PDUType, b []byte) (int, error) {
	off := headerLen
	switch t {
	case PDUL1LANHello, PDUL2LANHello, PDUPointToPointHello:
		off = 17
	}

	n := int(binary.BigEndian.Uint16(b[off:]))
	if n < t.fixedHeaderLen() || n > len(b) {
		return 0, fmt.Errorf("isis: %s PDU length %d is outside its %d octet header and the %d octets received", t, n, t.fixedHeaderLen(), len(b))
	}

	return n, nil
}

// A Header is the common fixed header every IS-IS PDU begins with, as
// described in ISO 10589 clause 9.5. The type specific header follows it
// and LengthIndicator covers both.
//
// Maximum area addresses is fixed at three, the ISO 10589 default.
type Header struct {
	// Type is the PDU type.
	Type PDUType

	// LengthIndicator is the length in octets of the PDU's whole fixed
	// header. It is fixed by Type, so a Header which parses always
	// carries the length Type requires.
	LengthIndicator uint8
}

// AppendBinary implements encoding.BinaryAppender. LengthIndicator is
// written from Type, so a zero value there is filled in rather than
// rejected. Call AppendBinary with a nil buffer for a standalone
// encoding.
func (h Header) AppendBinary(b []byte) ([]byte, error) {
	n := h.Type.fixedHeaderLen()
	if n == 0 {
		return nil, fmt.Errorf("isis: PDU type %d does not exist", uint8(h.Type))
	}

	if h.LengthIndicator != 0 && int(h.LengthIndicator) != n {
		return nil, fmt.Errorf("isis: a %s header is %d octets, not the %d given", h.Type, n, h.LengthIndicator)
	}

	return append(
		b,
		discriminator,
		uint8(n),
		protocolIDExtension,
		idLength,
		uint8(h.Type),
		protocolVersion,
		0, // Reserved.
		0, // Maximum area addresses: zero means three.
	), nil
}

// ParseHeader parses the common fixed header at the start of b, which may
// hold the rest of the PDU after it.
//
// The validation rules of ISO 10589, clause 9.5 are applied:
//
//   - the discriminator must be 0x83
//   - the version/protocol ID extension and the version must be 1
//   - the ID length must be 0 or 6
//   - the PDU type must exist, and the length indicator must match it
//   - b must hold at least the whole fixed header the type requires
//   - the maximum area addresses must be 0 or 3
//
// Reserved bits are ignored.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, fmt.Errorf("isis: PDU is %d octets, too short for its %d octet common header", len(b), headerLen)
	}

	if b[0] != discriminator {
		return Header{}, fmt.Errorf("isis: PDU discriminator is %#02x, not %#02x", b[0], discriminator)
	}

	if b[2] != protocolIDExtension {
		return Header{}, fmt.Errorf("isis: unsupported version/protocol ID extension %d", b[2])
	}

	// Zero means six, which is the only length this package implements.
	if b[3] != 0 && b[3] != 6 {
		return Header{}, fmt.Errorf("isis: unsupported ID length %d", b[3])
	}

	if b[5] != protocolVersion {
		return Header{}, fmt.Errorf("isis: unsupported version %d", b[5])
	}

	// The three high bits of the type octet and the whole of octet six
	// are reserved: transmitted as zero and ignored on receipt.
	h := Header{
		Type:            PDUType(b[4] & 0x1f),
		LengthIndicator: b[1],
	}

	n := h.Type.fixedHeaderLen()
	if n == 0 {
		return Header{}, fmt.Errorf("isis: PDU type %d does not exist", uint8(h.Type))
	}

	if int(h.LengthIndicator) != n {
		return Header{}, fmt.Errorf("isis: a %s header is %d octets, not the %d the length indicator claims", h.Type, n, h.LengthIndicator)
	}

	if len(b) < n {
		return Header{}, fmt.Errorf("isis: %s PDU is %d octets, too short for its %d octet header", h.Type, len(b), n)
	}

	if b[7] != 0 && b[7] != maxAreaAddresses {
		return Header{}, fmt.Errorf("isis: maximum area addresses %d does not match the %d this package permits", b[7], maxAreaAddresses)
	}

	return h, nil
}
