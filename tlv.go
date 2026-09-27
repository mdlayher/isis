package isis

import (
	"fmt"
	"iter"
)

// maxTLVValueLen is the longest value a TLV can carry: its length field
// is one octet.
const maxTLVValueLen = 255

// A TLVType is the code point of a TLV, from the IANA IS-IS TLV
// Codepoints registry.
type TLVType uint8

// The TLV code points this package names: those an IPv4 and IPv6 IGP
// with wide metrics and multi-topology carries in its hellos, link state
// PDUs, and sequence numbers PDUs. Naming a code point is not the same as
// modeling its value: every code point without a typed accessor is
// walked past, since RFC 8918 section 3.1 requires that a disallowed or
// unrecognised TLV be ignored rather than reject the PDU carrying it.
const (
	TLVAreaAddresses                TLVType = 1
	TLVLANNeighbors                 TLVType = 6
	TLVPadding                      TLVType = 8
	TLVLSPEntries                   TLVType = 9
	TLVAuthentication               TLVType = 10
	TLVExtendedISReachability       TLVType = 22
	TLVProtocolsSupported           TLVType = 129
	TLVIPv4InterfaceAddresses       TLVType = 132
	TLVExtendedIPReachability       TLVType = 135
	TLVDynamicHostname              TLVType = 137
	TLVMTISReachability             TLVType = 222
	TLVMultiTopology                TLVType = 229
	TLVIPv6InterfaceAddresses       TLVType = 232
	TLVIPv6GlobalInterfaceAddresses TLVType = 233
	TLVMTIPv4Reachability           TLVType = 235
	TLVIPv6Reachability             TLVType = 236
	TLVMTIPv6Reachability           TLVType = 237
	TLVThreeWayAdjacency            TLVType = 240
)

// String returns the registry name of a TLVType, or its code point when
// this package does not name it.
func (t TLVType) String() string {
	switch t {
	case TLVAreaAddresses:
		return "Area Addresses"
	case TLVLANNeighbors:
		return "LAN Neighbors"
	case TLVPadding:
		return "Padding"
	case TLVLSPEntries:
		return "LSP Entries"
	case TLVAuthentication:
		return "Authentication"
	case TLVExtendedISReachability:
		return "Extended IS Reachability"
	case TLVProtocolsSupported:
		return "Protocols Supported"
	case TLVIPv4InterfaceAddresses:
		return "IP Interface Address"
	case TLVExtendedIPReachability:
		return "Extended IP Reachability"
	case TLVDynamicHostname:
		return "Dynamic Hostname"
	case TLVMTISReachability:
		return "MT Intermediate Systems"
	case TLVMultiTopology:
		return "Multi-Topology"
	case TLVIPv6InterfaceAddresses:
		return "IPv6 Interface Address"
	case TLVIPv6GlobalInterfaceAddresses:
		return "IPv6 Global Interface Address"
	case TLVMTIPv4Reachability:
		return "MT IPv4 Reachability"
	case TLVIPv6Reachability:
		return "IPv6 Reachability"
	case TLVMTIPv6Reachability:
		return "MT IPv6 Reachability"
	case TLVThreeWayAdjacency:
		return "Point-to-Point Three-Way Adjacency"
	default:
		return fmt.Sprintf("TLV %d", uint8(t))
	}
}

// A TLV is one element of a PDU's variable length part, as described in
// ISO 10589 clause 9.1: a one octet type, a one octet length, and up to
// 255 octets of value.
type TLV struct {
	// Type is the TLV's code point.
	Type TLVType

	// Value is the TLV's value. A TLV from TLVs aliases the PDU it was
	// parsed from, so copy Value to retain it past that PDU's lifetime.
	Value []byte
}

// AppendBinary implements encoding.BinaryAppender. Call it with a nil
// buffer for a standalone encoding.
func (t TLV) AppendBinary(b []byte) ([]byte, error) {
	if n := len(t.Value); n > maxTLVValueLen {
		return nil, fmt.Errorf("isis: %s value is %d octets, over the wire's %d", t.Type, n, maxTLVValueLen)
	}

	b = append(b, uint8(t.Type), uint8(len(t.Value)))
	return append(b, t.Value...), nil
}

// TLVs returns an iterator over the TLVs packed into b, which is a PDU's
// variable length part. Every octet of b must belong to a TLV: a b which
// ends part way through one yields a zero TLV with a non-nil error, once,
// and the iteration stops. Values alias b, with their capacity capped at
// their length, so an append to one copies it rather than overwriting the
// TLV which follows.
//
// The iterator is the whole of the walk. A TLV whose code point this
// package does not name is yielded like any other, since RFC 8918 section
// 3.1 requires it be ignored rather than reject the PDU.
func TLVs(b []byte) iter.Seq2[TLV, error] {
	return func(yield func(TLV, error) bool) {
		for len(b) > 0 {
			if len(b) < 2 {
				yield(TLV{}, fmt.Errorf("isis: %d octets remain, too few for a TLV header", len(b)))
				return
			}

			t := TLV{Type: TLVType(b[0])}
			n := int(b[1])
			if len(b)-2 < n {
				yield(TLV{}, fmt.Errorf("isis: %s declares %d octets but %d remain", t.Type, n, len(b)-2))
				return
			}

			t.Value = b[2 : 2+n : 2+n]
			if !yield(t, nil) {
				return
			}

			b = b[2+n:]
		}
	}
}

// appendPadding appends padding TLVs, code 8, to b until it is n octets
// long. ISO 10589 clause 8.2.3 pads a hello so an Adjacency forms only
// between systems able to exchange PDUs of the link's full size, and RFC
// 3719 section 6 makes the padding unobservable to the receiver: "The
// presence or absence of padding TLVs MUST NOT be one of the acceptance
// tests applied to a received IIH."
//
// A target one octet beyond what a two octet TLV header can reach leaves
// b one octet short, which is how FRR's own add_padding behaves.
func appendPadding(b []byte, n int) []byte {
	for n-len(b) >= 2 {
		v := min(n-len(b)-2, maxTLVValueLen)
		b = append(b, uint8(TLVPadding), uint8(v))
		b = append(b, make([]byte, v)...)
	}

	return b
}
