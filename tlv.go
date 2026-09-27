package isis

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"
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
				yield(TLV{}, errors.New("isis: one octet remains, too few for a TLV header"))
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

// expect reports an error unless t carries the code point want.
func (t TLV) expect(want TLVType) error {
	if t.Type != want {
		return fmt.Errorf("isis: TLV is %s, not %s", t.Type, want)
	}

	return nil
}

// AreaAddressesTLV builds the area addresses TLV, code 1, described in
// ISO 10589 clause 9.5. An Instance sends it in every hello and in link
// state PDU fragment zero.
func AreaAddressesTLV(as []AreaAddress) (TLV, error) {
	var v []byte
	for _, a := range as {
		if a.n == 0 {
			return TLV{}, fmt.Errorf("isis: area address is empty")
		}

		v = append(v, a.n)
		v = append(v, a.octets[:a.n]...)
	}

	if len(v) > maxTLVValueLen {
		return TLV{}, fmt.Errorf("isis: %d area addresses need %d octets, over the wire's %d", len(as), len(v), maxTLVValueLen)
	}

	return TLV{
		Type:  TLVAreaAddresses,
		Value: v,
	}, nil
}

// AreaAddresses parses t, which must be the area addresses TLV, code 1.
func (t TLV) AreaAddresses() ([]AreaAddress, error) {
	if err := t.expect(TLVAreaAddresses); err != nil {
		return nil, err
	}

	var as []AreaAddress
	for b := t.Value; len(b) > 0; {
		n := int(b[0])
		if len(b)-1 < n {
			return nil, fmt.Errorf("isis: area address declares %d octets but %d remain", n, len(b)-1)
		}

		a, err := NewAreaAddress(b[1 : 1+n])
		if err != nil {
			return nil, err
		}

		as = append(as, a)
		b = b[1+n:]
	}

	return as, nil
}

// An NLPID is a network layer protocol identifier, from the IANA NLPID
// registry: what a protocols supported TLV lists. This package names only
// the NLPIDs it routes, but an NLPID it does not name is valid: it parses
// and re-encodes unchanged.
type NLPID uint8

// The NLPIDs of the protocols this package routes.
const (
	NLPIDIPv4 NLPID = 0xcc
	NLPIDIPv6 NLPID = 0x8e
)

// String returns the name of an NLPID.
func (n NLPID) String() string {
	switch n {
	case NLPIDIPv4:
		return "IPv4"
	case NLPIDIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("NLPID %#02x", uint8(n))
	}
}

// ProtocolsSupportedTLV builds the protocols supported TLV, code 129,
// described in RFC 1195 section 4.2. Section 5.2 requires it in every
// hello and in link state PDU fragment zero of an IP capable Instance.
func ProtocolsSupportedTLV(ps []NLPID) (TLV, error) {
	if len(ps) > maxTLVValueLen {
		return TLV{}, fmt.Errorf("isis: %d protocols are over the wire's %d", len(ps), maxTLVValueLen)
	}

	v := make([]byte, 0, len(ps))
	for _, p := range ps {
		v = append(v, uint8(p))
	}

	return TLV{
		Type:  TLVProtocolsSupported,
		Value: v,
	}, nil
}

// ProtocolsSupported parses t, which must be the protocols supported
// TLV, code 129.
func (t TLV) ProtocolsSupported() ([]NLPID, error) {
	if err := t.expect(TLVProtocolsSupported); err != nil {
		return nil, err
	}

	ps := make([]NLPID, 0, len(t.Value))
	for _, b := range t.Value {
		ps = append(ps, NLPID(b))
	}

	return ps, nil
}

// IPv4InterfaceAddressesTLV builds the IP interface address TLV, code
// 132, described in RFC 1195 section 4.2, which carries only IPv4
// addresses. RFC 3787 section 10 requires it in every hello so an
// implementation which checks the neighbor's addressing still forms the
// Adjacency.
func IPv4InterfaceAddressesTLV(addrs []netip.Addr) (TLV, error) {
	v := make([]byte, 0, 4*len(addrs))
	for _, a := range addrs {
		if !a.Is4() {
			return TLV{}, fmt.Errorf("isis: %s is not an IPv4 address", a)
		}

		v4 := a.As4()
		v = append(v, v4[:]...)
	}

	if len(v) > maxTLVValueLen {
		return TLV{}, fmt.Errorf("isis: %d IPv4 interface addresses need %d octets, over the wire's %d", len(addrs), len(v), maxTLVValueLen)
	}

	return TLV{
		Type:  TLVIPv4InterfaceAddresses,
		Value: v,
	}, nil
}

// IPv4InterfaceAddresses parses t, which must be the IP interface
// address TLV, code 132.
func (t TLV) IPv4InterfaceAddresses() ([]netip.Addr, error) {
	if err := t.expect(TLVIPv4InterfaceAddresses); err != nil {
		return nil, err
	}

	if len(t.Value)%4 != 0 {
		return nil, fmt.Errorf("isis: %s is %d octets, not a whole number of IPv4 addresses", t.Type, len(t.Value))
	}

	addrs := make([]netip.Addr, 0, len(t.Value)/4)
	for b := t.Value; len(b) > 0; b = b[4:] {
		addrs = append(addrs, netip.AddrFrom4([4]byte(b[:4])))
	}

	return addrs, nil
}

// IPv6InterfaceAddressesTLV builds the IPv6 interface address TLV, code
// 232, described in RFC 5308 section 3. A hello carries only the
// link-local addresses of the sending Circuit. An IPv4 mapped address is
// an error: unmap it and carry it in the IP interface address TLV.
func IPv6InterfaceAddressesTLV(addrs []netip.Addr) (TLV, error) {
	v := make([]byte, 0, 16*len(addrs))
	for _, a := range addrs {
		if a.Is4In6() {
			return TLV{}, fmt.Errorf("isis: %s is an IPv4 mapped address: unmap it and use the IPv4 interface address TLV", a)
		}

		if !a.Is6() {
			return TLV{}, fmt.Errorf("isis: %s is not an IPv6 address", a)
		}

		v6 := a.As16()
		v = append(v, v6[:]...)
	}

	if len(v) > maxTLVValueLen {
		return TLV{}, fmt.Errorf("isis: %d IPv6 interface addresses need %d octets, over the wire's %d", len(addrs), len(v), maxTLVValueLen)
	}

	return TLV{
		Type:  TLVIPv6InterfaceAddresses,
		Value: v,
	}, nil
}

// IPv6InterfaceAddresses parses t, which must be the IPv6 interface
// address TLV, code 232. An IPv4 mapped address is an error, as it is to
// IPv6InterfaceAddressesTLV, since IPv4 belongs in the IP interface
// address TLV.
func (t TLV) IPv6InterfaceAddresses() ([]netip.Addr, error) {
	if err := t.expect(TLVIPv6InterfaceAddresses); err != nil {
		return nil, err
	}

	if len(t.Value)%16 != 0 {
		return nil, fmt.Errorf("isis: %s is %d octets, not a whole number of IPv6 addresses", t.Type, len(t.Value))
	}

	addrs := make([]netip.Addr, 0, len(t.Value)/16)
	for b := t.Value; len(b) > 0; b = b[16:] {
		a := netip.AddrFrom16([16]byte(b[:16]))
		if a.Is4In6() {
			return nil, fmt.Errorf("isis: %s carries IPv4 mapped address %s", t.Type, a)
		}

		addrs = append(addrs, a)
	}

	return addrs, nil
}

// A ThreeWayState is one system's view of a point to point Adjacency, as
// carried in the three way adjacency TLV of RFC 5303 section 3.1. It is
// the sender's claim about the Adjacency, not the receiver's state. Its
// values are the wire encoding, so the zero ThreeWayState is ThreeWayUp.
type ThreeWayState uint8

// The three way states, in their wire encoding.
const (
	ThreeWayUp           ThreeWayState = 0
	ThreeWayInitializing ThreeWayState = 1
	ThreeWayDown         ThreeWayState = 2
)

// String returns the name of a ThreeWayState.
func (s ThreeWayState) String() string {
	switch s {
	case ThreeWayUp:
		return "Up"
	case ThreeWayInitializing:
		return "Initializing"
	case ThreeWayDown:
		return "Down"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// A ThreeWayAdjacency is the point to point three way adjacency TLV, code
// 240, described in RFC 5303 section 3.1. RFC 5303 requires it in every
// point to point hello from a system which implements the handshake.
//
// A sender omits the neighbor fields until it has heard the receiving
// system, so both are zero until then. A SystemID is never zero, so the
// zero NeighborSystemID is unambiguous: it means the neighbor fields are
// absent, never that they name a system.
type ThreeWayAdjacency struct {
	// State is the sender's view of the Adjacency. The zero State is
	// ThreeWayUp.
	State ThreeWayState

	// ExtendedLocalCircuitID identifies the sending Circuit, uniquely on
	// the sending system and for the life of that Circuit. A change to
	// it is how the receiver learns the sender restarted.
	ExtendedLocalCircuitID uint32

	// NeighborSystemID is the system the sender last heard on this
	// Circuit, or zero if it has heard none. The receiver treats a hello
	// which names some other system as evidence the Adjacency is not yet
	// two way.
	NeighborSystemID SystemID

	// NeighborExtendedLocalCircuitID is the ExtendedLocalCircuitID the
	// sender last heard from NeighborSystemID. It is zero when
	// NeighborSystemID is.
	NeighborExtendedLocalCircuitID uint32
}

// ThreeWayAdjacencyTLV builds the three way adjacency TLV, code 240. The
// neighbor fields are emitted only when NeighborSystemID is set, giving
// the 15 octet form RFC 5303 defines for a sender which has heard its
// neighbor and the 5 octet form for one which has not. A
// NeighborExtendedLocalCircuitID without a NeighborSystemID has no form to
// carry it and is an error.
func ThreeWayAdjacencyTLV(a ThreeWayAdjacency) (TLV, error) {
	if a.State > ThreeWayDown {
		return TLV{}, fmt.Errorf("isis: three way state %d does not exist", uint8(a.State))
	}

	if a.NeighborSystemID == (SystemID{}) && a.NeighborExtendedLocalCircuitID != 0 {
		return TLV{}, fmt.Errorf("isis: neighbor extended local circuit ID %d has no neighbor system ID", a.NeighborExtendedLocalCircuitID)
	}

	v := binary.BigEndian.AppendUint32([]byte{uint8(a.State)}, a.ExtendedLocalCircuitID)
	if a.NeighborSystemID != (SystemID{}) {
		v = append(v, a.NeighborSystemID[:]...)
		v = binary.BigEndian.AppendUint32(v, a.NeighborExtendedLocalCircuitID)
	}

	return TLV{
		Type:  TLVThreeWayAdjacency,
		Value: v,
	}, nil
}

// ThreeWayAdjacency parses t, which must be the three way adjacency TLV,
// code 240. RFC 5303 lets a sender omit the trailing fields it does not
// know, so the 1, 5, 11, and 15 octet forms all parse and an omitted
// field is zero. A neighbor system ID which is present but zero names no
// system and is an error, as FRR and holo both refuse a hello carrying
// one.
func (t TLV) ThreeWayAdjacency() (ThreeWayAdjacency, error) {
	if err := t.expect(TLVThreeWayAdjacency); err != nil {
		return ThreeWayAdjacency{}, err
	}

	b := t.Value
	switch len(b) {
	case 1, 5, 11, 15:
	default:
		return ThreeWayAdjacency{}, fmt.Errorf("isis: %s is %d octets, not 1, 5, 11, or 15", t.Type, len(b))
	}

	a := ThreeWayAdjacency{State: ThreeWayState(b[0])}
	if a.State > ThreeWayDown {
		return ThreeWayAdjacency{}, fmt.Errorf("isis: three way state %d does not exist", uint8(a.State))
	}

	if len(b) >= 5 {
		a.ExtendedLocalCircuitID = binary.BigEndian.Uint32(b[1:5])
	}

	if len(b) >= 11 {
		a.NeighborSystemID = SystemID(b[5:11])
		if a.NeighborSystemID == (SystemID{}) {
			return ThreeWayAdjacency{}, fmt.Errorf("isis: %s names the zero neighbor system ID", t.Type)
		}
	}

	if len(b) >= 15 {
		a.NeighborExtendedLocalCircuitID = binary.BigEndian.Uint32(b[11:15])
	}

	return a, nil
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
