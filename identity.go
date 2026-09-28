package isis

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// A SystemID is the six octet identifier of one instance, unique within
// the routing domain. It is not an address and is not derived from one.
type SystemID [6]byte

// String returns the conventional encoding of a SystemID: three groups of
// two octets in hexadecimal, separated by periods, as in
// "0000.0000.0001".
func (s SystemID) String() string {
	return fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x", s[0], s[1], s[2], s[3], s[4], s[5])
}

// An LSPID identifies one link state PDU: the SystemID of the instance
// which originated it, the pseudonode octet naming a broadcast circuit's
// Pseudonode or zero for the instance itself, and the fragment number.
type LSPID struct {
	// SystemID is the originating instance.
	SystemID SystemID

	// Pseudonode names one of the originator's broadcast circuits, or is
	// zero for the originator itself.
	Pseudonode uint8

	// Fragment numbers the fragments sharing one origin.
	Fragment uint8
}

// String returns the conventional encoding of an LSPID: the SystemID, the
// pseudonode octet, then the fragment number, as in
// "0000.0000.0001.00-00".
func (l LSPID) String() string {
	return fmt.Sprintf("%s.%02x-%02x", l.SystemID, l.Pseudonode, l.Fragment)
}

// An SNPA, a subnetwork point of attachment, is a neighbor's link layer
// address on a Circuit: the destination a Circuit puts on a frame.
// IS-IS over Ethernet, including the RFC 5309 point to point form,
// addresses frames by six octet link layer address, so an SNPA is six
// octets.
type SNPA [6]byte

// String returns the SNPA as colon separated hexadecimal octets, as in
// "01:80:c2:00:00:14".
func (s SNPA) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", s[0], s[1], s[2], s[3], s[4], s[5])
}

// AllL1ISs returns the ISO 10589 clause 8.4.8 multicast destination
// 01:80:c2:00:00:14, which carries Level 1 traffic on a broadcast Circuit.
func AllL1ISs() SNPA { return SNPA{0x01, 0x80, 0xc2, 0x00, 0x00, 0x14} }

// AllL2ISs returns the ISO 10589 clause 8.4.8 multicast destination
// 01:80:c2:00:00:15, which carries Level 2 traffic on a broadcast Circuit.
func AllL2ISs() SNPA { return SNPA{0x01, 0x80, 0xc2, 0x00, 0x00, 0x15} }

// AllISs returns the ISO 10589 clause 8.4.8 multicast destination
// 09:00:2b:00:00:05, which carries every PDU on a point to point Circuit
// over a LAN, as RFC 5309 section 4.1 recommends.
func AllISs() SNPA { return SNPA{0x09, 0x00, 0x2b, 0x00, 0x00, 0x05} }

// A Level is one of the two IS-IS routing hierarchies. Level 1 routes
// within an area and Level 2 between areas.
type Level uint8

// The levels, valued as the bit each occupies in a LevelSet.
const (
	Level1 Level = 1
	Level2 Level = 2
)

// String returns the name of a Level.
func (l Level) String() string {
	switch l {
	case Level1:
		return "Level 1"
	case Level2:
		return "Level 2"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(l))
	}
}

// A LevelSet is a set of Levels: the wire encoding of a hello's circuit
// type field and of a link state PDU's IS type field. Level 1 is bit zero
// and Level 2 is bit one, so a Circuit running both encodes as 3. Zero
// means neither, which the wire reserves and no Circuit may use.
type LevelSet uint8

// The LevelSet values ISO 10589 clause 9.5 assigns to the circuit type
// field.
const (
	Level1Only LevelSet = 0b01
	Level2Only LevelSet = 0b10
	Level1And2 LevelSet = 0b11
)

// Has reports whether s contains l.
func (s LevelSet) Has(l Level) bool { return s&LevelSet(l) != 0 }

// String returns the name of a LevelSet.
func (s LevelSet) String() string {
	switch s {
	case 0:
		return "no levels"
	case Level1Only:
		return "Level 1 only"
	case Level2Only:
		return "Level 2 only"
	case Level1And2:
		return "Level 1 and 2"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// A Topology is one RFC 5120 multi-topology identifier, twelve bits on
// the wire. Each Topology has its own reachability TLVs and its own
// computed result.
type Topology uint16

// The reserved topology identifiers this package names, from RFC 5120
// section 7.5. TopologyStandard carries IPv4 unicast and is the topology
// a neighbor which sends no multi-topology TLV participates in.
const (
	TopologyStandard    Topology = 0
	TopologyIPv6Unicast Topology = 2
)

// String returns the name of a Topology.
func (t Topology) String() string {
	switch t {
	case TopologyStandard:
		return "standard"
	case TopologyIPv6Unicast:
		return "IPv6 unicast"
	default:
		return fmt.Sprintf("MT %d", uint16(t))
	}
}

const (
	// maxNSAPLen is the longest network service access point address ISO
	// 8348 defines, and so the longest network entity title.
	maxNSAPLen = 20

	// maxAreaAddressLen is the longest area address a TLV can carry: an
	// area address is the leading part of an NSAP.
	maxAreaAddressLen = maxNSAPLen
)

// An AreaAddress is the variable length prefix of an instance's NSAP
// which names its area. A Level 1 adjacency requires one in common and a
// Level 2 adjacency does not. It is comparable by value, so it serves as
// a map key.
type AreaAddress struct {
	n      uint8
	octets [maxAreaAddressLen]byte
}

// NewAreaAddress produces an AreaAddress from b, which must be 1 to 20
// octets. It copies b.
func NewAreaAddress(b []byte) (AreaAddress, error) {
	if n := len(b); n < 1 || n > maxAreaAddressLen {
		return AreaAddress{}, fmt.Errorf("isis: area address must be 1 to %d octets: %d octets", maxAreaAddressLen, n)
	}

	a := AreaAddress{n: uint8(len(b))}
	copy(a.octets[:], b)
	return a, nil
}

// String returns the conventional encoding of an AreaAddress: the first
// octet, then pairs of octets, separated by periods, as in "49.0001".
func (a AreaAddress) String() string {
	var sb strings.Builder
	for i, o := range a.octets[:a.n] {
		fmt.Fprintf(&sb, "%02x", o)
		if i%2 == 0 && i != int(a.n)-1 {
			sb.WriteByte('.')
		}
	}

	return sb.String()
}

// ParseNET parses a network entity title in its conventional encoding:
// hexadecimal octets separated by periods, as in
// "49.0001.0000.0000.0001.00". The trailing NSEL octet must be zero, the
// six octets before it are the SystemID, and everything before those is
// the AreaAddress.
func ParseNET(s string) (AreaAddress, SystemID, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ".", ""))
	if errors.Is(err, hex.ErrLength) {
		return AreaAddress{}, SystemID{}, fmt.Errorf("isis: network entity title %q has an odd number of hexadecimal digits", s)
	}

	if err != nil {
		return AreaAddress{}, SystemID{}, fmt.Errorf("isis: network entity title %q is not hexadecimal", s)
	}

	// A whole NSAP is 20 octets, and the shortest useful one is a single
	// octet of area address, six of system ID, and the NSEL.
	if n := len(b); n < 8 || n > maxNSAPLen {
		return AreaAddress{}, SystemID{}, fmt.Errorf("isis: network entity title %q is %d octets, outside 8 to %d", s, n, maxNSAPLen)
	}

	if nsel := b[len(b)-1]; nsel != 0 {
		return AreaAddress{}, SystemID{}, fmt.Errorf("isis: network entity title %q must end in a zero NSEL octet: %#02x", s, nsel)
	}

	area, err := NewAreaAddress(b[:len(b)-7])
	if err != nil {
		return AreaAddress{}, SystemID{}, err
	}

	return area, SystemID(b[len(b)-7 : len(b)-1]), nil
}

// A CircuitType is the kind of link a Circuit attaches to. It selects the
// hello PDUs the Circuit exchanges and whether the link elects a DIS. The
// zero value is not valid: the layer which takes a CircuitType supplies
// its default.
type CircuitType uint8

// The circuit types.
const (
	_ CircuitType = iota

	// CircuitBroadcast is a multi-access link: Level 1 and Level 2 LAN
	// hellos, a DIS, and a Pseudonode.
	CircuitBroadcast

	// CircuitPointToPoint is a link with exactly one neighbor: point to
	// point hellos and the RFC 5303 three way handshake, no DIS and no
	// Pseudonode. RFC 5309 allows an Ethernet link to be one.
	CircuitPointToPoint
)

// String returns the name of a CircuitType.
func (t CircuitType) String() string {
	switch t {
	case CircuitBroadcast:
		return "broadcast"
	case CircuitPointToPoint:
		return "point to point"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}
