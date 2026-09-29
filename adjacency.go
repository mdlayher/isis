package isis

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// An AdjacencyState is the state of an adjacency, as described in ISO
// 10589 clause 8.2. An adjacency which does not exist is Down, so Down is
// the zero value.
type AdjacencyState uint8

// The adjacency states.
const (
	AdjacencyDown AdjacencyState = iota
	AdjacencyInitializing
	AdjacencyUp
)

// String returns the name of an AdjacencyState.
func (s AdjacencyState) String() string {
	switch s {
	case AdjacencyDown:
		return "Down"
	case AdjacencyInitializing:
		return "Initializing"
	case AdjacencyUp:
		return "Up"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// A DownReason is why an adjacency fell to Down. The zero value is the
// reason of an event which is not a fall to Down.
type DownReason uint8

// The reasons an adjacency falls to Down.
const (
	_ DownReason = iota

	// DownHoldingTimeExpired reports that the neighbor's holding time ran
	// out with no further hello.
	DownHoldingTimeExpired

	// DownCircuitStopped reports that the Circuit stopped running.
	DownCircuitStopped

	// DownNeighborSystemIDChanged reports that a hello named a system other
	// than the neighbor's (RFC 3719 section 9).
	DownNeighborSystemIDChanged

	// DownNoLevelInCommon reports that a hello left the two systems no
	// level in common (ISO 10589 clause 8.2.4.2).
	DownNoLevelInCommon
)

// String returns a description of a DownReason.
func (r DownReason) String() string {
	switch r {
	case 0:
		return "none"
	case DownHoldingTimeExpired:
		return "holding time expired"
	case DownCircuitStopped:
		return "circuit stopped"
	case DownNeighborSystemIDChanged:
		return "neighbor system ID changed"
	case DownNoLevelInCommon:
		return "no level in common"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

// An AdjacencyEvent reports one adjacency reaching a new state. Its slices
// are parsed from the neighbor's hello. A later hello replaces them rather
// than editing them in place, so an event's slices never change after the
// hook returns and a caller may keep them.
type AdjacencyEvent struct {
	// State is the state the adjacency has reached.
	State AdjacencyState

	// Levels is the set of levels the adjacency carries: the levels both
	// systems run, narrowed to Level 2 when they share no area address
	// (ISO 10589 clause 8.2.4.2).
	Levels LevelSet

	// Neighbor is the neighbor's system identifier.
	Neighbor SystemID

	// SNPA is the neighbor's link layer address on the Circuit.
	SNPA SNPA

	// AreaAddresses are the area addresses the neighbor claims.
	AreaAddresses []AreaAddress

	// Protocols are the network layer protocols the neighbor routes.
	Protocols []NLPID

	// IPv4Addresses and IPv6Addresses are the neighbor's interface
	// addresses on this link. The IPv6 addresses are link-local, which is
	// all RFC 5308 section 3 permits a hello to carry, and they are what
	// a caller needs to bring up a BFD session over the link.
	IPv4Addresses, IPv6Addresses []netip.Addr

	// Reason explains a fall to Down, and is zero otherwise.
	Reason DownReason
}

// An adjacency is one Circuit's relationship with its neighbor: the state
// ISO 10589 clause 8.2 and RFC 5303 section 3.2 keep for it.
type adjacency struct {
	snpa     SNPA
	neighbor SystemID
	levels   LevelSet
	state    AdjacencyState

	// threeWay is this system's RFC 5303 view of the adjacency, which is
	// what its hellos advertise. It is not the neighbor's view. The zero
	// ThreeWayState is Up, so a new adjacency sets Down explicitly.
	threeWay ThreeWayState

	// remoteCircuitID is the neighbor's extended local circuit ID, echoed
	// back so the neighbor can tell this system has heard it.
	remoteCircuitID uint32

	areas     []AreaAddress
	protocols []NLPID
	v4, v6    []netip.Addr

	// expires is when the holding timer fires: the deadline the last
	// accepted hello set. A deadline needs no periodic sweep and behaves
	// correctly under a synthetic clock.
	expires time.Time
}

// event renders the adjacency as an AdjacencyEvent.
func (a *adjacency) event(reason DownReason) AdjacencyEvent {
	return AdjacencyEvent{
		State:         a.state,
		Levels:        a.levels,
		Neighbor:      a.neighbor,
		SNPA:          a.snpa,
		AreaAddresses: a.areas,
		Protocols:     a.protocols,
		IPv4Addresses: a.v4,
		IPv6Addresses: a.v6,
		Reason:        reason,
	}
}

// nextThreeWay applies the RFC 5303 section 3.2 state table: local is
// this system's current three way state and rx the state a hello carries.
// A result of ThreeWayDown means the neighbor claims an adjacency this
// system does not hold, so none forms until the neighbor has walked the
// handshake again. That happens only with no adjacency held: a held one
// is never three way Down.
func nextThreeWay(local, rx ThreeWayState) ThreeWayState {
	switch rx {
	case ThreeWayDown:
		return ThreeWayInitializing
	case ThreeWayInitializing:
		return ThreeWayUp
	default:
		if local == ThreeWayDown {
			return ThreeWayDown
		}

		return ThreeWayUp
	}
}

// sharesArea reports whether two sets of area addresses intersect. ISO
// 10589 clause 8.2.4.2 makes a common area address the condition for an
// adjacency valid at Level 1.
func sharesArea(local, remote []AreaAddress) bool {
	for _, a := range local {
		if slices.Contains(remote, a) {
			return true
		}
	}

	return false
}
