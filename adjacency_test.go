package isis_test

import (
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mdlayher/isis"
)

// Two Circuits on one link walk the RFC 5303 handshake to Up, each
// reporting Initializing first, and each Up event names the Circuit which
// fired and carries what the neighbor's hellos claim.
func TestCircuitsReachUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)
		defer b.stop(t)

		for _, n := range []*node{a, b} {
			n.wantAdjacency(t, isis.AdjacencyInitializing)
		}

		ends := []struct {
			n    *node
			peer end
			snpa isis.SNPA
		}{
			{
				n:    a,
				peer: endB,
				snpa: snpaB,
			},
			{
				n:    b,
				peer: endA,
				snpa: snpaA,
			},
		}

		for _, e := range ends {
			want := adjEvent{
				Circuit: e.n.c,
				Event: isis.AdjacencyEvent{
					State:         isis.AdjacencyUp,
					Levels:        isis.Level2Only,
					Neighbor:      e.peer.sys,
					SNPA:          e.snpa,
					AreaAddresses: []isis.AreaAddress{mustAreaAddress(t, []byte{0x49, 0x00, 0x01})},
					Protocols:     []isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6},
					IPv4Addresses: []netip.Addr{e.peer.v4},
					IPv6Addresses: []netip.Addr{e.peer.v6},
				},
			}

			if d := diff(t, want, e.n.wantAdjacency(t, isis.AdjacencyUp)); d != "" {
				t.Fatalf("unexpected adjacency (-want +got):\n%s", d)
			}
		}
	})
}

// What each Circuit puts on the wire during the handshake is three way
// Down, then Initializing, then Up.
func TestCircuitsAdvertiseThreeWayProgression(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)
		defer b.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		// Reaching Up fires the hook at once but sends the first Up hello
		// on the Circuit's next pass, so wait for both Circuits to go
		// idle, which is after that hello is on the wire and in the tap.
		synctest.Wait()

		want := []isis.ThreeWayState{
			isis.ThreeWayDown,
			isis.ThreeWayInitializing,
			isis.ThreeWayUp,
		}

		if d := diff(t, want, a.sentThreeWayStates(t)); d != "" {
			t.Fatalf("unexpected three way progression on a (-want +got):\n%s", d)
		}

		if d := diff(t, want, b.sentThreeWayStates(t)); d != "" {
			t.Fatalf("unexpected three way progression on b (-want +got):\n%s", d)
		}
	})
}

// A neighbor which falls silent is taken Down once its holding time runs
// out, and the adjacency forms again when the link heals.
func TestCircuitHoldingTimeExpires(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)
		defer b.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		start := time.Now()
		b.tr.drop(true)

		ae := a.waitAdjacency(t, isis.AdjacencyDown)
		if want := isis.DownHoldingTimeExpired; ae.Event.Reason != want {
			t.Fatalf("unexpected reason: got %q, want %q", ae.Event.Reason, want)
		}

		// The holding time runs from the last hello a heard, which b sent
		// no more than one jittered hello interval before the drop began.
		got := time.Since(start)
		if lo := holdingTime - helloInterval; got < lo || got > holdingTime {
			t.Fatalf("adjacency expired %s after the drop, outside [%s, %s]", got, lo, holdingTime)
		}

		// Whether a passes through Initializing again depends on how far
		// b's own handshake had unwound, so only Up is asserted.
		b.tr.drop(false)
		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)
	})
}

// A stopping Circuit's last hello advertises three way Down, which RFC
// 5303 section 3.2 turns into Initializing on a neighbor in Up. That takes
// the link out of service at once rather than after a holding time, and
// the holding time then finishes the job.
func TestCircuitFarewellLeavesNeighborInitializing(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		start := time.Now()
		b.stop(t)

		// b reports its own adjacency Down as it stops.
		ae := b.wantAdjacency(t, isis.AdjacencyDown)
		if want := isis.DownCircuitStopped; ae.Event.Reason != want {
			t.Fatalf("unexpected reason on b: got %q, want %q", ae.Event.Reason, want)
		}

		a.wantAdjacency(t, isis.AdjacencyInitializing)
		if got := time.Since(start); got >= holdingTime {
			t.Fatalf("adjacency left Up after %s, no sooner than the %s holding time", got, holdingTime)
		}

		ae = a.wantAdjacency(t, isis.AdjacencyDown)
		if want := isis.DownHoldingTimeExpired; ae.Event.Reason != want {
			t.Fatalf("unexpected reason on a: got %q, want %q", ae.Event.Reason, want)
		}
	})
}

// A neighbor which restarts on the same link with a new RFC 5303 extended
// local circuit ID forms the adjacency again, and what the survivor echoes
// afterwards is the new identifier, not the one which is gone.
func TestCircuitRestartWithNewCircuitID(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		trA, trB := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		b := newNode(t, trB, circuitConfig(t, endB))
		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		b.stop(t)
		a.waitAdjacency(t, isis.AdjacencyInitializing)

		const restartedID = 0x0c
		cfg := circuitConfig(t, endB)
		cfg.ExtendedLocalCircuitID = restartedID

		b2 := newNode(t, trB.reopen(), cfg)
		defer b2.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b2.waitAdjacency(t, isis.AdjacencyUp)

		a.drainTap()

		if got := a.sentThreeWay(t).NeighborExtendedLocalCircuitID; got != restartedID {
			t.Fatalf("unexpected echoed circuit ID: got %#x, want %#x", got, restartedID)
		}
	})
}

// This end restarted and the neighbor never noticed: it still advertises
// Up and echoes this system's own identifiers. RFC 5303 section 3.2
// forbids accepting that, so no adjacency forms until the neighbor has
// itself been through Initializing, and then this end answers with Up at
// once.
func TestCircuitIgnoresStaleNeighborUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		trA, peer := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		stale := isis.ThreeWayAdjacency{
			State:                          isis.ThreeWayUp,
			ExtendedLocalCircuitID:         endB.id,
			NeighborSystemID:               endA.sys,
			NeighborExtendedLocalCircuitID: endA.id,
		}

		if err := peer.WritePDU(isis.AllISs(), scriptedHello(t, stale)); err != nil {
			t.Fatalf("failed to write hello: %v", err)
		}

		// Sleeping in the bubble advances its clock across two hellos, and
		// once the Circuit is idle again nothing has formed.
		time.Sleep(2 * helloInterval)
		synctest.Wait()

		a.wantNoAdjacency(t)
		a.drainTap()

		// Once the neighbor has seen this system's Down and moved to
		// Initializing, the handshake completes.
		stale.State = isis.ThreeWayInitializing
		if err := peer.WritePDU(isis.AllISs(), scriptedHello(t, stale)); err != nil {
			t.Fatalf("failed to write hello: %v", err)
		}

		a.wantAdjacency(t, isis.AdjacencyUp)

		// The neighbor completes its own handshake only once it hears Up,
		// so the Circuit answers at once. Nothing sleeps from here, so the
		// clock has not moved and no periodic hello can be the answer.
		synctest.Wait()

		sent := slices.DeleteFunc(a.tapped(), func(te tapEvent) bool {
			return te.Event.Direction != isis.DirectionSent
		})

		if len(sent) != 1 {
			t.Fatalf("expected one hello in answer, but sent %d", len(sent))
		}

		want := isis.ThreeWayAdjacency{
			State:                          isis.ThreeWayUp,
			ExtendedLocalCircuitID:         endA.id,
			NeighborSystemID:               endB.sys,
			NeighborExtendedLocalCircuitID: endB.id,
		}

		if d := diff(t, want, threeWayOf(t, sent[0].Event.Raw)); d != "" {
			t.Fatalf("unexpected three way adjacency in answer (-want +got):\n%s", d)
		}
	})
}

// ISO 10589's assumption for a neighbor which does not implement RFC
// 5303 is that "the link is assumed to be functional in both directions",
// so the adjacency goes straight to Up.
func TestCircuitScriptedNeighborWithoutThreeWayTLV(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		trA, peer := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		h := &isis.PointToPointHello{
			Levels:      isis.Level2Only,
			SourceID:    endB.sys,
			HoldingTime: holdingTime,
			TLVs: []isis.TLV{
				mustAreaAddressesTLV(t, []byte{0x49, 0x00, 0x01}),
				mustProtocolsTLV(t),
			},
		}

		b, err := h.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to append hello: %v", err)
		}

		if err := peer.WritePDU(isis.AllISs(), b); err != nil {
			t.Fatalf("failed to write hello: %v", err)
		}

		ae := a.wantAdjacency(t, isis.AdjacencyUp)
		if ae.Event.Neighbor != endB.sys {
			t.Fatalf("unexpected neighbor: %s", ae.Event.Neighbor)
		}
	})
}

// A packet socket is handed its own outgoing multicast back. The
// Transport's filter drops it, and this is the Circuit's second line: a
// hello whose source is this end's own SNPA, and one whose source system
// ID is this system's own, form nothing.
func TestCircuitDropsItsOwnHello(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		trA, peer := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		own := a.sentPDU(t)

		if err := peer.writeFrom(snpaA, own); err != nil {
			t.Fatalf("failed to write echoed hello: %v", err)
		}

		if err := peer.writeFrom(snpaB, own); err != nil {
			t.Fatalf("failed to write hello from another SNPA: %v", err)
		}

		time.Sleep(2 * helloInterval)
		synctest.Wait()

		a.wantNoAdjacency(t)
	})
}

// The same neighbor arriving from a new link layer address, as after a
// replaced interface, keeps its adjacency without a transition, and the
// next event it reports carries the new address.
func TestCircuitNeighborChangesSNPA(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		trA, peer := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		// A neighbor without the three way adjacency TLV goes straight to
		// Up, which keeps the handshake out of this test.
		h := &isis.PointToPointHello{
			Levels:      isis.Level2Only,
			SourceID:    endB.sys,
			HoldingTime: holdingTime,
			TLVs: []isis.TLV{
				mustAreaAddressesTLV(t, []byte{0x49, 0x00, 0x01}),
				mustProtocolsTLV(t),
			},
		}

		b, err := h.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to append hello: %v", err)
		}

		if err := peer.WritePDU(isis.AllISs(), b); err != nil {
			t.Fatalf("failed to write hello: %v", err)
		}

		a.wantAdjacency(t, isis.AdjacencyUp)

		snpaC := isis.SNPA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0c}
		if err := peer.writeFrom(snpaC, b); err != nil {
			t.Fatalf("failed to write hello from the new SNPA: %v", err)
		}

		synctest.Wait()
		a.wantNoAdjacency(t)

		// The neighbor falls silent, and its holding time runs out at the
		// new address.
		ae := a.wantAdjacency(t, isis.AdjacencyDown)
		if want := isis.DownHoldingTimeExpired; ae.Event.Reason != want {
			t.Fatalf("unexpected reason: got %q, want %q", ae.Event.Reason, want)
		}

		if ae.Event.SNPA != snpaC {
			t.Fatalf("unexpected SNPA: got %s, want %s", ae.Event.SNPA, snpaC)
		}
	})
}
