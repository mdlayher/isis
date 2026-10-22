package isis_test

import (
	"sync"
	"testing"
	"testing/synctest"

	"github.com/mdlayher/isis"
)

// A liveness session falls after the adjacency is Up. The adjacency goes
// Down with the reason, and the neighbor's next hellos walk it back up
// through the handshake, which is where a caller starts a fresh liveness
// session.
func TestCircuitUnusableNeighborGoesDownAndReforms(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)
		defer b.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		// The report comes from a goroutine other than the one running Run,
		// as a caller's liveness check does.
		var wg sync.WaitGroup
		wg.Go(func() { a.c.SetUsable(endB.sys, false) })
		wg.Wait()

		ae := a.wantAdjacency(t, isis.AdjacencyDown)
		if want := isis.DownNeighborUnusable; ae.Event.Reason != want {
			t.Fatalf("unexpected reason: want %q, got %q", want, ae.Event.Reason)
		}

		a.waitAdjacency(t, isis.AdjacencyUp)
	})
}

// A report of a usable neighbor, and a report naming a system the Circuit
// holds no adjacency with, leave the adjacency as it is.
func TestCircuitUsableReportsChangeNothing(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)
		defer b.stop(t)

		a.waitAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		a.c.SetUsable(endB.sys, true)
		a.c.SetUsable(isis.SystemID{0, 0, 0, 0, 0, 3}, false)

		synctest.Wait()
		a.wantNoAdjacency(t)
	})
}

// Liveness tears down only what it watched come up, so a report applied
// before the handshake brings the adjacency Up is dropped.
func TestCircuitUnusableBeforeUpIsIgnored(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// a is silent at first, so it hears b and holds an Initializing
		// adjacency which cannot reach Up until a is heard. That holds a
		// short of Up for as long as the report takes to apply.
		trA, trB := memLink(snpaA, snpaB, linkPDULength)
		trA.drop(true)

		a := newNode(t, trA, circuitConfig(t, endA))
		defer a.stop(t)

		b := newNode(t, trB, circuitConfig(t, endB))
		defer b.stop(t)

		a.wantAdjacency(t, isis.AdjacencyInitializing)

		a.c.SetUsable(endB.sys, false)
		synctest.Wait()

		trA.drop(false)
		a.wantAdjacency(t, isis.AdjacencyUp)
		b.waitAdjacency(t, isis.AdjacencyUp)

		synctest.Wait()
		a.wantNoAdjacency(t)
	})
}
