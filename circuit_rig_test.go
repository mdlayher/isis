package isis_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/isis"
)

// The timings every rig node runs at: short enough that a holding time
// costs nothing in fake time, and in the ratio FRR's interop
// configuration uses.
const (
	helloInterval = 1 * time.Second
	holdingTime   = 3 * time.Second
)

// timeout bounds every rig wait. It exceeds the longest wait a correct
// Circuit can impose, a holding time noticed up to one hello interval
// late. Inside a synctest bubble it is fake time, so a passing test never
// spends any of it.
const timeout = 5 * time.Second

// An end is the identity one side of a rig link claims: its system ID,
// its interface addresses, and its circuit identifier.
type end struct {
	sys    isis.SystemID
	v4, v6 netip.Addr
	id     uint32
}

// The two sides of a rig link.
var (
	endA = end{
		sys: isis.SystemID{0, 0, 0, 0, 0, 1},
		v4:  netip.MustParseAddr("192.0.2.1"),
		v6:  netip.MustParseAddr("fe80::a"),
		id:  0x0a,
	}

	endB = end{
		sys: isis.SystemID{0, 0, 0, 0, 0, 2},
		v4:  netip.MustParseAddr("192.0.2.2"),
		v6:  netip.MustParseAddr("fe80::b"),
		id:  0x0b,
	}
)

// circuitConfig is e's Circuit configuration, which both sides of a rig
// link share but for their identities.
func circuitConfig(t *testing.T, e end) isis.CircuitConfig {
	t.Helper()

	return isis.CircuitConfig{
		SystemID:               e.sys,
		AreaAddresses:          []isis.AreaAddress{mustAreaAddress(t, []byte{0x49, 0x00, 0x01})},
		Levels:                 isis.Level2Only,
		Type:                   isis.CircuitPointToPoint,
		HelloInterval:          helloInterval,
		HoldingMultiplier:      uint8(holdingTime / helloInterval),
		LocalCircuitID:         uint8(e.id),
		ExtendedLocalCircuitID: e.id,
		IPv4Addresses:          []netip.Addr{e.v4},
		IPv6Addresses:          []netip.Addr{e.v6},
	}
}

// A tapEvent is one call of a node's OnPDU hook: the Circuit which fired
// and the event it reported.
type tapEvent struct {
	Circuit *isis.Circuit
	Event   isis.PDUEvent
}

// A node is one Circuit under test, with the channel its tap feeds and
// the goroutine its Run occupies, which wg tracks and stop joins.
type node struct {
	c      *isis.Circuit
	tr     *memTransport
	pduC   chan tapEvent
	runC   chan error
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newPair builds two nodes joined by one in-memory link, each overriding
// the shared configuration when a config is given.
func newPair(t *testing.T, ca, cb *isis.CircuitConfig) (a, b *node) {
	t.Helper()

	trA, trB := memLink(snpaA, snpaB, linkPDULength)

	cfgA := circuitConfig(t, endA)
	if ca != nil {
		cfgA = *ca
	}

	cfgB := circuitConfig(t, endB)
	if cb != nil {
		cfgB = *cb
	}

	return newNode(t, trA, cfgA), newNode(t, trB, cfgB)
}

// newNode builds one Circuit over tr and runs it.
func newNode(t *testing.T, tr *memTransport, cfg isis.CircuitConfig) *node {
	t.Helper()

	n := &node{
		tr:   tr,
		pduC: make(chan tapEvent, 256),
		runC: make(chan error, 1),
	}

	cfg.OnPDU = func(c *isis.Circuit, e isis.PDUEvent) {
		// The tap's bytes alias a buffer the Circuit reuses, which is the
		// contract every hook keeping a PDU must honor. A hook must also
		// return promptly, so a full channel drops rather than stalling
		// the Circuit.
		e.Raw = bytes.Clone(e.Raw)
		select {
		case n.pduC <- tapEvent{Circuit: c, Event: e}:
		default:
		}
	}

	c, err := isis.NewCircuit(tr, cfg)
	if err != nil {
		t.Fatalf("failed to build circuit: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	n.c, n.cancel = c, cancel
	n.wg.Go(func() { n.runC <- c.Run(ctx) })

	return n
}

// stop cancels the node and waits for Run to return, which closes its
// Transport, requiring the error a cancellation returns.
func (n *node) stop(t *testing.T) {
	t.Helper()

	n.cancel()
	if err := n.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected run error: %v", err)
	}
}

// wait waits for Run to return and its goroutine to exit, and returns
// Run's error.
func (n *node) wait(t *testing.T) error {
	t.Helper()

	select {
	case err := <-n.runC:
		n.wg.Wait()
		return err
	case <-time.After(timeout):
		t.Fatal("timed out waiting for run to return")
		return nil
	}
}

// sentPDU waits for the next PDU this node put on the wire.
func (n *node) sentPDU(t *testing.T) []byte {
	t.Helper()

	for {
		select {
		case te := <-n.pduC:
			if te.Event.Direction == isis.DirectionSent {
				return te.Event.Raw
			}
		case <-time.After(timeout):
			t.Fatal("timed out waiting for a sent PDU")
			return nil
		}
	}
}

// tapped returns every PDU the tap has already recorded, in order, without
// waiting for more.
func (n *node) tapped() []tapEvent {
	var tes []tapEvent
	for {
		select {
		case te := <-n.pduC:
			tes = append(tes, te)
		default:
			return tes
		}
	}
}

// drainTap discards every PDU the tap has already recorded, so the next
// read is one the node sent after this point.
func (n *node) drainTap() {
	for {
		select {
		case <-n.pduC:
		default:
			return
		}
	}
}

// sentThreeWay waits for the next hello this node sent and returns its
// three way adjacency TLV.
func (n *node) sentThreeWay(t *testing.T) isis.ThreeWayAdjacency {
	t.Helper()

	return threeWayOf(t, n.sentPDU(t))
}

// threeWayOf parses the hello b and returns its three way adjacency TLV.
func threeWayOf(t *testing.T, b []byte) isis.ThreeWayAdjacency {
	t.Helper()

	h, err := isis.ParsePointToPointHello(b)
	if err != nil {
		t.Fatalf("failed to parse hello: %v", err)
	}

	for _, tlv := range h.TLVs {
		if tlv.Type != isis.TLVThreeWayAdjacency {
			continue
		}

		a, err := tlv.ThreeWayAdjacency()
		if err != nil {
			t.Fatalf("failed to parse three way adjacency TLV: %v", err)
		}

		return a
	}

	t.Fatal("hello carried no three way adjacency TLV")
	return isis.ThreeWayAdjacency{}
}
