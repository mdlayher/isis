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

// An adjEvent is one call of a node's OnAdjacency hook: the Circuit which
// fired and the event it reported.
type adjEvent struct {
	Circuit *isis.Circuit
	Event   isis.AdjacencyEvent
}

// A node is one Circuit under test, with the channels its hooks feed and
// the goroutine its Run occupies, which wg tracks and stop joins.
type node struct {
	c      *isis.Circuit
	tr     *memTransport
	adjC   chan adjEvent
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
		adjC: make(chan adjEvent, 64),
		pduC: make(chan tapEvent, 256),
		runC: make(chan error, 1),
	}

	// Every adjacency event is kept: a test which misses one would pass
	// over the transition it asserts.
	cfg.OnAdjacency = func(c *isis.Circuit, e isis.AdjacencyEvent) {
		n.adjC <- adjEvent{
			Circuit: c,
			Event:   e,
		}
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

// wantAdjacency waits for the next adjacency state change and requires it
// to be want.
func (n *node) wantAdjacency(t *testing.T, want isis.AdjacencyState) adjEvent {
	t.Helper()

	select {
	case ae := <-n.adjC:
		if ae.Event.State != want {
			t.Fatalf("unexpected adjacency state: got %s, want %s", ae.Event.State, want)
		}

		return ae
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for adjacency state %s", want)
		return adjEvent{}
	}
}

// waitAdjacency waits for the adjacency to reach want, passing over the
// states it reaches on the way.
func (n *node) waitAdjacency(t *testing.T, want isis.AdjacencyState) adjEvent {
	t.Helper()

	for {
		select {
		case ae := <-n.adjC:
			if ae.Event.State == want {
				return ae
			}
		case <-time.After(timeout):
			t.Fatalf("timed out waiting for adjacency state %s", want)
			return adjEvent{}
		}
	}
}

// wantNoAdjacency requires that no adjacency state change has been
// reported.
func (n *node) wantNoAdjacency(t *testing.T) {
	t.Helper()

	select {
	case ae := <-n.adjC:
		t.Fatalf("unexpected adjacency event: %+v", ae.Event)
	default:
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

// sentThreeWayStates drains the tap and returns the three way state each
// hello this node sent advertised, with consecutive repeats collapsed so
// the result is the progression rather than the cadence.
func (n *node) sentThreeWayStates(t *testing.T) []isis.ThreeWayState {
	t.Helper()

	var out []isis.ThreeWayState
	for _, te := range n.tapped() {
		if te.Event.Direction != isis.DirectionSent {
			continue
		}

		s := threeWayOf(t, te.Event.Raw).State
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}

	return out
}

// scriptedHello encodes a hello from endB running levels and carrying the
// given three way adjacency TLV, for a test which plays the far end of the
// link itself.
func scriptedHello(t *testing.T, levels isis.LevelSet, a isis.ThreeWayAdjacency) []byte {
	t.Helper()

	h := &isis.PointToPointHello{
		Levels:      levels,
		SourceID:    endB.sys,
		HoldingTime: holdingTime,
		TLVs: []isis.TLV{
			mustAreaAddressesTLV(t, []byte{0x49, 0x00, 0x01}),
			mustProtocolsTLV(t),
			mustThreeWayTLV(t, a),
		},
	}

	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append hello: %v", err)
	}

	return b
}

// mustAreaAddressesTLV builds the area addresses TLV for the area b or
// fails the test.
func mustAreaAddressesTLV(t *testing.T, b []byte) isis.TLV {
	t.Helper()

	tlv, err := isis.AreaAddressesTLV([]isis.AreaAddress{mustAreaAddress(t, b)})
	if err != nil {
		t.Fatalf("failed to build area addresses TLV: %v", err)
	}

	return tlv
}

// mustProtocolsTLV builds the protocols supported TLV for IPv4 and IPv6 or
// fails the test.
func mustProtocolsTLV(t *testing.T) isis.TLV {
	t.Helper()

	tlv, err := isis.ProtocolsSupportedTLV([]isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6})
	if err != nil {
		t.Fatalf("failed to build protocols supported TLV: %v", err)
	}

	return tlv
}

// mustThreeWayTLV builds the three way adjacency TLV or fails the test.
func mustThreeWayTLV(t *testing.T, a isis.ThreeWayAdjacency) isis.TLV {
	t.Helper()

	tlv, err := isis.ThreeWayAdjacencyTLV(a)
	if err != nil {
		t.Fatalf("failed to build three way adjacency TLV: %v", err)
	}

	return tlv
}
