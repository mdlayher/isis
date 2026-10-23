//go:build interop && linux

package interop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mdlayher/frrtest"
	"github.com/mdlayher/frrtest/netns"
	"github.com/mdlayher/isis"
)

// holdingTime is what both ends advertise: the one second hello interval
// of the FRR template and the host, times a multiplier of three.
const holdingTime = 3 * time.Second

// frrExtendedCircuitID is the extended local circuit ID FRR sends for
// its only circuit, which is its index.
const frrExtendedCircuitID = 0

// md5Key is the interface password the authentication scenarios share.
const md5Key = "hunter2"

func TestFRRAdjacencyUp(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// FRR's own neighbor output reports this implementation in state Up.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	e := h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	if d := diff(t, wantHostEvent(t, f, isis.AdjacencyUp), e); d != "" {
		t.Fatalf("unexpected adjacency event (-want +got):\n%s", d)
	}

	// FRR's own view, which is the assertion that matters. The expiry
	// counts down, so it is checked on its own below.
	adj := awaitAdjacency(ctx, t, f, "Up")
	if d := diff(t, wantFRRAdjacency(h), adj); d != "" {
		t.Fatalf("unexpected FRR adjacency (-want +got):\n%s", d)
	}

	// FRR counts down the holding time this end advertised, so it can
	// never exceed it.
	expires, err := time.ParseDuration(adj.ExpiresIn)
	if err != nil {
		t.Fatalf("failed to parse the expiry FRR reports: %v", err)
	}

	if expires <= 0 || expires > holdingTime {
		t.Fatalf("FRR reports the adjacency expiring in %s, outside the advertised %s", expires, holdingTime)
	}
}

func TestFRRVersionPinned(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// The tripwire the harness already enforces against the daemon
	// binary, asserted again through the oracle's own output so a
	// mismatched vtysh cannot hide it.
	f := startFRR(ctx, t, defaultFRRConfig())

	out, err := f.Vtysh("show version")
	if err != nil {
		t.Fatalf("failed to run vtysh: %v: %s", err, out)
	}

	if want := "FRRouting " + frrVersion + " "; !strings.HasPrefix(string(out), want) {
		t.Fatalf("the oracle must be FRR %s, but reports: %q", frrVersion, out)
	}
}

func TestFRRThreeWayProgression(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// The tap shows a three way handshake rather than two systems
	// declaring an adjacency at each other.
	//
	// Whether this end ever puts Initializing on the wire is FRR's to
	// decide: if FRR answers the opening Down with a reactive hello
	// before its next periodic one, this end reads Initializing from FRR
	// and goes straight to Up. Both orders are correct, and the
	// deterministic progression is proved against a peer this repository
	// controls, under synctest. What is asserted here is what cannot
	// race: the opening hello names nobody, the states only ever advance,
	// and Up is never advertised before FRR has echoed this system back.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	// FRR's echo is in the tap already, since it is what brought the
	// adjacency Up. The Circuit sends its Up hello in the same wakeup
	// which reports Up, so it is recorded ahead of any hello received
	// after the drain, and waiting for one guarantees it is seen.
	ms := h.tap()
	ms = append(ms, h.waitReceivedHellos(ctx, t, 1)...)

	var (
		sent      []isis.ThreeWayState
		first     isis.ThreeWayAdjacency
		echoed    isis.ThreeWayAdjacency
		hellos    int
		firstUp   = -1
		firstEcho = -1
	)

	for _, m := range ms {
		if m.Header.Type != isis.PDUPointToPointHello {
			continue
		}

		hellos++
		a := threeWayOf(t, m.Raw)

		switch m.Direction {
		case isis.DirectionSent:
			if len(sent) == 0 {
				first = a
			}

			if len(sent) == 0 || sent[len(sent)-1] != a.State {
				sent = append(sent, a.State)
			}

			if a.State == isis.ThreeWayUp && firstUp < 0 {
				firstUp = hellos
			}
		case isis.DirectionReceived:
			if a.NeighborSystemID == h.id && firstEcho < 0 {
				firstEcho, echoed = hellos, a
			}
		}
	}

	// The opening hello: Down, this Circuit's own identifier, and no
	// neighbor, because nothing has been heard yet.
	wantFirst := isis.ThreeWayAdjacency{
		State:                  isis.ThreeWayDown,
		ExtendedLocalCircuitID: hostExtendedCircuitID,
	}

	if d := diff(t, wantFirst, first); d != "" {
		t.Fatalf("unexpected opening three way adjacency (-want +got):\n%s", d)
	}

	// The states only ever advance, and settle on Up.
	if len(sent) < 2 {
		t.Fatalf("the tap recorded only %d distinct three way states sent: %v", len(sent), sent)
	}

	for i, s := range sent {
		if i > 0 && threeWayRank(s) <= threeWayRank(sent[i-1]) {
			t.Fatalf("the three way state went backwards: %v", sent)
		}
	}

	if got := sent[len(sent)-1]; got != isis.ThreeWayUp {
		t.Fatalf("unexpected final three way state: want %q, got %q", isis.ThreeWayUp, got)
	}

	// FRR echoes this end's identifiers back, and only then does this end
	// advertise Up. That ordering is the handshake.
	if firstEcho < 0 {
		t.Fatal("FRR never echoed this system back")
	}

	// FRR's state in its first echo is Initializing or Up, depending on
	// which system's opening hello arrived first, so it is not compared.
	wantEcho := isis.ThreeWayAdjacency{
		State:                          echoed.State,
		ExtendedLocalCircuitID:         frrExtendedCircuitID,
		NeighborSystemID:               h.id,
		NeighborExtendedLocalCircuitID: hostExtendedCircuitID,
	}

	if d := diff(t, wantEcho, echoed); d != "" {
		t.Fatalf("unexpected echoed three way adjacency (-want +got):\n%s", d)
	}

	if firstUp < firstEcho {
		t.Fatalf("this end advertised Up at hello %d, before FRR echoed it at hello %d", firstUp, firstEcho)
	}
}

func TestFRRHelloPaddingToMTU(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// FRR pads every hello to the interface MTU less the LLC header, so a
	// receive buffer sized to ISO 10589's ReceiveLSPBufferSize of 1492
	// truncates all of them.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	want := h.tr.MaxPDULen()
	if want <= 1492 {
		t.Fatalf("the harness link carries %d octets, which does not exercise the truncation", want)
	}

	// Up guarantees a hello in each direction is in the tap already: the
	// Circuit sent its opening hello when it started, and a received
	// hello is what brought the adjacency Up.
	var sent, received int
	for _, m := range h.tap() {
		if m.Header.Type != isis.PDUPointToPointHello {
			continue
		}

		if len(m.Raw) != want {
			t.Fatalf("unexpected %s hello length: want %d, got %d", m.Direction, want, len(m.Raw))
		}

		// Every octet of the padding is part of a TLV, so the walk
		// accounts for the whole PDU with nothing left over.
		p, err := isis.ParsePointToPointHello(m.Raw)
		if err != nil {
			t.Fatalf("failed to parse a %s hello: %v", m.Direction, err)
		}

		var n int
		for _, tlv := range p.TLVs {
			n += 2 + len(tlv.Value)
		}

		if n != want-20 {
			t.Fatalf("the TLV walk did not account for a %s hello: want %d, got %d", m.Direction, want-20, n)
		}

		switch m.Direction {
		case isis.DirectionSent:
			sent++
		case isis.DirectionReceived:
			received++
		}
	}

	if sent == 0 || received == 0 {
		t.Fatalf("the tap recorded %d hellos sent and %d received", sent, received)
	}
}

func TestFRRUnpaddedHellosAccepted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// RFC 3719 section 6: "The presence or absence of padding TLVs MUST
	// NOT be one of the acceptance tests applied to a received IIH." The
	// far end pads nothing and this end pads everything.
	cfg := defaultFRRConfig()
	cfg.NoHelloPadding = true

	f := startFRR(ctx, t, cfg)
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	awaitAdjacency(ctx, t, f, "Up")

	for _, m := range h.tap() {
		if !isReceivedHello(m) {
			continue
		}

		if n := len(m.Raw); n >= h.tr.MaxPDULen() {
			t.Fatalf("FRR was asked not to pad but sent a %d octet hello", n)
		}
	}
}

func TestFRRAdjacencyWithoutMulticastMembership(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Whether the link layer multicast membership is needed at all is a
	// property of the driver, not of IS-IS, so it is measured here rather
	// than assumed. On the veth pair this harness builds it is not
	// needed: nothing filters by group address, and the adjacency forms
	// with no membership at all.
	//
	// A production interface is not a veth, which is why joining is the
	// default. If this test ever fails, the measurement changed and the
	// comment above is the thing to correct.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{Groups: []isis.SNPA{}})

	if d := diff(t, []isis.SNPA{}, h.tr.Groups()); d != "" {
		t.Fatalf("unexpected groups joined (-want +got):\n%s", d)
	}

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	awaitAdjacency(ctx, t, f, "Up")
}

func TestFRRAdjacencyExpires(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Stopping this end reports the adjacency Down and sends one last
	// hello advertising three way Down. FRR moves its own three way state
	// to Initializing on that but leaves the adjacency Up, so what
	// actually removes it is the holding time this end advertised.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	awaitAdjacency(ctx, t, f, "Up")

	start := time.Now()
	h.stop(t)

	want := wantHostEvent(t, f, isis.AdjacencyDown)
	want.Reason = isis.DownCircuitStopped

	if d := diff(t, want, h.waitAdjacency(ctx, t, isis.AdjacencyDown)); d != "" {
		t.Fatalf("unexpected adjacency event (-want +got):\n%s", d)
	}

	if err := f.Poll(ctx, func() error {
		if adjs := adjacencies(t, f); len(adjs) != 0 {
			return fmt.Errorf("FRR holds %d adjacencies: %+v", len(adjs), adjs)
		}

		return nil
	}); err != nil {
		t.Fatalf("the adjacency never expired: %v", err)
	}

	// Generously bounded: the assertion is that FRR times the adjacency
	// out on the holding time rather than keeping it indefinitely.
	if got := time.Since(start); got > holdingTime+5*time.Second {
		t.Fatalf("FRR held the adjacency for %s, well past the advertised %s", got, holdingTime)
	}
}

func TestFRRAdjacencyReformsAfterRestart(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// This end restarts while FRR is still Up, which is the case RFC 5303
	// section 3.2 answers: a fresh system must not accept a neighbor's
	// stale Up, and the two must walk the handshake again.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	awaitAdjacency(ctx, t, f, "Up")
	h.stop(t)

	h2 := startHost(ctx, t, f, hostConfig{})
	h2.waitAdjacency(ctx, t, isis.AdjacencyUp)

	if d := diff(t, wantFRRAdjacency(h2), awaitAdjacency(ctx, t, f, "Up")); d != "" {
		t.Fatalf("unexpected FRR adjacency (-want +got):\n%s", d)
	}
}

func TestFRRInterfaceBounce(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// This end's interface goes down under a running Circuit and comes
	// back. A link down is silence rather than a failure: this end's
	// adjacency times out on the holding time and re-forms on the same
	// Circuit, which never stops.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)
	awaitAdjacency(ctx, t, f, "Up")

	// Read while the link is up, since FRR's view of its own interface is
	// what the event carries.
	want := wantHostEvent(t, f, isis.AdjacencyDown)
	want.Reason = isis.DownHoldingTimeExpired

	t.Cleanup(func() {
		if err := netns.LinkUp(oracle.Host); err != nil {
			t.Errorf("failed to set %s up: %v", oracle.Host, err)
		}
	})

	if err := netns.LinkDown(oracle.Host); err != nil {
		t.Fatalf("failed to set %s down: %v", oracle.Host, err)
	}

	if d := diff(t, want, h.waitAdjacency(ctx, t, isis.AdjacencyDown)); d != "" {
		t.Fatalf("unexpected adjacency event (-want +got):\n%s", d)
	}

	// FRR's end of the veth loses carrier, so FRR takes its circuit down
	// and deletes the adjacency rather than waiting out the holding time.
	if err := f.Poll(ctx, func() error {
		if adjs := adjacencies(t, f); len(adjs) != 0 {
			return fmt.Errorf("FRR holds %d adjacencies: %+v", len(adjs), adjs)
		}

		return nil
	}); err != nil {
		t.Fatalf("FRR never dropped the adjacency: %v", err)
	}

	if err := netns.LinkUp(oracle.Host); err != nil {
		t.Fatalf("failed to set %s up: %v", oracle.Host, err)
	}

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	// The adjacency FRR re-forms is a new one, so it reports one flap.
	if d := diff(t, wantFRRAdjacency(h), awaitAdjacency(ctx, t, f, "Up")); d != "" {
		t.Fatalf("unexpected FRR adjacency (-want +got):\n%s", d)
	}

	// The hellos sent while the link was down failed, and the tap
	// reported each failure rather than the Circuit stopping on it.
	if !slices.ContainsFunc(h.tap(), func(e isis.PDUEvent) bool {
		return e.Direction == isis.DirectionSent && errors.Is(e.Err, syscall.ENETDOWN)
	}) {
		t.Fatal("the tap reported no hello failing with the link down")
	}
}

func TestFRRTLVAudit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Every TLV FRR sends is walked, the ones this module models decode
	// to what FRR reports, and the set of code points is pinned so a new
	// one from a future FRR is a loud failure rather than a silent skip.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f, hostConfig{})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	var (
		seen  []isis.TLVType
		v4    []netip.Addr
		v6    []netip.Addr
		areas []isis.AreaAddress
	)

	// FRR sends every TLV in every hello once isisd holds its
	// link-local, which startFRR waited for, and a received hello is what
	// brought the adjacency Up, so the tap already holds one.
	for _, m := range h.tap() {
		if !isReceivedHello(m) {
			continue
		}

		p, err := isis.ParsePointToPointHello(m.Raw)
		if err != nil {
			t.Fatalf("failed to parse a hello FRR sent: %v", err)
		}

		for _, tlv := range p.TLVs {
			if !slices.Contains(seen, tlv.Type) {
				seen = append(seen, tlv.Type)
			}

			switch tlv.Type {
			case isis.TLVAreaAddresses:
				areas, err = tlv.AreaAddresses()
			case isis.TLVIPv4InterfaceAddresses:
				v4, err = tlv.IPv4InterfaceAddresses()
			case isis.TLVIPv6InterfaceAddresses:
				v6, err = tlv.IPv6InterfaceAddresses()
			}

			if err != nil {
				t.Fatalf("failed to parse %s from a hello FRR sent: %v", tlv.Type, err)
			}
		}
	}

	slices.Sort(seen)

	// What FRR sends in a point to point hello for this configuration.
	// TLV 233 is RFC 6119's global IPv6 address, which this module walks
	// past without modeling.
	want := []isis.TLVType{
		isis.TLVAreaAddresses,
		isis.TLVPadding,
		isis.TLVProtocolsSupported,
		isis.TLVIPv4InterfaceAddresses,
		isis.TLVIPv6InterfaceAddresses,
		isis.TLVIPv6GlobalInterfaceAddresses,
		isis.TLVThreeWayAdjacency,
	}
	slices.Sort(want)

	if d := diff(t, want, seen); d != "" {
		t.Fatalf("unexpected TLV code points from FRR (-want +got):\n%s", d)
	}

	// The addresses decode to FRR's own: the area of its NET, its IPv4
	// address, and the link-local its interface output reports.
	area, _, err := isis.ParseNET(frrNET)
	if err != nil {
		t.Fatalf("failed to parse the FRR NET: %v", err)
	}

	if d := diff(t, []isis.AreaAddress{area}, areas); d != "" {
		t.Fatalf("unexpected area addresses (-want +got):\n%s", d)
	}

	if d := diff(t, []netip.Addr{f.Addresses().Peer[0].Addr()}, v4); d != "" {
		t.Fatalf("unexpected IPv4 interface addresses (-want +got):\n%s", d)
	}

	if d := diff(t, frrLinkLocal(t, f), v6); d != "" {
		t.Fatalf("unexpected IPv6 interface addresses (-want +got):\n%s", d)
	}
}

func TestFRRAuthMD5(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Both ends authenticate their hellos with RFC 5304 HMAC-MD5 under
	// one interface password. FRR reaching Up proves it verifies the
	// hellos this end signs, padding included, and this end reaching Up
	// proves the reverse.
	cfg := defaultFRRConfig()
	cfg.MD5Password = md5Key

	f := startFRR(ctx, t, cfg)
	h := startHost(ctx, t, f, hostConfig{MD5Key: md5Key})

	h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	if d := diff(t, wantFRRAdjacency(h), awaitAdjacency(ctx, t, f, "Up")); d != "" {
		t.Fatalf("unexpected FRR adjacency (-want +got):\n%s", d)
	}
}

func TestFRRAuthKeyMismatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// FRR and this end hold different passwords, so each drops every
	// hello the other sends. Once this end has seen several of FRR's
	// signed hellos, each reported as failing authentication, and so has
	// had as many chances to accept one, neither side holds an adjacency.
	cfg := defaultFRRConfig()
	cfg.MD5Password = md5Key

	f := startFRR(ctx, t, cfg)
	h := startHost(ctx, t, f, hostConfig{MD5Key: "not-" + md5Key})

	for _, m := range h.waitReceivedHellos(ctx, t, 5) {
		if !isReceivedHello(m) {
			continue
		}

		if !errors.Is(m.Err, isis.ErrAuthentication) {
			t.Fatalf("a hello FRR sent was not reported as failing authentication: %v", m.Err)
		}

		p, err := isis.ParsePointToPointHello(m.Raw)
		if err != nil {
			t.Fatalf("failed to parse a hello FRR sent: %v", err)
		}

		if got := p.TLVs[0].Type; got != isis.TLVAuthentication {
			t.Fatalf("FRR sent a hello which does not lead with authentication: want %q, got %q", isis.TLVAuthentication, got)
		}
	}

	h.wantNoAdjacency(t)

	if adjs := adjacencies(t, f); len(adjs) != 0 {
		t.Fatalf("FRR formed an adjacency despite the key mismatch: %+v", adjs)
	}
}

// threeWayRank orders the three way states by how far through the RFC
// 5303 handshake they are. The wire encoding runs the other way.
func threeWayRank(s isis.ThreeWayState) int {
	switch s {
	case isis.ThreeWayDown:
		return 0
	case isis.ThreeWayInitializing:
		return 1
	default:
		return 2
	}
}

// threeWayOf returns the three way adjacency TLV of the hello in b.
func threeWayOf(t *testing.T, b []byte) isis.ThreeWayAdjacency {
	t.Helper()

	h, err := isis.ParsePointToPointHello(b)
	if err != nil {
		t.Fatalf("failed to parse a hello: %v", err)
	}

	for _, tlv := range h.TLVs {
		if tlv.Type != isis.TLVThreeWayAdjacency {
			continue
		}

		a, err := tlv.ThreeWayAdjacency()
		if err != nil {
			t.Fatalf("failed to parse a three way adjacency TLV: %v", err)
		}

		return a
	}

	t.Fatal("a hello carried no three way adjacency TLV")
	return isis.ThreeWayAdjacency{}
}

// wantHostEvent returns the event the host's Circuit reports in state
// for its adjacency with f.
func wantHostEvent(t *testing.T, f *frrtest.Instance, state isis.AdjacencyState) isis.AdjacencyEvent {
	t.Helper()

	area, id, err := isis.ParseNET(frrNET)
	if err != nil {
		t.Fatalf("failed to parse the FRR NET: %v", err)
	}

	return isis.AdjacencyEvent{
		State:         state,
		Levels:        isis.Level2Only,
		Neighbor:      id,
		SNPA:          frrSNPA(t, f),
		AreaAddresses: []isis.AreaAddress{area},
		Protocols:     []isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6},
		IPv4Addresses: []netip.Addr{f.Addresses().Peer[0].Addr()},
		IPv6Addresses: frrLinkLocal(t, f),
	}
}

// wantFRRAdjacency returns FRR's view of its first Up adjacency with h.
func wantFRRAdjacency(h *host) frrAdjacency {
	var want frrAdjacency
	want.Adj = h.id.String()
	want.Level = 2

	want.Interface.Name = oracle.Peer
	want.Interface.State = "Up"
	want.Interface.AdjFlaps = 1
	want.Interface.CircuitType = "L2"
	want.Interface.Speaks = "IPv4, IPv6"
	want.Interface.AreaAddress.ISONet = "49.0001"
	want.Interface.IPv4Address.IPv4 = h.v4.String()
	want.Interface.IPv6LinkLocal.IPv6 = h.v6.String()

	return want
}

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal. Comparisons compare AreaAddress and netip.Addr by value, which cmp
// otherwise refuses for their unexported fields, treat a nil and an empty
// slice alike, which no scenario distinguishes, and leave out an
// frrAdjacency's expiry, which counts down and is bounded on its own.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()

	return cmp.Diff(
		want, got,
		cmp.Comparer(func(x, y isis.AreaAddress) bool { return x == y }),
		cmp.Comparer(func(x, y netip.Addr) bool { return x == y }),
		cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(frrAdjacency{}, "ExpiresIn"),
	)
}
