package isis_test

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mdlayher/isis"
)

func TestNewCircuitRejects(t *testing.T) {
	t.Parallel()

	tr, _ := memLink(snpaA, snpaB, linkPDULength)
	base := circuitConfig(t, endA)

	// Each case changes one field of a valid configuration, so the error
	// it pins proves the configuration reached the check it names.
	tests := []struct {
		name string
		tr   isis.Transport
		edit func(c *isis.CircuitConfig)
		err  string
		is   error
	}{
		{
			name: "no transport",
			err:  "isis: a circuit needs a transport",
		},
		{
			name: "zero system ID",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.SystemID = isis.SystemID{} },
			err:  "isis: system ID must be nonzero",
		},
		{
			name: "no area addresses",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.AreaAddresses = nil },
			err:  "isis: at least one area address is required",
		},
		{
			name: "no levels",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.Levels = 0 },
			err:  "isis: circuit levels are required",
		},
		{
			name: "a level set which does not exist",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.Levels = 4 },
			err:  "isis: level set 4 does not exist",
		},
		{
			name: "no circuit type",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.Type = 0 },
			err:  "isis: circuit type is required",
		},
		{
			name: "a broadcast circuit",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.Type = isis.CircuitBroadcast },
			err:  "isis: broadcast circuits are not implemented yet: unsupported operation",
			is:   errors.ErrUnsupported,
		},
		{
			name: "a circuit type which does not exist",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.Type = 9 },
			err:  "isis: circuit type 9 does not exist",
		},
		{
			name: "a negative hello interval",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.HelloInterval = -1 * time.Second },
			err:  "isis: hello interval must be positive: -1s",
		},
		{
			name: "IPv4 advertised without an address",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.IPv4Addresses = nil },
			err:  "isis: IPv4 is advertised but no IPv4 address is set",
		},
		{
			name: "IPv6 advertised without an address",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.IPv6Addresses = nil },
			err:  "isis: IPv6 is advertised but no IPv6 address is set",
		},
		{
			name: "an IPv6 address in the IPv4 addresses",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) { c.IPv4Addresses = []netip.Addr{endA.v6} },
			err:  "isis: fe80::a is not an IPv4 address",
		},
		{
			name: "an IPv6 address which is not link-local",
			tr:   tr,
			edit: func(c *isis.CircuitConfig) {
				c.IPv6Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
			},
			err: "isis: IPv6 interface address 2001:db8::1 is not link-local",
		},
		{
			// The rig's largest hello, which names a neighbor, is 71 octets
			// before padding.
			name: "a hello too large for the transport",
			tr:   &memTransport{maxPDU: 70},
			err:  "isis: hello is 71 octets, more than the transport's 70",
		},
		{
			name: "a transport too small for a PDU",
			tr:   &memTransport{maxPDU: 4},
			err:  "isis: transport carries 4 octets, too few for any PDU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			if tt.edit != nil {
				tt.edit(&cfg)
			}

			c, err := isis.NewCircuit(tt.tr, cfg)
			if err == nil {
				t.Fatalf("expected an error, but built %+v", c)
			}

			if err.Error() != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, err)
			}

			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Fatalf("error does not wrap %v: %v", tt.is, err)
			}
		})
	}
}

// A Circuit advertising one protocol needs an address of that family
// only, as on a link which routes IPv4 or IPv6 but not both.
func TestNewCircuitOneProtocol(t *testing.T) {
	t.Parallel()

	tr, _ := memLink(snpaA, snpaB, linkPDULength)
	base := circuitConfig(t, endA)

	tests := []struct {
		name string
		edit func(c *isis.CircuitConfig)
	}{
		{
			name: "IPv4",
			edit: func(c *isis.CircuitConfig) {
				c.Protocols = []isis.NLPID{isis.NLPIDIPv4}
				c.IPv6Addresses = nil
			},
		},
		{
			name: "IPv6",
			edit: func(c *isis.CircuitConfig) {
				c.Protocols = []isis.NLPID{isis.NLPIDIPv6}
				c.IPv4Addresses = nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			tt.edit(&cfg)

			if _, err := isis.NewCircuit(tr, cfg); err != nil {
				t.Fatalf("failed to build circuit: %v", err)
			}
		})
	}
}

// Run may be called once: the Run which took the Circuit owns its
// Transport.
func TestCircuitRunsOnce(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		tr, _ := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, tr, circuitConfig(t, endA))
		defer a.stop(t)

		// The rig's own Run must have taken the Circuit before a second
		// call can be refused.
		synctest.Wait()

		err := a.c.Run(t.Context())
		if err == nil {
			t.Fatal("expected an error from a second run")
		}

		if want := "isis: circuit is already running or has run"; err.Error() != want {
			t.Fatalf("unexpected second run error: want %q, got %q", want, err)
		}
	})
}

// A terminal read failure ends Run with an error which names the Circuit
// and wraps the Transport's own.
func TestCircuitTransportFailureEndsRun(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		tr, _ := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, tr, circuitConfig(t, endA))
		defer a.cancel()

		want := errors.New("the interface went away")
		tr.failRead(want)

		err := a.wait(t)
		if !errors.Is(err, want) {
			t.Fatalf("unexpected run error: %v", err)
		}

		if want := "isis: circuit 10 transport read failed: the interface went away"; err.Error() != want {
			t.Fatalf("unexpected run error text: want %q, got %q", want, err)
		}
	})
}

// A lone Circuit sends its first hello as soon as it runs and each later
// one between three quarters of the hello interval and the whole of it
// after the one before, as ISO 10589 clause 10.1 requires. Every hello
// carries what the configuration says, advertises three way Down since
// the Circuit holds no adjacency, and is padded to the link's PDU size.
func TestCircuitHelloCadence(t *testing.T) {
	t.Parallel()

	// hellos is how many consecutive hellos the test times, enough that
	// the jitter lands at many points within its bounds.
	const hellos = 20

	synctest.Test(t, func(t *testing.T) {
		// The far end only listens, and the hellos are read from it rather
		// than the tap, so the test sees what reached the wire.
		tr, peer := memLink(snpaA, snpaB, linkPDULength)
		cfg := circuitConfig(t, endA)

		start := time.Now()
		a := newNode(t, tr, cfg)
		defer a.stop(t)

		want := &isis.PointToPointHello{
			Levels:         cfg.Levels,
			SourceID:       cfg.SystemID,
			HoldingTime:    time.Duration(cfg.HoldingMultiplier) * cfg.HelloInterval,
			LocalCircuitID: cfg.LocalCircuitID,
			TLVs:           helloTLVs(t, cfg),
		}

		last := start
		for i := range hellos {
			b := make([]byte, peer.MaxPDULen())
			n, src, err := peer.ReadPDU(b)
			if err != nil {
				t.Fatalf("failed to read hello %d: %v", i, err)
			}

			gap := time.Since(last)
			last = time.Now()

			if i == 0 && gap != 0 {
				t.Fatalf("first hello sent %s after run began", gap)
			}

			if i > 0 && (gap < helloInterval*3/4 || gap > helloInterval) {
				t.Fatalf("hello %d sent %s after the one before, outside [%s, %s]", i, gap, helloInterval*3/4, helloInterval)
			}

			if src != snpaA {
				t.Fatalf("unexpected hello source SNPA: %v", src)
			}

			if n != linkPDULength {
				t.Fatalf("hello %d is %d octets, not padded to the link's %d", i, n, linkPDULength)
			}

			h, err := isis.ParsePointToPointHello(b[:n])
			if err != nil {
				t.Fatalf("failed to parse hello %d: %v", i, err)
			}

			h.TLVs = slices.DeleteFunc(h.TLVs, func(tlv isis.TLV) bool { return tlv.Type == isis.TLVPadding })
			if d := diff(t, want, h); d != "" {
				t.Fatalf("unexpected hello %d (-want +got):\n%s", i, d)
			}
		}
	})
}

// A PDU from the far end is reported once through the tap as received,
// naming the Circuit, with its source, decoded header, and octets. A PDU
// whose common header fails validation is reported too, with the
// validation error and no header.
func TestCircuitTapsReceivedPDUs(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		tr, peer := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, tr, circuitConfig(t, endA))
		defer a.stop(t)

		// Once the Circuit is idle its first hello is in the tap, and
		// discarding it leaves the tap to what follows.
		synctest.Wait()
		a.drainTap()

		h := &isis.PointToPointHello{
			Levels:         isis.Level2Only,
			SourceID:       endB.sys,
			HoldingTime:    holdingTime,
			LocalCircuitID: uint8(endB.id),
		}

		pdu, err := h.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to append hello: %v", err)
		}

		bad := bytes.Clone(pdu)
		bad[0] = 0x82

		for _, b := range [][]byte{bad, pdu} {
			if err := peer.WritePDU(isis.AllISs(), b); err != nil {
				t.Fatalf("failed to write PDU: %v", err)
			}
		}

		synctest.Wait()

		// The hello forms an adjacency, whose change of three way state
		// sends a hello in reply at once. The tap records that as sent,
		// and only what was received is this test's.
		want := []tapEvent{
			{
				Circuit: a.c,
				Event: isis.PDUEvent{
					Direction: isis.DirectionReceived,
					SNPA:      snpaB,
					Raw:       bad,
					Err:       errors.New("isis: PDU discriminator is 0x82, not 0x83"),
				},
			},
			{
				Circuit: a.c,
				Event: isis.PDUEvent{
					Direction: isis.DirectionReceived,
					SNPA:      snpaB,
					Header: isis.Header{
						Type: isis.PDUPointToPointHello,
						// The point to point hello's whole fixed header.
						LengthIndicator: 20,
					},
					Raw: pdu,
				},
			},
		}

		if d := diff(t, want, received(a.tapped())); d != "" {
			t.Fatalf("unexpected tap events (-want +got):\n%s", d)
		}
	})
}

// A hello whose write fails is reported through the tap with the
// Transport's error, and the failure is not terminal: the next hello
// after the link recovers is written and reported cleanly.
func TestCircuitTapsFailedWrite(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		tr, _ := memLink(snpaA, snpaB, linkPDULength)

		a := newNode(t, tr, circuitConfig(t, endA))
		defer a.stop(t)

		// Once the Circuit is idle its first hello is in the tap, and
		// discarding it leaves the tap to what follows.
		synctest.Wait()
		a.drainTap()

		// Sleeping in the bubble advances its clock by a whole interval,
		// past the next hello, which is then the only event.
		errWrite := errors.New("no buffer space available")
		tr.failWrites(errWrite)
		time.Sleep(helloInterval)
		synctest.Wait()

		tes := a.tapped()
		if len(tes) != 1 {
			t.Fatalf("expected one tap event for the failed hello, but tapped %+v", tes)
		}

		if d := diff(t, errWrite, tes[0].Event.Err); d != "" {
			t.Fatalf("unexpected failed write error (-want +got):\n%s", d)
		}

		if got := tes[0].Event.Direction; got != isis.DirectionSent {
			t.Fatalf("unexpected failed write direction: %v", got)
		}

		if got := len(tes[0].Event.Raw); got != linkPDULength {
			t.Fatalf("failed hello is %d octets, not the link's %d", got, linkPDULength)
		}

		tr.failWrites(nil)
		time.Sleep(helloInterval)
		synctest.Wait()

		tes = a.tapped()
		if len(tes) != 1 || tes[0].Event.Direction != isis.DirectionSent || tes[0].Event.Err != nil {
			t.Fatalf("expected one clean hello once the link recovered, but tapped %+v", tes)
		}
	})
}

// Canceling Run's context sends one last hello, which advertises three
// way Down and reaches the neighbor, then closes the Transport, and Run
// returns the cancellation.
func TestCircuitShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		a, b := newPair(t, nil, nil)
		defer a.stop(t)

		// Once both Circuits are idle, what either tap holds from here on
		// follows the cancellation.
		synctest.Wait()
		a.drainTap()
		b.drainTap()

		b.stop(t)

		// The tap records only a hello whose write succeeded, so this one
		// went out before the Transport closed.
		want := isis.ThreeWayAdjacency{
			State:                  isis.ThreeWayDown,
			ExtendedLocalCircuitID: endB.id,
		}

		if d := diff(t, want, b.sentThreeWay(t)); d != "" {
			t.Fatalf("unexpected last hello three way adjacency (-want +got):\n%s", d)
		}

		if tes := b.tapped(); len(tes) != 0 {
			t.Fatalf("unexpected tap events after the last hello: %+v", tes)
		}

		// The neighbor answers the last hello at once, since it moves its
		// adjacency to Initializing, so only what it received is checked.
		synctest.Wait()

		tes := received(a.tapped())
		if len(tes) != 1 || tes[0].Event.SNPA != snpaB {
			t.Fatalf("expected the last hello to reach the neighbor alone, but tapped %+v", tes)
		}

		if d := diff(t, want, threeWayOf(t, tes[0].Event.Raw)); d != "" {
			t.Fatalf("unexpected received three way adjacency (-want +got):\n%s", d)
		}

		if _, _, err := b.tr.ReadPDU(make([]byte, linkPDULength)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected read error on a stopped Transport: %v", err)
		}
	})
}

// helloTLVs builds the TLVs a hello from cfg carries, in the order a
// Circuit sends them, less padding.
func helloTLVs(t *testing.T, cfg isis.CircuitConfig) []isis.TLV {
	t.Helper()

	areas, err := isis.AreaAddressesTLV(cfg.AreaAddresses)
	if err != nil {
		t.Fatalf("failed to build area addresses TLV: %v", err)
	}

	// The rig leaves Protocols to the Circuit's default.
	protocols, err := isis.ProtocolsSupportedTLV([]isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6})
	if err != nil {
		t.Fatalf("failed to build protocols supported TLV: %v", err)
	}

	v4, err := isis.IPv4InterfaceAddressesTLV(cfg.IPv4Addresses)
	if err != nil {
		t.Fatalf("failed to build IPv4 interface addresses TLV: %v", err)
	}

	v6, err := isis.IPv6InterfaceAddressesTLV(cfg.IPv6Addresses)
	if err != nil {
		t.Fatalf("failed to build IPv6 interface addresses TLV: %v", err)
	}

	threeWay, err := isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{
		State:                  isis.ThreeWayDown,
		ExtendedLocalCircuitID: cfg.ExtendedLocalCircuitID,
	})
	if err != nil {
		t.Fatalf("failed to build three way adjacency TLV: %v", err)
	}

	return []isis.TLV{areas, protocols, v4, v6, threeWay}
}

// received returns the events of tes which report a received PDU.
func received(tes []tapEvent) []tapEvent {
	return slices.DeleteFunc(tes, func(te tapEvent) bool {
		return te.Event.Direction != isis.DirectionReceived
	})
}
