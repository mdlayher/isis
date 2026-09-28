package isis_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/isis"
)

func TestPointToPointHelloRoundTrip(t *testing.T) {
	t.Parallel()

	h := helloFixture(t)

	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append hello: %v", err)
	}

	if d := diff(t, helloWire, b); d != "" {
		t.Fatalf("unexpected hello bytes (-want +got):\n%s", d)
	}

	got, err := isis.ParsePointToPointHello(b)
	if err != nil {
		t.Fatalf("failed to parse hello: %v", err)
	}

	if d := diff(t, h, got); d != "" {
		t.Fatalf("unexpected hello (-want +got):\n%s", d)
	}
}

func TestPointToPointHelloTypedTLVs(t *testing.T) {
	t.Parallel()

	h, err := isis.ParsePointToPointHello(helloWire)
	if err != nil {
		t.Fatalf("failed to parse hello: %v", err)
	}

	if h.Levels != isis.Level2Only {
		t.Fatalf("unexpected levels: want %s, got %s", isis.Level2Only, h.Levels)
	}

	if want := (isis.SystemID{0, 0, 0, 0, 0, 1}); h.SourceID != want {
		t.Fatalf("unexpected source ID: want %s, got %s", want, h.SourceID)
	}

	if h.HoldingTime != 30*time.Second {
		t.Fatalf("unexpected holding time: want %s, got %s", 30*time.Second, h.HoldingTime)
	}

	// Every modeled TLV decodes to the value the fixture was built from,
	// and the walk visits them in wire order with nothing left over.
	type typed struct {
		Types      []isis.TLVType
		Areas      []string
		Protocols  []isis.NLPID
		IPv4, IPv6 []netip.Addr
		ThreeWay   isis.ThreeWayAdjacency
	}

	var got typed
	for _, tlv := range h.TLVs {
		got.Types = append(got.Types, tlv.Type)

		switch tlv.Type {
		case isis.TLVAreaAddresses:
			var as []isis.AreaAddress
			as, err = tlv.AreaAddresses()
			got.Areas = stringsOf(as)
		case isis.TLVProtocolsSupported:
			got.Protocols, err = tlv.ProtocolsSupported()
		case isis.TLVIPv4InterfaceAddresses:
			got.IPv4, err = tlv.IPv4InterfaceAddresses()
		case isis.TLVIPv6InterfaceAddresses:
			got.IPv6, err = tlv.IPv6InterfaceAddresses()
		case isis.TLVThreeWayAdjacency:
			got.ThreeWay, err = tlv.ThreeWayAdjacency()
		default:
			t.Fatalf("unexpected TLV in the fixture: %s", tlv.Type)
		}

		if err != nil {
			t.Fatalf("failed to parse %s: %v", tlv.Type, err)
		}
	}

	want := typed{
		Types: []isis.TLVType{
			isis.TLVAreaAddresses,
			isis.TLVProtocolsSupported,
			isis.TLVIPv4InterfaceAddresses,
			isis.TLVIPv6InterfaceAddresses,
			isis.TLVThreeWayAdjacency,
		},
		Areas:     []string{"49.0001"},
		Protocols: []isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6},
		IPv4:      []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		IPv6:      []netip.Addr{netip.MustParseAddr("fe80::1")},
		ThreeWay: isis.ThreeWayAdjacency{
			State:                          isis.ThreeWayInitializing,
			ExtendedLocalCircuitID:         0x2a,
			NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
			NeighborExtendedLocalCircuitID: 0x0b,
		},
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected typed TLVs (-want +got):\n%s", d)
	}
}

func TestPointToPointHelloPaddedToMTU(t *testing.T) {
	t.Parallel()

	// FRR pads every hello to the interface MTU less the LLC header. A
	// receiver which sizes its buffer from the ISO default of 1492 loses
	// the whole PDU, so the codec is exercised at the size FRR really
	// sends.
	const mtu = 1497

	h := helloFixture(t)
	h.PadTo = mtu

	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append hello: %v", err)
	}

	if len(b) != mtu {
		t.Fatalf("unexpected padded length: want %d, got %d", mtu, len(b))
	}

	if n := int(binary.BigEndian.Uint16(b[17:19])); n != mtu {
		t.Fatalf("unexpected PDU length field: want %d, got %d", mtu, n)
	}

	got, err := isis.ParsePointToPointHello(b)
	if err != nil {
		t.Fatalf("failed to parse padded hello: %v", err)
	}

	// The padding arrives as ordinary TLVs after the five the fixture
	// carries, and the walk accounts for every octet of the PDU.
	var pad int
	for _, tlv := range got.TLVs[5:] {
		if tlv.Type != isis.TLVPadding {
			t.Fatalf("unexpected TLV after the fixture's: %s", tlv.Type)
		}

		if d := diff(t, make([]byte, len(tlv.Value)), tlv.Value); d != "" {
			t.Fatalf("padding TLV is not zero filled (-want +got):\n%s", d)
		}

		pad += 2 + len(tlv.Value)
	}

	if want := mtu - len(helloWire); pad != want {
		t.Fatalf("unexpected padding octets: want %d, got %d", want, pad)
	}
}

func TestPointToPointHelloEthernetTrailer(t *testing.T) {
	t.Parallel()

	// An Ethernet frame below the medium's 60 octet minimum arrives
	// padded by the sender's hardware, so a short hello is delivered with
	// octets past its PDU length which are not TLVs.
	h := &isis.PointToPointHello{
		Levels:      isis.Level2Only,
		SourceID:    isis.SystemID{0, 0, 0, 0, 0, 1},
		HoldingTime: 30 * time.Second,
	}

	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append hello: %v", err)
	}

	got, err := isis.ParsePointToPointHello(append(b, make([]byte, 60-len(b))...))
	if err != nil {
		t.Fatalf("failed to parse hello with a frame trailer: %v", err)
	}

	if d := diff(t, h, got); d != "" {
		t.Fatalf("unexpected hello (-want +got):\n%s", d)
	}
}

func TestParsePointToPointHelloMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mut  func(b []byte)
		err  string
	}{
		{
			name: "wrong discriminator",
			mut:  func(b []byte) { b[0] = 0x82 },
			err:  "isis: PDU discriminator is 0x82, not 0x83",
		},
		{
			name: "wrong length indicator",
			mut:  func(b []byte) { b[1] = 27 },
			err:  "isis: a point to point hello header is 20 octets, not the 27 the length indicator claims",
		},
		{
			name: "wrong protocol ID extension",
			mut:  func(b []byte) { b[2] = 2 },
			err:  "isis: unsupported version/protocol ID extension 2",
		},
		{
			name: "unsupported ID length",
			mut:  func(b []byte) { b[3] = 8 },
			err:  "isis: unsupported ID length 8",
		},
		{
			// A LAN hello header is longer, so the length indicator must
			// match it for the PDU to reach the hello's own type check.
			name: "LAN hello type",
			mut: func(b []byte) {
				b[1] = 27
				b[4] = uint8(isis.PDUL2LANHello)
			},
			err: "isis: PDU is a Level 2 LAN hello, not a point to point hello",
		},
		{
			name: "unassigned type",
			mut:  func(b []byte) { b[4] = 19 },
			err:  "isis: PDU type 19 does not exist",
		},
		{
			name: "wrong version",
			mut:  func(b []byte) { b[5] = 2 },
			err:  "isis: unsupported version 2",
		},
		{
			name: "unsupported maximum area addresses",
			mut:  func(b []byte) { b[7] = 5 },
			err:  "isis: maximum area addresses 5 does not match the 3 this package permits",
		},
		{
			name: "no levels",
			mut:  func(b []byte) { b[8] = 0 },
			err:  "isis: hello circuit type 0 names no level",
		},
		{
			name: "zero source ID",
			mut:  func(b []byte) { clear(b[9:15]) },
			err:  "isis: hello source system ID must be nonzero",
		},
		{
			name: "zero holding time",
			mut:  func(b []byte) { clear(b[15:17]) },
			err:  "isis: hello holding time must be nonzero",
		},
		{
			name: "PDU length past the octets received",
			mut:  func(b []byte) { binary.BigEndian.PutUint16(b[17:19], uint16(len(b)+1)) },
			err:  "isis: point to point hello PDU length 72 is outside its 20 octet header and the 71 octets received",
		},
		{
			name: "PDU length inside the header",
			mut:  func(b []byte) { binary.BigEndian.PutUint16(b[17:19], 19) },
			err:  "isis: point to point hello PDU length 19 is outside its 20 octet header and the 71 octets received",
		},
		{
			name: "TLV overruns the PDU",
			mut:  func(b []byte) { b[21] = 0xff },
			err:  "isis: Area Addresses declares 255 octets but 49 remain",
		},
		{
			name: "TLV value cut short by the PDU end",
			mut:  func(b []byte) { binary.BigEndian.PutUint16(b[17:19], uint16(len(helloWire)-1)) },
			err:  "isis: Point-to-Point Three-Way Adjacency declares 15 octets but 14 remain",
		},
		{
			// The PDU ends one octet into the three way adjacency TLV's
			// header, after the 34 octets of the four TLVs before it.
			name: "TLV header straddles the PDU end",
			mut:  func(b []byte) { binary.BigEndian.PutUint16(b[17:19], 20+34+1) },
			err:  "isis: one octet remains, too few for a TLV header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := bytes.Clone(helloWire)
			tt.mut(b)

			h, err := isis.ParsePointToPointHello(b)
			if err == nil {
				t.Fatalf("expected an error, but parsed: %+v", h)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestPointToPointHelloAppendRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    isis.PointToPointHello
		err  string
	}{
		{
			name: "no levels",
			h: isis.PointToPointHello{
				SourceID:    isis.SystemID{1},
				HoldingTime: 1 * time.Second,
			},
			err: "isis: hello circuit type 0 names no level",
		},
		{
			name: "zero source ID",
			h: isis.PointToPointHello{
				Levels:      isis.Level2Only,
				HoldingTime: 1 * time.Second,
			},
			err: "isis: hello source system ID must be nonzero",
		},
		{
			name: "zero holding time",
			h: isis.PointToPointHello{
				Levels:   isis.Level2Only,
				SourceID: isis.SystemID{1},
			},
			err: "isis: holding time must be 1 to 65535 whole seconds: 0s",
		},
		{
			name: "fractional holding time",
			h: isis.PointToPointHello{
				Levels:      isis.Level2Only,
				SourceID:    isis.SystemID{1},
				HoldingTime: 1500 * time.Millisecond,
			},
			err: "isis: holding time must be 1 to 65535 whole seconds: 1.5s",
		},
		{
			name: "holding time over the wire's 16 bits",
			h: isis.PointToPointHello{
				Levels:      isis.Level2Only,
				SourceID:    isis.SystemID{1},
				HoldingTime: 65536 * time.Second,
			},
			err: "isis: holding time must be 1 to 65535 whole seconds: 18h12m16s",
		},
		{
			name: "oversized TLV",
			h: isis.PointToPointHello{
				Levels:      isis.Level2Only,
				SourceID:    isis.SystemID{1},
				HoldingTime: 1 * time.Second,
				TLVs: []isis.TLV{{
					Type:  isis.TLVPadding,
					Value: make([]byte, 256),
				}},
			},
			err: "isis: Padding value is 256 octets, over the wire's 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.h.AppendBinary(nil)
			if err == nil {
				t.Fatalf("expected an error, but appended: %x", b)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestPointToPointHelloAppendToBuffer(t *testing.T) {
	t.Parallel()

	// A caller may reuse one marshal buffer, so the PDU length field must
	// count only the octets this call appended.
	h := helloFixture(t)

	b, err := h.AppendBinary(make([]byte, 0, 2048))
	if err != nil {
		t.Fatalf("failed to append hello: %v", err)
	}

	b = append(b, 0xde, 0xad)

	b, err = h.AppendBinary(b)
	if err != nil {
		t.Fatalf("failed to append second hello: %v", err)
	}

	if d := diff(t, helloWire, b[len(helloWire)+2:]); d != "" {
		t.Fatalf("unexpected second hello bytes (-want +got):\n%s", d)
	}
}

func FuzzParsePointToPointHello(f *testing.F) {
	f.Add(helloWire)
	f.Add(append(bytes.Clone(helloWire), make([]byte, 40)...))
	f.Add(helloWire[:20])
	f.Add([]byte{0x83, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00})

	padded := helloFixture(f)
	padded.PadTo = 1497

	b, err := padded.AppendBinary(nil)
	if err != nil {
		f.Fatalf("failed to append padded hello: %v", err)
	}

	f.Add(b)

	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := isis.ParsePointToPointHello(b)
		if err != nil {
			return
		}

		// The walk accounted for every octet of the variable length part,
		// which is the PDU length less the fixed header.
		var n int
		for _, tlv := range h.TLVs {
			n += 2 + len(tlv.Value)
		}

		if want := int(binary.BigEndian.Uint16(b[17:19])) - 20; n != want {
			t.Fatalf("TLVs account for %d octets, not the %d in the PDU", n, want)
		}

		// Encoding is stable: what parses re-encodes, and what that
		// produces parses to the same hello and the same bytes. The
		// reserved bits a receiver must ignore are why this is idempotence
		// rather than byte for byte equality with b.
		b1, err := h.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-append a hello which parsed: %v", err)
		}

		h2, err := isis.ParsePointToPointHello(b1)
		if err != nil {
			t.Fatalf("failed to parse a hello this package built: %v", err)
		}

		if d := diff(t, h, h2); d != "" {
			t.Fatalf("unstable hello (-first +second):\n%s", d)
		}

		b2, err := h2.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-append a hello this package built: %v", err)
		}

		// cmp compares a []byte one element at a time, which stalls the
		// fuzzer while it minimizes a large input, so bytes.Equal decides
		// and diff only reports.
		if !bytes.Equal(b1, b2) {
			t.Fatalf("unstable encoding (-first +second):\n%s", diff(t, b1, b2))
		}
	})
}

// helloWire is the fixture hello's wire form, assembled from ISO 10589
// clause 9.7 and the TLV formats of RFC 1195, RFC 5303, and RFC 5308. Its
// variable length part is tlvRegion itself, so the two cannot drift.
var helloWire = slices.Concat(
	[]byte{
		// Common header: discriminator, length indicator 20, protocol ID
		// extension 1, ID length 0 meaning 6, PDU type 17, version 1, the
		// reserved octet, maximum area addresses 0 meaning 3.
		0x83, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00,

		// Circuit type: Level 2 only.
		0x02,

		// Source ID 0000.0000.0001.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

		// Holding time, 30 seconds.
		0x00, 0x1e,

		// PDU length, 71 octets: this header and the 51 of tlvRegion.
		0x00, 0x47,

		// Local circuit ID.
		0x01,
	},
	tlvRegion,
)

// helloFixture builds the typed hello helloWire encodes.
func helloFixture(tb testing.TB) *isis.PointToPointHello {
	tb.Helper()

	area, err := isis.NewAreaAddress([]byte{0x49, 0x00, 0x01})
	if err != nil {
		tb.Fatalf("failed to build area address: %v", err)
	}

	areas, err := isis.AreaAddressesTLV([]isis.AreaAddress{area})
	if err != nil {
		tb.Fatalf("failed to build area addresses TLV: %v", err)
	}

	protocols, err := isis.ProtocolsSupportedTLV([]isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6})
	if err != nil {
		tb.Fatalf("failed to build protocols supported TLV: %v", err)
	}

	v4, err := isis.IPv4InterfaceAddressesTLV([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		tb.Fatalf("failed to build IPv4 interface addresses TLV: %v", err)
	}

	v6, err := isis.IPv6InterfaceAddressesTLV([]netip.Addr{netip.MustParseAddr("fe80::1")})
	if err != nil {
		tb.Fatalf("failed to build IPv6 interface addresses TLV: %v", err)
	}

	threeWay, err := isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{
		State:                          isis.ThreeWayInitializing,
		ExtendedLocalCircuitID:         0x2a,
		NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
		NeighborExtendedLocalCircuitID: 0x0b,
	})
	if err != nil {
		tb.Fatalf("failed to build three way adjacency TLV: %v", err)
	}

	return &isis.PointToPointHello{
		Levels:         isis.Level2Only,
		SourceID:       isis.SystemID{0, 0, 0, 0, 0, 1},
		HoldingTime:    30 * time.Second,
		LocalCircuitID: 1,
		TLVs:           []isis.TLV{areas, protocols, v4, v6, threeWay},
	}
}
