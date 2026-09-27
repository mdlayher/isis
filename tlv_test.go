package isis_test

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/mdlayher/isis"
)

func TestTLVsAccountForEveryOctet(t *testing.T) {
	t.Parallel()

	// The walk consumes every octet of the variable length part with no
	// remainder and no overrun.
	var (
		types []isis.TLVType
		n     int
	)

	for tlv, err := range isis.TLVs(tlvRegion) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		types = append(types, tlv.Type)
		n += 2 + len(tlv.Value)
	}

	if n != len(tlvRegion) {
		t.Fatalf("unexpected octets accounted for: want %d, got %d", len(tlvRegion), n)
	}

	want := []isis.TLVType{
		isis.TLVAreaAddresses,
		isis.TLVProtocolsSupported,
		isis.TLVIPv4InterfaceAddresses,
		isis.TLVIPv6InterfaceAddresses,
		isis.TLVThreeWayAdjacency,
	}

	if d := diff(t, want, types); d != "" {
		t.Fatalf("unexpected TLV types (-want +got):\n%s", d)
	}
}

func TestTLVsStopAtFirstError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
		err  string
	}{
		{
			name: "one octet remains",
			b:    []byte{0x01, 0x02, 0xaa, 0xbb, 0x08},
			err:  "isis: one octet remains, too few for a TLV header",
		},
		{
			name: "length overruns the region",
			b:    []byte{0x01, 0x02, 0xaa, 0xbb, 0x08, 0x04, 0x00},
			err:  "isis: Padding declares 4 octets but 1 remain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				got  []isis.TLVType
				gerr error
			)

			for tlv, err := range isis.TLVs(tt.b) {
				if err != nil {
					gerr = err
					continue
				}

				got = append(got, tlv.Type)
			}

			if gerr == nil {
				t.Fatal("expected an error, but the walk succeeded")
			}

			// The well formed prefix is still yielded, and the walk stops
			// at the malformed remainder rather than looping on it.
			if d := diff(t, []isis.TLVType{isis.TLVAreaAddresses}, got); d != "" {
				t.Fatalf("unexpected TLV types (-want +got):\n%s", d)
			}

			if got := gerr.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestTLVsBreakEarly(t *testing.T) {
	t.Parallel()

	// A caller which finds what it wants stops the walk.
	var got []isis.TLVType
	for tlv := range isis.TLVs(tlvRegion) {
		got = append(got, tlv.Type)
		if tlv.Type == isis.TLVProtocolsSupported {
			break
		}
	}

	if d := diff(t, []isis.TLVType{isis.TLVAreaAddresses, isis.TLVProtocolsSupported}, got); d != "" {
		t.Fatalf("unexpected TLV types (-want +got):\n%s", d)
	}
}

func TestTLVsValueAppendCopies(t *testing.T) {
	t.Parallel()

	// A value aliases the region, but appending to it must copy rather
	// than overwrite the TLV which follows it.
	b := bytes.Clone(tlvRegion)

	for tlv, err := range isis.TLVs(b) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		_ = append(tlv.Value, 0xff, 0xff)
		break
	}

	if d := diff(t, tlvRegion, b); d != "" {
		t.Fatalf("unexpected region after append (-want +got):\n%s", d)
	}
}

func TestTLVAppendBinaryLongestValue(t *testing.T) {
	t.Parallel()

	// A value of 255 octets is the most the one octet length field can
	// declare, and it survives a round trip through the walk.
	want := isis.TLV{
		Type:  isis.TLVPadding,
		Value: make([]byte, 255),
	}

	b, err := want.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append TLV: %v", err)
	}

	if len(b) != 2+255 {
		t.Fatalf("unexpected encoded length: want %d, got %d", 2+255, len(b))
	}

	var got []isis.TLV
	for tlv, err := range isis.TLVs(b) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		got = append(got, tlv)
	}

	if d := diff(t, []isis.TLV{want}, got); d != "" {
		t.Fatalf("unexpected TLVs (-want +got):\n%s", d)
	}
}

func TestTLVAppendBinaryRejectsLongValue(t *testing.T) {
	t.Parallel()

	// One octet more than the length field can declare is refused rather
	// than truncated on the wire.
	tlv := isis.TLV{
		Type:  isis.TLVPadding,
		Value: make([]byte, 256),
	}

	b, err := tlv.AppendBinary(nil)
	if err == nil {
		t.Fatalf("expected an error, but appended %d octets", len(b))
	}

	if want := "isis: Padding value is 256 octets, over the wire's 255"; err.Error() != want {
		t.Fatalf("unexpected error: want %q, got %q", want, err)
	}
}

func TestTLVTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  isis.TLVType
		want string
	}{
		{
			name: "named",
			typ:  isis.TLVThreeWayAdjacency,
			want: "Point-to-Point Three-Way Adjacency",
		},
		{
			name: "unnamed",
			typ:  250,
			want: "TLV 250",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.typ.String(); got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestTLVRoundTrip(t *testing.T) {
	t.Parallel()

	// Each case builds a TLV from typed values, encodes it to the exact
	// wire octets, walks it back out, and parses the typed values again.
	tests := []struct {
		name  string
		build func() (isis.TLV, error)
		wire  []byte
		parse func(isis.TLV) (any, error)
		want  any
	}{
		{
			name: "area addresses",
			build: func() (isis.TLV, error) {
				return isis.AreaAddressesTLV([]isis.AreaAddress{
					mustAreaAddress(t, []byte{0x49, 0x00, 0x01}),
					mustAreaAddress(t, []byte{0x47, 0x00, 0x23, 0x00, 0x00}),
				})
			},
			wire: []byte{
				0x01, 0x0a,
				0x03, 0x49, 0x00, 0x01,
				0x05, 0x47, 0x00, 0x23, 0x00, 0x00,
			},
			parse: func(tlv isis.TLV) (any, error) { return tlv.AreaAddresses() },
			want: []isis.AreaAddress{
				mustAreaAddress(t, []byte{0x49, 0x00, 0x01}),
				mustAreaAddress(t, []byte{0x47, 0x00, 0x23, 0x00, 0x00}),
			},
		},
		{
			name: "protocols supported",
			build: func() (isis.TLV, error) {
				return isis.ProtocolsSupportedTLV([]isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6})
			},
			wire:  []byte{0x81, 0x02, 0xcc, 0x8e},
			parse: func(tlv isis.TLV) (any, error) { return tlv.ProtocolsSupported() },
			want:  []isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6},
		},
		{
			name: "IPv4 interface addresses",
			build: func() (isis.TLV, error) {
				return isis.IPv4InterfaceAddressesTLV([]netip.Addr{
					netip.MustParseAddr("192.0.2.1"),
					netip.MustParseAddr("192.0.2.2"),
				})
			},
			wire: []byte{
				0x84, 0x08,
				0xc0, 0x00, 0x02, 0x01,
				0xc0, 0x00, 0x02, 0x02,
			},
			parse: func(tlv isis.TLV) (any, error) { return tlv.IPv4InterfaceAddresses() },
			want: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("192.0.2.2"),
			},
		},
		{
			name: "IPv6 interface addresses",
			build: func() (isis.TLV, error) {
				return isis.IPv6InterfaceAddressesTLV([]netip.Addr{
					netip.MustParseAddr("fe80::1"),
					netip.MustParseAddr("fe80::2"),
				})
			},
			wire: []byte{
				0xe8, 0x20,
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
			parse: func(tlv isis.TLV) (any, error) { return tlv.IPv6InterfaceAddresses() },
			want: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("fe80::2"),
			},
		},
		{
			name: "three way adjacency, neighbor heard",
			build: func() (isis.TLV, error) {
				return isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{
					State:                          isis.ThreeWayUp,
					ExtendedLocalCircuitID:         0x2a,
					NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
					NeighborExtendedLocalCircuitID: 0x0b,
				})
			},
			wire: []byte{
				0xf0, 0x0f,
				0x00,
				0x00, 0x00, 0x00, 0x2a,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				0x00, 0x00, 0x00, 0x0b,
			},
			parse: func(tlv isis.TLV) (any, error) { return tlv.ThreeWayAdjacency() },
			want: isis.ThreeWayAdjacency{
				State:                          isis.ThreeWayUp,
				ExtendedLocalCircuitID:         0x2a,
				NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
				NeighborExtendedLocalCircuitID: 0x0b,
			},
		},
		{
			// A SystemID is never zero, so the zero NeighborSystemID is
			// what selects the five octet form.
			name: "three way adjacency, neighbor not heard",
			build: func() (isis.TLV, error) {
				return isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{
					State:                  isis.ThreeWayDown,
					ExtendedLocalCircuitID: 0x2a,
				})
			},
			wire:  []byte{0xf0, 0x05, 0x02, 0x00, 0x00, 0x00, 0x2a},
			parse: func(tlv isis.TLV) (any, error) { return tlv.ThreeWayAdjacency() },
			want: isis.ThreeWayAdjacency{
				State:                  isis.ThreeWayDown,
				ExtendedLocalCircuitID: 0x2a,
			},
		},
		{
			// The states are the wire encoding, where Up is 0, so a zero
			// ThreeWayAdjacency claims Up rather than Down.
			name:  "three way adjacency, zero value",
			build: func() (isis.TLV, error) { return isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{}) },
			wire:  []byte{0xf0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
			parse: func(tlv isis.TLV) (any, error) { return tlv.ThreeWayAdjacency() },
			want:  isis.ThreeWayAdjacency{State: isis.ThreeWayUp},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tlv, err := tt.build()
			if err != nil {
				t.Fatalf("failed to build TLV: %v", err)
			}

			b, err := tlv.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to append TLV: %v", err)
			}

			if d := diff(t, tt.wire, b); d != "" {
				t.Fatalf("unexpected encoding (-want +got):\n%s", d)
			}

			var tlvs []isis.TLV
			for w, err := range isis.TLVs(b) {
				if err != nil {
					t.Fatalf("failed to walk TLVs: %v", err)
				}

				tlvs = append(tlvs, w)
			}

			if len(tlvs) != 1 {
				t.Fatalf("unexpected TLV count: want 1, got %d", len(tlvs))
			}

			got, err := tt.parse(tlvs[0])
			if err != nil {
				t.Fatalf("failed to parse TLV: %v", err)
			}

			if d := diff(t, tt.want, got); d != "" {
				t.Fatalf("unexpected typed value (-want +got):\n%s", d)
			}
		})
	}
}

func TestTypedTLVsParseRegion(t *testing.T) {
	t.Parallel()

	// Each TLV of a hello's variable length part parses through its typed
	// accessor to the values the fixture states.
	type region struct {
		Areas      []isis.AreaAddress
		Protocols  []isis.NLPID
		IPv4, IPv6 []netip.Addr
		ThreeWay   isis.ThreeWayAdjacency
	}

	var got region
	for tlv, err := range isis.TLVs(tlvRegion) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		switch tlv.Type {
		case isis.TLVAreaAddresses:
			got.Areas, err = tlv.AreaAddresses()
		case isis.TLVProtocolsSupported:
			got.Protocols, err = tlv.ProtocolsSupported()
		case isis.TLVIPv4InterfaceAddresses:
			got.IPv4, err = tlv.IPv4InterfaceAddresses()
		case isis.TLVIPv6InterfaceAddresses:
			got.IPv6, err = tlv.IPv6InterfaceAddresses()
		case isis.TLVThreeWayAdjacency:
			got.ThreeWay, err = tlv.ThreeWayAdjacency()
		default:
			t.Fatalf("unexpected TLV in the region: %s", tlv.Type)
		}

		if err != nil {
			t.Fatalf("failed to parse %s: %v", tlv.Type, err)
		}
	}

	want := region{
		Areas:     []isis.AreaAddress{mustAreaAddress(t, []byte{0x49, 0x00, 0x01})},
		Protocols: []isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6},
		IPv4:      []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		IPv6:      []netip.Addr{netip.MustParseAddr("fe80::1")},
		ThreeWay: isis.ThreeWayAdjacency{
			State:                          isis.ThreeWayInitializing,
			ExtendedLocalCircuitID:         42,
			NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
			NeighborExtendedLocalCircuitID: 11,
		},
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected typed TLVs (-want +got):\n%s", d)
	}

	if d := diff(t, []string{"49.0001"}, stringsOf(got.Areas)); d != "" {
		t.Fatalf("unexpected area address strings (-want +got):\n%s", d)
	}
}

func TestThreeWayAdjacencyForms(t *testing.T) {
	t.Parallel()

	// RFC 5303 section 3.1 lets a sender omit the trailing fields it does
	// not know, and FRR emits the five octet form until it has heard its
	// neighbor.
	tests := []struct {
		name string
		v    []byte
		want isis.ThreeWayAdjacency
	}{
		{
			name: "state only",
			v:    []byte{0x02},
			want: isis.ThreeWayAdjacency{State: isis.ThreeWayDown},
		},
		{
			name: "neighbor not yet heard",
			v:    []byte{0x02, 0x00, 0x00, 0x00, 0x2a},
			want: isis.ThreeWayAdjacency{
				State:                  isis.ThreeWayDown,
				ExtendedLocalCircuitID: 0x2a,
			},
		},
		{
			name: "neighbor system ID only",
			v:    []byte{0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			want: isis.ThreeWayAdjacency{
				State:                  isis.ThreeWayInitializing,
				ExtendedLocalCircuitID: 0x2a,
				NeighborSystemID:       isis.SystemID{0, 0, 0, 0, 0, 2},
			},
		},
		{
			name: "neighbor fully known",
			v: []byte{
				0x00,
				0x00, 0x00, 0x00, 0x2a,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				0x00, 0x00, 0x00, 0x0b,
			},
			want: isis.ThreeWayAdjacency{
				State:                          isis.ThreeWayUp,
				ExtendedLocalCircuitID:         0x2a,
				NeighborSystemID:               isis.SystemID{0, 0, 0, 0, 0, 2},
				NeighborExtendedLocalCircuitID: 0x0b,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tlv := isis.TLV{
				Type:  isis.TLVThreeWayAdjacency,
				Value: tt.v,
			}

			got, err := tlv.ThreeWayAdjacency()
			if err != nil {
				t.Fatalf("failed to parse three way adjacency: %v", err)
			}

			if d := diff(t, tt.want, got); d != "" {
				t.Fatalf("unexpected three way adjacency (-want +got):\n%s", d)
			}
		})
	}
}

func TestTLVBuildRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() (isis.TLV, error)
		err   string
	}{
		{
			name: "IPv6 in the IPv4 TLV",
			build: func() (isis.TLV, error) {
				return isis.IPv4InterfaceAddressesTLV([]netip.Addr{netip.MustParseAddr("fe80::1")})
			},
			err: "isis: fe80::1 is not an IPv4 address",
		},
		{
			name: "IPv4 in the IPv6 TLV",
			build: func() (isis.TLV, error) {
				return isis.IPv6InterfaceAddressesTLV([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
			},
			err: "isis: 192.0.2.1 is not an IPv6 address",
		},
		{
			name: "IPv4 mapped IPv6 in the IPv6 TLV",
			build: func() (isis.TLV, error) {
				return isis.IPv6InterfaceAddressesTLV([]netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")})
			},
			err: "isis: ::ffff:192.0.2.1 is an IPv4 mapped address: unmap it and use the IPv4 interface address TLV",
		},
		{
			name: "too many IPv6 interface addresses",
			build: func() (isis.TLV, error) {
				return isis.IPv6InterfaceAddressesTLV(slices.Repeat([]netip.Addr{netip.MustParseAddr("fe80::1")}, 16))
			},
			err: "isis: 16 IPv6 interface addresses need 256 octets, over the wire's 255",
		},
		{
			name:  "three way state which does not exist",
			build: func() (isis.TLV, error) { return isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{State: 3}) },
			err:   "isis: three way state 3 does not exist",
		},
		{
			name: "neighbor circuit without a neighbor system ID",
			build: func() (isis.TLV, error) {
				return isis.ThreeWayAdjacencyTLV(isis.ThreeWayAdjacency{
					State:                          isis.ThreeWayUp,
					ExtendedLocalCircuitID:         0x2a,
					NeighborExtendedLocalCircuitID: 0x0b,
				})
			},
			err: "isis: neighbor extended local circuit ID 11 has no neighbor system ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tlv, err := tt.build()
			if err == nil {
				t.Fatalf("expected an error, but built: %+v", tlv)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestTLVParseRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		tlv   isis.TLV
		parse func(isis.TLV) error
		err   string
	}{
		{
			name:  "area addresses on the wrong code point",
			tlv:   isis.TLV{Type: isis.TLVPadding},
			parse: func(tlv isis.TLV) error { _, err := tlv.AreaAddresses(); return err },
			err:   "isis: TLV is Padding, not Area Addresses",
		},
		{
			name: "area address past the TLV end",
			tlv: isis.TLV{
				Type:  isis.TLVAreaAddresses,
				Value: []byte{0x05, 0x49, 0x00},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.AreaAddresses(); return err },
			err:   "isis: area address declares 5 octets but 2 remain",
		},
		{
			name: "empty area address",
			tlv: isis.TLV{
				Type:  isis.TLVAreaAddresses,
				Value: []byte{0x00},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.AreaAddresses(); return err },
			err:   "isis: area address must be 1 to 20 octets: 0 octets",
		},
		{
			name: "partial IPv4 address",
			tlv: isis.TLV{
				Type:  isis.TLVIPv4InterfaceAddresses,
				Value: []byte{0xc0, 0x00, 0x02},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.IPv4InterfaceAddresses(); return err },
			err:   "isis: IP Interface Address is 3 octets, not a whole number of IPv4 addresses",
		},
		{
			name: "partial IPv6 address",
			tlv: isis.TLV{
				Type:  isis.TLVIPv6InterfaceAddresses,
				Value: make([]byte, 15),
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.IPv6InterfaceAddresses(); return err },
			err:   "isis: IPv6 Interface Address is 15 octets, not a whole number of IPv6 addresses",
		},
		{
			name: "IPv4 mapped IPv6 address",
			tlv: isis.TLV{
				Type:  isis.TLVIPv6InterfaceAddresses,
				Value: netip.MustParseAddr("::ffff:192.0.2.1").AsSlice(),
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.IPv6InterfaceAddresses(); return err },
			err:   "isis: IPv6 Interface Address carries IPv4 mapped address ::ffff:192.0.2.1",
		},
		{
			name: "three way adjacency of an undefined length",
			tlv: isis.TLV{
				Type:  isis.TLVThreeWayAdjacency,
				Value: make([]byte, 7),
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.ThreeWayAdjacency(); return err },
			err:   "isis: Point-to-Point Three-Way Adjacency is 7 octets, not 1, 5, 11, or 15",
		},
		{
			name: "three way state which does not exist",
			tlv: isis.TLV{
				Type:  isis.TLVThreeWayAdjacency,
				Value: []byte{0x03},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.ThreeWayAdjacency(); return err },
			err:   "isis: three way state 3 does not exist",
		},
		{
			name: "zero neighbor system ID",
			tlv: isis.TLV{
				Type:  isis.TLVThreeWayAdjacency,
				Value: []byte{0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.ThreeWayAdjacency(); return err },
			err:   "isis: Point-to-Point Three-Way Adjacency names the zero neighbor system ID",
		},
		{
			name: "zero neighbor system ID with a neighbor circuit",
			tlv: isis.TLV{
				Type: isis.TLVThreeWayAdjacency,
				Value: []byte{
					0x00,
					0x00, 0x00, 0x00, 0x2a,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x0b,
				},
			},
			parse: func(tlv isis.TLV) error { _, err := tlv.ThreeWayAdjacency(); return err },
			err:   "isis: Point-to-Point Three-Way Adjacency names the zero neighbor system ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.parse(tt.tlv)
			if err == nil {
				t.Fatal("expected an error, but the parse succeeded")
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestNLPIDString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    isis.NLPID
		want string
	}{
		{
			name: "IPv4",
			n:    isis.NLPIDIPv4,
			want: "IPv4",
		},
		{
			name: "IPv6",
			n:    isis.NLPIDIPv6,
			want: "IPv6",
		},
		{
			name: "unnamed",
			n:    0x81,
			want: "NLPID 0x81",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.n.String(); got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestThreeWayStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    isis.ThreeWayState
		want string
	}{
		{
			name: "Up",
			s:    isis.ThreeWayUp,
			want: "Up",
		},
		{
			name: "Initializing",
			s:    isis.ThreeWayInitializing,
			want: "Initializing",
		},
		{
			name: "Down",
			s:    isis.ThreeWayDown,
			want: "Down",
		},
		{
			name: "unknown",
			s:    3,
			want: "unknown(3)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.s.String(); got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, got)
			}
		})
	}
}

func FuzzTLVs(f *testing.F) {
	f.Add(tlvRegion)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(tlvRegion[:len(tlvRegion)-3])

	f.Fuzz(func(t *testing.T, b []byte) {
		// Either every TLV is well formed and re-encoding them in order
		// reproduces b exactly, or the walk yields one error as its last
		// element and what came before it re-encodes to a prefix of b.
		var (
			out  []byte
			gerr error
		)

		for tlv, err := range isis.TLVs(b) {
			if gerr != nil {
				t.Fatalf("walk yielded %+v after its error: %v", tlv, gerr)
			}

			if err != nil {
				if d := diff(t, isis.TLV{}, tlv); d != "" {
					t.Fatalf("unexpected TLV alongside error (-want +got):\n%s", d)
				}

				gerr = err
				continue
			}

			out, err = tlv.AppendBinary(out)
			if err != nil {
				t.Fatalf("failed to append walked TLV: %v", err)
			}
		}

		if gerr != nil {
			b = b[:min(len(out), len(b))]
		}

		// cmp compares a []byte one element at a time, which stalls the
		// fuzzer while it minimizes a large input, so bytes.Equal decides
		// and diff only reports.
		if !bytes.Equal(b, out) {
			t.Fatalf("unexpected re-encoding (-want +got):\n%s", diff(t, b, out))
		}
	})
}

func FuzzTypedTLVs(f *testing.F) {
	for tlv, err := range isis.TLVs(tlvRegion) {
		if err != nil {
			f.Fatalf("failed to walk TLVs: %v", err)
		}

		f.Add(tlv.Value)
	}

	f.Add([]byte{})

	// An IPv4 mapped IPv6 address, which the parser refuses.
	f.Add(netip.MustParseAddr("::ffff:192.0.2.1").AsSlice())

	f.Fuzz(func(t *testing.T, b []byte) {
		// A longer value has no TLV to arrive in.
		if len(b) > 255 {
			return
		}

		fuzzTypedTLV(t, b, typedTLV[[]isis.AreaAddress]{
			Type:  isis.TLVAreaAddresses,
			Parse: isis.TLV.AreaAddresses,
			Build: isis.AreaAddressesTLV,
		})

		fuzzTypedTLV(t, b, typedTLV[[]isis.NLPID]{
			Type:  isis.TLVProtocolsSupported,
			Parse: isis.TLV.ProtocolsSupported,
			Build: isis.ProtocolsSupportedTLV,
		})

		fuzzTypedTLV(t, b, typedTLV[[]netip.Addr]{
			Type:  isis.TLVIPv4InterfaceAddresses,
			Parse: isis.TLV.IPv4InterfaceAddresses,
			Build: isis.IPv4InterfaceAddressesTLV,
		})

		fuzzTypedTLV(t, b, typedTLV[[]netip.Addr]{
			Type:  isis.TLVIPv6InterfaceAddresses,
			Parse: isis.TLV.IPv6InterfaceAddresses,
			Build: isis.IPv6InterfaceAddressesTLV,
		})

		fuzzTypedTLV(t, b, typedTLV[isis.ThreeWayAdjacency]{
			Type:  isis.TLVThreeWayAdjacency,
			Parse: isis.TLV.ThreeWayAdjacency,
			Build: isis.ThreeWayAdjacencyTLV,

			// RFC 5303 section 3.1 lets a sender omit trailing fields, but
			// the constructor emits only the 5 octet form without a
			// neighbor and the 15 octet form with one, so the 1 and 11
			// octet forms re-encode with their omitted fields as zero.
			Encoding: func(b []byte) []byte {
				v := make([]byte, 15)
				copy(v, b)
				if len(b) < 11 {
					return v[:5]
				}

				return v
			},
		})
	})
}

// tlvRegion is the variable length part of a point to point hello: the
// TLVs 1, 129, 132, 232, and 240 exactly as they follow the 20 octet
// fixed header of a Level 2 only hello from system 0000.0000.0001.
var tlvRegion = []byte{
	// TLV 1, area addresses: one address of three octets, 49.0001.
	0x01, 0x04, 0x03, 0x49, 0x00, 0x01,

	// TLV 129, protocols supported: IPv4 and IPv6.
	0x81, 0x02, 0xcc, 0x8e,

	// TLV 132, IP interface address 192.0.2.1.
	0x84, 0x04, 0xc0, 0x00, 0x02, 0x01,

	// TLV 232, IPv6 interface address fe80::1.
	0xe8, 0x10,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

	// TLV 240, three way adjacency: Initializing, extended local circuit
	// ID 42, neighbor 0000.0000.0002 on its circuit 11.
	0xf0, 0x0f,
	0x01,
	0x00, 0x00, 0x00, 0x2a,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x0b,
}

// mustAreaAddress builds an AreaAddress or fails the test.
func mustAreaAddress(t *testing.T, b []byte) isis.AreaAddress {
	t.Helper()

	a, err := isis.NewAreaAddress(b)
	if err != nil {
		t.Fatalf("failed to build area address: %v", err)
	}

	return a
}

// A typedTLV is one typed accessor and its constructor, for
// fuzzTypedTLV.
type typedTLV[T any] struct {
	Type  isis.TLVType
	Parse func(isis.TLV) (T, error)
	Build func(T) (isis.TLV, error)

	// Encoding returns what the constructor emits for the value b parses
	// to. Nil means b itself: the value has one encoding.
	Encoding func(b []byte) []byte
}

// fuzzTypedTLV checks one typed accessor against the TLV of type tt.Type
// whose value is b. A value which parses re-encodes through the
// constructor to exactly its one encoding, and the parsed value shares no
// memory with b.
func fuzzTypedTLV[T any](t *testing.T, b []byte, tt typedTLV[T]) {
	t.Helper()

	// The value is a copy, so flipping it below leaves the fuzzer's input
	// untouched for the accessors which follow.
	v := bytes.Clone(b)
	got, err := tt.Parse(isis.TLV{
		Type:  tt.Type,
		Value: v,
	})
	if err != nil {
		return
	}

	tlv, err := tt.Build(got)
	if err != nil {
		t.Fatalf("failed to build parsed %s %+v: %v", tt.Type, got, err)
	}

	enc := b
	if tt.Encoding != nil {
		enc = tt.Encoding(b)
	}

	// cmp compares a []byte one element at a time, which stalls the
	// fuzzer while it minimizes a large input, so bytes.Equal decides
	// and diff only reports.
	if !bytes.Equal(enc, tlv.Value) {
		t.Fatalf("unexpected %s re-encoding (-want +got):\n%s", tt.Type, diff(t, enc, tlv.Value))
	}

	// The encoding stands in for the parsed value: the constructors
	// allocate it afresh and give distinct values distinct encodings, so
	// an alias shows as a changed re-encoding, and bytes.Equal decides as
	// above.
	for i := range v {
		v[i] ^= 0xff
	}

	again, err := tt.Build(got)
	if err != nil {
		t.Fatalf("parsed %s aliases its input: failed to build %+v: %v", tt.Type, got, err)
	}

	if !bytes.Equal(tlv.Value, again.Value) {
		t.Fatalf("parsed %s aliases its input (-want +got):\n%s", tt.Type, diff(t, tlv.Value, again.Value))
	}
}
