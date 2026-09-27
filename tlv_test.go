package isis

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTLVsAccountForEveryOctet(t *testing.T) {
	t.Parallel()

	// The walk consumes every octet of the variable length part with no
	// remainder and no overrun.
	var (
		types []TLVType
		n     int
	)

	for tlv, err := range TLVs(tlvRegion) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		types = append(types, tlv.Type)
		n += 2 + len(tlv.Value)
	}

	if n != len(tlvRegion) {
		t.Fatalf("unexpected octets accounted for: want %d, got %d", len(tlvRegion), n)
	}

	want := []TLVType{
		TLVAreaAddresses,
		TLVProtocolsSupported,
		TLVIPv4InterfaceAddresses,
		TLVIPv6InterfaceAddresses,
		TLVThreeWayAdjacency,
	}

	if diff := cmp.Diff(want, types); diff != "" {
		t.Fatalf("unexpected TLV types (-want +got):\n%s", diff)
	}
}

func TestTLVsStopAtFirstError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "one octet remains",
			b:    []byte{0x01, 0x02, 0xaa, 0xbb, 0x08},
		},
		{
			name: "length overruns the region",
			b:    []byte{0x01, 0x02, 0xaa, 0xbb, 0x08, 0x04, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				got  []TLVType
				gerr error
			)

			for tlv, err := range TLVs(tt.b) {
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
			if diff := cmp.Diff([]TLVType{TLVAreaAddresses}, got); diff != "" {
				t.Fatalf("unexpected TLV types (-want +got):\n%s", diff)
			}

			t.Logf("err: %v", gerr)
		})
	}
}

func TestTLVsBreakEarly(t *testing.T) {
	t.Parallel()

	// A caller which finds what it wants stops the walk.
	var got []TLVType
	for tlv := range TLVs(tlvRegion) {
		got = append(got, tlv.Type)
		if tlv.Type == TLVProtocolsSupported {
			break
		}
	}

	if diff := cmp.Diff([]TLVType{TLVAreaAddresses, TLVProtocolsSupported}, got); diff != "" {
		t.Fatalf("unexpected TLV types (-want +got):\n%s", diff)
	}
}

func TestTLVsValueAppendCopies(t *testing.T) {
	t.Parallel()

	// A value aliases the region, but appending to it must copy rather
	// than overwrite the TLV which follows it.
	b := bytes.Clone(tlvRegion)

	for tlv, err := range TLVs(b) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		_ = append(tlv.Value, 0xff, 0xff)
		break
	}

	if diff := cmp.Diff(tlvRegion, b); diff != "" {
		t.Fatalf("unexpected region after append (-want +got):\n%s", diff)
	}
}

func TestTLVAppendBinaryLongestValue(t *testing.T) {
	t.Parallel()

	// A value of 255 octets is the most the one octet length field can
	// declare, and it survives a round trip through the walk.
	want := TLV{
		Type:  TLVPadding,
		Value: make([]byte, maxTLVValueLen),
	}

	b, err := want.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to append TLV: %v", err)
	}

	if len(b) != 2+maxTLVValueLen {
		t.Fatalf("unexpected encoded length: want %d, got %d", 2+maxTLVValueLen, len(b))
	}

	var got []TLV
	for tlv, err := range TLVs(b) {
		if err != nil {
			t.Fatalf("failed to walk TLVs: %v", err)
		}

		got = append(got, tlv)
	}

	if diff := cmp.Diff([]TLV{want}, got); diff != "" {
		t.Fatalf("unexpected TLVs (-want +got):\n%s", diff)
	}
}

func TestTLVAppendBinaryRejectsLongValue(t *testing.T) {
	t.Parallel()

	// One octet more than the length field can declare is refused rather
	// than truncated on the wire.
	tlv := TLV{
		Type:  TLVPadding,
		Value: make([]byte, maxTLVValueLen+1),
	}

	b, err := tlv.AppendBinary(nil)
	if err == nil {
		t.Fatalf("expected an error, but appended %d octets", len(b))
	}

	t.Logf("err: %v", err)
}

func TestTLVTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  TLVType
		want string
	}{
		{
			name: "named",
			typ:  TLVThreeWayAdjacency,
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

func TestAppendPadding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		have, n int
		want    int
	}{
		{
			name: "nothing to pad",
			have: 20,
			n:    20,
			want: 20,
		},
		{
			name: "one octet short of a TLV header",
			have: 20,
			n:    21,
			want: 20,
		},
		{
			name: "an empty padding TLV",
			have: 20,
			n:    22,
			want: 22,
		},
		{
			name: "one full TLV",
			have: 20,
			n:    277,
			want: 277,
		},
		{
			name: "the interface MTU",
			have: 71,
			n:    1497,
			want: 1497,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := appendPadding(make([]byte, tt.have), tt.n)
			if len(b) != tt.want {
				t.Fatalf("unexpected length: want %d, got %d", tt.want, len(b))
			}

			// Whatever was appended must itself be a well formed TLV run.
			var got int
			for tlv, err := range TLVs(b[tt.have:]) {
				if err != nil {
					t.Fatalf("failed to walk padding: %v", err)
				}

				if tlv.Type != TLVPadding {
					t.Fatalf("unexpected TLV in the padding: %s", tlv.Type)
				}

				got += 2 + len(tlv.Value)
			}

			if got != tt.want-tt.have {
				t.Fatalf("unexpected padding octets: want %d, got %d", tt.want-tt.have, got)
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

		for tlv, err := range TLVs(b) {
			if gerr != nil {
				t.Fatalf("walk yielded %+v after its error: %v", tlv, gerr)
			}

			if err != nil {
				if diff := cmp.Diff(TLV{}, tlv); diff != "" {
					t.Fatalf("unexpected TLV alongside error (-want +got):\n%s", diff)
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
		// and cmp.Diff only reports.
		if !bytes.Equal(b, out) {
			t.Fatalf("unexpected re-encoding (-want +got):\n%s", cmp.Diff(b, out))
		}
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
