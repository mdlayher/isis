package isis

import (
	"encoding/binary"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ PDUType
		li  uint8
	}{
		{
			typ: PDUL1LANHello,
			li:  27,
		},
		{
			typ: PDUL2LANHello,
			li:  27,
		},
		{
			typ: PDUPointToPointHello,
			li:  20,
		},
		{
			typ: PDUL1LinkState,
			li:  27,
		},
		{
			typ: PDUL2LinkState,
			li:  27,
		},
		{
			typ: PDUL1CompleteSequence,
			li:  33,
		},
		{
			typ: PDUL2CompleteSequence,
			li:  33,
		},
		{
			typ: PDUL1PartialSequence,
			li:  17,
		},
		{
			typ: PDUL2PartialSequence,
			li:  17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			t.Parallel()

			// LengthIndicator is left zero for AppendBinary to fill in
			// from Type.
			b, err := Header{Type: tt.typ}.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to append header: %v", err)
			}

			wire := []byte{0x83, tt.li, 1, 0, uint8(tt.typ), 1, 0, 0}
			if d := diff(t, wire, b); d != "" {
				t.Fatalf("unexpected header octets (-want +got):\n%s", d)
			}

			h, err := ParseHeader(pad(b, int(tt.li)))
			if err != nil {
				t.Fatalf("failed to parse header: %v", err)
			}

			want := Header{
				Type:            tt.typ,
				LengthIndicator: tt.li,
			}

			if d := diff(t, want, h); d != "" {
				t.Fatalf("unexpected header (-want +got):\n%s", d)
			}

			// The parsed header carries its length indicator, which
			// AppendBinary accepts, and appends after what b holds.
			b, err = h.AppendBinary([]byte{0xff})
			if err != nil {
				t.Fatalf("failed to append parsed header: %v", err)
			}

			if d := diff(t, append([]byte{0xff}, wire...), b); d != "" {
				t.Fatalf("unexpected appended octets (-want +got):\n%s", d)
			}
		})
	}
}

func TestParseHeaderRejects(t *testing.T) {
	t.Parallel()

	// Each case is a point to point hello header, 20 octets, with one
	// thing wrong.
	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "shorter than the common header",
			b:    []byte{0x83, 20, 1, 0, 17, 1, 0},
		},
		{
			name: "discriminator",
			b:    pad([]byte{0x82, 20, 1, 0, 17, 1, 0, 0}, 20),
		},
		{
			name: "protocol ID extension",
			b:    pad([]byte{0x83, 20, 2, 0, 17, 1, 0, 0}, 20),
		},
		{
			name: "ID length",
			b:    pad([]byte{0x83, 20, 1, 4, 17, 1, 0, 0}, 20),
		},
		{
			name: "version",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 2, 0, 0}, 20),
		},
		{
			name: "a type which does not exist",
			b:    pad([]byte{0x83, 20, 1, 0, 19, 1, 0, 0}, 20),
		},
		{
			name: "a length indicator which does not match the type",
			b:    pad([]byte{0x83, 27, 1, 0, 17, 1, 0, 0}, 27),
		},
		{
			name: "shorter than the type's fixed header",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 1, 0, 0}, 19),
		},
		{
			name: "maximum area addresses",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 1, 0, 2}, 20),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, err := ParseHeader(tt.b)
			if err == nil {
				t.Fatalf("expected an error, but parsed %+v", h)
			}

			t.Logf("err: %v", err)
		})
	}
}

func TestParseHeaderAccepts(t *testing.T) {
	t.Parallel()

	// Each case is a point to point hello header, 20 octets, which
	// another router may send although this package never does.
	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "reserved bits set",
			b:    pad([]byte{0x83, 20, 1, 0, 0xe0 | 17, 1, 0xff, 0}, 20),
		},
		{
			name: "an ID length of six spelled out",
			b:    pad([]byte{0x83, 20, 1, 6, 17, 1, 0, 0}, 20),
		},
		{
			name: "maximum area addresses of three spelled out",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 1, 0, 3}, 20),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, err := ParseHeader(tt.b)
			if err != nil {
				t.Fatalf("failed to parse header: %v", err)
			}

			want := Header{
				Type:            PDUPointToPointHello,
				LengthIndicator: 20,
			}

			if d := diff(t, want, h); d != "" {
				t.Fatalf("unexpected header (-want +got):\n%s", d)
			}
		})
	}
}

func TestHeaderAppendBinaryRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    Header
	}{
		{
			name: "a type which does not exist",
			h:    Header{Type: 19},
		},
		{
			name: "a length indicator which does not match the type",
			h: Header{
				Type:            PDUPointToPointHello,
				LengthIndicator: 27,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.h.AppendBinary(nil)
			if err == nil {
				t.Fatalf("expected an error, but appended %x", b)
			}

			t.Logf("err: %v", err)
		})
	}
}

func TestPDULength(t *testing.T) {
	t.Parallel()

	// Each case builds a header of typ padded to size octets and writes
	// length at off, where the PDU length field sits for that type.
	tests := []struct {
		name   string
		typ    PDUType
		size   int
		off    int
		length uint16
		ok     bool
	}{
		{
			name:   "a hello, after the source ID",
			typ:    PDUPointToPointHello,
			size:   32,
			off:    17,
			length: 30,
			ok:     true,
		},
		{
			name:   "a sequence numbers PDU, after the common header",
			typ:    PDUL2CompleteSequence,
			size:   40,
			off:    8,
			length: 40,
			ok:     true,
		},
		{
			name:   "below the fixed header",
			typ:    PDUPointToPointHello,
			size:   32,
			off:    17,
			length: 19,
		},
		{
			name:   "beyond the octets received",
			typ:    PDUL2CompleteSequence,
			size:   40,
			off:    8,
			length: 41,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := Header{Type: tt.typ}.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to append header: %v", err)
			}

			b = pad(b, tt.size)
			binary.BigEndian.PutUint16(b[tt.off:], tt.length)

			n, err := pduLength(tt.typ, b)
			if !tt.ok {
				if err == nil {
					t.Fatalf("expected an error, but got length %d", n)
				}

				t.Logf("err: %v", err)
				return
			}

			if err != nil {
				t.Fatalf("failed to read PDU length: %v", err)
			}

			if n != int(tt.length) {
				t.Fatalf("unexpected PDU length: want %d, got %d", tt.length, n)
			}
		})
	}
}

func TestPDUTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ  PDUType
		want string
	}{
		{
			typ:  PDUL1LANHello,
			want: "Level 1 LAN hello",
		},
		{
			typ:  PDUL2LANHello,
			want: "Level 2 LAN hello",
		},
		{
			typ:  PDUPointToPointHello,
			want: "point to point hello",
		},
		{
			typ:  PDUL1LinkState,
			want: "Level 1 link state",
		},
		{
			typ:  PDUL2LinkState,
			want: "Level 2 link state",
		},
		{
			typ:  PDUL1CompleteSequence,
			want: "Level 1 complete sequence numbers",
		},
		{
			typ:  PDUL2CompleteSequence,
			want: "Level 2 complete sequence numbers",
		},
		{
			typ:  PDUL1PartialSequence,
			want: "Level 1 partial sequence numbers",
		},
		{
			typ:  PDUL2PartialSequence,
			want: "Level 2 partial sequence numbers",
		},
		{
			typ:  19,
			want: "unknown(19)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.typ.String(); got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, got)
			}
		})
	}
}

// pad returns b extended with zero octets to n octets.
func pad(b []byte, n int) []byte {
	return append(b, make([]byte, n-len(b))...)
}
