package isis_test

import (
	"testing"

	"github.com/mdlayher/isis"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ isis.PDUType
		li  uint8
	}{
		{
			typ: isis.PDUL1LANHello,
			li:  27,
		},
		{
			typ: isis.PDUL2LANHello,
			li:  27,
		},
		{
			typ: isis.PDUPointToPointHello,
			li:  20,
		},
		{
			typ: isis.PDUL1LinkState,
			li:  27,
		},
		{
			typ: isis.PDUL2LinkState,
			li:  27,
		},
		{
			typ: isis.PDUL1CompleteSequence,
			li:  33,
		},
		{
			typ: isis.PDUL2CompleteSequence,
			li:  33,
		},
		{
			typ: isis.PDUL1PartialSequence,
			li:  17,
		},
		{
			typ: isis.PDUL2PartialSequence,
			li:  17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			t.Parallel()

			// LengthIndicator is left zero for AppendBinary to fill in
			// from Type.
			b, err := isis.Header{Type: tt.typ}.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to append header: %v", err)
			}

			wire := []byte{0x83, tt.li, 1, 0, uint8(tt.typ), 1, 0, 0}
			if d := diff(t, wire, b); d != "" {
				t.Fatalf("unexpected header octets (-want +got):\n%s", d)
			}

			h, err := isis.ParseHeader(pad(b, int(tt.li)))
			if err != nil {
				t.Fatalf("failed to parse header: %v", err)
			}

			want := isis.Header{
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
		err  string
	}{
		{
			name: "shorter than the common header",
			b:    []byte{0x83, 20, 1, 0, 17, 1, 0},
			err:  "isis: PDU is 7 octets, too short for its 8 octet common header",
		},
		{
			name: "discriminator",
			b:    pad([]byte{0x82, 20, 1, 0, 17, 1, 0, 0}, 20),
			err:  "isis: PDU discriminator is 0x82, not 0x83",
		},
		{
			name: "protocol ID extension",
			b:    pad([]byte{0x83, 20, 2, 0, 17, 1, 0, 0}, 20),
			err:  "isis: unsupported version/protocol ID extension 2",
		},
		{
			name: "ID length",
			b:    pad([]byte{0x83, 20, 1, 4, 17, 1, 0, 0}, 20),
			err:  "isis: unsupported ID length 4",
		},
		{
			name: "version",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 2, 0, 0}, 20),
			err:  "isis: unsupported version 2",
		},
		{
			name: "a type which does not exist",
			b:    pad([]byte{0x83, 20, 1, 0, 19, 1, 0, 0}, 20),
			err:  "isis: PDU type 19 does not exist",
		},
		{
			name: "a length indicator which does not match the type",
			b:    pad([]byte{0x83, 27, 1, 0, 17, 1, 0, 0}, 27),
			err:  "isis: a point to point hello header is 20 octets, not the 27 the length indicator claims",
		},
		{
			name: "shorter than the type's fixed header",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 1, 0, 0}, 19),
			err:  "isis: point to point hello PDU is 19 octets, too short for its 20 octet header",
		},
		{
			name: "maximum area addresses",
			b:    pad([]byte{0x83, 20, 1, 0, 17, 1, 0, 2}, 20),
			err:  "isis: maximum area addresses 2 does not match the 3 this package permits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, err := isis.ParseHeader(tt.b)
			if err == nil {
				t.Fatalf("expected an error, but parsed %+v", h)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
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

			h, err := isis.ParseHeader(tt.b)
			if err != nil {
				t.Fatalf("failed to parse header: %v", err)
			}

			want := isis.Header{
				Type:            isis.PDUPointToPointHello,
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
		h    isis.Header
		err  string
	}{
		{
			name: "a type which does not exist",
			h:    isis.Header{Type: 19},
			err:  "isis: PDU type 19 does not exist",
		},
		{
			name: "a length indicator which does not match the type",
			h: isis.Header{
				Type:            isis.PDUPointToPointHello,
				LengthIndicator: 27,
			},
			err: "isis: a point to point hello header is 20 octets, not the 27 given",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.h.AppendBinary(nil)
			if err == nil {
				t.Fatalf("expected an error, but appended %x", b)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestPDUTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ  isis.PDUType
		want string
	}{
		{
			typ:  isis.PDUL1LANHello,
			want: "Level 1 LAN hello",
		},
		{
			typ:  isis.PDUL2LANHello,
			want: "Level 2 LAN hello",
		},
		{
			typ:  isis.PDUPointToPointHello,
			want: "point to point hello",
		},
		{
			typ:  isis.PDUL1LinkState,
			want: "Level 1 link state",
		},
		{
			typ:  isis.PDUL2LinkState,
			want: "Level 2 link state",
		},
		{
			typ:  isis.PDUL1CompleteSequence,
			want: "Level 1 complete sequence numbers",
		},
		{
			typ:  isis.PDUL2CompleteSequence,
			want: "Level 2 complete sequence numbers",
		},
		{
			typ:  isis.PDUL1PartialSequence,
			want: "Level 1 partial sequence numbers",
		},
		{
			typ:  isis.PDUL2PartialSequence,
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
