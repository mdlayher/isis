package isis

import (
	"encoding/binary"
	"testing"
)

// The tests in this file call unexported functions directly, as do those
// in internal_linux_test.go. Every other test is in package isis_test and
// uses only the exported API.

func Test_pduLength(t *testing.T) {
	t.Parallel()

	// Each case builds a header of typ padded to size octets and writes
	// length at off, where the PDU length field sits for that type.
	tests := []struct {
		name   string
		typ    PDUType
		size   int
		off    int
		length uint16
		err    string
	}{
		{
			name:   "a hello, after the source ID",
			typ:    PDUPointToPointHello,
			size:   32,
			off:    17,
			length: 30,
		},
		{
			name:   "a sequence numbers PDU, after the common header",
			typ:    PDUL2CompleteSequence,
			size:   40,
			off:    8,
			length: 40,
		},
		{
			name:   "below the fixed header",
			typ:    PDUPointToPointHello,
			size:   32,
			off:    17,
			length: 19,
			err:    "isis: point to point hello PDU length 19 is outside its 20 octet header and the 32 octets received",
		},
		{
			name:   "beyond the octets received",
			typ:    PDUL2CompleteSequence,
			size:   40,
			off:    8,
			length: 41,
			err:    "isis: Level 2 complete sequence numbers PDU length 41 is outside its 33 octet header and the 40 octets received",
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
			if tt.err != "" {
				if err == nil {
					t.Fatalf("expected an error, but got length %d", n)
				}

				if got := err.Error(); got != tt.err {
					t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
				}

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

func Test_appendPadding(t *testing.T) {
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

// pad returns b extended with zero octets to n octets.
func pad(b []byte, n int) []byte {
	return append(b, make([]byte, n-len(b))...)
}
