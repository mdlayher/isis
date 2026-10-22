package isis

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

func Test_verifyFRRHello(t *testing.T) {
	t.Parallel()

	// FRR's hello verifying proves the digest covers the whole PDU,
	// padding included, with the digest octets zeroed, which is the RFC
	// 5304 rule FRR implements.
	b := frrMD5Hello(t)
	want := bytes.Clone(b)

	auth := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte(frrMD5Key),
	}

	if err := auth.verify(b); err != nil {
		t.Fatalf("FRR's hello did not verify: %v", err)
	}

	if d := cmp.Diff(want, b); d != "" {
		t.Fatalf("verify changed the PDU (-want +got):\n%s", d)
	}

	const errVerify = "isis: HMAC-MD5 digest does not verify"

	wrong := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte("hunter3"),
	}

	err := wrong.verify(b)
	if err == nil {
		t.Fatal("FRR's hello verified with the wrong key")
	}

	if got := err.Error(); got != errVerify {
		t.Fatalf("unexpected error with the wrong key: want %q, got %q", errVerify, got)
	}

	// The last octet is padding, which the digest covers.
	b[len(b)-1] ^= 0xff

	err = auth.verify(b)
	if err == nil {
		t.Fatal("FRR's hello verified with its padding altered")
	}

	if got := err.Error(); got != errVerify {
		t.Fatalf("unexpected error with the padding altered: want %q, got %q", errVerify, got)
	}
}

func Test_signMatchesFRR(t *testing.T) {
	t.Parallel()

	// Zeroing FRR's digest and signing again must reproduce it exactly,
	// so a hello this package signs is one FRR verifies.
	b := frrMD5Hello(t)
	want := bytes.Clone(b)

	hello, err := ParsePointToPointHello(b)
	if err != nil {
		t.Fatalf("failed to parse hello: %v", err)
	}

	if got := hello.TLVs[0].Type; got != TLVAuthentication {
		t.Fatalf("unexpected first TLV: want %q, got %q", TLVAuthentication, got)
	}

	// The digest follows the fixed header, the TLV header, and the type
	// octet.
	off := PDUPointToPointHello.fixedHeaderLen() + 3
	clear(b[off : off+hmacMD5Len])

	auth := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte(frrMD5Key),
	}

	if err := auth.sign(b); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if d := cmp.Diff(want, b); d != "" {
		t.Fatalf("unexpected signed hello (-want +got):\n%s", d)
	}
}

func Test_hmacMD5LSPExcludesLifetimeAndChecksum(t *testing.T) {
	t.Parallel()

	// RFC 5304 section 2 zeroes an LSP's Remaining Lifetime and Checksum
	// before computing the digest, so both may change in flight, as the
	// lifetime does at every hop, and the LSP still verifies. Any other
	// octet may not.
	auth := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte("secret"),
	}

	b := lspWithAuth(t, auth)

	if err := auth.sign(b); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	binary.BigEndian.PutUint16(b[lspRemainingLifetimeOff:], 1199)
	binary.BigEndian.PutUint16(b[lspChecksumOff:], 0xbeef)

	if err := auth.verify(b); err != nil {
		t.Fatalf("LSP did not verify after its lifetime and checksum changed: %v", err)
	}

	// The last octet of the sequence number, just before the checksum.
	b[lspChecksumOff-1]++

	err := auth.verify(b)
	if err == nil {
		t.Fatal("LSP verified with its sequence number altered")
	}

	const want = "isis: HMAC-MD5 digest does not verify"
	if got := err.Error(); got != want {
		t.Fatalf("unexpected error: want %q, got %q", want, got)
	}
}

func Test_hmacMD5Rejects(t *testing.T) {
	t.Parallel()

	auth := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte("secret"),
	}

	md5TLV, err := auth.placeholderTLV()
	if err != nil {
		t.Fatalf("failed to build placeholder: %v", err)
	}

	clearTLV, err := AuthenticationTLV(Authentication{
		Type:  AuthTypeCleartext,
		Value: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("failed to build cleartext TLV: %v", err)
	}

	// Each case encodes a hello carrying tlvs, then appends trailer and
	// extends the PDU length over it, for octets no TLV encodes.
	tests := []struct {
		name    string
		tlvs    []TLV
		trailer []byte
		err     string
	}{
		{
			name: "no authentication TLV",
			err:  "isis: PDU carries no authentication TLV",
		},
		{
			name: "two authentication TLVs",
			tlvs: []TLV{md5TLV, md5TLV},
			err:  "isis: PDU carries more than one authentication TLV",
		},
		{
			name: "a cleartext password",
			tlvs: []TLV{clearTLV},
			err:  "isis: authentication TLV is cleartext, not HMAC-MD5",
		},
		{
			name:    "an empty authentication TLV ending the PDU",
			trailer: []byte{uint8(TLVAuthentication), 0x00},
			err:     "isis: authentication TLV is empty, with no type octet",
		},
		{
			name:    "a short HMAC-MD5 digest",
			trailer: append([]byte{uint8(TLVAuthentication), 1 + 15, uint8(AuthTypeHMACMD5)}, make([]byte, 15)...),
			err:     "isis: HMAC-MD5 authentication value is 15 octets, not 16",
		},
		{
			name:    "one octet after the last TLV",
			tlvs:    []TLV{md5TLV},
			trailer: []byte{uint8(TLVPadding)},
			err:     "isis: one octet remains, too few for a TLV header",
		},
		{
			name:    "a TLV past the PDU end",
			tlvs:    []TLV{md5TLV},
			trailer: []byte{uint8(TLVPadding), 0x08, 0x00},
			err:     "isis: Padding declares 8 octets but 1 remain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &PointToPointHello{
				Levels:      Level2Only,
				SourceID:    SystemID{0, 0, 0, 0, 0, 1},
				HoldingTime: 30 * time.Second,
				TLVs:        tt.tlvs,
			}

			b, err := h.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to encode hello: %v", err)
			}

			b = append(b, tt.trailer...)
			binary.BigEndian.PutUint16(b[17:], uint16(len(b)))

			err = auth.sign(b)
			if err == nil {
				t.Fatal("expected sign to fail")
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected sign error: want %q, got %q", tt.err, got)
			}

			err = auth.verify(b)
			if err == nil {
				t.Fatal("expected verify to fail")
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected verify error: want %q, got %q", tt.err, got)
			}

			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("verify error does not wrap %v: %v", ErrAuthentication, err)
			}
		})
	}
}

func Fuzz_hmacMD5(f *testing.F) {
	auth := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte(frrMD5Key),
	}

	wrong := &AuthConfig{
		Type: AuthTypeHMACMD5,
		Key:  []byte("hunter3"),
	}

	lsp := lspWithAuth(f, auth)
	if err := auth.sign(lsp); err != nil {
		f.Fatalf("failed to sign LSP: %v", err)
	}

	f.Add(frrMD5Hello(f))
	f.Add(lsp)

	f.Fuzz(func(t *testing.T, b []byte) {
		in := bytes.Clone(b)

		sum, err := hmacMD5(b, auth.Key)
		if d := cmp.Diff(in, b); d != "" {
			t.Fatalf("hmacMD5 changed the PDU (-want +got):\n%s", d)
		}

		if err != nil {
			return
		}

		if err := auth.sign(b); err != nil {
			t.Fatalf("failed to sign a PDU hmacMD5 accepted: %v", err)
		}

		// Signing writes the digest and nothing else.
		want := bytes.Clone(in)
		copy(want[sum.off:sum.off+hmacMD5Len], sum.mac[:])
		if d := cmp.Diff(want, b); d != "" {
			t.Fatalf("sign changed more than the digest (-want +got):\n%s", d)
		}

		if err := auth.verify(b); err != nil {
			t.Fatalf("failed to verify a PDU just signed: %v", err)
		}

		const errVerify = "isis: HMAC-MD5 digest does not verify"

		err = wrong.verify(b)
		if err == nil {
			t.Fatal("PDU verified with the wrong key")
		}

		if got := err.Error(); got != errVerify {
			t.Fatalf("unexpected error with the wrong key: want %q, got %q", errVerify, got)
		}

		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("error with the wrong key does not wrap %v: %v", ErrAuthentication, err)
		}
	})
}

// pad returns b extended with zero octets to n octets.
func pad(b []byte, n int) []byte {
	return append(b, make([]byte, n-len(b))...)
}

// frrMD5Key is the interface password FRR signed the captured hello
// with: `isis password md5 hunter2` on a point to point circuit.
const frrMD5Key = "hunter2"

// frrMD5Hello returns a point to point hello captured from FRR 10.6.1 on
// 2026-09-28, on a veth pair addressed from 192.0.2.0/24 and
// 2001:db8::/64. FRR ran with this interface and router configuration:
//
//	interface v-frr
//	 isis circuit-type level-2-only
//	 isis network point-to-point
//	 isis password md5 hunter2
//	router isis lab
//	 is-type level-2-only
//	 net 49.0001.0000.0000.0002.00
//
// The hello is the first FRR sent, unedited: 1497 octets, padded to the
// link's PDU size. Its first TLV is the HMAC-MD5 authentication TLV, then
// come protocols supported, area addresses, three way adjacency, IPv4,
// IPv6, and IPv6 global interface addresses, and six padding TLVs.
func frrMD5Hello(t testing.TB) []byte {
	t.Helper()

	s, err := os.ReadFile("testdata/frr-p2p-hello-md5-hunter2.hex")
	if err != nil {
		t.Fatalf("failed to read capture: %v", err)
	}

	b, err := hex.DecodeString(strings.TrimSpace(string(s)))
	if err != nil {
		t.Fatalf("failed to decode capture: %v", err)
	}

	return b
}

// lspWithAuth returns a Level 2 LSP from system 0000.0000.0001 carrying
// only auth's placeholder authentication TLV, ready for sign.
func lspWithAuth(t testing.TB, auth *AuthConfig) []byte {
	t.Helper()

	b, err := Header{Type: PDUL2LinkState}.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to encode header: %v", err)
	}

	id := SystemID{0, 0, 0, 0, 0, 1}

	lengthOff := len(b)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1200)
	b = append(b, id[:]...)
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint32(b, 7)
	b = binary.BigEndian.AppendUint16(b, 0x1234)
	b = append(b, uint8(Level2Only))

	tlv, err := auth.placeholderTLV()
	if err != nil {
		t.Fatalf("failed to build placeholder: %v", err)
	}

	if b, err = tlv.AppendBinary(b); err != nil {
		t.Fatalf("failed to encode TLV: %v", err)
	}

	binary.BigEndian.PutUint16(b[lengthOff:], uint16(len(b)))
	return b
}
