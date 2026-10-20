package isis_test

import (
	"bytes"
	"testing"

	"github.com/mdlayher/isis"
)

func TestAuthenticationTLVRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    isis.Authentication
	}{
		{
			name: "cleartext",
			a: isis.Authentication{
				Type:  isis.AuthTypeCleartext,
				Value: []byte("hunter2"),
			},
		},
		{
			name: "HMAC-MD5",
			a: isis.Authentication{
				Type:  isis.AuthTypeHMACMD5,
				Value: bytes.Repeat([]byte{0xa5}, 16),
			},
		},
		{
			name: "generic cryptographic",
			a: isis.Authentication{
				Type:  isis.AuthTypeGenericCryptographic,
				Value: append([]byte{0x00, 0x01}, bytes.Repeat([]byte{0x5a}, 32)...),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tlv, err := isis.AuthenticationTLV(tt.a)
			if err != nil {
				t.Fatalf("failed to build TLV: %v", err)
			}

			got, err := tlv.Authentication()
			if err != nil {
				t.Fatalf("failed to parse TLV: %v", err)
			}

			if d := diff(t, tt.a, got); d != "" {
				t.Fatalf("unexpected authentication (-want +got):\n%s", d)
			}
		})
	}
}

func TestAuthenticationTLVRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tlv  isis.TLV
		err  string
	}{
		{
			name: "another TLV",
			tlv: isis.TLV{
				Type:  isis.TLVPadding,
				Value: []byte{uint8(isis.AuthTypeCleartext), 'x'},
			},
			err: "isis: TLV is Padding, not Authentication",
		},
		{
			name: "no type octet",
			tlv:  isis.TLV{Type: isis.TLVAuthentication},
			err:  "isis: authentication TLV is empty, with no type octet",
		},
		{
			name: "an empty cleartext password",
			tlv: isis.TLV{
				Type:  isis.TLVAuthentication,
				Value: []byte{uint8(isis.AuthTypeCleartext)},
			},
			err: "isis: cleartext authentication has an empty password",
		},
		{
			name: "a short HMAC-MD5 digest",
			tlv: isis.TLV{
				Type:  isis.TLVAuthentication,
				Value: append([]byte{uint8(isis.AuthTypeHMACMD5)}, make([]byte, 15)...),
			},
			err: "isis: HMAC-MD5 authentication value is 15 octets, not 16",
		},
		{
			name: "a generic cryptographic key ID with no digest",
			tlv: isis.TLV{
				Type:  isis.TLVAuthentication,
				Value: []byte{uint8(isis.AuthTypeGenericCryptographic), 0x00, 0x01},
			},
			err: "isis: generic cryptographic authentication value is 2 octets, too short for a key ID and a digest",
		},
		{
			name: "a value too long for its TLV",
			tlv: isis.TLV{
				Type:  isis.TLVAuthentication,
				Value: append([]byte{uint8(isis.AuthTypeCleartext)}, bytes.Repeat([]byte{'x'}, 255)...),
			},
			err: "isis: cleartext authentication value is 255 octets, over the TLV's 254",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, err := tt.tlv.Authentication()
			if err == nil {
				t.Fatalf("expected an error, but parsed %+v", a)
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}

func TestAuthTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    isis.AuthType
		want string
	}{
		{
			name: "cleartext",
			a:    isis.AuthTypeCleartext,
			want: "cleartext",
		},
		{
			name: "generic cryptographic",
			a:    isis.AuthTypeGenericCryptographic,
			want: "generic cryptographic",
		},
		{
			name: "HMAC-MD5",
			a:    isis.AuthTypeHMACMD5,
			want: "HMAC-MD5",
		},
		{
			name: "unknown",
			a:    2,
			want: "unknown(2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.a.String(); got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, got)
			}
		})
	}
}
