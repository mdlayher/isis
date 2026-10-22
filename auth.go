package isis

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// hmacMD5Len is the length of an HMAC-MD5 digest, which is the whole of
// an RFC 5304 authentication value after its type octet.
const hmacMD5Len = md5.Size

// An AuthType is the type octet which opens an authentication TLV's
// value, from the IANA IS-IS Authentication Type Codes registry.
type AuthType uint8

// The authentication types. ISO 10589 clause 9.5 assigns the cleartext
// password, RFC 5304 HMAC-MD5, and RFC 5310 the generic cryptographic
// type which carries a key ID and an HMAC-SHA digest.
const (
	AuthTypeCleartext            AuthType = 1
	AuthTypeGenericCryptographic AuthType = 3
	AuthTypeHMACMD5              AuthType = 54
)

// String returns the name of an AuthType.
func (t AuthType) String() string {
	switch t {
	case AuthTypeCleartext:
		return "cleartext"
	case AuthTypeGenericCryptographic:
		return "generic cryptographic"
	case AuthTypeHMACMD5:
		return "HMAC-MD5"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}

// An Authentication is the value of the authentication TLV, code 10: a
// type octet and the octets that type defines.
type Authentication struct {
	// Type is the authentication type.
	Type AuthType

	// Value follows the type octet. For AuthTypeCleartext it is the
	// password. For AuthTypeHMACMD5 it is the 16 octet digest. For
	// AuthTypeGenericCryptographic it is the two octet key ID and then
	// the digest. The Value which TLV.Authentication returns aliases the
	// TLV it was parsed from.
	Value []byte
}

// AuthenticationTLV builds the authentication TLV, code 10, described in
// ISO 10589 clause 9.5, RFC 5304, and RFC 5310. The value must be the
// length its type requires: at least one octet of cleartext password,
// exactly 16 octets of HMAC-MD5 digest, or a key ID and a digest.
func AuthenticationTLV(a Authentication) (TLV, error) {
	if err := a.validate(); err != nil {
		return TLV{}, err
	}

	v := make([]byte, 0, 1+len(a.Value))
	v = append(v, uint8(a.Type))
	v = append(v, a.Value...)

	return TLV{
		Type:  TLVAuthentication,
		Value: v,
	}, nil
}

// Authentication parses t, which must be the authentication TLV, code 10.
// A type this package does not name parses with its value unchecked,
// since ISO 10589 clause 8.2.4.1 leaves accepting it to the receiver.
func (t TLV) Authentication() (Authentication, error) {
	if err := t.expect(TLVAuthentication); err != nil {
		return Authentication{}, err
	}

	if len(t.Value) < 1 {
		return Authentication{}, errors.New("isis: authentication TLV is empty, with no type octet")
	}

	a := Authentication{
		Type:  AuthType(t.Value[0]),
		Value: t.Value[1:],
	}

	if err := a.validate(); err != nil {
		return Authentication{}, err
	}

	return a, nil
}

// validate checks a's value against the length its type requires.
func (a Authentication) validate() error {
	n := len(a.Value)
	if n+1 > maxTLVValueLen {
		return fmt.Errorf("isis: %s authentication value is %d octets, over the TLV's %d", a.Type, n, maxTLVValueLen-1)
	}

	switch a.Type {
	case AuthTypeCleartext:
		if n == 0 {
			return errors.New("isis: cleartext authentication has an empty password")
		}
	case AuthTypeHMACMD5:
		if n != hmacMD5Len {
			return fmt.Errorf("isis: HMAC-MD5 authentication value is %d octets, not %d", n, hmacMD5Len)
		}
	case AuthTypeGenericCryptographic:
		// RFC 5310 section 2: a two octet key ID, then a digest of the
		// length the key's algorithm produces.
		if n <= 2 {
			return fmt.Errorf("isis: generic cryptographic authentication value is %d octets, too short for a key ID and a digest", n)
		}
	}

	return nil
}

// ErrAuthentication reports a received PDU which failed authentication:
// it carries no authentication TLV, one this package does not verify, or
// a digest which does not match the key. A Circuit reports such a PDU to
// CircuitConfig.OnPDU with an error wrapping ErrAuthentication, whose
// text is the reason the PDU failed.
var ErrAuthentication = errors.New("isis: authentication failed")

// An AuthConfig is the authentication type and shared key with which a
// Circuit signs the PDUs it sends and verifies those it receives.
//
// HMAC-MD5 guards against misconfiguration and casual injection, not a
// determined attacker: RFC 5304 section 5 describes its limits.
type AuthConfig struct {
	// Type is the authentication type. It must be AuthTypeHMACMD5, the
	// type this package implements.
	Type AuthType

	// Key is the shared secret. It must not be empty.
	Key []byte
}

// validate checks a against the one type this package implements and
// requires a key.
func (a *AuthConfig) validate() error {
	if a.Type != AuthTypeHMACMD5 {
		return fmt.Errorf("isis: authentication type %s is not implemented", a.Type)
	}

	if len(a.Key) == 0 {
		return errors.New("isis: authentication key must not be empty")
	}

	return nil
}

// placeholderTLV is the authentication TLV an encoder emits before
// signing: the right type and length, with a zero digest for sign to
// fill in once the whole PDU, padding included, is encoded.
func (a *AuthConfig) placeholderTLV() (TLV, error) {
	return AuthenticationTLV(Authentication{
		Type:  a.Type,
		Value: make([]byte, hmacMD5Len),
	})
}

// sign fills in the digest of the authentication TLV in b, one encoded
// PDU which carries exactly one, as emitted by placeholderTLV.
func (a *AuthConfig) sign(b []byte) error {
	sum, err := hmacMD5(b, a.Key)
	if err != nil {
		return err
	}

	copy(b[sum.off:], sum.mac[:])
	return nil
}

// verify returns an error wrapping ErrAuthentication unless b, one
// received PDU, carries exactly one HMAC-MD5 authentication TLV whose
// digest matches Key. It leaves b as it found it.
func (a *AuthConfig) verify(b []byte) error {
	sum, err := hmacMD5(b, a.Key)
	if err != nil {
		return authError{err}
	}

	if !hmac.Equal(sum.mac[:], b[sum.off:sum.off+hmacMD5Len]) {
		return authError{errors.New("isis: HMAC-MD5 digest does not verify")}
	}

	return nil
}

// An authError is a failure of verify. Its text is its cause's alone, so
// the reason reads without a second prefix, and it wraps both the cause
// and ErrAuthentication.
type authError struct {
	err error
}

func (e authError) Error() string   { return e.err.Error() }
func (e authError) Unwrap() []error { return []error{ErrAuthentication, e.err} }

// An hmacMD5Sum is the HMAC-MD5 of one PDU and the offset in it of the
// digest the sum belongs at.
type hmacMD5Sum struct {
	off int
	mac [hmacMD5Len]byte
}

// hmacMD5 computes the RFC 5304 section 2 HMAC-MD5 of b, one encoded PDU
// carrying exactly one HMAC-MD5 authentication TLV. The digest octets are
// zeroed for the computation, as are an LSP's Remaining Lifetime and
// Checksum, and every octet is restored before hmacMD5 returns.
//
// The whole PDU is covered, so a hello's padding is inside the digest:
// "The HMAC-MD5 result for the IS-IS Hello PDUs SHALL be calculated after
// the packet is padded to the MTU size."
func hmacMD5(b, key []byte) (hmacMD5Sum, error) {
	hdr, err := ParseHeader(b)
	if err != nil {
		return hmacMD5Sum{}, err
	}

	n, err := pduLength(hdr.Type, b)
	if err != nil {
		return hmacMD5Sum{}, err
	}

	b = b[:n]

	// TLVs accounts for every octet of the variable length part, so the
	// running sum of each TLV's header and value is the offset in b of
	// the TLV which follows.
	off := -1
	i := hdr.Type.fixedHeaderLen()
	for t, err := range TLVs(b[i:]) {
		if err != nil {
			return hmacMD5Sum{}, err
		}

		if t.Type == TLVAuthentication {
			// With two TLVs there is no one digest to zero, so neither
			// can be verified.
			if off >= 0 {
				return hmacMD5Sum{}, errors.New("isis: PDU carries more than one authentication TLV")
			}

			a, err := t.Authentication()
			if err != nil {
				return hmacMD5Sum{}, err
			}

			if a.Type != AuthTypeHMACMD5 {
				return hmacMD5Sum{}, fmt.Errorf("isis: authentication TLV is %s, not HMAC-MD5", a.Type)
			}

			// The digest follows the TLV header and the type octet.
			off = i + 3
		}

		i += 2 + len(t.Value)
	}

	if off < 0 {
		return hmacMD5Sum{}, errors.New("isis: PDU carries no authentication TLV")
	}

	// RFC 5304 section 2: "When LSPs are authenticated, the Checksum and
	// Remaining Lifetime fields are set to zero (0) before authentication
	// is computed." Both are restored with the digest below.
	var (
		lsp      = hdr.Type == PDUL1LinkState || hdr.Type == PDUL2LinkState
		digest   [hmacMD5Len]byte
		lifetime uint16
		checksum uint16
	)

	copy(digest[:], b[off:])
	clear(b[off : off+hmacMD5Len])
	if lsp {
		lifetime = binary.BigEndian.Uint16(b[lspRemainingLifetimeOff:])
		checksum = binary.BigEndian.Uint16(b[lspChecksumOff:])
		binary.BigEndian.PutUint16(b[lspRemainingLifetimeOff:], 0)
		binary.BigEndian.PutUint16(b[lspChecksumOff:], 0)
	}

	sum := hmacMD5Sum{off: off}
	mac := hmac.New(md5.New, key)
	mac.Write(b)
	mac.Sum(sum.mac[:0])

	copy(b[off:], digest[:])
	if lsp {
		binary.BigEndian.PutUint16(b[lspRemainingLifetimeOff:], lifetime)
		binary.BigEndian.PutUint16(b[lspChecksumOff:], checksum)
	}

	return sum, nil
}
