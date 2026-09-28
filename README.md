# isis [![Test Status](https://github.com/mdlayher/isis/workflows/Test/badge.svg)](https://github.com/mdlayher/isis/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/isis.svg)](https://pkg.go.dev/github.com/mdlayher/isis)

Package `isis` implements the Intermediate System to Intermediate System
(IS-IS) routing protocol, as described in ISO/IEC 10589,
[RFC 1195](https://www.rfc-editor.org/rfc/rfc1195), and related RFCs: a
link-state interior gateway protocol running directly over the data link,
independent of IP. MIT Licensed.

The package is built in layers. Each layer is usable without the ones above
it:

- The codec: the common `Header`, the `PointToPointHello`, the `TLVs` walk,
  and the typed TLV constructors and parsers, such as `AreaAddressesTLV` and
  `TLV.AreaAddresses`, with their binary encoding.
- `Transport` carries PDUs between one Circuit and the link it attaches to,
  with `ErrDropped` for a frame an implementation discards.
  `ListenEthernet` opens the Ethernet implementation.
- `Circuit` runs one system's attachment to a link over its `Transport`,
  sending hellos and reporting every PDU in both directions to
  `CircuitConfig.OnPDU`.

## Platform support

The codec, `Transport`, and `Circuit` layers are portable Go.
`ListenEthernet`, the Ethernet packet socket, is only supported on Linux;
elsewhere, it returns an error which wraps `errors.ErrUnsupported`.

## Testing

The package is tested against the standards and against itself:

- Codec tests encode and parse a hello assembled octet by octet from
  ISO 10589 and the RFCs defining its TLVs, requiring a byte-for-byte round
  trip.
- Fuzz targets cover hello parsing, the TLV walk, and the typed TLV parsers.
- `Transport` conformance tests run against an in-memory link, and the
  Ethernet packet filter runs in a software BPF machine.
