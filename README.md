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
