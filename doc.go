// Package isis implements the Intermediate System to Intermediate System
// (IS-IS) routing protocol, as described in ISO/IEC 10589, RFC 1195, and
// related RFCs: a link-state interior gateway protocol which runs directly
// over the data link and is independent of IP.
//
// The package is built in layers. Each layer is usable without the ones
// above it:
//
//   - The codec: the common [Header], the [PointToPointHello], the [TLVs]
//     walk, and the typed TLV constructors and parsers, such as
//     [AreaAddressesTLV] and [TLV.AreaAddresses], with their binary
//     encoding.
//   - [Transport] carries PDUs between one Circuit and the link it
//     attaches to, with [ErrDropped] for a frame an implementation
//     discards. [ListenEthernet] opens the Ethernet implementation.
//   - [Circuit] runs one system's attachment to a link over its
//     [Transport], sending hellos and reporting every PDU in both
//     directions to [CircuitConfig.OnPDU]. It forms one adjacency with its
//     neighbor through the RFC 5303 three way handshake and reports its
//     state changes to [CircuitConfig.OnAdjacency].
//
// This package has no daemon and computes no routes on its own. A caller
// owns the forwarding table, liveness, and policy, and gates them on the
// adjacency events a Circuit reports.
//
// # Glossary
//
// The acronyms this package uses, spelled out once each:
//
//   - DIS: designated intermediate system, the instance elected on a
//     broadcast link to speak for the link as a whole.
//   - IGP: interior gateway protocol, a routing protocol which runs within
//     one routing domain. IS-IS is one.
//   - NET: network entity title, the NSAP which names an instance itself
//     rather than a service on it. [ParseNET] parses one.
//   - NSAP: network service access point, the ISO 8348 address of up to 20
//     octets from which an [AreaAddress] and a [SystemID] are drawn.
//   - NSEL: NSAP selector, the final octet of an NSAP, which is zero in a
//     NET.
//   - PDU: protocol data unit, one IS-IS packet. Its type is a [PDUType].
//
// The terms which are types, such as [SNPA], [SystemID], [AreaAddress],
// [LSPID], [Level], [Topology], [NLPID], and [TLV], are defined in their
// own documentation.
package isis
