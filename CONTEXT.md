# isis

A Go library for the IS-IS routing protocol: adjacency formation over the
data link, link-state PDU flooding, the link-state database, and shortest
path first computation, for IPv4 and IPv6 through multi-topology. It
produces routes; installing them and resolving BGP next hops through them
is the composing router's job. No import edge with bgp in either
direction, and liveness comes from a BFD session the router wires in,
exactly as bgp's does. The first deployment is point-to-point Level 2 in
one area; the library models Level 1, Level 1/2, broadcast circuits, DIS
election and pseudonode LSPs from the start regardless, so that first
shape is a subset shipped early, never an assumption baked in.

## Language

A term is capitalized in prose, here and in Go doc comments, only when it
names an exported identifier in this package, such as Circuit or
Transport. Every other term, such as instance or neighbor, is lowercase,
so a capitalized word always points at a type. Entry headings below are
the exception.

### The router and its links

**Instance**:
One IS-IS router: a system ID, the area addresses it claims, the levels
it runs, and the circuits it owns.
_Avoid_: router, process, IS, area

**System ID**:
The six octet identifier unique to one instance within the routing
domain. Not an address, and not derived from one.

**Area address**:
The variable length prefix of an instance's NSAP that names its area. A
Level 1 adjacency requires one in common; a Level 2 adjacency does not.

**Circuit**:
One instance's attachment to a single link, owning that link's hellos,
its adjacencies, and its flooding flags. Broadcast or point to point.
_Avoid_: interface, link, port

**Link**:
The medium one or more Circuits attach to, point to point or broadcast:
ISO 10589's subnetwork. Each instance on a link attaches through a
Circuit of its own, over a Transport.
_Avoid_: subnetwork, segment, wire

**Transport**:
This system's handle on one link: the interface a Circuit sends and
receives PDUs through, which owns the framing. `ListenEthernet` opens one
over a Linux packet socket, and a test supplies an in-memory one.
_Avoid_: socket, driver, interface

**Adjacency**:
The relationship one Circuit holds with one neighbor, from Initializing
through Up, with a level and a topology set of its own.
_Avoid_: session, peering

**Neighbor**:
The remote instance reached through an adjacency, named by its system ID.
_Avoid_: peer

**SNPA**:
A neighbor's link layer address on a Circuit: the destination an instance
puts on a frame.
_Avoid_: MAC address

**Level**:
Which of the two routing hierarchies a Circuit, adjacency, LSDB, or
computation belongs to. Level 1 routes within an area, Level 2 between
areas.

### The link-state database

**LSP**:
One link-state PDU: what an instance originates to describe itself, and
what it floods unchanged on behalf of every other instance. Fragments of
one origin share a system ID and differ by fragment number.
_Avoid_: LSA, advertisement, update

**LSDB**:
Every LSP an instance holds for one Level, and the sole input to that
Level's route computation.
_Avoid_: RIB, table

**Topology**:
One multi-topology ID, with its own reachability TLVs and its own
computed result. Topology 0 carries IPv4 and topology 2 carries IPv6.
_Avoid_: address family, AFI

**Pseudonode**:
The virtual instance that stands in for a broadcast link in the LSDB,
so the link costs one vertex instead of an edge between every pair of
routers on it. Its LSP is originated by that link's DIS.

**DIS**:
The instance elected on a broadcast link to originate that link's
pseudonode LSP and to send the link's periodic CSNPs.
_Avoid_: designated router, DR

**Overload**:
The condition an instance advertises when its LSDB is incomplete. Others
stop routing transit traffic through it while still reaching the prefixes
it originates.

### The boundary with the router

**Route diff**:
What one route computation hands to the composing router: the entries
added, replaced, and withdrawn since the previous computation, never a
whole table.
_Avoid_: table, RIB, update

**BFD session**:
The caller's single hop BFD session protecting a link, whose up and down
signals gate an adjacency. The router owns it. This library never creates
one, never imports bfd, and has no other meaning for the words.
