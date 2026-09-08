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

### The router and its links

**Instance**:
One IS-IS router: a system ID, the area addresses it claims, the levels
it runs, and the circuits it owns.
_Avoid_: router, process, IS, area

**System ID**:
The six octet identifier unique to one Instance within the routing
domain. Not an address, and not derived from one.

**Area address**:
The variable length prefix of an Instance's NSAP that names its area. A
Level 1 adjacency requires one in common; a Level 2 adjacency does not.

**Circuit**:
One Instance's attachment to a single link, owning that link's hellos,
its adjacencies, and its flooding flags. Broadcast or point to point.
_Avoid_: interface, link, port

**Adjacency**:
The relationship one Circuit holds with one Neighbor, from Initializing
through Up, with a level and a topology set of its own.
_Avoid_: session, peering

**Neighbor**:
The remote Instance reached through an Adjacency, named by its system ID.
_Avoid_: peer

**SNPA**:
A Neighbor's link layer address on a Circuit: the destination an Instance
puts on a frame.
_Avoid_: MAC address

**Level**:
Which of the two routing hierarchies a Circuit, Adjacency, LSDB, or
computation belongs to. Level 1 routes within an area, Level 2 between
areas.

### The link-state database

**LSP**:
One link-state PDU: what an Instance originates to describe itself, and
what it floods unchanged on behalf of every other Instance. Fragments of
one origin share a system ID and differ by fragment number.
_Avoid_: LSA, advertisement, update

**LSDB**:
Every LSP an Instance holds for one Level, and the sole input to that
Level's route computation.
_Avoid_: RIB, table

**Topology**:
One multi-topology ID, with its own reachability TLVs and its own
computed result. Topology 0 carries IPv4 and topology 2 carries IPv6.
_Avoid_: address family, AFI

**Pseudonode**:
The virtual Instance that stands in for a broadcast link in the LSDB,
so the link costs one vertex instead of an edge between every pair of
routers on it. Its LSP is originated by that link's DIS.

**DIS**:
The Instance elected on a broadcast link to originate that link's
Pseudonode LSP and to send the link's periodic CSNPs.
_Avoid_: designated router, DR

**Overload**:
The condition an Instance advertises when its LSDB is incomplete. Others
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
signals gate an Adjacency. The router owns it. This library never creates
one, never imports bfd, and has no other meaning for the words.
