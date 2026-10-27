# Punch Through Both NATs

*   Status: proposed
*   Date: 2026-10-27

[TOC]

## Context and problem statement

[ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md)
(decision 7) leaves links between two nodes behind NATs out of scope. The
selection loop meets a candidate at its published rendezvous address: its
probe is a rendezvous echo, and its establishment a rendezvous exchange. A
node behind a NAT answers neither, so no node links to it unless it dials.
Two nodes behind NATs never link. In the NAT lab of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md),
nodes 3 to 6 sit behind NATs of their own and link only to the dialable
nodes 0 to 2. Two of them 2ms apart reach each other through a dialable
node, and the worst pair takes 22.5 times its reference.

NATs differ in how they map a socket
([RFC 4787](https://www.rfc-editor.org/rfc/rfc4787)):

*   **Endpoint-independent mapping** gives one internal socket one external
    address for every destination. The full-cone, restricted, and
    port-restricted kinds do; most home and office NATs are of these kinds.
    Their filters admit at least the sources the socket has sent to.
*   **Address-and-port-dependent mapping**, the symmetric kind, draws a new
    external address per destination.

What exists to build on:

*   Each node's directory entry says whether its published rendezvous
    address went unanswered, its own report
    ([ADR-0027](/docs/adrs/0027-tag-the-nodes-peers-cannot-dial.md),
    decision 1).
*   The channel both chains authenticate rides SCION paths. Its clients
    resolve a path from local state alone, which reaches the cores and the
    nodes above the caller; the core's segments compose a path to any
    enrolled node.
*   The rendezvous reply carries the requester's reflexive address, and the
    rendezvous messages are protobuf
    ([proposal 0080](/docs/proposals/0080-carry-the-rendezvous-in-protobuf.md)).
    The acceptor caps the rate of a node's claims by the address claimed,
    and each claim, the selection's probe included, holds an entry in its
    table.
*   A link's socket is unconnected, its BFD stream holds each direction's
    mapping open (ADR-0021, decisions 5 and 6), and a link records the source
    it observes its peer at
    ([ADR-0029](/docs/adrs/0029-follow-each-links-own-flow.md)).

## Decision drivers

*   **Direct links between nodes behind NATs**, wherever both NATs map
    endpoint-independently.
*   **Measured, not estimated:** the selection judges a candidate behind a
    NAT by a round trip it measures, as it judges every other candidate.
*   **Possession before opening:** both chains authenticate the exchange
    that asks a node to open its NAT.
*   **No new service or port:** the link service and the rendezvous acceptor
    carry it.
*   **Nothing amplifies:** no unauthenticated request buys a reply larger
    than itself.

## Considered options

*   **Keep the detour:** two nodes behind NATs reach each other through a
    dialable node, as today.
*   **A punching application:** an application beside the others punches
    between nodes behind NATs and hands the topology the result.
*   **An estimated candidate, punched at promotion:** the selection prices a
    candidate behind a NAT from the routes it already holds, and punches
    only to establish.
*   **A punched probe and a punched establishment, in the measured
    provider:** the selection measures a candidate behind a NAT over a
    punched pair of sockets, and establishes over a punch from the link's own
    socket.

## Decision outcome

Chosen option: **a punched probe and a punched establishment, in the
measured provider**, amending ADR-0021's decision 7 and ADR-0027's
decision 3:

1.  **The selection punches a candidate that reports itself undialable.** A
    candidate whose directory entry says its published rendezvous address
    went unanswered is probed and established by punch; every other
    candidate keeps the rendezvous exchange. The report chooses the
    instrument and nothing else: a node that misreports is punched
    needlessly, or stays unlinked as before.
2.  **The authenticated channel coordinates a punch.** The node asks the
    candidate's link service to punch, over a SCION path it resolves before
    the request, segment lookups allowed. The request names the node's
    reflexive address and a nonce, and the reply names the candidate's. A
    node admits at most one probe's punch and one link's punch per peer per
    second.
3.  **Each side learns its reflexive address from a reflector.** Before an
    exchange, each side sends a binding request from the socket it punches
    with to its reflector: the rendezvous acceptor of an established
    neighbor that reports itself dialable. The reply echoes the source the
    acceptor observed. A binding request is a rendezvous request that claims
    no link address, so the acceptor records nothing. The acceptor caps the
    rate per observed source, so a node's concurrent punches never refuse
    each other, and it answers no binding request shorter than its reply.
4.  **The probe punches ephemeral sockets, for the life of a stream; the
    establishment punches the link's own.** A probe's punch is a stream:
    the candidate binds an ephemeral socket and sends its reflexive address,
    and the socket sends toward the node's and echoes the node's packets
    while the stream stays open, four seconds at most. The node takes the
    median of three round trips, as its echoes over a link do, and closes
    the stream. For an establishment, each side binds its link address,
    sends five datagrams toward the other's reflexive address, releases the
    socket, and records the other's address as the entry's locator. The
    confirm then establishes the link and records the link's observation
    (ADR-0029, decision 1).
5.  **Simultaneous establishments yield.** A node asked to punch a link
    toward a peer it is punching itself refuses, and a node whose own punch
    finds the link address held by the peer's punch fails. One establishment
    lands, or both try again in a later window.
6.  **The punch belongs to the measured provider.** It writes the link
    table, and it serves the selection's probe and establishment.

### Positive consequences

*   Nodes behind endpoint-independent NATs link to each other, and to
    dialable nodes that select them.
*   Measured in the NAT lab, five runs each: every pair of nodes behind NATs
    linked, and every pair's best path over the formed links is its
    reference, where the worst stood at 22.5 times. With the founder lost,
    the survivors reached each other within a second, where it took up to
    114 seconds.
*   The selection judges a candidate behind a NAT by the same measured round
    trip as every other candidate.
*   A probe's answering socket lives exactly as long as the request that
    asked for it.
*   The wire grows by two methods on the link service and one field pair on
    the rendezvous request, with no new service or port.

### Negative consequences

*   More links form, and the network settles later: 3 to 3.5 minutes in the
    lab, against 1.7 to 1.8.
*   A node behind an address-and-port-dependent NAT links to no peer behind
    a NAT: its reflector observes a mapping its peer's packets never reach.
    Its links to dialable nodes stand.
*   Two nodes behind one NAT stay unlinked by the punch unless the NAT
    hairpins, returning inside what is sent to its own external address;
    the site directories ADR-0028 proposes serve them.
*   A node behind a NAT with no dialable neighbor can neither punch nor be
    punched.
*   A punched link does not follow a peer's new mapping through a NAT with
    address-dependent filtering, which drops what the new mapping sends:
    once a NAT remaps, the link stays down until both ends retire it on its
    verdict, and the selection punches again. In the lab, every pair with a
    remapped node answered again within 14.6 to 108 seconds, against 13.4;
    in two runs of five, its pings waited for those links to retire.
*   A punch costs an authenticated request over a resolved path, its own
    QUIC handshake included, two binding requests, and ten datagrams. A
    probe's punch holds an answering socket and its stream for up to four
    seconds.
*   An enrolled peer can make the node send five datagrams to an address it
    names, at most once per second per kind.
*   The selection now acts on a node's own report, where ADR-0027 only showed
    it.

## Pros and cons of the options

### Keep the detour

*   Good, because nothing changes.
*   Bad, because two nodes behind NATs 2ms apart take a dialable node's
    route, 22.5 times their reference in the lab.

### A punching application

*   Good, because the topology stays as it is.
*   Bad, because an application writes no link: the topology provider owns
    the link table, and two writers of one entry flap by construction.
*   Bad, because the selection's probe and establishment would cross a
    boundary for every candidate behind a NAT.

### An estimated candidate, punched at promotion

*   Good, because only a promotion pays for a punch.
*   Bad, because the routes the node holds price the detour, not the direct
    link a punch would open: the estimate never shows a candidate behind a
    NAT beats its route.
*   Bad, because the selection would judge one kind of candidate by a
    different instrument.

### A punched probe and a punched establishment, in the measured provider

*   Good, because a candidate behind a NAT is measured like every other.
*   Good, because the punch reuses the selection's establishment, the
    confirm, and the link's observation.
*   Bad, because every window's probe of a candidate behind a NAT pays for a
    punch.
