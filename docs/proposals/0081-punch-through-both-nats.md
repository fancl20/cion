# Punch through both NATs

This proposal implements
[ADR-0030](/docs/adrs/0030-punch-through-both-nats.md). The selection probes
and establishes a candidate that reports itself undialable by punch. The
link service gains `Punch` and the streamed `PunchProbe`, the rendezvous
acceptor answers binding requests, and the NAT lab asserts the links
between nodes behind NATs.

[TOC]

## Summary

The selection loop probes a candidate with a rendezvous echo and
establishes it with a rendezvous exchange
([selection.go](/pkg/modules/topology/impl/measured/selection.go)), both sent
to the candidate's published rendezvous address. A node behind a NAT
answers neither, though its directory entry says so
([directory.go](/pkg/modules/topology/impl/measured/directory.go)). The
link service answers link requests alone
([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)), and
every client of the authenticated channel resolves its path from local state
alone: up segments, which reach the cores and the nodes above the caller.

Measured on the change below, five runs each, in the NAT network of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md):

*   **Settled:** every pair of nodes 3 to 6 punched a link in every run, and
    every pair's best path over the formed links is its reference, where the
    worst stood at 22.5 times. The worst chosen path stood at 1.0 to 1.35
    times its reference, the excess the path choice's among the formed
    links, and the mean at 1.00 to 1.03, where it was 7.14. The network
    settled in 3 to 3.5 minutes, against 1.7 to 1.8, over 7 to 11 link
    changes, against 4 to 6.
*   **Restart, symmetric, founder down:** a restarted dialable node was
    reached again in 13 to 13.3 seconds, against 13, and a node behind a
    symmetric NAT enrolled in 44 to 112 seconds, against 55 to 109. With the
    founder lost, the survivors reached each other within a second, where it
    took 17 to 114 seconds, and the restarted node 5 returned in 196 to 276
    seconds, against 215 to 261.
*   **Rebinding:** once node 3's NAT dropped its mappings, every pair with it
    answered again within 14.6 to 108 seconds, where it took 13.4. Node 3's
    punched links to the nodes behind port-restricted NATs stay down until
    both ends retire them, 75 to 90 seconds on, and a pair whose route
    crossed one waits for its route to move: in two runs, until those links
    retired.

Two faults surfaced in the measurements and land first, each as a fix of
its own. The useless test retired the only link between the two cores: it
never counted a neighbor that only the link reaches as cut off. And a
stranded node's revived entries waited on the confirm pass, which could
have ended, so their acceptors retired them unconfirmed.

## Motivation

### Goals

*   Two nodes behind NATs link directly when both NATs map
    endpoint-independently, and the selection judges them by a measured
    round trip.
*   The NAT lab asserts a link between every pair of nodes behind NATs.

### Non-goals

*   No links through an address-and-port-dependent NAT.
*   No links between two nodes behind one NAT: the site directories of
    [ADR-0028](/docs/adrs/0028-serve-each-site-a-directory-of-its-own.md)
    serve them.
*   No relay.

## Proposal

### The wire

*   `node.v1.LinkService` gains `Punch(PunchRequest) returns (PunchReply)`
    and `PunchProbe(PunchProbeRequest) returns (stream PunchProbeReply)`.
    Each request carries `reflexive_addr`, the caller's socket as
    `host:port`, and `nonce`, 16 bytes; `PunchRequest` adds `if_id`, the
    caller's interface of the link. Each reply carries the peer's
    `reflexive_addr`; `PunchReply` adds its `if_id`.
*   `node.v1.RendezvousRequest` gains `binding` and `padding`. A binding
    request claims no link address, names the zero ISD-AS, and carries 64
    bytes of padding, past the longest binding reply's 78 bytes. The
    acceptor answers it with the nonce, its ISD-AS, and the reflexive
    address, and records nothing. It refuses one that names an ISD-AS or is
    shorter than its reply, and admits one per observed source per
    `RendezvousMinInterval`.
*   A punch datagram is 19 bytes: version 1, the exchange's nonce, and a
    kind, open or echo. A link's data plane drops it as malformed.

### The handler

The link service serves an authenticated caller, at most one probe's punch
and one link's punch per peer per `PunchMinInterval`, one second. It
refuses a caller when no established neighbor that reports itself dialable
can serve as its reflector.

*   **A probe's punch** binds an ephemeral socket on the control host,
    learns the socket's reflexive address by a binding request to the
    reflector, and sends it on the stream. The socket then sends five opens
    toward the caller's reflexive address, 50ms apart, while it echoes the
    caller's opens, until the stream ends or four seconds pass.
*   **A link's punch** refuses a caller it is punching itself, or one whose
    link stands. It takes the caller's entry that names no locator, or
    records a candidate under the link cap. It binds the entry's link
    address, learns its reflexive address, sends five opens toward the
    caller's, and releases the socket. It then records the caller's
    reflexive address and interface on the entry and replies with its own
    and its interface.

### The puncher

The provider's puncher rides a SCION conn of its own, one more drawn
through `NewConn`. Before each request it resolves the path to the peer
with segment lookups, and it sends the request through an HTTP client of
the request's own, whose dial rides that path and whose connection closes
with the request.

*   **A probe** binds an ephemeral socket, learns its reflexive address,
    opens a probe's punch, and sends three opens toward the peer's reflexive
    address, each awaiting its echo for a second. It closes the stream and
    returns the median round trip.
*   **An establishment** marks the peer in flight, binds the entry's link
    address, learns its reflexive address, asks for a link's punch, and
    sends five opens toward the peer's reflexive address before it releases
    the socket.

### The selection

`SelectionConfig` gains `Punch`. For a candidate whose entry reports its
published rendezvous address unanswered, the probe takes the punch's round
trip, and a promotion seeds its entry with the punch's reflexive address
and interface. The confirm then establishes it as any other.

### The labs

*   **The NAT lab:** once settled, every pair of nodes 3 to 6 holds a direct
    link.

### Packages touched

| Package                              | Change                                          |
| :----------------------------------- | :---------------------------------------------- |
| `proto/node/v1`                      | The punches, the binding request                |
| `pkg/modules/topology/impl/measured` | The binding request, the handler, the puncher   |
| `internal/testnetwork/behavior`      | The NAT lab's links                             |

## Compatibility

*   A link service of an earlier release answers `Punch` and `PunchProbe` as
    unimplemented, and the candidate stays unlinked as before.
*   An acceptor of an earlier release reads a binding request as a claim of
    no address and refuses it, so a node whose reflector runs one cannot
    punch.
*   A node of an earlier release probes candidates behind NATs by
    rendezvous, as before.

## Test plan

*   **The binding request:** it round-trips claiming no link address,
    padded past the longest binding reply, and one claiming a link address
    is refused. The acceptor answers two sockets of one host each with its
    own address and records nothing; it refuses a second request from one
    source within the interval, a request naming an ISD-AS, and one shorter
    than its reply. A dialer refuses a reply to its claim that names no link
    address.
*   **The handler:** a probe's punch sends a socket that echoes the caller's
    opens while the request stays open, returns once it ends, and records
    nothing. A link's punch records a candidate aimed at the caller's
    reflexive address and sends its opens from the entry's link address
    before it replies, and adopts an entry that names no locator. It refuses
    an unauthenticated caller, a malformed request, a node with no
    reflector, a standing link, its own punch in flight, and the link cap,
    each with its code. A second probe within the interval is refused, while
    a link's punch beside it is not.
*   **The selection:** an undialable candidate is probed and seeded by the
    punch, and the confirm records the link's observation; a failed punch
    seeds nothing.
*   **The NAT lab:** it passes in the behavior labs' runs.
*   **The benchmarks:** five runs each. In the settled benchmark every pair
    of nodes behind NATs links, and every pair's best path over the formed
    links is its reference. The restart, symmetric, and founder-down
    benchmarks recover as before, and the rebinding benchmark recovers.

## Implementation history

*   Landed as proposed: the punches and the binding request
    ([link.proto](/proto/node/v1/link.proto),
    [rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)), the
    handler and the puncher
    ([punch.go](/pkg/modules/topology/impl/measured/punch.go),
    [provider.go](/pkg/modules/topology/impl/measured/provider.go)), the
    selection's instrument
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)), and
    the NAT lab's links
    ([nat_test.go](/internal/testnetwork/behavior/nat_test.go)). The
    Summary's figures are the benchmarks' five runs each.
