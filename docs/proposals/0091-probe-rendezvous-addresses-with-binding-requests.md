# Probe rendezvous addresses with binding requests

This proposal moves the rendezvous round trips that record nothing onto the
binding request
([ADR-0030](/docs/adrs/0030-punch-through-both-nats.md), decision 3): the
selection loop's probe of a candidate, its candidate sweep, and the link
service's echo of a requester. The acceptor answers a binding request and
records nothing, so these round trips stop minting entries at the nodes
they measure, and the rendezvous exchange drops the cases it kept for them.

[TOC]

## Summary

Three round trips ask only whether a peer's rendezvous socket answers, and
how fast:

*   **The selection's probe** of a candidate measures its direct round trip
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)).
*   **The candidate sweep** keeps a named candidate past its window while
    its rendezvous socket answers.
*   **The link service's echo** tells a requester whether its published
    rendezvous address answered
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)).

Each sends a full rendezvous request from an ephemeral port, claiming the
zero ISD-AS and the node's control address
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)). The
acceptor handles it as a joiner's first claim:

*   **It mints an unnamed candidate**, one per claimed address: a link
    address from the band, a data plane generation that binds it, and
    another once the candidate window retires it. In five runs of each
    settled benchmark, the regions network minted 300 to 337 such entries a
    run and swapped generations 511 to 563 times, the stranded network 86 to
    91 and 165 to 171, and the NAT network 26 to 33 and 73 to 84.
*   **The entries count toward the caps.** The link service and the punch
    refuse a link once eight live entries stand, unnamed ones included: in
    three of the five regions runs, punched establishments were refused at
    11 to 14 live entries. The acceptor refuses an unnamed claim once eight
    unnamed entries stand.
*   **Its rate cap keys on the claimed address,** the prober's control
    address, at one claim a second: a node's round trips to one peer within
    a second refuse each other. A refused echo reports the requester
    undialable, and its peers punch it: the regions network, every node of
    it dialable, attempted punches in three of its five runs.

To keep a node's probes on one entry, the acceptor records an unnamed claim
by the claim rule, the claimed address with the observed host under a
wildcard, where a named claim records the observed source whole. A joiner
dials its bootstrap neighbor twice from its link socket, the first claim
unnamed. Behind a NAT, the first entry records the claim, an address inside
the NAT, so the named dial that follows finds no entry at its observed
source and mints a second; the first retires with the window.
`RendezvousEcho` likewise keeps a case for the probes' ephemeral dials: it
skips the datagram that maps the link's own flow first.

## Motivation

### Goals

*   A round trip that records nothing changes nothing at the node it
    measures: no entry, no link address, no generation.
*   No two of a node's round trips refuse each other.
*   The rendezvous exchange keeps no case for probes.

### Non-goals

*   What each round trip decides stays: a direct sample, a candidate kept,
    an answer reported. The punched probe stays as it is.
*   The establishment and the joiner's dials keep the full rendezvous
    exchange.

## Proposal

### The round trips

The probe, the sweep, and the echo send a binding request from an ephemeral
port on the control host to the peer's rendezvous socket. The acceptor
answers it with the requester's reflexive address, under a rate cap per
observed source, so each round trip's socket is a key of its own. The round
trip crosses the same underlay path, without the admission's store work. As
before, the probe and the sweep learn the node's external host from the
reflexive address, and the echo learns nothing.

### The rendezvous exchange

*   **Every claim records its observed source whole.** An unnamed claim now
    comes only from a joiner's first dial, from the link socket its named
    dial leaves from, so the named dial finds the entry at its observed
    source and names it.
*   **`RendezvousEcho` dials from a link's own socket.** Its callers are the
    joiner's dials and the establishment, so every answered exchange sends
    the datagram that maps the link's own flow first.

### The labs

The stranded lab waits, once its blackholes lift, until every node of each
side has probed the other's, and reads the entries those probes minted.
The fabric gains a watch on an address, which hears the hosts whose
datagrams it delivers there, and the lab waits until each node's
rendezvous socket has heard every node of the other side, or a link joins
the pair.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The probe, the sweep, and the echo send binding requests; the acceptor records every claim's observed source; `RendezvousEcho` drops the ephemeral case |
| `internal/testnetwork/fabric` | `Watch` |
| `internal/testnetwork/behavior` | The stranded lab hears the probes on the fabric |

## Compatibility

There is no wire change: every node answers binding requests since
[proposal 0081](/docs/proposals/0081-punch-through-both-nats.md).

## Test plan

*   **The round trips:** the probe and the sweep measure a candidate and
    learn the node's external host over a binding request, and the echo
    reports an answer; the acceptor records nothing for any of them.
*   **The exchange:** an unnamed claim from a socket other than the one it
    names records the observed source, and a named claim from that socket
    names the same entry.
*   **The fabric's watch:** it hears a datagram delivered to its address,
    and nothing delivered before it was drawn, dropped, or addressed to
    another port.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each against the node before it. The
    settled and cut benchmarks hold or improve, with fewer unnamed entries
    and generations, and no punch in the regions or stranded network; the
    NAT benchmarks hold or improve.

## Implementation history

*   Landed as proposed: the binding echo and the acceptor's record
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)),
    the probe and the sweep
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)), the
    echo ([provider.go](/pkg/modules/topology/impl/measured/provider.go)),
    the fabric's watch ([watch.go](/internal/testnetwork/fabric/watch.go)),
    and the stranded lab
    ([stranded_test.go](/internal/testnetwork/behavior/stranded_test.go)).
    `SelectionConfig.ControlAddr` became `ControlHost`, for the probes claim
    no address. Five runs each against the node before it:
    *   **Churn:** the regions network minted 8 unnamed entries a run, the
        joiners' first claims, against 300 to 337, and swapped generations
        53 to 65 times against 511 to 563; the stranded network 5 and 26 to
        28 against 86 to 91 and 165 to 171; the NAT network 6 and 36 to 38
        against 26 to 33 and 73 to 84. Neither the regions nor the stranded
        network attempted a punch.
    *   **NAT network:** it settled in 2m40s in three runs and 4m30s in two,
        against 2m20s to 2m50s in four and 4m30s in one, on paths as short;
        each slow run retired a public pair's link as useless and promoted
        it again a minute later, as before. A rebind recovered in 16.5 to
        18.7 seconds, a restarted peer in 13.0 to 13.4, a node behind a
        symmetric NAT joined in 54 to 55, and the founder returned in 206
        to 275.
    *   **Stranded and site networks:** they settled as before, and the
        stranded network recovered from its cut as before.
    *   **Regions network:** its worst pair reached 1.13 to 1.31 times the
        reference in fifteen runs, eight of them 1.19 or more, against 1.11
        to 1.16 in fifteen, and after its cut 1.23 to 1.36 against 1.20 to
        1.23. The link between nodes 2 and 6, the cheapest between the
        regions, was missing in five of ten runs, and in none on the node
        before. Every candidate now measures in every window; before, a
        probe the target's caps refused left its candidate unmeasured and
        its promotion streak reset. Node 2 promoted three links within its
        region in every run, its link to node 1 among them, against one or
        two and never that one. Above its floor, node 2 retires its link to
        node 6 as useless: node 0's link serves node 2's own routes within
        the demotion ratio, while node 6's routes into node 2's region cost
        up to 1.23 times the reference without it. The end that dialed a
        link judges it by its own routes alone; the selection's fix follows
        in a proposal of its own.
