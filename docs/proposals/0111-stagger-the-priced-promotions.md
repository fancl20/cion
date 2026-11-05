# Stagger the priced promotions

This proposal staggers the topology selection's promotions on sustained
evidence
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
decision 5): each pair of ends waits its own number of windows, so the nodes
one change moves promote in turn, and the first link's routes can reach the
others before their own promotions are due.

[TOC]

## Summary

Today:

*   **Every priced promotion waits two windows.** A candidate whose direct
    link beats its own price, or that gives a single-route tier its second
    route, is promoted on its second consecutive window of that evidence
    (`PromoteWindows`), at every node alike
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)).
*   **A cut moves several nodes at once.** A cut ejects the routes over its
    link at every node within seconds, and several nodes then find a far
    peer priced well above their direct round trip: 233 milliseconds
    against 165 in one instrumented run. In the regions cut benchmark's slow
    runs, two to seven such links were promoted within a minute of each
    other, by several nodes or by one node a window apart. A new link's
    routes take 30 to 60 seconds to reach other nodes, so the other streaks
    ended before the first link's routes arrived.
*   **The surplus links retire minutes later.** Three windows decided
    useless (`DemoteWindows`) retire each surplus link, one and a half to
    two and a half minutes after its promotion, and the paths over it break
    for seconds until the leases move. The regions network recovered from
    its cut in 10 seconds in 4 runs of 6 at the commit before, and in 3 to
    4 minutes in the others; the commits since
    [proposal 0107](/docs/proposals/0107-request-the-selections-route-measurements.md)
    showed this tail in 0 to 4 runs of 6.

## Motivation

### Goals

*   The nodes one change moves promote in turn: the first link's routes
    reach the others before most of their promotions are due.
*   A node with several candidates waits for its first link's routes before
    the next promotion as often.
*   The promotions that restore reach, below the floor and into a stranded
    tier, stay immediate.

### Non-goals

*   Coordinating the nodes: each still decides on its own measurements.
*   Retiring a link gracefully: draining before retirement stays shelved
    ([proposal 0092](/docs/proposals/0092-drain-a-link-before-retiring-it.md)).
*   The promotion and retirement rules: the ratios, the margin floor, and
    `DemoteWindows` stay as they are.

## Proposal

*   **Each pair waits its own windows.** A priced promotion, a beaten price
    or a second route, needs `PromoteWindows` consecutive windows of its
    evidence plus the pair's draw of 0 to `PromoteJitter` windows. The draw
    is SHA-256 over both ends' ISD-ASes, the pair's own and the same in
    every window. ISD-ASes are drawn at random, so two pairs wait the same
    windows one time in eleven.
*   **The jitter spans `StaleAfter`.** `PromoteJitter` is `StaleAfter`'s
    worth of windows, 10 of 30 seconds: the horizon in which a link change
    plays out in every node's segments
    ([provider.go](/pkg/libs/scion/provider.go)). A new link's routes
    reach another node within a registration and a lookup refresh, a minute
    each, so most nodes the change moves price the first link before their
    own promotions fall due. No cap ends the herd: two pairs whose waits
    end a window apart still both promote.
*   **The reach cases stay immediate.** Below the floor and for a stranded
    tier, a node promotes in the window that finds the need, as today.

With 30-second windows, a priced promotion waits one to six minutes,
against one. A promotion the network needs alone waits up to five minutes
longer, and settling after a start, which runs on priced promotions once
the floor stands, can take longer: the NAT and site labs get an hour to
settle, as the regions lab does. The stagger stands in for coordination: a
coordinated topology layer, with this per-node selection as its fallback
([proposal 0092](/docs/proposals/0092-drain-a-link-before-retiring-it.md)),
would choose who promotes and promote at once.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | `PromoteJitter`; the priced promotions wait each pair's draw |
| `internal/testnetwork/behavior` | The NAT and site labs settle within an hour |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **The draw.** Each pair waits from `PromoteWindows` to
    `PromoteWindows` + `PromoteJitter` windows; a range of peers draws every
    value between from one node, and a range of nodes from one peer.
*   **The selection.** A beaten price and a second route each promote on
    the pair's last window, never before, and a flapping candidate starts
    over; the floor and a stranded tier promote at once for a pair that
    waits the most.
*   **The labs and benchmarks** pass. The regions cut benchmark runs six
    times against the commit before, with its cut's link changes and
    recovery reported, and the regions settled and stranded cut benchmarks
    three times each.
