# Select beacons per origin and per link

This proposal implements
[ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md): a node
sends each neighbor, and registers for itself, each origin's cheapest
route, a backup, and each link's cheapest route, among the routes whose
beacons keep arriving, in place of its five freshest beacons.

[TOC]

## Summary

Today:

*   **A node forwards and registers its five freshest candidates**
    (`BestSetSize` in [beacon.go](/pkg/core/controlplane/beacon.go)). The
    store keys a candidate by its arrival interface, its origin, and its
    segment ID, so every origination of one route is a candidate of its own,
    and copies of one route take several of the five slots
    ([beaconstore.go](/pkg/core/controlplane/beaconstore.go)).
*   **Every neighbor receives the same five,** less those that cross it,
    and a neighbor that has not enrolled the founder's five freshest
    ([0113](/docs/proposals/0113-send-unenrolled-peers-the-founders-beacons.md)).
*   **Nothing in the set is ensured:** neither an origin, nor a backup, nor
    a link's routes.

## Motivation

### Goals

*   The store holds one candidate per route over each interface, and the
    time its newest origination arrived (ADR-0036, decisions 1 and 2).
*   A set holds each origin's cheapest route, the founder's first, the
    backups, and each link's cheapest route, ranked by price, and at most
    64 routes (decisions 3, 4, and 6).
*   A neighbor's set is chosen among the routes it can take, and the node
    registers its own set (decision 5).
*   ADR-0036 is accepted.

### Non-goals

*   The topology selection's promotion herds after a cut (decision 7).
*   Core segments in path composition.
*   When the probe of a peer's enrollment runs (0113).

## Proposal

### The store

*   **A candidate is a route over an interface.** The store keys a
    candidate by its arrival interface and its route: each entry's ISD-AS
    and ingress and egress interfaces, the path database's key
    ([pathdb.go](/pkg/modules/pathdb/pathdb.go)). A fresher origination of
    the route replaces the candidate, and the store records when it
    arrived. The bound of 64 per interface now counts routes, the stalest
    leaving first.
*   **A candidate qualifies while its route's beacons arrive.**
    `Qualifying` returns the unexpired candidates whose newest origination
    arrived within a window the caller gives, among those a filter admits.
    It replaces `BestSet`.

### The selection

*   **The qualifying routes.** Each pass reads the candidates whose newest
    origination arrived within three propagation intervals, over an
    interface the link table still binds to their sender, the check
    `bestSet` makes today.
*   **The price.** A route's price is twice its declared one-way delay plus
    twice `TransitPenalty` for each AS between the node and the origin:
    every entry but the origin's. An edge's declared delay is the higher of
    its two ends' declarations, the rule the library prices composed paths
    by, which moves to `segment.EdgeDelay`; the edge into the node carries
    its sender's declaration alone. A route with an undeclared edge ranks
    after every priced one. Ties go to fewer entries, then to the newer
    origination, then to the route's key.
*   **The picks, in order.**
    1.  Each origin's cheapest route, the founder's first.
    2.  While some link is crossed by every route picked and an unpicked
        route avoids one such link, the cheapest such route.
    3.  For each interface with routes of which none was picked, its
        cheapest route.

    A link is named by the interface an entry leaves by, the last entry's
    being the link into the node. The set keeps its first 64 picks: a
    receiver keeps at most 64 candidates per interface, so more routes over
    one link would only evict one another.
*   **The sets.**
    *   A neighbor's set is chosen among the qualifying routes that do not
        cross it, the founder's alone for a neighbor that has not enrolled.
    *   The node's own set, which it terminates and registers, is chosen
        among every qualifying route. A core terminates the routes of its
        own set that a core sent into core segments, as today.
    *   `BestSetSize` and `BestSet` are removed.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/core/controlplane` | The store keyed by route, with arrival times; the selection; a set per neighbor; registration of the node's own set |
| `pkg/libs/segment` | `EdgeDelay`, the rule pricing one edge |
| `pkg/libs/scion` | Composition prices its edges with `EdgeDelay` |
| `docs` | The architecture's path discovery; ADR-0036 accepted |

## Compatibility

Nothing on the wire changes. A node of this release sends each neighbor a
set of its own, and neighbors of an earlier release accept any beacon that
verifies. Networks start afresh, as none is in production.

## Test plan

*   **The store.** Originations of one route over one interface share one
    candidate, the fresher kept; distinct routes are distinct candidates;
    the bound counts the routes per interface, the stalest leaving first. A
    route qualifies until the window passes without a fresher origination,
    and again once one arrives.
*   **The price.** Declared delays, the transit penalty, and the edge rule
    order the routes; a route with an undeclared edge ranks after every
    priced one; ties go to fewer entries, then to the newer origination.
*   **The picks.** The founder's cheapest route leads, and each origin's
    cheapest follows. A backup avoids a link every pick crosses, and none
    joins once no link is common or no route avoids one. Each interface's
    cheapest route joins when none of its routes was picked. A set holds
    at most 64 routes.
*   **The sets.** A neighbor's set skips the routes that cross it and still
    carries the cheapest route it can take; a neighbor that has not
    enrolled receives the founder's routes alone; the node registers its
    own set; a route whose beacons stopped leaves every set three
    propagation intervals later.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before.

## Implementation history

*   The store keys a candidate by its arrival interface and its route,
    encoded as the path database encodes its key, and records when its
    latest origination arrived; `Qualifying` returns the unexpired
    candidates whose latest origination arrived within the window
    ([beaconstore.go](/pkg/core/controlplane/beaconstore.go)).
*   The selection lives in
    [beaconselect.go](/pkg/core/controlplane/beaconselect.go): `rankRoutes`
    prices and orders the qualifying routes once per pass, and `pickSet`
    picks a set among the ranked routes a neighbor can take, or among all of
    them for the node's own set. Ties after the newer origination go to the
    route's key, then to the interface, so the order is total.
*   `segment.EdgeDelay` holds the edge rule, and the library's composition
    prices its edges with it
    ([segment.go](/pkg/libs/segment/segment.go),
    [provider.go](/pkg/libs/scion/provider.go)).
*   The tests landed as planned. Mutations 30 of 30 killed.
*   Benchmarks against the commit before (two or three runs here, the
    parent's from earlier runs of the same code, five in the site and NAT
    labs):
    *   The regions lab settled after 18 and 19 link changes within 6.2
        and 8.3 minutes, against 18 and 21 within 7.5 and 17.7, its worst
        pair at 1.11 times the reference, against 1.05 and 1.11.
    *   After the regions cut, reach held from 20 seconds in all three runs,
        against 10, 10, and 570 before: no promotion herd, two or three link
        changes, and the worst pair at 1.23 times the reference, against
        1.17 to 1.19.
    *   After the stranded cut, reach held from 10 seconds in every run. One
        run never settled: the cut left a node one link and no candidate it
        could reach, a case earlier runs show too.
    *   The site lab joined both ways settled after 12 changes within 7.3
        minutes, against 12 within 10.7, its worst pair at 1.1 to 1.5 times
        the reference, as before; the NAT lab after 12.5 changes within 5.3
        minutes, against 12 within 6.0; the NAT lab's founder-down nodes
        survived in 14.8 seconds and returned in 225, against 15.8 and 209.
    *   The path databases hold fewer up segments: 77 in the regions lab, 39
        in the site lab joined both ways, and 38.5 in the NAT lab, against
        171, 90, and 105.
