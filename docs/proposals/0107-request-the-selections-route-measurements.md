# Request the selection's route measurements

This proposal implements
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 6
for the topology selection, and decision 7's part for it. The selection
requests its baseline and excluded routes on the node bus, the ping
application measures them beside the leases' paths, and the comparator reads
their health and cost from the path provider. The ten-second hold stays; its
removal lands through a proposal of its own.

[TOC]

## Summary

Today:

*   **The selection echoes its own routes.** Each thirty-second window, it
    echoes every peer's freshest clean route, and for every up link the
    freshest clean route that avoids the link, three echoes each, the median
    priced ([selection.go](/pkg/modules/topology/impl/measured/selection.go),
    [tiers.go](/pkg/modules/topology/impl/measured/tiers.go)). A route whose
    echoes go unanswered prices nothing that window; every other composed
    route prices by its declared delays.
*   **Its view of a route is its own.** A route counts while it crosses no
    held signal and none of the node's down links
    ([queries.go](/pkg/modules/topology/impl/measured/queries.go)). A route
    through a link that died elsewhere counts until its segments expire,
    though the prober ejected it, and the prober measures some of the same
    routes again for the picks and leases.

## Motivation

### Goals

*   One instrument and one budget: the prober measures every route the
    selection prices, once for every requester.
*   The selection reads what the picks read: a route the prober ejected is
    no route, and a measured route prices at its measured cost.
*   Without the ping application, the selection decides what declared delays
    decide, and leaves undecided what needs a route measurement.

### Non-goals

*   Removing the ten-second hold: health, composition's `Crossing`, and the
    prober still read it.
*   The direct side: the one-hop echo to each neighbor, the binding requests
    and punch probes to candidates, and the declared latencies stay the
    selection's.
*   The cost's definition: the selection prices a route as the picks do.
*   Probes beside traffic without the ping application: the library sends
    nothing of its own and runs no loop (ADR-0035, decisions 1 and 7), and
    the selection's routes rarely carry traffic.

## Proposal

*   **A priced role** ([paths.go](/pkg/libs/bus/paths.go)). `PathPriced`
    names a route a requester prices. The prober probes it every thirty
    seconds while its destination is hot, first at once, and a lost probe
    calls a burst ([prober.go](/pkg/apps/ping/prober.go)). Where two
    requesters name one path, it ranks after `PathInUse` and before
    `PathStandby`.
*   **What the selection requests**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)). Each
    window, under its own requester:
    *   every peer's baseline, its freshest clean route, priced;
    *   every up link's freshest clean survivor, priced;
    *   each peer's freshest ejected route fresher than its baseline,
        half-open once its backoff elapses, so a route that recovers counts
        again.

    A window's requests replace the last window's.
*   **Health in the comparator**
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go),
    [queries.go](/pkg/modules/topology/impl/measured/queries.go)). A route
    is clean while it is healthy or unknown and crosses none of the node's
    down links. It prices at its cost: the measured round trip raised by
    loss, else twice its declared delays; a member's price adds its
    transits, as today. A tier is stranded when no up link and no clean
    route reach it. The useless test decides when the link's freshest clean
    survivor is healthy.
*   **The path echoes go.** The baseline and excluded echoes go with their
    test seams; the one-hop echo stays.
*   **An ejected candidate carries its retry**
    ([health.go](/pkg/libs/scion/health.go)). `Candidate.Retry` is when an
    ejected path is due its half-open probe; the picks' requests read it
    too.

Without the ping application nothing measures the selection's routes, and
every route stays unknown: a tier is stranded only when no clean route
composes, the useless test never decides, and promotions price by declared
delays.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | The priced role; replacing a requester's entries |
| `pkg/libs/scion` | `Candidate.Retry` |
| `pkg/apps/ping` | Probes priced routes |
| `pkg/modules/topology/impl/measured` | Requests its routes and reads their health; the path echoes go |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **Requests.** A window requests each peer's baseline and each up link's
    freshest clean survivor priced, and an ejected route fresher than a
    baseline half-open at its retry; the next window's requests replace
    them.
*   **The comparator.** An ejected or suspect route neither counts nor
    prices; a measured route prices at its cost; a tier with no up link is
    stranded once no clean route reaches it; the useless test waits for a
    healthy survivor. With every route unknown, prices are declared, no tier
    is stranded while a clean route composes, and no link is judged useless.
*   **The prober.** A priced route is probed every thirty seconds while hot,
    first at once, and a lost probe calls a burst; a path two requesters
    name follows the merged role.
*   **The labs and benchmarks** pass; the regions settled and cut benchmarks
    and the stranded cut benchmark hold against the commit before.

## Implementation history

*   Landed with two changes to the plan
    ([queries.go](/pkg/modules/topology/impl/measured/queries.go),
    [selection.go](/pkg/modules/topology/impl/measured/selection.go)).
    *   A route counts and prices unless it is ejected, crosses a held
        signal, or crosses one of the node's down links. A suspect route
        counts, as it did before, while the window's request decides it. A
        tier is stranded, as planned, once no up link reaches it and none of
        its routes is healthy or unknown. With suspect routes left out, the
        regions network promoted and retired links in turn: one of three cut
        runs promoted 28 links whose direct round trip beat their price and
        retired 21 as useless, against 13 to 17 and 4 to 7 the commit
        before, and its links never held for ten minutes within the hour.
        One settled run took 28 minutes.
    *   A half-open request skips a route over one of the node's down
        links.

    In three runs on one machine against the commit before, the regions
    network settled after 12 to 15 link changes in 6 to 7 minutes, against
    11 to 14 in 4 to 7, and recovered from its cut in 10 seconds every
    time. In 11 runs each, the stranded network recovered from its cut in
    10 seconds in 9, against 10; the slowest took 3.5 minutes, against
    2.8. Two runs each never settled: the cut took one of the founder's
    two links, and the lab had cut the founder off the far side.
