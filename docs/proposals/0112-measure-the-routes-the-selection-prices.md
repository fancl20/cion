# Measure the routes the selection prices

This proposal has the topology selection request measurements of every
route it prices by: each member's cheapest route with every link, and its
cheapest survivor of each up link, beside the baseline and the freshest
survivor it requests today. A route through a link gone elsewhere then fails
its probe and stops pricing within a window, instead of pricing at its last
measurement until its segments age out.

[TOC]

## Summary

Today:

*   **The selection measures its freshest routes.** It prices each member
    by its cheapest clean route, and the useless test prices the tier and
    each member without an up link by the cheapest clean survivors
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)). It requests
    each peer's freshest clean route and each up link's freshest survivor
    priced ([selection.go](/pkg/modules/topology/impl/measured/selection.go));
    the routes it prices by may go unprobed.
*   **An unprobed route keeps its last cost.** A route's cost is the round
    trip its record measured, else its declared delays
    ([health.go](/pkg/libs/scion/health.go)), and a route no one requests
    reads unknown or suspect, not ejected, while no probe fails. A route
    through a link retired elsewhere keeps pricing at its last measurement
    while its segments read fresh, five minutes on, and as a suspect route
    after.
*   **Prices rest on routes that are gone.** In the site lab joined both
    ways, 4 of 18 useless retirements in four runs rested on such a route,
    through a link retired 29 to 165 seconds before. In one run, a site node
    priced a public node at 114 milliseconds through a link retired six
    minutes before; the routes that served priced it at 130 or more, enough
    for the node's own 100-millisecond link to qualify, and it promoted none.

## Motivation

### Goals

*   The routes the selection prices by are measured: a live one answers,
    and one through a dead link loses its probe's burst and is ejected.
*   Promotions and retirements rest on the routes as they are, not as they
    were.

### Non-goals

*   What prices a route: its measured round trip, else its declared delays
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 2).
*   Route counts, which keep counting every clean route (ADR-0017, decision
    4).
*   Ordering the retirements of nodes that count on each other's links,
    which takes coordination between nodes.

## Proposal

*   **The routes the members are priced by are requested.** The selection
    requests, priced, the route each tier member is priced by, its cheapest
    at its price, beside the peer's baseline; and for each up link, the
    survivor each member is priced by without the link, beside the freshest
    survivor. The prober probes each every 30 seconds, the first at once,
    and a burst lost whole ejects it.
*   **The useless count leaves the probe its time.** A link retires after
    three windows decided useless, so a survivor through a dead link is
    ejected before the count it priced retires the link, unless the two
    links go within a probe of each other.

A member's cheapest route avoids every up link but the one it leaves
through, so for each member the requests add its cheapest route and its
cheapest around that link: two routes at most.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | Each member's cheapest route, with every link and without each up link, requested |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **The tiers.** Each member's price comes with the route it is: the
    cheapest at its price, transits charged. Without each up link, the
    survivor each member is priced by; none for a member no survivor
    prices.
*   **The requests.** The window requests each member's cheapest route, in
    a tier no up link reaches as well, and its cheapest survivor of each up
    link, priced, beside the baselines and the freshest survivors.
*   **The labs and benchmarks** pass. The regions settled, regions cut,
    stranded cut, and site settled benchmarks run against the commit
    before, with their useless retirements and settling reported.

## Implementation history

*   Landed as planned. Pricing the useless test only by survivors that
    answered would also have stopped those decisions, but ADR-0017 decision
    2 prices an unprobed route by its declared delays; the requests leave
    that rule as it is.

    In runs on one machine against the commit before, the site lab joined
    both ways settled after 9 to 13 link changes in 6 to 9 minutes in three
    runs, with 3 or 4 useless retirements each, against 10 to 26 changes in
    8 to 43 minutes and 3 to 9 retirements; joined the other two ways it
    settled as before. The regions network recovered from its cut in 10
    seconds in 5 runs of 6, against 6 of 6: in the slow run, two links
    promoted two windows apart after the cut retired as useless, the herd
    [proposal 0111](/docs/proposals/0111-stagger-the-priced-promotions.md)
    staggers. It settled after 14 to 21 link changes in 7 to 13 minutes in
    three runs, against 13 to 17 in 5.5 to 8. The stranded network
    recovered from its cut in 10 seconds in three runs of three.
