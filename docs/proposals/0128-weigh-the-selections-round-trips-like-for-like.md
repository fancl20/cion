# Weigh the selection's round trips like for like

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
first driver, like for like, for the topology selection: the direct side
counts the probes it lost, as every route's price does, and every price the
selection weighs carries its route's transit charge. The selection's rules
stand; the values they weigh change.

[TOC]

## Summary

Today:

*   **The direct side forgets its losses**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)): an
    echo, a binding request, or a punch probe that goes unanswered leaves no
    sample, so a peer's reading and bounds rest on its answered round trips
    alone. A route's price divides by its delivery rate, so a direct link
    that loses one probe in three reads a third cheaper than a route over
    the same link would.
*   **A tier's price leaves its transits uncharged**
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)): the
    cheapest route into a tier, the excluded measurement's, and their bounds
    are read at their costs, while each member's own price is read at its
    price, charged for every transit. The second-route rule, the useless
    test's tier-level comparison, the eviction's harm, and the price of a
    member no route prices weigh an uncharged round trip where a charged one
    stands beside it.

## Motivation

### Goals

*   Both sides of every comparison the selection takes read alike: the
    direct side's estimates divide by its delivery rate as a route's do, and
    every price is charged as the picks charge it.
*   The rules, their lines, and their streaks stand; a later proposal moves
    them onto the library's comparisons and holds.

### Non-goals

*   How the selection decides: its ratios, its confirmed case, its streaks.
*   The readings' and bounds' spans and statistic, the leases' cost, and the
    picks.
*   Liveness, whose down verdict stays a count of windows.

## Proposal

### The lines and their reasons

| Line | Value | Reason |
| :-- | :-- | :-- |
| A direct probe's outcome | its round trip, or lost: an echo no reply answered within its wait, the binding request that ended a run unanswered, a punch probe whose echo never came | the outcomes a route's probes record |
| A window's direct side | measured when one of its probes answered; its reading and bounds those of the instrument's samples, the losses counted | an unanswered window still measures nothing, so a silent peer is no candidate, while a lossy peer's losses weigh |
| A price | a route's cost charged `scion.TransitPenalty` for every AS it crosses between its ends, each way, at every level: a member's, a tier's, the excluded measurement's | the price the picks rank by, which the selection buys and keeps links for |

### The direct side

*   **The outcomes.** Each window's probe of a peer records every probe's
    outcome on its instrument: each of the `ProbeRuns` echoes' round trip or
    loss; the binding requests answered and the one unanswered that ended
    the run; a punch probe's echoes answered, the rest of its `ProbeRuns`
    lost. A probe the instrument could not send, for want of a probe conn
    or a resolved host, and a punch probe that failed record nothing.
*   **The estimates.** The instrument's samples, the losses among them, give
    the direct side's reading and bounds through `scion.ReadingEstimate` and
    `scion.BoundsEstimate`, each divided by its window's delivery rate as a
    route's are. A window none of whose probes answered measures nothing:
    the peer classes into no tier, as today.
*   **The reports and declarations** publish the direct side's value, its
    losses counted.

### The prices

*   **A tier's price** is its cheapest clean read route at its price, and
    its low the lowest lower bound of those routes at their prices.
*   **The excluded measurement's** price, low, and high read the survivors'
    and the crossing routes' prices and bounds at their prices.
*   **The harm** of an exclusion is how far it moves the tier's price at
    its price.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The direct side's outcomes; the prices at every level charged |

## Compatibility

Nothing on the wire changes. A peer that loses probes reads, reports, and
declares dearer, as a route over the same link does, and a tier's price and
the second-route rule's ratio rise by the transits of the route that prices
it.

## Test plan

*   **The outcomes.** An echo run answered in part records its losses; a
    binding request run ended by a loss records it; a punch probe answered
    in part records its losses; a probe never sent records nothing.
*   **The estimates.** The direct side's reading and bounds divide by the
    delivery of the instrument's samples; a window none of whose probes
    answered measures nothing, its losses kept.
*   **The prices.** A tier priced by a route through a transit carries the
    transit's charge, as the excluded measurement and the harm do.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the loss sweeps, the settled labs, the cuts, the delay changes,
    and the jitter sweeps.
