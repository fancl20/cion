# Price each peer by its own route

This proposal implements
[ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md) in the
measured provider's selection loop:

*   each peer's price is the cheapest route into it, each route charged 5ms
    for every node it crosses;
*   promotion compares a candidate with its own price, beyond a 2ms margin
    floor;
*   the useless test holds every member to its own price, and the link's
    neighbor to its direct round trip.

The implementing commit flips ADR-0026 to accepted. No wire message, stored
field, or run argument changes.

[TOC]

## Summary

The selection loop prices tiers
([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)):

*   `windowTiers` prices a tier by the cheapest of its members' clean
    candidates, a probed carrier by its baseline echo and every other by
    its declared sum.
*   `measureExcluded` prices the same over the candidates that avoid an up
    link, its survivors.
*   `qualifies` compares a candidate's direct round trip with the tier's
    price.
*   `judge` decides a link useless from the tier's price and route count
    alone.

A member served only by a detour never shows, and a route through one more
node prices as a few milliseconds.

Measured on a scratch copy of the change below, five runs of each
benchmark:

*   **Regions lab:** the worst pair stood 1.20 to 1.24 times the reference
    under the labs' 5ms penalty, where it stands 1.97 to 2.13 today; the
    worst pair after any single cut stood 1.38 to 1.58 times, where it
    stands 2.53 to 4.83.
*   **Stranded lab:** it never left a 7-times pair.
*   **Labs:** both settled and healed in every run.
*   **Costs:**
    *   the regions lab's link set settled on 20 or 21 links where 15 to 17
        stand;
    *   it stored 126 to 159 up segment records where 92 to 109 stand;
    *   46 to 54 of its 72 pairs still reached right after a cut, where 56
        to 63 do.

## Motivation

### Goals

*   Every peer earns the link its own route lacks. A member of a reached
    tier whose route rides a detour beyond the promotion ratio, transits
    charged, gets its link.
*   Promotion and retirement read one price: a link promotion would re-add
    never tests useless.
*   The labs settle and heal as before, and the benchmarks record the
    change.

### Non-goals

*   No change to the floor, the cap, the stranded clause, the second route
    for a single-route tier, the down-verdict retirement, or eviction's
    harm, which still reads the tier's price.
*   No transit penalty in the path ranking
    ([proposal 0072](/docs/proposals/0072-serve-every-pair-a-live-path-ranked-by-declared-latency.md)):
    the topology carries it.
*   No change to beacon selection or segment lifetime.
*   No data shared between nodes beyond what they share today.

## Proposal

### Member prices

`tier` gains `prices`, each member's own price:

*   the cheapest of its clean candidates, its carrier by its baseline echo
    and the others by their declared sums;
*   each charged `TransitPenalty` for every node the route crosses, each
    way;
*   absent for a member nothing prices.

`excludedSample` gains two fields:

*   `prices`, each member's price over its survivors: the freshest survivor
    by the excluded echo, a surviving carrier by its baseline echo, the
    others by their declared sums;
*   `cutOff`, the members a clean route reached and no survivor does.

A route's transits are the distinct ASes of its link set beyond its two
ends.

### Promotion

`tier.qualifies` takes the candidate's ISD-AS. Its priced case admits a
direct round trip that beats the member's price by `PromotionRatio` and by at
least `MarginFloor`. A member without a price takes the tier's price. The
second route for a single-route tier is unchanged.

### The useless test

`judge` keeps the tier's conditions, then reads every member:

*   the link's own neighbor against its direct round trip;
*   any other member against its own price with the link.

A cut-off member, or a survivor price beyond the demotion ratio, decides the
link useful.

### Constants

`TransitPenalty` is 5ms and `MarginFloor` is 2ms
([selection.go](/pkg/modules/topology/impl/measured/selection.go)).

### Packages touched

| Package                              | Change                                                   |
| :----------------------------------- | :------------------------------------------------------- |
| `pkg/modules/topology/impl/measured` | Member prices, promotion, the useless test, the constants |
| `docs/adrs`                          | ADR-0026 accepted                                        |

### Migration

One commit keeps the tree green. Member prices, promotion, and the useless
test land together: promotion by member price beside a tier-priced useless
test retires the links it promotes. The commit flips ADR-0026 to accepted,
and its history entry records the benchmarks across five runs.

## Compatibility

Nothing on the wire or in the store changes. A node decides only its own
links: a link it dialed retires by its own test, a link a peer dialed by the
peer's. Nodes on the previous release keep pricing tiers, and a mixed network
converges, each end applying its own rule to the links it dialed.

## Test plan

*   **Member prices:** a member's price is the cheapest route into it, its
    carrier by echo and the others by declared sums, each charged the
    penalty for every transit. A member no route prices has no price.
*   **Promotion:**
    *   a candidate whose own route detours beyond the promotion ratio and
        the margin floor promotes, even while another member prices the
        tier cheaply;
    *   one within the floor does not;
    *   a candidate without a price promotes on the tier's.
*   **The useless test:**
    *   a link stays when a member's route needs it, or when its neighbor
        keeps no route within the ratio of its direct round trip;
    *   a link every member's route avoids within the ratio retires.
*   **Existing tests:** the selection tests that price detours on raw round
    trips update their expectations.
*   **Labs:** the regions lab settles and the stranded lab heals.
*   **Benchmarks:** the settled and cut benchmarks of both networks, five
    runs each.

## Implementation history
