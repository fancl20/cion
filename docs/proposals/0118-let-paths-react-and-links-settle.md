# Let paths react and links settle

This proposal implements the link policy of
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md):
only read routes price a decision, a link retires as useless only once it
helps no one and its history confirms it, a gain the history confirms buys a
link once the path policy would move a lease for it, and the cap's victim is
a link whose history confirms it would not earn its place.

[TOC]

## Summary

Today:

*   **One line.** The useless test retires a link once no member's price
    without it exceeds `DemotionRatio`, 1.25, times its price with it; the
    priced promotion admits a direct round trip below `PromotionRatio`,
    0.8, times the price and 2ms under it
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)). 1.25 is the
    inverse of 0.8. The cap evicts among the links the useless test
    qualifies.
*   **Any price decides.** A route's price is its reading, however few
    probes it rests on, else twice its declared one-way sum
    ([health.go](/pkg/libs/scion/health.go)), and the tier's facts price
    members and survivors by the cheapest route either way.
*   **Five minutes of evidence.** Every decision reads the readings of
    ADR-0038 alone: the 80th percentile of the last five minutes. The prober
    keeps five minutes of probes, and the selection five minutes of each
    peer's round trips.

## Motivation

### Goals

*   Only read routes price a decision (ADR-0039, principle 5).
*   The useless test retires a link only when it helps no one, on its
    readings and on its history (principles 2 and 5).
*   Promotion buys a link on its readings by a fifth, as today, or on its
    history by what the path policy moves a lease for (principles 3 to 5).
*   The cap's victim is a link that would not earn its place today, its
    history confirming it (principle 6).
*   The labs report the formed links.

### Non-goals

*   The path library's picks, leases, health, and cost.
*   The coordination of link changes, the streaks, the floor, and the cap.
*   ADR-0039's clusters (principles 7 to 10).

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| Line to buy, on the readings | a fifth of the price, at least 2ms | at or above the path policy's band at every price, with room for the readings' error (principles 3 and 4) |
| Line to buy, on the history | the band: a fifth of the smaller price, from 2 to 10ms | what moves a lease (principle 3); the confidence holds the error (principle 5) |
| Line to keep | any lead | losing the link moves every lease on its routes (principle 2) |
| The cap's victim | short of the line to buy on the readings, and confirmed within the band | a displacement is a retirement (principle 6) |
| A read route | at least five probes within the five minutes | the fewest of which a fifth may stand high (ADR-0038) |
| Confidence | one-sided 95% | a wrong retirement costs two reshapes and five minutes or more of slower paths; a wrong keep, a window's upkeep |
| History | fifteen minutes, three `StaleAfter` horizons | the shortest span whose upper bound, for a route probed every half minute, tolerates a high probe; a lasting slowdown moves the lower bound after about one horizon |
| A second route | within 1.25 of the tier's price | unchanged: it buys independence, not latency |

### The evidence

*   **Read routes.** `scion.ReadingSamples` is five. `Candidate.Read`
    reports a reading that rests on at least that many probes answered
    within `ReadingSpan`.
*   **Bounds.** `scion.ReadingBounds` returns the bounds of the 80th
    percentile that round trips sample, each with `BoundConfidence`, 95%:
    the order statistics a binomial count of the round trips below the
    percentile reaches with that confidence. They assume nothing of how the
    round trips spread, and a noisy pair's bounds lie wide apart, so it needs
    a larger difference to confirm. The lower bound takes two round trips,
    the upper fourteen.
*   **History.** `scion.BoundSpan` is three `StaleAfter` horizons, fifteen
    minutes. The prober keeps each path's probes sent within it, beside its
    last `PathSamples`. `Candidate.Low` and `Candidate.High` are the bounds
    of the record's probes answered within it, divided by their delivery
    rate. The selection keeps each instrument's round trips within it; a
    peer's direct side is still the reading of those within `ReadingSpan`,
    beside the bounds of all it keeps. An instrument with no round trip
    within `ReadingSpan` starts from those of the instrument that read the
    peer last.
*   **The tier's facts.** The tier's price, each member's own price, the
    survivors' price, and each member's price over its survivors read the
    read routes alone. Each member's cheapest route and cheapest survivor
    are still chosen by their costs, read or not, and the window requests
    them priced, so they get read. Beside the prices, the facts hold the
    read routes' bounds: each member's lowest lower bound, and for each
    up link's exclusion, the lowest lower bound of the routes crossing the
    link and the lowest upper bound of the survivors, the tier's at their
    costs and each member's at their prices. `Candidate.Charge` is what a
    price adds to a round trip, and the bounds take it too.

### The decisions

*   **Promotion.** A member whose routes none read beats no price until one
    is read. A direct round trip beats its price on the readings by
    `PromotionRatio` and `MarginFloor`, as today, or confirmed: the direct
    reading below the price, and the direct upper bound below the price's
    lower bound, each by the band, `scion.BeyondBand`.
*   **The useless test.** The link is useful when its exclusion raises the
    tier's price or any priced member's price at all — its own neighbor's
    against its direct round trip — changes the route count, or cuts a
    member off. A member whose routes none read, or whose survivors none
    read, leaves the window undecided. A window the readings decide useless
    decides it so only where the bounds confirm it: for the tier and for
    each member a read route over the link reaches, the survivors' upper
    bound no higher than the link's lower bound, the neighbor's by its
    direct side's. Otherwise the window decides the link useful.
*   **The eviction.** The cap's victim is drawn from the links that would
    not earn their place: no price the link holds down beaten by
    `PromotionRatio` and `MarginFloor` on the readings, and the bounds
    confirming that it gains no one the band.
*   **The second route.** `SecondRouteRatio`, 1.25, replaces
    `DemotionRatio` there.

### The labs

*   The grading counts the formed links, and the settled benchmarks and the
    jitter sweep report them.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | `ReadingSamples`, `BoundSpan`, `BoundConfidence`, `ReadingBounds`, `Candidate.Read`, `Low`, `High`, and `Charge`; `BeyondBand` exported |
| `pkg/apps/ping` | The prober keeps `BoundSpan` of probes |
| `pkg/modules/topology/impl/measured` | Read prices, the history and its bounds, the confirmed tests, `SecondRouteRatio` |
| `internal/testnetwork/behavior` | The formed links in the grading and the benchmarks |

## Compatibility

Nothing changes on the wire or in configuration.

## Test plan

*   **The evidence.** A record with four probes answered within the
    reading's span is unread, one with five read. The bounds are the order
    statistics the confidence names, from none to 180 round trips, in any
    order; a record's bounds read its probes within `BoundSpan`, divided by
    their delivery rate. The prober keeps the probes of `BoundSpan`. The
    selection's direct side reads `ReadingSpan` and bounds `BoundSpan`, and
    an instrument with no round trip within the reading's span starts from
    the peer's last one.
*   **The facts.** An unread route prices and bounds no fact but is
    requested; the exclusion's bounds split the routes crossing the link
    from the survivors.
*   **The decisions.** Promotion waits on a member whose routes none read,
    and promotes short of a fifth once its history confirms a gain by the
    band, never within it. The useless test decides a link useful on any
    rise, useless on none where the bounds confirm it, useful where they do
    not, and nothing on an unread price; a link whose reading turns useless
    retires only once its history follows. A link that helps by less than
    the band stays, yet yields at the cap; one that gains the band keeps its
    slot. The second route keeps 1.25.
*   **The labs.** The labs pass, and the benchmarks, the unstable delay
    ones included, run against the commit before, reporting the formed
    links.
