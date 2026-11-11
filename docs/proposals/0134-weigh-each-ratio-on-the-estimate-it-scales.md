# Weigh each ratio on the estimate it scales

This proposal reads
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
decision 2 literally for ratios: a comparison against a ratio of an
estimate scales that estimate, its value and both bounds, and decides only
once one side's bounds lie apart from the other's. A ratio no longer enters
as a line computed at the value of the estimate it scales. The library's
operations on estimates take Go's names, `Add`, `Sub`, a new `Mul`, `Min`,
and `Max`, and the share of samples answered takes statistics' name,
`Proportion`.

[TOC]

## Summary

Today:

*   **A ratio is a line at the value.** The tiers' gap adds the median's
    value to its bounds; the second route's room, the buy line's share, and
    the cluster gap each compute their line from the value of the estimate
    they scale, and the comparison adds it to that estimate's bounds.
*   **That keeps the estimate's own spread.** Scaling an estimate scales
    its spread: twice a median whose bounds run from 9ms to 11ms lies
    between 18ms and 22ms, where the line form places it between 19ms and
    21ms. Over one, the line form narrows the spread, and a verdict claims
    beyond its evidence, the cluster gap of eight the most; under one, as at
    the buy line's 0.8, it widens the spread, and a verdict waits for more
    evidence than it needs.
*   **The operations' names differ from Go's:** `Plus` adds a duration,
    `Minus` subtracts an estimate, and `Least` and `Most` read the least and
    the most of several, where Go names its own `min` and `max`; `Share`
    holds a binomial proportion and its exact bounds.

## Motivation

### Goals

*   A ratio scales the estimate it applies to: `Estimate.Mul`, the value
    and each bound times the ratio.
*   Every comparison against a ratio weighs the scaled estimate through
    `evidence.Beats` with no line: it decides once one side's lower bound
    clears the other's upper bound.
*   Margins in time stay lines: the band, the transit charge, and the
    margin floor.
*   `Plus` becomes `Add` and `Minus` becomes `Sub`, as `time.Time` names
    its own; `Least` becomes `Min` and `Most` becomes `Max`, as Go's
    builtins and `slices` name theirs; `Share` and `ShareOf` become
    `Proportion` and `ProportionOf`, a binomial proportion's name.
*   A record weighs the scaled estimate, named for what it states.

### Non-goals

*   The band's share: it sets the band only between its floor and its cap,
    2ms and 4ms, for prices between 10ms and 20ms; the band stays the
    margin a move must gain.
*   `Div`: every ratio here is a factor, and one under one multiplies.

## Proposal

### The ratios

| Decision | Weighs | Today's line |
| :-- | :-- | :-- |
| A peer opens the next tier | the tier's median times `TierGap` against the peer | `TierGap` less one times the median's value |
| A single-route tier's second route | the direct side against the tier's price times `SecondRouteRatio` | the room the ratio leaves above the price's value |
| A pair buys a link: the coordination's violation, the lighter pair, the budget | the pair against the path times `PromotionRatio`, and against the path by `MarginFloor` | the share the ratio leaves of the path's value, at least the floor |
| A natural cluster | its diameter times `ClusterGap` against its separation | `ClusterGap` less one times the diameter's value |

*   **`Mul`** scales the value and each bound the estimate has by the
    ratio, keeping its samples; a ratio not above zero is a caller's
    mistake.
*   **A ratio beside a floor** decides as both: better once the pair beats
    the scaled path and beats the path by the floor, not better once
    either comparison is not better.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/evidence` | `Add`, `Sub`, `Mul`, `Min`, `Max`, and `Proportion` |
| `pkg/libs/scion` | `Add` for the transit charge; `Proportion` for the ejection |
| `pkg/modules/topology/impl/measured` | The tiers' gap, the second route, the buy line, and the cluster gap weigh scaled estimates; the records weigh them |

## Compatibility

Nothing on the wire changes. A verdict against a ratio over one waits until
the bounds part by the scaled estimate's whole spread: a peer leaves its tier
once its lower bound clears twice the median's upper bound, and joins one
once its upper bound lies under twice the median's lower bound. A pair buys
a link a little sooner: a path's bounds scaled by 0.8 spread narrower than
its own.

## Test plan

*   **The library.** `Mul` scales the value and each bound, and leaves an
    estimate without an answered sample as it is; `Add`, `Sub`, `Min`,
    `Max`, and `Proportion` as `Plus`, `Minus`, `Least`, `Most`, and `Share`
    did.
*   **The sites.** Each ratio decides at the edge of its scaled comparison
    and stays undecided within the scaled estimate's spread, where the line
    form decided; the buy line's floor still decides where the ratio's
    share falls under it.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before.

## Implementation history

*   **One comparison to buy.** `buys` weighs a pair against the round trip
    it would replace, both conditions folded, for the coordination's
    violation, the lighter pair, and the budget. `secondRouteCeiling`,
    `buyCeiling`, and `separationFloor` name the scaled estimates.
*   **The records' names.** A second route's record weighs the direct side
    and the tier's `ceiling`, the price scaled; a natural cluster's, its
    `floor`, the diameter scaled, beside its separation; a broken budget's,
    the direct round trip, the `ceiling` of the round trip through the
    clusters, and that round trip, with `MarginFloor` as its line.
*   **`Mul` needs no case for an estimate without an answered sample:** it
    states nothing, and scaling leaves it so.
*   Mutations: 11 of 11 killed.
*   The pipeline passed but for `TestJoinByEnrollAuthTelegramRestart` under
    the race detector, which timed out waiting for the joiner to enroll
    after the core's restart; alone, it passed six runs of six.
*   **The labs of fixed delays decide as before.** Their estimates carry no
    spread, so a ratio weighs alike scaled and as a line: 30 runs of the
    NAT lab and 2 of the metros lab weighed every ratio both ways, and no
    decision differed. Two verdicts did, both buys in the metros lab: not
    better where the line leaves undecided, which every caller of `buys`
    treats alike.
*   Benchmarks against the commit before: every lab reached every pair, its
    worst pair as the commit before's. The NAT lab, fourteen runs each,
    settled at 15 or 16 links within a median 6.8 minutes against 6.5;
    three runs took 12.5 to 15 minutes, against the commit before's longest
    9.2, as one instrumented run of thirty did: two nodes announce
    retirements of links to public nodes and wait on each other, and once
    the first retires, the second waits the five minutes the departed
    link's routes take to go stale. The metros lab, three runs each,
    settled at 24 links against 25, as an instrumented run with no verdict
    differing did, within 5.2 to 7.3 minutes against 5.5 to 6.8. One run
    each: the regions lab at 30 links within 7.7 minutes against 8.0; the
    ring at 46 links within 8.8 minutes against 45 within 8.2; the site
    placements on the same links within 4.5 to 4.8 minutes against 5.2 to
    9.3; the metros and regions cuts recovered within 10 seconds, as the
    commit before's.
