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
