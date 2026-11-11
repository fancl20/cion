# Weigh the links' changes on confidence

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
decisions 2 to 4 for the topology selection's link changes: every
promotion, eviction, and useless retirement decides through the evidence
library's comparisons on the bounds of like estimates; an undecided
comparison changes nothing; and a verdict acts once it has stood through a
hold of windows that fresh probes of both sides cross. Every bound rests on
its subject's last thirty samples, so the direct side, probed three times a
window, crosses a lasting change within minutes.

[TOC]

## Summary

Today:

*   **A price is beaten two ways**
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)): on the
    readings alone, by the promotion ratio and the margin floor, room for
    the readings' error; or confirmed, by the band on the readings and on
    the bounds. A window without the bound the confirmed case needs resets
    the streak.
*   **The useless test and the eviction's** decide on the readings and
    confirm on the bounds, each with its own ratio; a missing bound reads as
    useful, and an unpriced member as undecided.
*   **The streaks count windows**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)):
    two for a beaten price, two to twelve for a second route, three for a
    useless link, with no fresh probe asked of either side between.
*   **A bound reads every sample within fifteen minutes**
    ([provider.go](/pkg/libs/scion/provider.go)): ninety of the direct
    side's, whose upper bound crosses a lasting drop only after about
    thirteen minutes, against thirty of a route probed every half minute.

## Motivation

### Goals

*   Every link change the selection weighs decides through
    `evidence.Beats` on two estimates of the bounds' kind: better, not
    better, or undecided, as ADR-0040's second decision has it.
*   A noise margin gives way to confidence: the promotion ratio and the
    margin floor leave the promotion's test, whose line is the band, what
    the path policy moves a lease for.
*   An undecided comparison changes nothing, and missing evidence reads as
    undecided everywhere.
*   The streaks become holds: a verdict acts once it has stood for its
    windows, with a fresh probe of each side answered in between.
*   A subject sampled often reacts within its last samples: every bound
    reads a subject's last thirty samples within its span.

### Non-goals

*   The coordination's waits and the clusters, whose ratio tests and holds
    on the round trips other nodes report move in a later proposal; until
    then the waits keep the promotion ratio.
*   Liveness: a link whose verdict stays down retires after
    `DemoteWindows` windows, as today.
*   The floor's and the stranded tier's promotions, which weigh
    reachability, not a price.
*   The tiers' walk, which classes the peers by their readings.

## Proposal

### The lines and their reasons

| Decision | Better when | Line | Hold |
| :-- | :-- | :-- | :-- |
| A beaten price | the direct side beats the member's price, the tier's for a member no route prices | the band of the two values | `PromoteWindows` |
| A second route | the direct side beats the single-route tier's price | the room `SecondRouteRatio` leaves above the price's value, a negative margin | the pair's `promoteWindows` draw |
| Useless | the survivors beat the routes crossing the link, for the tier and for every member those routes reach, and the link's own neighbor by its direct side | none: a link that helps at all stays | `DemoteWindows` |
| Yields its slot | never: the link yields once the routes crossing it, for the tier and every member they reach, and the neighbor's direct side, are each not better than the survivors | the band of the two values | none: the candidate's promotion holds |
| Outgained | the candidate's gain on its price beats what the link saves every price it reaches | the band of the two values | none: the candidate's promotion holds |

*   **A verdict other than better** releases the decision's hold, as a
    lease's does: the link state holds while the evidence gathers. A
    member whose routes none read leaves the useless test undecided and
    keeps a link's slot, its price unknown.
*   **The confidence** of every bound stays `scion.BoundConfidence`, 0.95:
    a link change reshapes segments network-wide, the costliest mistake the
    node makes.

### The estimates

*   **The bounds' window.** `scion.BoundSamples`, thirty, joins
    `BoundSpan`: a bound reads the last thirty samples sent within fifteen
    minutes, the thirty a route probed every half minute holds over the
    span. The direct side's bounds, three probes a window, read its last ten
    windows, and its upper bound crosses a lasting drop after about ten.
*   **A price** is the least of its routes' price estimates
    (`evidence.Least`): the least value; the least lower bound, which needs
    every route's; and the least upper bound of those that give one. The
    tier's price reads its clean read routes, a member's its own, and the
    excluded measurement the survivors' and the routes crossing the link,
    each at their prices.
*   **A gain and a saving** are differences of estimates
    (`evidence.Estimate.Minus`): the value's difference, each bound against
    the other's opposite bound.
*   **The direct side** is its bounds' estimate, its losses counted.

### The holds

*   **One hold per peer and decision.** A candidate holds its promotion, a
    link its useless retirement; each is an `evidence.Hold` on the direct
    side's estimate and the price or the survivors it weighs, its clock the
    windows run: the hold stands once the verdict has stood for its windows
    and a sample of each side has been answered since it began.
*   **The announcements** keep their own course: a promotion is announced
    while its candidate is the fastest the clustering allows whose price it
    beats and that waits on no other node; a retirement from the first
    window that finds its link useless until one finds it useful, the
    windows that decide nothing keeping it.

### The records

*   **A link's record** weighs the comparison that decided it: the direct
    side and the price for a promotion, its line the band or the
    second-route room; the candidate's beside the tier's price with and
    without the link for an eviction; the direct side, the crossing
    routes, and the survivors for a useless retirement. A beaten price
    records one reason, its direct link beating its own price.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/evidence` | `Least` and `Minus` |
| `pkg/libs/scion` | The bounds' window counts thirty samples |
| `pkg/modules/topology/impl/measured` | The link decisions through the library; the holds; the records |

## Compatibility

Nothing on the wire changes. A beaten price promotes once the direct
side's upper bound stands, after fourteen samples, five windows of probes,
and then its hold, where the readings alone promoted in two windows; a gain
within the promotion ratio that beats the price by the band promotes, as
the confirmed case did. A window that decides nothing retires, promotes,
and evicts nothing, and a bound crosses a lasting change within a
subject's last thirty samples.

## Test plan

*   **The library.** The least of estimates: the least value, the least
    lower bound only with every one, the least upper bound of those giving
    one, and a mistake across kinds; a difference's value and bounds, a
    bound missing where either side's needed one is.
*   **The bounds' window.** A subject's bounds read its last thirty samples
    within the span.
*   **The decisions.** A beaten price promotes on better, not on not better
    nor undecided; a second route within its ratio's room promotes and one
    beyond it does not; a useless link retires once every comparison is
    better, stays at one not better, and holds at one undecided; a link
    yields its slot only when every comparison finds it not better by the
    band, and is outgained only when the gain beats every saving by it.
*   **The holds.** A verdict acts once it has stood for its windows with a
    fresh sample of each side, not before; a window not better restarts
    the hold; an announcement survives a window that decides nothing.
*   **The records.** Each change weighs its comparison's estimates and
    line.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the settled labs, the cuts, the delay changes, the jitter and
    loss sweeps, and the bursts.
