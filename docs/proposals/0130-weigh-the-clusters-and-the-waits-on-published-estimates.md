# Weigh the clusters and the waits on published estimates

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
decisions 1, 2, and 5 for the round trips nodes report to each other: a
report states one estimate, its value and bounds of one kind; every node
reads the reports back as estimates; and every comparison the clusters and
the coordination's waits take on them decides through the evidence
library's comparisons, an undecided one changing nothing. A cluster joined
or left records the numbers that decided it.

[TOC]

## Summary

Today:

*   **A report mixes two estimates**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)): its
    round trip is the direct side's reading, over five minutes of samples,
    and its bounds those of the last thirty samples within fifteen minutes.
*   **The waits weigh readings alone**
    ([coordination.go](/pkg/modules/topology/impl/measured/coordination.go)):
    a pair whose reported round trip beats the summed round trips of the
    published path between its ends by the promotion ratio and the margin
    floor is predicted to promote, and holds back the promotions it would
    serve, whatever the bounds.
*   **The clusters confirm by hand**
    ([clusters.go](/pkg/modules/topology/impl/measured/clusters.go)): a
    natural cluster weighs its upper bounds against the lower bounds around
    it; a lighter pair outruns a linked one at the linked pair's round trip
    and at its lower bound; a unit breaks its budget at the round trips and
    again at the bounds. Each test mixes the readings and the bounds its own
    way.
*   **A cluster change records its reason** without the numbers it weighed.

## Motivation

### Goals

*   A report states one estimate: the value and the bounds of the direct
    side's bounds estimate.
*   Every node reads each report back as an estimate, combines the
    estimates through the library — the sum along a path, the least of
    several, the most of a cluster's pairs — and weighs them through
    `evidence.Beats`.
*   The lines stay the sites': the promotion ratio and the margin floor for
    the waits, the outrunning pair, and the budget; `ClusterGap` for a
    natural cluster.
*   An undecided comparison changes nothing: it predicts no promotion,
    switches no pair, and forms or breaks no cluster.
*   A cluster joined or left records the estimates and the line that
    decided it.

### Non-goals

*   The coordination's protocol waits: the windows another node's announced
    or predicted promotion holds a promotion back, the window an
    announcement waits before it acts, and the `scion.StaleAfter` a new or
    departed link is waited on. They time the protocol, not evidence, as
    link liveness does.
*   A hold on cluster changes: the clustering holds still by its own rules,
    a node joining only a natural cluster and leaving only a unit that fell
    below two members or broke its budget.
*   The delays a node declares, which beacon selection ranks.

## Proposal

### The lines and their reasons

| Decision | Better when | Line |
| :-- | :-- | :-- |
| A pair violates | the pair beats the cheapest published path between its ends, or no path joins them | the share `PromotionRatio` leaves of the path's value, at least `MarginFloor` |
| A lighter pair outruns a linked one | the lighter pair beats the linked one | the share `PromotionRatio` leaves of the linked pair's value, at least `MarginFloor` |
| A natural cluster | its diameter beats its separation | `ClusterGap` less one times the diameter's value |
| A unit breaks its budget | a pair across its edge beats the round trip through the two units' closest members | the share `PromotionRatio` leaves of that round trip's value, at least `MarginFloor` |

*   **A violating pair** is one the comparison finds better. Another node's
    pair predicted to promote is one; a node's own promotion waits on a
    lighter pair while linking it would leave the node's pair no longer
    better; and a node whose own pair is not better than the published path
    waits only while a link on that path is too new for its routes to see.
*   **A verdict other than better** changes nothing: no prediction, no
    switch from the linked pair, no cluster formed, no cluster broken.
*   **The confidence** stays that of the bounds the nodes report,
    `scion.BoundConfidence`: a cluster or a wait moves links network-wide.

### The estimates

*   **A report** publishes the direct side's bounds estimate: its value,
    stepped as today, and its bounds.
*   **A published estimate** (`evidence.Published`) states a value and the
    bounds the publisher gave, for a reader that holds no samples: one
    answered sample stands for the publisher's.
*   **A pair's estimate** is the larger of its ends' reported values, of
    their lower bounds, and of their upper bounds, as today.
*   **A path's estimate** sums its pairs' estimates (`evidence.Sum`),
    charged a transit for every node between its ends: the values, the
    lower bounds where any pair gives one, a missing one counting zero, for
    no round trip is shorter, and the upper bounds where every pair gives
    one. The cheapest published path between two nodes is the least of all
    paths' estimates, as `evidence.Least` has it: the least value, the
    least lower bound, and the least upper bound, each over the paths.
*   **A cluster's diameter** is the most of its pairs' estimates
    (`evidence.Most`), and its separation the least of the pairs from its
    members to the nodes outside that a report weighs.
*   **The round trip through two units' closest members** sums its hops'
    estimates.

### The records

*   **A cluster joined** records the natural cluster's diameter and
    separation and the line; **a cluster left** for a broken budget, the
    pair's estimate beside the round trip through the clusters and the line;
    one left for a unit below two members, its reason alone.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/evidence` | `Published`, `Sum`, and `Most` |
| `pkg/libs/scion` | The estimate a published round trip states |
| `pkg/modules/topology/impl/measured` | The reports; the view's estimates; the waits' and the clusters' comparisons; the cluster records |

## Compatibility

A report's round trip becomes the direct side's bounds estimate's value:
for a neighbor, probed three times a window, the 80th percentile of about
the same five minutes as its reading; for a candidate probed sparsely, of
its last thirty samples within fifteen minutes. Nothing else on the wire
changes. A pair or a path without the bounds its comparison needs decides
nothing: until either end reports an upper bound for a pair, after fourteen
samples, no node predicts its promotion, as the node's own promotion waits
for the same bound. A natural cluster's separation clears its diameter's
upper bound beside `ClusterGap` less one diameters at its value, where it
cleared `ClusterGap` upper bounds.

## Test plan

*   **The library.** A published estimate's value, bounds, and sample; a
    sum's value and bounds, a missing lower bound counting zero and a
    missing upper bound leaving none; the most of estimates; a mistake
    across kinds.
*   **The reports.** A report states the direct side's bounds estimate.
*   **The view.** A pair's estimate from its ends' reports; a path's as the
    least of its paths' sums, charged for each transit.
*   **The waits.** A pair is predicted only when better; a promotion waits
    on a lighter pair only while linking it would leave the node's pair not
    better; a pair not better than the published path waits only on a link
    its routes do not see yet.
*   **The clusters.** A natural cluster at its line and not past it, and
    none while a bound is missing; a lighter pair outruns a linked one only
    when better; a unit breaks only when better.
*   **The records.** A cluster joined and a cluster left weigh their
    comparisons' estimates and line.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the settled labs, the cuts, the delay changes, the jitter and
    loss sweeps, and the bursts.
