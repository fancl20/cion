# Benchmark the networks by the paths they serve

This proposal implements the measures of
[ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md)
as benchmarks of the behavior labs' networks: one assessment of a settled
network, the path layer naming the segments a chosen path joins, and
scenarios that cut and restore a link, raise and lower delays, and sweep a
link's loss. They grade how well the network serves, not whether it is
correct — no design is held to an optimum it may never reach — so they run
on demand, compared across runs and commits, and stay out of CI and the
commit gate, as the record's decision 7 holds them. Its one gate, every
pair reaching over its chosen path, is a correctness property: the CI labs
assert it with the change that stops stale segments from being chosen,
which flips the record to accepted. No wire message, stored field, or run
argument changes.

[TOC]

## Summary

A scratch prototype of the assessment, run on the regions lab's network as
it stands since proposal 0070, reported what the labs never asked:

*   In four runs of six, one to four pairs of 72 had a chosen path crossing
    a link already gone, each from a segment that outlived its link.
*   Charging 5ms per transit node, chosen paths averaged 1.21 times the
    global reference, the worst 65ms over it; the formed links alone
    allowed 1.17 times, so the choice added a little on average and most of
    the worst case.
*   Three of every four stored segment records were the chosen path of no
    pair.
*   No settled link set held a link whose cut would split the network.

This proposal brings that assessment into the tree, gives the path layer
the one seam it needs, and adds the scenarios the record decided, each a
benchmark that reports its measures in the form `benchstat` compares.

## Motivation

ADR-0025 decided what the networks are judged by and against which
reference; nothing measures any of it. Its measures grade quality rather
than correctness: a path within twice the reference is not a bug, and a
better design moves the number rather than passing a test. Run on demand
with repeated counts, benchmarks give each measure a distribution, and two
commits' runs compare directly. The fixes the measures already point at —
segments outliving their links, a choice ranked by hop fields, beaconing
that keeps what no pair chooses — are their own proposals, judged by what
these benchmarks report.

### Goals

*   A benchmark reports the assessment of every behavior lab's network once
    it settles.
*   The path layer names the segments a chosen path joins, for the choice
    `Path` makes and no other.
*   Benchmarks measure a cut and its restoration, a delay raised on a link
    the network uses, a delay lowered between nodes it left unlinked, and a
    loss swept from none to total and back down.
*   Every benchmark reports in the form `benchstat` reads, so repeated runs
    and two commits compare without tooling of our own.

### Non-goals

*   No change to CI or the commit gate: the benchmarks are skipped unless
    asked for.
*   No new assertion in the CI labs until reachability binds.
*   No change to path choice, beaconing, segment lifetime, or selection.
*   No change to the fabric: its delay, loss, and cut taps already shape
    every scenario.

## Proposal

### The path layer names a choice's segments

`Candidate` in [provider.go](/pkg/libs/scion/provider.go) gains the
segments it joins, in travel order: an up segment and a down segment for a
meeting, one segment for a containing branch or a down-only meeting.
`PathProvider` gains `Choose`, which returns the candidate `Path` takes —
the containing up segment's branch, else the bootstrap route, which joins
no segment, else the best-ranked candidate, a crossing one kept as the last
resort as today — and `Path` returns its path. What `Path` returns does not
change.

### The assessment

The assessment is test code in the behavior package, compiled with the CI
labs so it never rots and so the CI labs can assert reachability through it
once that binds. A caller passes a settled network's nodes, its delays — a
function giving the one-way delay between two of its nodes as the fabric
holds it now, a scenario's change included and a cut pair reading as no
edge — and a penalty per transit node, 5ms unless the caller sets its own.
Each report carries the caller's penalty and zero beside it. Four measures
make it up:

*   **Reachability.** Each ordered pair's `Choose` result, walked hop by hop
    over the links established and up at both ends: whether it reaches.
*   **Path cost.** A path costs its links' delays plus the penalty for each
    node it crosses between its ends. The reference is the all-pairs
    shortest cost over every pair's delay, computed with each edge charged
    the penalty and the destination's charge refunded — the node split into
    an in-node and an out-node — and the formed links' shortest is the same
    over the links established and up at both ends. Each pair yields its
    chosen path's ratio to the reference and its excess over it, the
    topology's share — the formed links' shortest against the reference —
    and the choice's share — the chosen path against the formed links'
    shortest. The report gives each one's mean, 95th percentile, and
    maximum.
*   **Segment noise.** Every node's up segment records and the core's down
    segment records, keyed by route — the identity the path database
    already keeps. A record is chosen when some pair's chosen candidate
    joins its route, and the report counts the chosen and the stored ones
    of each type.
*   **Single cuts.** The formed links whose removal would leave some node
    unreachable over the rest.

### The benchmarks

The benchmarks are tests in the behavior package, each skipped unless
`CION_BENCH` is set, so `go test` runs them only when asked: for example
`CION_BENCH=1 go test -run Bench -count=10 -v
./internal/testnetwork/behavior/`. `synctest` bubbles take a `*testing.T`
alone, so the benchmarks cannot be `testing.B` functions; each instead
prints, per run, a line in the benchmark format — a `Benchmark` name, one
iteration, and each measure as a value and a unit — which `benchstat`
reads from the output of `-v` beside a human-readable report. The networks
come from builders the CI labs share: the regions lab's nine nodes over
three regions and the stranded lab's two sides, each booted and settled as
its lab does.

*   **Settled.** Each network, once settled, reports the assessment.
*   **A cut and its restoration.** The fabric cuts the formed link the most
    chosen paths cross. The benchmark measures the time until either end's
    verdict goes down; the interim path — each pair's best candidate among
    the segments present at the cut that avoids the cut link, graded as the
    assessment grades a path; the time until every pair reaches; the time
    until every pair's best candidate matches the shortest over the links
    formed then, the replacement surfacing; the time until the link set
    holds for five minutes; and the link changes on the way. It lifts the
    cut and measures the same again.
*   **A delay raised.** The fabric triples the delay of the formed link the
    most chosen paths cross. The benchmark measures the time until the link
    set or a chosen path first changes; the chosen paths' cost against the
    reference the changed delays give, as it recovers; the time until the
    link set holds for five minutes; and the link changes on the way. It
    restores the delay and measures the same again.
*   **A delay lowered.** The fabric lowers the delay between the unlinked
    pair whose direct path would cut the reference most, to a tenth of its
    shortest over the formed links; the benchmark measures the same as for
    a raised delay, and whether the network links the pair.
*   **A loss swept.** On the formed link the most chosen paths cross that no
    single cut needs, the fabric steps the loss through 0, 1, 2, 5, 10, 20,
    50, and 100 percent and back down to 0, holding each level until the
    link set and the link's verdicts hold for five minutes or fifteen pass.
    At every level the benchmark reports whether the link's verdicts and
    the link stand, the verdict and link changes the level caused, the
    chosen paths that still cross the link and the loss they inherit, and
    every pair's reachability and path cost. Across the sweep it reports
    the loss at which the network dropped the link on the way up, the loss
    at which it took the link back on the way down, and any level that
    never settled.

Every scenario runs on both networks. A benchmark's wall time is the
network's virtual time at the bubble's speed: the regions network's
settling costs about a minute, its scenarios minutes more, and a sweep up to
four virtual hours.

### Packages touched

| Package                         | Change                                                      |
| :------------------------------ | :---------------------------------------------------------- |
| `pkg/libs/scion`                | `Candidate`'s segments; `PathProvider.Choose`               |
| `internal/testnetwork/behavior` | The assessment; the shared network builders; the benchmarks |

The behavior package's doc names the benchmarks and how to run them.

### Migration

Each commit keeps the tree green:

1.  **The path layer.** `Candidate`'s segments and `Choose`, with the
    provider's tests.
2.  **The assessment.** The measures with their own tests on synthetic
    networks; the network builders the CI labs then share; the settled
    benchmarks.
3.  **The changes.** The cut and its restoration, and the raised and lowered
    delays.
4.  **The loss sweep.**

Each commit's history entry records its benchmarks' distributions across
ten runs.

## Compatibility

Production behavior is unchanged: `Choose` exposes the choice `Path` makes,
and `Path` returns what it returned before. CI and the commit gate run what
they ran before, plus the assessment's own tests.

## Test plan

The assessment's tests and the provider's run in CI; the benchmarks run on
demand.

*   **Reachability (decision 1):** `Choose` returns what `Path` returns on
    every branch — the containing up segment, the bootstrap route, the
    best-ranked candidate, and the crossing last resort — and the
    assessment reports each pair's reach over it.
*   **Path cost (decision 2):** on a synthetic delay matrix, the penalized
    all-pairs shortest cost equals the shortest over the graph whose nodes
    are split into in- and out-nodes; a path's cost charges each transit
    node once; the topology's and the choice's shares multiply to the
    ratio.
*   **Segment noise (decision 3):** a candidate names the segments
    composition joined; a stored record whose route a chosen path joins
    counts as chosen, and a down segment fetched from the core matches the
    core's record by route.
*   **Single cuts (decision 4):** a ring has no single cut and a tree's
    every link is one; the cut benchmark reports every pair reaching again.
*   **Changes (decision 5):** the cut, restoration, and delay benchmarks
    report each timing in every run.
*   **The loss sweep (decision 6):** the sweep reports every level and both
    thresholds in every run, and a level that never settles is reported,
    not failed.
*   **Benchmarks (decision 7):** the benchmarks assert nothing and the CI
    labs nothing new; each history entry records the benchmarks'
    distributions.

## Implementation history
