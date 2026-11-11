# Record every link and cluster change

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
fifth decision for the topology selection: every change it makes to the
node's links and to the cluster it joined, and every change it announces,
leaves a record in the node's journal of changes, which the node logs as one
structured line beside the estimates the decision weighed. The selection
reads its round trips through the evidence library to give them; no
decision changes.

[TOC]

## Summary

Today:

*   **A link change logs a phrase**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)):
    "Link seeded" and "Link retired" name the neighbor and the reason, such
    as "its tier served no worse without it" or "displaced by the least-harm
    eviction", but no number the decision rested on. "Promotion announced"
    and "Retirement announced" name the neighbor alone, and a withdrawn
    announcement logs nothing. "Joined a cluster" and "Left the cluster"
    name the cluster, not why.
*   **The selection's round trips are bare durations.** The direct side's
    reading and bounds come from the selection's own helper over the round
    trips it heard, and each route's from its candidate's reading and
    bounds: durations that no longer say how many probes they rest on.
*   **A link that moves takes instrumentation to explain**, as a lease that
    moved did before
    [proposal 0124](/docs/proposals/0124-weigh-the-leases-moves-in-an-evidence-library.md).

## Motivation

### Goals

*   Every link the selection promotes or retires, every promotion and
    retirement it announces or withdraws, and every cluster it joins,
    switches, or leaves leaves a record: the change, its subject, the
    options left and taken, why, and the line and the estimates the decision
    weighed.
*   The records carry the numbers the decisions use today, read through the
    library from the same probes; every decision and every value stands.
*   The selection's change lines become the records' lines, one per change.

### Non-goals

*   How the selection decides: its lines, its streaks, and the evidence it
    asks for, which a later proposal moves onto the library's comparisons
    and holds.
*   Liveness, whose up and down verdicts ADR-0040 leaves to their protocol,
    and the establishment's own lines.
*   The clusters' numbers: their diameters and separations rest on the
    round trips other nodes report, which the library learns to read in a
    later proposal.

## Proposal

### The estimates

*   **A route's.** A candidate carries the estimates its reading and its
    bounds come from: its reading's, the 80th percentile of its probes
    within `ReadingSpan`, and its bounds', that percentile within
    `BoundSpan` with its bounds. A price shifts either by the route's
    transit charge.
*   **The direct side's.** The selection reads the round trips it heard
    through the same two kinds, so the direct side's reading and bounds are
    the estimates' value and bounds.
*   **An aggregate's route.** A tier's price and lower bound, a member's,
    and an excluded link's survivors' and crossing routes' are each the
    least over a set of routes; the selection keeps the route each comes
    from, so a record weighs that route's estimate.

### The records

Each change appends a record to the node's journal of changes, which the
selection's config takes.

| Change | Subject | From → to | Why | Weighed |
| :-- | :-- | :-- | :-- | :-- |
| Link promoted | the peer | none → its interface | the redundancy floor, its stranded tier, a second route for its tier, or its direct link beats its own price on its readings or, its history confirming, by the band | `direct`, and `price` where a price decided |
| Link retired | the peer | its interface → none | the candidate window, the least-harm eviction for a named candidate, its verdict stayed down, its tier served no worse without it, or the clusters link its units elsewhere | the eviction: the candidate's `direct` and `price`, the tier's price `with` and `without` the link; the useless test: the `direct` side's, the `crossing` route's, and the `survivors'` bounds |
| Promotion announced, withdrawn | the peer | | the beaten price; what ended it: its peer no longer reachable, its link no longer allowed, its price no longer beaten, a wait on another node's change, or a faster candidate | the announcement: `direct` and `price` |
| Retirement announced, withdrawn | the peer | | a window found its link useless; what ended it: a window finding the link useful, or the dialed links at the floor | the announcement: `direct`, `crossing`, and `survivors` |
| Cluster joined, left | the node | its last cluster → its new one, none for no cluster | a natural cluster holds the node; its unit fell below two members, or its history confirms a break of the budget | none |

*   **The line** is the margin a decision cleared: the band, the gain the
    promotion ratio and the margin floor ask of a price, or the room the
    second-route ratio leaves above one.
*   **A cluster switched** is joined: the record names the cluster left
    beside the one joined.
*   **The establishment's lines** keep their mechanics: the seed's line,
    with the punched flag and the addresses, moves to Debug beside the
    record, and "Link established" stands.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | The candidates' reading and bound estimates, and the two kinds read from samples |
| `pkg/modules/topology/impl/measured` | The direct side's estimates, the aggregates' routes, the records, and the journal in the config |
| `docs/design` | The journal's changes |

## Compatibility

Nothing on the wire changes, and no decision does. The selection's change
lines read as records.

## Test plan

*   **The estimates.** A candidate's reading and bound estimates give its
    reading and bounds; the direct side's estimates give the reading and
    bounds the selection read before, its history's instruments included;
    each aggregate keeps the route its value comes from.
*   **The records.** Each change leaves its record once, with its reason and
    the estimates its decision weighed: a promotion for each reason, a
    retirement by each rule, a promotion and a retirement announced and
    withdrawn, and a cluster joined and left. A window that changes nothing
    records nothing.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the settled labs, the cuts, the delay changes, and the jitter
    sweeps, each as before.

## Implementation history

*   **The library's readings.** `scion.Reading` and `scion.ReadingBounds`,
    which read bare round trips, give way to `ReadingEstimate` and
    `BoundsEstimate`, which read samples, so the direct side and every
    candidate take their estimates from one place. `scion.Band` is exported
    for the records' lines.
*   **The promotion's interface.** The establishment returns the entry it
    seeded, so the record of a promotion names the interface the link took.
*   **A peer in no tier.** A link whose useless count runs while the window
    classes its peer into no tier is announced beside its direct side's
    bounds alone.
*   **The aggregates' routes.** The tiers' minima keep the route each comes
    from, the first of the least, and skip a zero bound as before, so every
    value the decisions read stands.
*   `TestLineCutHeals` reads the journal: one end's promotion of the healing
    link at the floor, and the dead link's retirement on its verdict.
*   `architecture.md` names the links' and the cluster's changes among the
    journal's.
*   ADR-0040 stays `proposed`.
*   Mutations: 46 of 46 killed. The first run let two live: a candidate's
    reading estimate left unset, which the test checked only where set, and
    the selection's journal left unwired, which no unit test reads.
    `TestCandidateReading` now checks the probes each reading rests on, and
    `TestLineCutHeals` the journal.
*   The pipeline passed.
*   Benchmarks against the commit before, interleaved, one run each: the
    jitter sweeps held their worst pairs (regions 1.007 against 1.007 to
    1.008, stranded at most 1.025 against 1.050, the ring 1.00) with no more
    lease moves; the settled labs reached every pair, their links within one
    of the commit before's, as reruns of both spread (metros 24 to 25
    against 25 to 26, NAT 15 to 16 against 15 to 16, stranded 8 against 8
    to 9); founder-down's survivors answered within 0.76 s; the cuts, the
    delay raises, and the bursts recovered alike, their worst pairs within
    0.03 of the commit before's or better, the regions cut's restore
    settling in 150 s against 50 s on one link change more, as earlier runs
    of the commit before spread from 50 s to 220 s.
