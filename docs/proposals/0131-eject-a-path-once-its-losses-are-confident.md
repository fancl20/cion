# Eject a path once its losses are confident

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
decisions 1 to 3 for the path library's ejection: a path's delivery becomes
an estimate whose bounds count its lost probes as evidence, and a path is
ejected once its delivery lies under one half with the bounds' confidence,
over the probes and callers' reports since its last answer or over its
recent probes.

[TOC]

## Summary

Today
([health.go](/pkg/libs/scion/health.go)):

*   **Three rules eject a path,** each counting losses its own way: a burst
    of five probes lost whole since its last answer; nine in ten of at
    least ten recent probes lost; three of its callers' losses since its
    last answer, within the trust window.
*   **A path that answers now and then stays,** for any answer clears the
    burst that would eject it. In the founder-down lab, a leased path
    answered three of its last twenty probes, priced at 687 ms beside a
    healthy path at 4 ms, and kept its lease until a burst was lost whole,
    about eighteen seconds after the cut.
*   **Its losses bound nothing:** a path's estimates divide their values by
    the delivery and bound them over the answered round trips alone, so a
    path that answers three of twenty has a price and no bounds.

## Motivation

### Goals

*   A path's delivery is an estimate: the share of its samples answered,
    with the binomial's bounds at the bounds' confidence, so that its lost
    probes count as evidence.
*   One comparison ejects a path: its delivery under one half, with
    confidence.
*   A caller's loss is a lost sample, and a caller's delivery an answer.

### Non-goals

*   Health's other states: healthy for an answer within the trust window,
    suspect for a signal, a caller's doubt, stale segments, or a link failed
    paths share, and unknown otherwise. They judge arrivals and silence, as
    link liveness does.
*   The bursts' pacing and the half-open probes' backoff.

## Proposal

### The line and its reason

| Decision | Under when | Line | Reason |
| :-- | :-- | :-- | :-- |
| Ejected | the samples since its last answer, its probes' and its callers' reports alike, deliver under the line; or its last `bus.PathSamples` probes do | one half | a path that delivers less than half of what it carries costs each exchange more than two attempts, which no detour the picks hold costs |

*   **The confidence** is `scion.BoundConfidence`, 0.95: five losses in a
    row put a delivery under one half, as a burst lost whole does today; of
    twenty recent probes, five answered or fewer.
*   **No hold:** an ejected path is ejected at once and recovers at its next
    answer, whose samples restart as today.

### The estimate

*   **`evidence.Share`** is the share of the samples given that were
    answered: the samples answered and sent, and the one-sided confidence
    of its bounds, the binomial's exact bounds — the share under which the
    answers seen, or fewer, would come with no more than the odds the
    confidence leaves, and the one over which they, or more, would.
*   **`Share.Under`** weighs whether the share lies under a line: better
    when its upper bound does, not better when its lower bound reaches it,
    undecided otherwise.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/evidence` | `Share`, `ShareOf`, and `Share.Under` |
| `pkg/libs/scion` | Ejection on the delivery; callers' reports as samples |

## Compatibility

Nothing on the wire changes. A path whose last twenty probes answered five
or fewer is ejected, where nine in ten lost ejected it; five losses in a
row eject a path whatever its bursts, and five of its callers' losses since
its last answer, where three did.

## Test plan

*   **The library.** A share's bounds against the binomial's, at their
    edges: five losses in a row under one half, four not; five answers of
    twenty under it, six not; a share of nothing undecided.
*   **The ejection.** Five losses in a row eject a path, four do not; five
    answers of twenty eject it, six do not; callers' losses count with its
    probes' since its last answer, and a caller's delivery ends them.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the founder-down lab, the settled labs, the cuts, the loss
    sweeps, and the bursts.

## Implementation history

*   **The share's verdict.** `Share.Under` weighs the binomial at the line
    itself: the share's upper bound lies under the line where the answers
    seen, or fewer, would come under it with no more than the odds the
    confidence leaves. It computes no bound it does not weigh.
*   **The ejection's windows.** The probes lost in a row at a record's end
    count from the callers' last delivery, so a loss a caller's delivery
    outran counts nothing; the callers' losses count from the probes' last
    answer within the trust window, and a report keeps its latest
    `bus.PathSamples` of them. A lost burst still spaces an ejected path's
    half-open probes.
*   **The tests' ejected records** carry the lost probes their bursts sent,
    as the prober records them; a record of lost bursts without its lost
    probes no longer ejects.
*   `architecture.md` says in one sentence what the evidence library is and
    who decides through it: the paths and the topology source.
*   Mutations: 10 of 10 killed. The first run let one live, the callers'
    losses past the trust window counted, which three losses could not
    tell from none; the case now reports five.
*   The pipeline passed.
*   Benchmarks against the commit before, interleaved, one run each: under
    heavy loss the confident ejection held the link sets (the stranded
    lab's 50% loss 17 link changes against 127, the regions lab's 0 against
    39), one unsettled level each against two; the regions jitter runs
    changed no link, the ring three at 20ms, its pairs at their best
    latency; the settled labs reached every pair, their links within one;
    founder-down's survivors answered within 0.75 s; the regions cut's
    restore as the commit before's.
