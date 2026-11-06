# Observe the network under unstable delay

This proposal lets the labs vary a pair's delay packet by packet, as a
queue does, and benchmarks the networks under three kinds of unstable delay:
jitter on every path, one link whose jitter grows, and bursts on the links
in use. No production code changes.

[TOC]

## Summary

Today:

*   **Every delay is fixed.** The fabric holds a pair's packets a drawn
    one-way time ([taps.go](/internal/testnetwork/fabric/taps.go)), and loss
    is its only random impairment. A delay changes only when a lab lifts and
    redraws it, as the delay benchmarks step one
    ([scenario_test.go](/internal/testnetwork/behavior/scenario_test.go)).
    On virtual time, every round trip a node measures is exact.
*   **Unstable delay is untested.** The margin floor of
    [ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md) was
    sized for jitter once links leave "the jitter-free lab fabric", and no
    lab has measured how the selection answers delay that varies. The
    selection samples a candidate by one binding request a window and a
    neighbor by the median of three echoes
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)), and
    prices a route by the median of its last twenty probes
    ([health.go](/pkg/libs/scion/health.go)).

Measured on the change below, at proposal 0115's code, two runs of each
regions benchmark and one of each stranded one:

*   **Jitter everywhere, regions:** up to 2ms of mean jitter, the link set
    changed at most once a level and settled. At 5, 10, and 20ms it changed
    10, 27, and 32 times in one run and 7, 15, and 27 in the other, and only
    the second run's 5ms level held for five minutes in its fifteen. On the
    way down, 10 and 5ms changed it 38 and 10 times, then 27 and 13. Over
    the jittered levels, the first run promoted 39 links for a beaten price
    and retired 38 as useless. At 20ms, one pair and then three went
    unreached at the level's end. The chosen paths stayed within 1.34 times
    the reference.
*   **Jitter everywhere, stranded:** 10 changes over the sweep, every level
    settling. Its delays sit in bands of 1, 15, and 40ms.
*   **One link's jitter:** the regions network kept its link between nodes
    2 and 6 at every level, up to twice its 82ms delay, and its chosen
    paths left the link, 16 of them crossing it at first and 1 at the end.
    The stranded network kept its link too. Neither flapped or changed a
    link.
*   **Bursts:** 16 bursts in thirty minutes. The regions network changed
    its link set 3 and 7 times: links retired as useless during a burst, or
    promoted during bursts and retired after them, and one read of the
    second run reached 58 of 72 pairs. The stranded network changed
    nothing.

## Motivation

### Goals

*   The fabric holds packets an extra time that varies packet by packet, as
    a queue does, each direction keeping its order.
*   Benchmarks measure each network's answer to jitter on every path, to
    one link's jitter swept up and back down, and to bursts on the links in
    use, by the measures of
    [ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md).

### Non-goals

*   No production change: how the selection smooths its samples is a
    decision of its own, which these benchmarks inform.
*   No asserted lab: what a network must do under unstable delay is
    asserted once that decision is taken.
*   No asymmetric delay, reordering within a direction, or bandwidth limit.

## Proposal

### The jitter tap

`Fabric.Jitter(a, b, mean)` draws a tap that holds each of the pair's
packets, either direction, an extra time drawn from an exponential
distribution of the mean: queueing delay, mostly short, at times long, and
never negative. Its hold adds to the other taps' as theirs add to each
other. Each direction of a jittered pair keeps its packets in order: a
packet is held at least until just after the one sent before it, as
through one queue.

### The benchmarks

On demand, like the others (ADR-0025, decision 7), on the regions and
stranded networks once settled:

*   **Jitter everywhere:** every pair takes a jitter of 1, 2, 5, 10, and
    20ms mean, up and back down: the queueing a path adds, from none to a
    congested access link's. Each level holds until the link set holds for
    five minutes, or fifteen minutes pass, and reports its link-set changes,
    whether it settled, and the reach and path cost at its end.
*   **One link's jitter:** the formed link the most chosen paths cross that
    no single cut needs takes a jitter of 0.1, 0.2, 0.5, 1, and 2 times its
    own one-way delay, up and back down, swept and reported as the loss
    sweep is (decision 6): whether the network keeps an unstable link or
    drops it, and never both by turns.
*   **Bursts:** for thirty minutes, the formed links take bursts, each
    tripling one link's delay. A burst starts every two minutes on average
    and lasts thirty seconds on average, both drawn from exponential
    distributions under a fixed seed, so every run draws the same schedule;
    each falls on a link drawn among those formed when it starts. The
    scenario reads the link set and the reach every ten seconds and reports
    the bursts, the link-set changes, and the reads below the reach before
    the bursts, then measures the network's answer once they stop, as the
    scenarios do (decision 5).

The loss sweep's code takes the impairment it steps as a parameter, so the
two sweeps share it; its output keeps its form.

### Packages touched

| Package | Change |
| :-- | :-- |
| `internal/testnetwork/fabric` | The jitter tap |
| `internal/testnetwork/behavior` | The jitter, link jitter, and burst benchmarks; the sweep over an impairment |

## Compatibility

Only the labs change, and only the new benchmarks draw a jitter tap.

## Test plan

*   **The tap.** On virtual time, each packet of a jittered pair is held at
    least the pair's delay, the extra hold averages the jitter's mean, and a
    burst of packets arrives in the order sent.
*   **The benchmarks** run at proposal 0115's code, and the loss sweep's
    output keeps its form.

## Implementation history

*   The jitter tap and the benchmarks landed as proposed, with
    `TestJitterOnVirtualTime` for the tap. A burst scenario logs each burst,
    its link, and its length; the first regions run predates that.
*   The pre-commit checks passed but for `TestBFDStaticLabEpisode`, the
    static lab's known failure under the race detector's load, which
    passed five runs of five alone.
