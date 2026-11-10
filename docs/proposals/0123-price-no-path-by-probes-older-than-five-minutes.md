# Price no path by probes older than five minutes

This proposal narrows the cost that the picks and the leases rank paths by
([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md), decision 3)
to the span every reading takes
([ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md)):
a path's cost reads its last twenty probes as before, but none sent more than
five minutes ago, and a path with no probe answered within the five minutes is
priced by its declared delays, as a path never measured. It narrows ADR-0038's
decision 4, under which the lease ranking read the last twenty probes of any
age.

[TOC]

## Summary

Today:

*   **A cost reads the last twenty probes, of any age**
    ([health.go](/pkg/libs/scion/health.go)): the median of a record's last
    twenty answered probes, divided by their delivery rate. The picks and the
    leases rank healthy paths by it, each transit charged
    ([provider.go](/pkg/libs/scion/provider.go)), and a lease moves to a path
    whose price beats its own by the band
    ([lease.go](/pkg/libs/scion/lease.go)).
*   **Twenty probes span from a minute to an hour.** The prober probes a
    destination's path in use every five seconds while the destination is
    hot and every minute after; its standby, and the path its lease would
    move to, first at once and then every minute while hot, and not at all
    after ([prober.go](/pkg/apps/ping/prober.go)). The twenty probes of a
    path in use span about 100 seconds; those of another path reach back to
    the times it was requested.
*   **A lease compares two times.** When delay changes, the path in use is
    priced by the network as it stands, and the path the lease would move to
    by the network as it was. An instrumented regions jitter sweep logged
    every candidate of its worst pairs:
    *   **Jitter rising to 20ms**, the lease from node 4 to node 5 left the
        direct route, 10.5ms one way, for the route through node 1, 15.7ms.
        The direct route's twenty probes lay within 317 seconds and cost
        83.1ms. The other route's reached back 1031 seconds, eighteen of them
        taken at calmer levels, and cost 52.2ms, though its probes of the
        last five minutes read 194.5ms. Charged its transit, it beat the
        direct route by 20.9ms, beyond the band.
    *   **Jitter falling to 10ms**, the lease stayed. The direct route's
        twenty probes still held ten of the 20ms level and cost 73.6ms,
        against the leased route's 69.7ms and its 10ms charge, within the
        band, though the direct route's probes of the last five minutes read
        64.4ms against the leased route's 98.0ms.
    *   At 20ms, five pairs rode 1.08 times their direct route's delay or
        more, the worst 1.49 times; at 10ms on the way down, one pair, at
        1.49. A build charging each transit 2ms each way, whose band is
        narrower, misplaced leases at 10ms on the way up as well, the worst
        pair at 1.09 to 1.21 times, and at 20ms at up to 3.58.

## Motivation

### Goals

*   No price that the picks rank by or a lease compares rests on a probe
    older than the readings' span.
*   A path in use keeps reacting within its last twenty probes.
*   A path with no probe answered within the span is priced by its declared
    delays, as a path never measured, and as its reading falls back.

### Non-goals

*   The statistic: the cost stays the median, the reading the 80th
    percentile.
*   Health: ejection keeps reading the last twenty probes.
*   The prober's cadences, and a count of probes within the span that a
    path must hold before it moves a lease.
*   The transit penalty and the band.

## Proposal

### The lines and their reasons

| Line | Value | Reason |
| :-- | :-- | :-- |
| The probes a cost reads | the last `bus.PathSamples`, twenty, sent within `ReadingSpan`, five minutes | twenty keep a path probed every five seconds reacting within its last 100 seconds, as today; five minutes is the horizon in which a link change plays out in every node's segments, and the span every reading takes, so no price reaches past the stretch of time the readings measure |
| A cost without a probe answered within the span | twice the declared one-way sum | the prior of a path never measured, and the reading's fallback |

### The cost

*   **Within the span.** `measuredCost` reads the record's last
    `bus.PathSamples` probes sent within `ReadingSpan` of the evaluation: the
    median of those answered, divided by their delivery rate, the loss
    capped as before. With none answered among them, the candidate's cost is
    twice its declared one-way sum.

### The labs

*   The jitter sweeps grade the paths at no penalty as well, by their delays
    alone, and print both gradings.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | The cost reads the last twenty probes within the span |
| `internal/testnetwork/behavior` | The jitter sweeps' grading at no penalty |

## Compatibility

Nothing on the wire changes. The topology selection prices its routes by
their readings, as before.

## Test plan

*   **The cost.** A record's cost is the median of its last twenty probes
    within the span, the one at the span's edge among them, divided by their
    delivery rate, the loss capped: recent probes past the span drop, probes
    within the span before the last twenty drop, and a record with none
    answered within the span prices nothing, its candidate taking the
    declared prior.
*   **The lease.** A path fast only in probes past the span never takes the
    lease, and a path left behind, slow only in probes past the span, takes
    it back once its probes within the span beat the leased path's beyond
    the band.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the jitter sweeps, the bursts, the delay changes, the cuts, the
    settled labs, and the founder down.

## Implementation history

*   **Test adaptations.** `TestCandidateReading`'s record answered six
    minutes before the evaluation prices its candidate at the declared
    prior, not at its probe.
*   Mutations: 6 of 6 killed.
*   The pipeline passed. Two earlier runs of the race detector each failed
    one lab on a loaded runner: `TestLineTopology` timed out waiting for the
    up segments at the line's far end, two hops of beacons, and
    `TestPingReadyRetriesResolution` received two of its three replies.
    Alone, they passed six runs of six and eight of eight; the line lab's
    wait now takes `PathTimeout`, as the other line labs' first path does.
*   Benchmarks against the commit before, one run each but the regions
    jitter sweep's two, and instrumented sweeps logging every lease's moves:
    six of the stranded lab, one each of the regions lab and the ring:
    *   **Jitter.** The regions sweep's worst pair stood at 1.008 times its
        direct route's delay at every level in both runs, against 1.50 at
        20ms in both. The ring's stood at 1.00 and 1.40 at 10ms over two
        runs, and at 1.40 and 1.50 at 20ms, against 1.40 and 3.00 in one,
        its mean pair at 1.009 and 1.010 against 1.144; on the way down it
        was back at 1.00 by 5ms and by 2ms, against 1ms. In the logged
        regions sweep, the leases moved 12 times at 20ms, none onto a longer
        route, against 26 times, 22 onto a longer route; in the six stranded
        sweeps, 49 times, none onto a longer route, against 121, 26 onto
        one.
    *   **What jitter still moves.** A route a lease does not use holds two
        or three probes within the span, and under 10 or 20ms of jitter on
        every pair their median errs by more than the band. In the logged
        ring sweep, the worst pairs rode a longer route priced by three to
        seven fresh probes against a shorter one priced by two or three, or
        by twenty through a busy link: 94.5ms over three probes against
        104.8ms over twenty. One stranded sweep put a pair 1ms apart on its
        sibling's 2ms route at 20ms.
    *   **A raised delay restored.** The regions lab's worst pair stood at
        1.063 times the reference with the transit penalty, against 1.683: a
        lease the commit before left on the route it took during the raise,
        its own route's probes still holding the raised delay.
    *   **Cuts restored.** The regions lab's links settled within 50 seconds
        after one change, against 180 after two, and the metros lab's within
        60 after one, against 160 after two. The cuts themselves settled as
        before.
    *   **Settled, the same networks.** The regions lab settled on 30 links,
        the metros lab on 25 against 26, the NAT lab on 16, the site lab on
        16, 11, and 15 by its joins, the stranded lab on 8 and the ring on
        45, every worst pair at no penalty where it stood before. The NAT
        lab's founder-down nodes returned within 229 seconds, against 221.
    *   **Bursts** changed no link either way, every read reaching every
        pair.
