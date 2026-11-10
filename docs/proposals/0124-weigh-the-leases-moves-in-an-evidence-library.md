# Weigh the leases' moves in an evidence library

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)
for the leases, the first site to move: a library of estimates,
comparisons, holds, and records; a lease that moves to a cheaper path only
once the bounds of both paths' prices part by the band, the path it weighs
probed every heartbeat until they do; and a record of every lease that
moves, published on the bus and logged as one structured line.

[TOC]

## Summary

Today:

*   **A lease moves on two point prices**
    ([lease.go](/pkg/libs/scion/lease.go)): a healthy path whose price, the
    median of its last twenty probes within five minutes beside its transit
    charge, beats the leased path's by the band takes the lease once it has
    done so for five seconds of wall clock
    ([health.go](/pkg/libs/scion/health.go)). No count of probes stands
    behind either price, and no probe need arrive within the five seconds.
*   **The path a lease would move to is probed every minute.** The lease
    requests it as a standby, which the prober probes at once and then every
    minute while the destination is hot
    ([prober.go](/pkg/apps/ping/prober.go)), so its price rests on one to
    three probes. Under 10 or 20ms of jitter on every pair, their median
    errs by more than the band: in the ring lab, leases rode routes 1.40 to
    1.50 times the shortest
    ([proposal 0123](/docs/proposals/0123-price-no-path-by-probes-older-than-five-minutes.md)).
*   **Nothing records a lease that moves.** The path library logs nothing.

## Motivation

### Goals

*   An estimate carries its value, its bounds, and the samples it rests on,
    and a comparison of two estimates answers better, not better, or
    undecided, as ADR-0040's decisions 1 to 4 have it.
*   A lease moves to a cheaper path only once both prices' bounds part by
    the band, after a hold that a fresh probe of each path crosses.
*   The path a lease weighs is probed as often as the path in use until the
    comparison decides.
*   A lease still leaves a path that fails, nears its expiry, or no longer
    composes at once.
*   Every lease that moves leaves a record on the bus, which the node logs
    as one structured line at Info.

### Non-goals

*   Health and ejection, the picks' ranking, and the topology selection's
    decisions, which keep their rules until later proposals move them.
*   The band's and the transit penalty's values.
*   The wire: no record leaves the node.

## Proposal

### The lines and their reasons

| Line | Value | Reason |
| :-- | :-- | :-- |
| A price's estimate | the median of the last `bus.PathSamples` probes sent within `ReadingSpan`, its bounds, and its transit charge | the cost proposal 0123 defined, now with the bounds a comparison needs |
| A bound's confidence | `BoundConfidence`, 0.95 one-sided | at the readings' confidence, a median's bounds need five probes, each missing it with odds of one in 32: `ReadingSamples`, the fewest round trips a reading decides on. A lease asks less than a retirement through its span and its hold, not its bounds |
| The line | the band of the two point prices | what a move must gain, as before; the bounds now answer the noise |
| The hold | `LeaseSwitchHold`, crossed by a probe of each path answered since the verdict first stood | a heartbeat, so that a probe of each path speaks in between, as the hold always meant |
| The weighed path's probes | every `Heartbeat` while its destination is hot, first at once; a lost probe calls a burst | as the path in use, so its bounds stand after five heartbeats |
| The records a node keeps | the last 256 | a reader may fall that far behind before records go unread: more than every lease of a node with 64 destinations moving four times between two reads |

### The library

*   **A sample** is one probe: when it was sent, its round trip, and whether
    it went unanswered.
*   **A kind** states what an estimate is: a quantile, the one-sided
    confidence of its bounds, and its window, a span and a count, each
    bounding the samples it reads.
*   **An estimate** is a kind read from samples at an instant: the quantile
    by nearest rank and its bounds, each divided by the delivery rate of the
    samples the window holds, the loss counted up to nine in ten, beside the
    samples answered and sent and when the newest answered one was sent. A
    bound is the order statistic the binomial count of samples below the
    quantile reaches with the confidence, zero where the samples give none,
    as `ReadingBounds` computes the 80th percentile's today. An estimate
    shifted by a charge moves its value and its bounds alike.
*   **A comparison** weighs whether one estimate beats another by a line:
    better when the one's upper bound and the line lie at or below the
    other's lower bound, not better when the one's lower bound and the line
    lie above the other's upper bound, undecided otherwise and whenever a
    bound is missing. Estimates of different kinds are a caller's mistake.
*   **A hold** stands once the verdict it holds has stood for its duration
    with a sample of each side answered since it first stood; a new subject
    starts it over.
*   **A record** is one change: the decision, its subject, the option left
    and the one taken, why, the line, and the estimates weighed, each named.
    The records a node keeps are numbered in order, so a reader asks for
    those after the last it read.
*   `binomialCDF` moves into the library, and `scion.ReadingBounds` reads
    its bounds from it.

### The leases

*   **A candidate's estimate.** Beside its cost, a candidate carries the
    estimate its cost rests on; its cost is the estimate's value, else twice
    its declared one-way sum. Its price's estimate is that estimate shifted
    by its transit charge.
*   **The move.** An evaluation ranks the candidates as today. When the best
    is healthy, another than the leased path, and cheaper beyond the band by
    their point prices, the lease weighs it: the comparison of the two
    prices' estimates against the band. Better holds the lease's hold on
    that path, and the lease moves once the hold stands; not better and
    undecided keep the lease, and a lapsed verdict ends the hold.
*   **What a lease leaves at once.** A leased path that no longer composes,
    nears its hop fields' expiry, or is ejected while the best is not, moves
    the lease at once, as today, and so does the first read.
*   **The weighed path's request.** The path a lease weighs is requested as
    `bus.PathWeighed`, the role between the path in use and the priced
    routes: the prober probes it every `Heartbeat` while its destination is
    hot, first at once, and a lost probe calls a burst.
*   **The record.** Each change of the leased path publishes a record on
    `Bus.Decisions`: the destination, the paths left and taken by their
    identities, why — the first read, a cheaper path beyond the band, an
    ejection, an expiry, a path that no longer composes, the bootstrap route
    standing in — and, for a move to a cheaper path, the band and both
    prices' estimates.

### The log

*   **One line per record.** A node loop reads `Bus.Decisions` and logs each
    record once, at Info: its change as the message, then the subject, the
    options, why, the line, and each estimate's value, bounds, and samples
    answered and sent. Records that went unread before the loop reached them
    log a warning with their count.

### The labs

*   **Reading a moved lease.** `readMoved` reads the leases every
    `LeaseSwitchHold` and `LeaseEvaluation` for as long as a weighed path
    takes to gather its bounds and stand its hold, `ReadingSamples` heartbeats
    and the hold, and returns the last read.
*   **The moves.** The jitter sweeps count each level's lease moves from the
    nodes' records and print them beside the gradings.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/evidence` | New: samples, kinds, estimates, comparisons, holds, and records |
| `pkg/libs/bus` | `Bus.Decisions`; the role `PathWeighed` |
| `pkg/libs/scion` | The candidates' estimates; the leases' comparison, hold, request, and records; `ReadingBounds` from the library |
| `pkg/apps/ping` | The weighed path's probes |
| `internal/services` | The decision log; the provider's records topic |
| `internal/testnetwork/behavior` | `readMoved`'s reads; the jitter sweeps' moves |

## Compatibility

Nothing on the wire changes. A lease moves to a cheaper path later than
before, after the weighed path's bounds stand, and leaves a failing path as
before.

## Test plan

*   **The estimates.** A window bounds the samples by span and by count,
    its edge included; the quantile by nearest rank; a median's bounds stand
    from five samples at 0.95 and none from four; the 80th percentile's
    bounds match `ReadingBounds`; the delivery divides the value and the
    bounds, the loss capped; a shift moves the value and both bounds.
*   **The comparisons and holds.** Better, not better, and undecided at
    their edges, undecided without a bound, and a mistake across kinds; a
    hold stands after its duration only once a sample of each side answered
    since it began, and starts over for a new subject.
*   **The records.** Numbered in order, the oldest dropped past the bound,
    and read after a number, the dropped ones counted.
*   **The leases.** A cheaper path with four probes keeps the lease weighed;
    with five steady ones beyond the band, it takes the lease once the hold
    stands with a fresh probe of each; with five whose bounds straddle the
    leased path's, it never does. An ejected leased path moves the lease at
    once. Each move leaves its record, the estimates and the band beside a
    move to a cheaper path, and a lease weighing a path requests it as
    weighed.
*   **The prober.** A weighed path is probed at once and every heartbeat
    while hot, not while cold, and its lost probe calls a burst.
*   **The log.** One line per record at Info, once; a warning for records
    that went unread.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the jitter sweeps with their moves, the cuts, the delay changes,
    the bursts, the settled labs, and the founder down.
