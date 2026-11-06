# Read round trips at their 80th percentile over five minutes

This proposal implements
[ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md):
every peer is sampled three times a window, and every round trip the
selection compares — a peer's direct side and a route's price — is read at
the 80th percentile of its answered samples of the last five minutes.

[TOC]

## Summary

Today:

*   **The direct side reads one window**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)). A
    neighbor's is the median of three SCMP echoes, a punched candidate's the
    median of three punch probes
    ([punch.go](/pkg/modules/topology/impl/measured/punch.go)), and any
    other candidate's one binding request: the first answer of up to three
    attempts under one nonce, so a reply later than an attempt's wait is
    timed from the next attempt
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)).
*   **The price side reads twenty probes.** A route's cost is the median of
    its record's answered probes, divided by its delivery rate
    ([health.go](/pkg/libs/scion/health.go)); the record keeps the last
    twenty ([paths.go](/pkg/libs/bus/paths.go)), which span about 100
    seconds for a route in use and ten minutes for a route priced alone
    ([prober.go](/pkg/apps/ping/prober.go)).

## Motivation

### Goals

*   Every peer is sampled three times a window, and a binding request's
    reply is timed from the attempt it answers (ADR-0038, decision 1).
*   The selection reads every round trip it compares at the 80th percentile
    of the answered samples of the last five minutes, a peer's per
    instrument and address (decisions 2 and 3).
*   Path records keep five minutes of probes beside their last twenty
    (decision 4).
*   ADR-0038 is accepted.

### Non-goals

*   The path library's health, loss, cost, and lease ranking, which keep
    reading a record's last twenty probes.
*   The ratios, the margin floor, the streaks, and the coordination's report
    hysteresis.

## Proposal

### The reading

*   **One statistic.** `scion.Reading` returns the 80th percentile of round
    trips, by nearest rank: the sample a fifth of the others lie above, the
    highest of up to four. `scion.ReadingSpan` is `StaleAfter`, five
    minutes.

### The direct side

*   **Three samples.** A neighbor's echoes and a punched candidate's probes
    return every answered round trip, not their median. A candidate takes up
    to three binding requests, the first unanswered one ending them.
*   **A nonce per attempt.** Each attempt of a rendezvous request, binding
    or not, draws its own nonce, and a reply is timed from the attempt whose
    nonce it echoes: a late reply still answers the request, timed from its
    own attempt rather than the next.
*   **Samples by instrument.** The selection keeps each peer's answered
    round trips with their times, per instrument: a link's echoes by its
    interface, the punch probe, the binding requests to one address. A
    window adds its answers to its instrument's samples and drops those
    older than `ReadingSpan`, and an instrument whose samples all aged out
    goes.
*   **A change of instrument.** An instrument with no sample within
    `ReadingSpan` starts from the samples of the instrument that read the
    peer last: a promoted link from its candidate's binding requests, a
    retired link's peer from the link's echoes.
*   **The window's sample.** A peer's direct side is the reading of its
    instrument's samples, zero, unreachable, when the window's probes went
    unanswered. The tiers, the promotion and useless tests, the eviction,
    the declarations, and the directory reports read it as they read the
    direct side today.

### The price side

*   **Five minutes of probes.** The prober keeps each path's probes sent
    within `ReadingSpan`, and at least its last `PathSamples`. The library's
    health, loss, and cost read the last `PathSamples`, as today.
*   **The route's reading.** `Candidate.Reading` is the reading of the
    record's probes answered within `ReadingSpan`, divided by their
    delivery rate, the loss capped as the cost caps it; without a
    measurement, twice the declared one-way sum, as the cost. The selection
    prices every route it enumerates by its reading.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | `Reading`, `ReadingSpan`, `Candidate.Reading`; health and cost on the last `PathSamples` |
| `pkg/libs/bus` | The record's samples: five minutes, at least the last `PathSamples` |
| `pkg/apps/ping` | The prober keeps five minutes of probes |
| `pkg/modules/topology/impl/measured` | Three samples per peer, the samples by instrument, the readings; a nonce per rendezvous request attempt |

## Compatibility

Nothing changes on the wire: a binding request's reply echoes the nonce of
the request it answers, whichever attempt drew it.

## Test plan

*   **The reading.** The percentile by nearest rank, from one sample to
    thirty.
*   **The direct side.** A window's answers join its instrument's samples,
    samples past `ReadingSpan` drop, an unanswered window reads zero and
    keeps its samples, each peer's instruments keep apart, and a new
    instrument starts from the peer's last one. A candidate takes three
    binding requests and stops at an unanswered one; a late reply to one
    attempt is timed from it, not from the next.
*   **The price side.** A record keeps the probes of the last five minutes
    beside its last twenty; the reading reads those answered within the
    span, divided by their delivery rate, while the cost, health, and loss
    read the last twenty.
*   **The selection.** Its tests hold on the readings: a burst shorter than
    a fifth of the span moves nothing, a lucky sample promotes nothing.
*   **The labs.** The labs pass, and the benchmarks, the unstable delay ones
    of proposal 0116 included, run against the commit before.

## Implementation history

*   **A change of instrument.** Without the carry-over, the regions jitter
    sweep changed links 164 and 130 times, and 26 of 49 links promoted for a
    beaten price retired as useless within five minutes, against 14 of 36
    and 5 of 26 in proposal 0116's runs. The stranded sweep changed links 21
    times and left a level unsettled, against 10 and none. In the bursts,
    the regions network retired a link and promoted it back about a minute
    later: the candidate's fresh binding requests, quiet between bursts,
    read low for the two windows a promotion counts.
*   **The sweep's price side.** An instrumented regions jitter sweep,
    without the carry-over, logged each priced decision. After the first
    half hour, 25 of 40 promotions for a beaten price stood at 1.25 to 1.32
    times the direct reading, and most of the 38 useless retirements at
    1.06 to 1.23: within a tenth of the threshold the two tests share. The
    direct readings rested on about 27 samples each, while the price was a
    declared prior in 11 promotions and read from fewer than five probes in
    12, and the survivor was a prior in 16 retirements and read from fewer
    than five probes in 5.
*   **Test adaptations.** `TestSelectionFlappingCandidate` breaks its
    streak with an unanswered window: a slow window now holds the reading,
    which `TestSelectionReadingDamps` checks. The selection's test seam
    counts its direct side as one sample a window.
*   **Left as they are.** The address chosen among a peer's addresses still
    compares one binding request each. The punch probe keeps one nonce per
    probe, its echo carrying no sequence number, so a reply later than its
    run's one-second wait times the next run.
*   Mutations: 44 of 44 killed.
*   The pipeline passed. A run before the carry-over failed once on
    `TestStaticLineWithoutMemberships`, a static lab's wait for reach under
    the race detector, as it did on 2026-11-02; alone, it passed five runs
    of five.
*   Benchmarks against the commit before, two or three runs each:
    *   The regions lab settled after 15 changes within 4.8 and 5.2
        minutes, against 14 and 17 within 4.5 and 10.5, its worst pair at
        1.05 and 1.11 times the reference, against 1.11.
    *   After the regions cut, reach held from 10 seconds in all three
        runs, as before, and the links settled within 50 to 70 seconds,
        against 10 to 120; the worst pair stood at 1.16 to 1.18 times the
        reference, against 1.16 to 1.23.
    *   After the stranded cut, the links settled within 10 to 80 seconds,
        against 10 to 310; after the restore, two of three runs kept their
        links and the third settled after 170 seconds, against one to three
        changes within 120 to 280.
    *   The site lab joined both ways settled after 8 to 10 changes within
        4.3 to 10.8 minutes, against 6 or 7 within 4.3 to 5.5; one run of
        three left one pair unreached, as at the commit before. Joined
        inside or outside, it settled as before.
    *   The NAT lab settled after 9 and 11 changes within 3.8 and 4.8
        minutes, against 9 and 10 within 4.3 and 4.8; its founder-down nodes
        survived in 15.5 and 15.7 seconds and returned in 201 and 225,
        against 1.6 and 16.1, and 216 and 219.
*   Proposal 0116's benchmarks, one run each but the regions jitter sweep's
    two:
    *   The regions jitter sweep changed links 126 and 139 times, four and
        five levels unsettled, against 122 and 95 with five and four; 13 of
        36 and 12 of 43 links promoted for a beaten price retired as useless
        within five minutes. The stranded sweep changed none and settled
        every level, against 10 changes.
    *   In the bursts, the regions network changed its links 3 times, every
        read reaching all 72 pairs, against 3 and 7 with a read at 58; the
        stranded network changed none, as before.
*   The delay changes, against the commit before with proposal 0116's lab:
    *   A lowered pair linked after 270 seconds in the regions lab and 280
        in the stranded one, against 50 and 70; its link retired after the
        restore within 170 to 180 seconds, against 190 and 130 to 140.
    *   A used link's delay tripled: the regions network moved off it from
        60 seconds and settled after six changes within 280, at the same
        worst pair, 1.17, where the commit before changed nothing; the
        stranded network changed nothing in either.
