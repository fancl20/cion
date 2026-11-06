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
