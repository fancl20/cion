# Decide From Measured Evidence in One Library and Record Every Change

*   Status: accepted
*   Date: 2026-11-10

[TOC]

## Context and problem statement

A node decides from what it measures in several places. The path library
judges each path's health from its probes and its callers' reports, ranks
the healthy paths by their cost, and moves a lease to a cheaper path
([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)). The
topology selection reads each peer's round trips and each route's price
([ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md)),
and on them sorts its peers into tiers, promotes, retires, and evicts links,
waits on other nodes' changes, and forms clusters
([ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)).

Each site weighs its evidence its own way. It picks a statistic, a window of
samples, a margin, and a hold, and hands on a bare round trip: a number that
no longer says how many samples it rests on, or how old they are. ADR-0038
made the selection's readings one statistic over one span, and ADR-0039
stated how its decisions weigh evidence, but each rule lives in the code of
the site that follows it, and nothing shows when a site does not. A survey
of the sites finds:

*   **Three statistics for one round trip:** the leases' median of up to
    twenty probes, the selection's 80th percentile over five minutes, and a
    single answer within three minutes for health.
*   **Evidence floors from none to fourteen samples:** a lease's cost and a
    peer's direct round trip need none, a route's reading five, a reading's
    upper bound fourteen.
*   **Unlike sides:** a reading divided by the delivery of five minutes
    beside bounds divided by that of fifteen, and a direct round trip,
    unadjusted for loss, weighed against route prices that are.
*   **Holds of every kind:** five seconds of wall clock for a lease, none
    for the picks or the tiers, window streaks for links, and missing
    evidence that one test reads as decided and the next as undecided.

Two defects in two days came from that:

*   **Two windows.** A lease priced the path it held by that path's last
    twenty probes, about 100 seconds of them, and the path it would move to
    by its own last twenty, which reached back tens of minutes. When delay
    rose, a path priced by calmer probes took the lease; when it fell, the
    path left behind kept the rough probes and never won it back. Under
    20ms of jitter, leases rode routes 1.50 times the shortest in the
    regions lab and 3.00 in the ring.
    [Proposal 0123](/docs/proposals/0123-price-no-path-by-probes-older-than-five-minutes.md)
    bounded the window at that one site.
*   **Thin evidence.** Bounded so, a path the lease does not use holds two
    or three probes in the window, and under heavy jitter their median errs
    by more than the band. In the ring lab, leases still rode routes 1.40 to
    1.50 times the shortest.

Neither showed in the logs. Nothing at the path level logs: no health
change, no lease that moves. A link change logs a phrase without its
numbers, such as "displaced by the least-harm eviction". Finding both
defects took instrumentation written for the purpose.

How should a node take its decisions from what it measures, so that every
decision weighs evidence by the same rules and every change explains
itself?

## Decision drivers

*   **Like for like:** both sides of a comparison read the same statistic
    over the same stretch of time, adjusted alike for loss; what differs by
    design, such as a transit's price, is part of the line.
*   **Evidence scales with noise:** a decision waits for as many samples as
    its noise needs to clear its line; a steady round trip decides on a
    few, a varying one waits. Short of that, the state holds while the
    evidence gathers, as ADR-0039 has it for the link policy: readings too
    thin decide nothing and rank what to measure.
*   **As confident as being wrong costs** (ADR-0039, principle 5): a margin
    states a cost, noise meets confidence, not a wider margin, and each
    decision asks the confidence its mistakes warrant.
*   **Every change explains itself:** what changed, what it was weighed
    against, on what evidence, and over which line.
*   **Each node decides alone,** from its own measurements, waiting on no
    other node.
*   **The rules are verified once,** not once per site.

## Considered options

*   **Each site its own rules, as today,** each defect fixed where it
    surfaces.
*   **Shared statistics:** the helpers that compute a reading, its bounds,
    and the band, extended, while each site still weighs them its own way.
*   **One evidence library:** estimates that carry their evidence,
    comparisons that decide on confidence or answer undecided, holds, and a
    record of every change, which every site that decides from measurements
    calls.
*   **One node service owning every sample:** a module that keeps every
    path's and peer's samples and answers the sites' questions.
*   **A network-wide decision service:** nodes send their measurements to
    one that decides for them.

## Decision outcome

Chosen option: **one evidence library**, realized as follows:

1.  **An estimate carries its evidence.** A site reads its samples through
    the library, which returns an estimate: the statistic's value and its
    bounds, the samples it rests on, answered and sent, and the stretch of
    time they span. A window bounds the samples both by age and by count,
    each for its own reason: age, so that no estimate describes a network
    that has since changed; count, so that a subject sampled often still
    reacts within its last samples. No bare round trip enters a decision.
2.  **A comparison decides on confidence.** It weighs two estimates of one
    kind against the decision's line, such as the band, a transit's price,
    or a ratio, and decides only when their bounds, at the decision's
    confidence, lie apart by the line: better when the one's upper bound
    clears the other's lower bound by the line, not better when the
    reverse holds. Otherwise, and wherever the samples are too few to give
    a bound, it answers undecided: the state holds, and the comparison
    names the evidence it lacks, which the prober gathers where it can. A
    path a lease weighs is probed as often as the path in use until the
    comparison decides.
3.  **Each decision asks the confidence its mistakes warrant.** A lease's
    wrong move costs its connections a handshake and is undone within
    seconds; a wrong retirement costs two reshapes and the wait for the
    promotion that undoes it. A lease therefore asks less confidence than a
    retirement, and every decision asks some: the samples a bound needs are
    each decision's floor, so no single sample decides anything.
4.  **A hold is one primitive.** A verdict acts only once it has stood for
    the decision's hold, with fresh evidence on both sides in between. The
    lease's switch hold and the selection's streaks become holds.
5.  **Every change is recorded.** A decision that changes the node's state,
    such as a lease that moves, a link promoted, retired, or evicted, or a
    cluster joined or left, emits a record: the decision, its subject, the
    options weighed with their estimates, the line, the verdict's reason,
    and the time. The node publishes the records on its bus and logs each as
    one structured line at Info. A verdict that changes nothing, an
    undecided one included, logs nothing. The labs read the records.
6.  **Sites keep their policies.** The library decides how evidence is
    read, compared, and held; each site still decides what it weighs,
    against which line, and what a verdict does.
7.  **The library weighs what is measured.** Its decisions are those taken
    from probes, echoes, binding requests, and callers' reports: health,
    prices, picks and leases, tiers, promotions, retirements, evictions,
    clusters, and the waits on other nodes' changes. Link liveness, which
    judges a protocol's arrivals and silence, and beacon selection, which
    ranks declared delays, keep their rules; the delays a node declares and
    the round trips it reports are estimates, published as values.
8.  **New decisions start in the library, and existing ones move to it** by
    proposals, the leases first.

This narrows ADR-0035's decision 5: a lease moves to a cheaper path only
once it is confident that the path beats its own by the band, its hold
crossing fresh probes of both paths; the band states what a move must gain,
and the bounds answer the noise. It extends ADR-0039's principle 5, whose
evidence rules the library realizes for every policy, not the link
policy's alone. ADR-0038's readings become the library's estimates,
unchanged.

### Positive consequences

*   A site that decides through the library cannot weigh a stale window
    against a fresh one, nor act on evidence its noise does not support: the
    window bounds age, and the bounds widen with the noise until the
    comparison decides.
*   Under noise, decisions hold rather than flip: a gain the samples cannot
    tell from their spread moves nothing, and a clear one moves as soon as
    the bounds part.
*   Every lease move and link change explains itself in the log, with the
    numbers it rested on. The labs read the same records and need no
    instrumentation of their own to tell why.
*   Probes go where decisions wait: an undecided comparison asks for the
    evidence it lacks.
*   The statistics and the rules are tested once, and the sites shrink to
    their policies.
*   The path policy and the link policy can ask one question by one rule,
    so that the link policy buys no finer than the path policy moves
    (ADR-0039, principle 3) becomes checkable.

### Negative consequences

*   Decisions wait for evidence: a lease moves to a cheaper path only once
    the bounds of both paths' prices part by the band, which takes the
    weighed path several probes, about twenty-five seconds with it probed
    every five while its round trips hold steady, and longer as they vary.
    A lease still leaves an ejected path at once.
*   Bounds treat samples as independent of one another; probes seconds
    apart within a lasting excursion are not, so an excursion can look
    confident. The hold, across fresh probes, answers part of that.
*   More probes: a path a lease weighs is probed every heartbeat while its
    comparison is undecided.
*   The migration touches every site that decides from measurements, and
    until it ends two styles stand side by side.
*   The records cost memory and log lines: one line per change, as often as
    the state changes, and a bounded history on the bus.
*   A decision the library cannot express waits for the library to grow.

## Pros and cons of the options

### Each site its own rules, as today

*   Good, because nothing moves, and each site tunes its rules to its own
    needs.
*   Bad, because each defect surfaces after the fact, through
    instrumentation written to find it; the rules drift apart; and no change
    explains itself.

### Shared statistics

*   Good, because the numbers come out alike wherever they are computed, at
    little cost.
*   Bad, because a helper computes a number and stops there: it neither
    bounds the samples a site passes it, nor refuses to decide on too few,
    nor records anything. Both defects passed through helpers that computed
    correctly.

### One evidence library

*   Good, because the evidence rules hold wherever a decision is taken,
    every decision brings its record, each node still decides alone, and
    the sites move one at a time.
*   Bad, because it must serve decisions as different as a lease's move and
    a cluster's formation, its rules make some decisions wait, and the
    migration is long.

### One node service owning every sample

*   Good, because every sample lives in one place, under one window policy,
    and one place answers why.
*   Bad, because the samples live with their instruments today, the
    prober's path records and the selection's samples per instrument, so it
    moves storage as well as rules, and it puts a service boundary into
    decisions taken every second. What it adds over the library is storage,
    not rules.

### A network-wide decision service

*   Good, because one view decides for every node, consistently, and one log
    explains every change.
*   Bad, because every decision then depends on the network and on the
    service, the failures it must route around included; measurements
    travel; and no node can decide alone.
