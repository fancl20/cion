# Read Round Trips at Their 80th Percentile over Five Minutes

*   Status: accepted
*   Date: 2026-11-06

[TOC]

## Context and problem statement

The selection decides its links by comparing round trips
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
[ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md)). A
candidate is promoted when its direct round trip beats its price, the cost
of its cheapest route; a link it dialed retires when the routes that
survive without it serve its tier no worse. The two sides of those
comparisons read their samples differently:

*   **The direct side** reads one window. A neighbor is read by the median
    of three echoes. A candidate is read by one binding request, the first
    answer of up to three attempts, which can time a late reply to one
    attempt from the next. No window remembers the last.
*   **The price side** reads a route by the median of its last twenty
    probes, divided by its delivery rate
    ([health.go](/pkg/libs/scion/health.go)). Twenty probes span about 100
    seconds for a route in use, probed every five seconds, and about ten
    minutes for a route priced alone, every thirty.

The first lab to vary delay
([proposal 0116](/docs/proposals/0116-observe-the-network-under-unstable-delay.md))
measured what this does:

*   **Jitter on every path:** at a mean of 5ms or more, the regions network
    changed its links 122 and 95 times over two sweeps and settled at no
    level of 10 or 20ms. Most changes were links promoted for a beaten price
    and retired as useless soon after.
*   **Bursts:** with a link's delay tripled for thirty seconds on average,
    every two minutes, the regions network changed its links 3 and 7 times
    in thirty minutes, and one read reached 58 of 72 pairs.
*   **One link's jitter alone,** up to twice its delay, changed nothing.

Three readings flip decisions:

*   **A single low sample:** a candidate's lucky answer beats a price that a
    median holds, and two such windows promote it.
*   **One change at two times:** a burst moves the median of a route in use
    within 100 seconds, while the direct side reads one window, so each side
    sees a change at its own time.
*   **Instability without cost:** a link whose round trip varies reads as
    well as its median.

How should the selection read a round trip, so that noise flips no
decision and instability costs?

## Decision drivers

*   **No outlier decides:** no single sample, low or high, moves a reading.
*   **Bursts below the evidence bar move nothing:** an excursion shorter
    than the two windows a promotion counts as sustained leaves every
    reading as it was.
*   **Instability costs:** a round trip that varies reads slower than its
    median.
*   **One span on both sides:** the direct side and the price side read the
    same stretch of time, so a change reaches both together.
*   **Real changes still play out** within the horizons the network keeps
    already.
*   **One statistic** for every reading.

## Considered options

*   **One window, as today,** with each candidate sampled three times.
*   **An exponential moving average** of the samples.
*   **The median over a span.**
*   **The 80th percentile over a span.**
*   **The minimum over a span,** as BBR estimates a path's propagation
    delay.

## Decision outcome

Chosen option: **the 80th percentile over a span**, realized as follows:

1.  **Every peer is sampled three times a window.** A candidate takes three
    binding requests, as a neighbor takes three echoes, and an unanswered
    request ends the window's sampling of it. Each attempt of a binding
    request draws its own nonce, and a reply is timed from the attempt it
    answers.
2.  **A reading is the 80th percentile of the answered samples of the last
    five minutes.** Up to a fifth of the samples may stand high and the
    reading holds, as BBR tolerates a fifth of an interval's packets lost
    before it judges the path policed. Five minutes, `StaleAfter`, makes
    that fifth one minute, the two windows promotion counts as sustained:
    a shorter excursion moves nothing, a lower round trip registers once it
    has held four minutes, and a higher one once it has held one. Five
    minutes is also the horizon in which a link change plays out in every
    node's segments.
3.  **Every reading is taken so.** A peer's direct round trip is its
    reading, and the tiers, the promotion and useless tests, the cap's
    eviction, the declared delays, and the directory reports all take it. A
    route's price is the same percentile of its probes over the same five
    minutes, divided by its delivery rate as today. A peer's samples are
    kept per instrument and address — a link's echoes, the binding requests
    to one address, a punched candidate's probes — so no reading mixes
    instruments, but for one change: an instrument with no sample in the
    five minutes starts from those of the instrument that read the peer
    last. A promoted link reads on from the binding requests that promoted
    it, and a retired link's peer from the link's echoes, so a change of
    instrument neither restarts a reading at its highest sample nor lets
    one quiet window bring a link back. A window in which a peer answers
    nothing still reads it unreachable.
4.  **Path records keep five minutes of probes**, beside their last twenty,
    which the path library's health, loss, and lease ranking read as today
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)).

The promotion and demotion ratios, the margin floor, and the streaks stay.
This narrows ADR-0026's prices: each peer is still priced by its own route,
read over five minutes.

### Positive consequences

*   A lucky sample cannot promote: a candidate must read low for four
    minutes of every five.
*   A burst shorter than a minute, on a link or on a route, moves no reading
    on either side.
*   A link or a route whose round trip varies reads at its 80th percentile,
    slower than its median by its spread.
*   Both sides of every measured comparison read the same five minutes.
*   The delays the beacons declare and the round trips the directory
    reports hold steady.

### Negative consequences

*   An improvement registers after four minutes and promotes after five,
    with the streak, against one minute today. A degradation registers after
    one minute and retires after two and a half.
*   Once excursions add up to more than a minute in five, they hold the
    reading up: a link that bursts for seventy seconds, or for half a minute
    every two, can retire as useless, and its pair promote again only once
    four minutes of five read low.
*   A peer no instrument has read yet reads at its highest samples until a
    window or two is in, so a new candidate whose round trip varies reads
    slow at first.
*   A candidate costs three binding requests a window, not one, and the
    window, which probes one peer at a time, spends three of its round trips
    on it rather than one.
*   A record holds about sixty probes for a route in use.
*   A route the selection prices by its declared delays, or by its first
    few probes, still decides as before: the five minutes hold about ten
    probes of a route priced alone, and none of one it has not requested.

## Pros and cons of the options

### One window, as today

*   Good, because three samples a candidate remove the single lucky sample.
*   Bad, because one window's median still flips with a burst inside it,
    the price side keeps its spans of 100 seconds to ten minutes, and
    instability costs nothing.

### An exponential moving average

*   Good, because it keeps one value per peer.
*   Bad, because it averages outliers in rather than rejecting them: at a
    weight of 0.3, one sample five times the round trip leaves the reading
    120%, 84%, and 59% high over the next three windows, turning one burst
    into the three windows a retirement needs. It reads a mean, so
    instability costs only what it adds to the mean.

### The median over a span

*   Good, because it is symmetric: an excursion must hold half the span to
    move it.
*   Bad, because instability costs nothing: a link that varies reads as well
    as its median.

### The 80th percentile over a span

*   Good, because no single sample decides, instability costs its spread
    above the median, and the excursion it tolerates matches the evidence
    bar.
*   Bad, because it is asymmetric: a slower round trip registers in a fifth
    of the span, a faster one in four fifths, so improvements wait and a
    long burst holds.

### The minimum over a span

*   Good, because it is BBR's estimate of propagation delay, blind to
    queueing.
*   Bad, because a single low sample sets it, against the first driver, and
    queueing that persists, the instability to cost, costs nothing.
