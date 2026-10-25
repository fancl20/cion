# Judge Network Behavior by the Paths It Serves

*   Status: proposed
*   Date: 2026-10-25

[TOC]

## Context and problem statement

CION's labs boot nodes through the run command's own assembly on a
userspace fabric that shapes every host pair's delay and loss, inside a
bubble of virtual time
([proposal 0067](/docs/proposals/0067-run-the-fabric-labs-on-virtual-time.md)).
The topology formation of
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
and the beaconing and path composition of
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)
are judged there. Each lab asserts what its scenario was written to show:
one that its link set settles — unchanged for ten minutes, every node at its
floor, the links connecting them all — another that a stranded tier heals.
Both describe links. None asks what traffic gets: whether the path a node
would choose to another works, how far it strays from what the delays
allow, what state the network keeps to serve it, or what one failure does.

Measured by its paths, the settling lab — nine nodes over three regions,
3 to 9ms across a region, 8 to 17ms between two of them, 82 to 106ms to the
third — told another story than its links. Before
[proposal 0070](/docs/proposals/0070-count-the-dialed-links-against-the-useless-retirements-floor.md)'s
guard its link sets settled on 10 or 11 links. In three runs of four no
link joined the two near regions, and pairs between them detoured through
the third, up to 23 times their direct delay; in two of four cutting a
single link would have split the network. The sparser sets held more
stored segments than the 16- or 17-link sets after the guard, 153 against
113, and only 27 of the 153 still crossed live links alone: the routes
convergence churned through linger until their hops expire, the staleness
bound ADR-0004 accepted. With the guard the best path between any pair
stayed within 1.5 times its direct delay in five runs of six and within 3.5
times in the sixth, and no single cut split the network. Even then
the path a node chooses — ranked by freshness and hop fields, never by
delay — crossed up to 26 times a pair's direct delay, it led up to four
pairs per run over a link already gone, and three stored segments in four
were the chosen path of no pair. Link counts, the one cost the labs
tracked, pointed the wrong way. And no lab has asked what the network does
with a link that loses part of its packets, neither failed nor whole: the
case liveness and selection judge least decisively, where a link can stand,
fall, or alternate between the two.

A lab holds a view no node holds: every pair's delay and every node's
links, segments, and choices. It can grade what the network serves against
what the delays allow, with a reference no design computes. This record
decides what every lab judges, against which reference, and which
judgments gate a change and which are benchmarked.

## Decision drivers

*   **What Traffic Gets:** a lab judges the path a pair's own node chooses
    — what traffic rides — not the links, the segments, or what a design
    intends.
*   **A Reference Outside the Design:** paths are compared with what the
    simulated delays allow, computed from the global view, never with a
    quantity the design under test computes.
*   **Cost Where It Accrues:** the state a network keeps and the churn it
    causes are its costs; a link is neither.
*   **Failures and Changes, Not Only Steady States:** a network is judged by
    what one failure does and how fast it recovers from a change as much as
    by where it settles.
*   **Stable Under Degradation:** a link that degrades without failing must
    not set the network oscillating: the network keeps it or drops it, never
    both by turns, and the loss at which it switches is a property to know.
*   **One Yardstick:** every lab reports the same measures, so a change to
    selection, beaconing, or path choice compares across all of them.
*   **Correctness Gates, Quality Is Benchmarked:** what a network must do
    fails a change that breaks it; how well a network serves is compared
    across runs and designs, never held to an optimum a design may not
    reach.
*   **Cheap to Run:** the judgment runs inside the labs on virtual time, so
    a run costs minutes, not the hours it models.

## Considered options

What a lab judges:

*   **Link-Level Assertions:** each lab asserts properties of its link set —
    settling, floors, connectivity — as today.
*   **Bespoke Measures per Lab:** each lab defines what it measures.
*   **Paths Against a Global Reference:** every lab grades the chosen paths,
    the segments, and the reactions to change against the shortest paths
    the simulated delays allow.

The reference a path's cost is graded against:

*   **Direct Delay:** each pair's own delay.
*   **Shortest over the Formed Links:** the best the settled topology allows.
*   **Global Shortest with a Transit Penalty:** the shortest over every
    pair's delay, each node a path crosses between its ends charged.

What counts as a segment's cost:

*   **Stored Segments:** every segment kept.
*   **Unchosen Segments as Noise:** a segment no pair's chosen path joins.

How a link that degrades without failing is judged:

*   **Failures Alone:** only cuts are scenarios; a lossy link is judged once
    it fails.
*   **One Loss Level:** a scenario applies one loss rate to a link and
    measures the response.
*   **A Swept Loss Rate:** a scenario steps a link's loss rate across a range,
    up and back down, and measures the response at every level.

How the measures are held:

*   **Bounds in Every Run:** every measure carries a bound the labs assert
    wherever they run.
*   **Benchmarks:** the measures of quality run on demand and compare across
    runs and designs; correctness alone is asserted.

## Decision outcome

Chosen options: **paths against a global reference**, **the global
shortest with a transit penalty**, **unchosen segments as noise**, **a
swept loss rate**, and **benchmarks** — realized as follows:

1.  **Every pair reaches over its chosen path.** After a lab settles, and
    after the network recovers from each change a scenario makes, every
    ordered pair's own node's chosen path to the other crosses only links
    up at both ends. A pair served only by a path its node would not choose
    fails.
2.  **Path cost is graded against the global shortest path.** A path's cost
    is its one-way delay over its links plus a penalty for each node it
    crosses between its ends: the node split into an in-node and an
    out-node joined by an edge weighing the penalty, which charges what
    forwarding costs — the transit node's processing and resources, and one
    more failure on the way. The reference is the all-pairs shortest cost
    over every pair's delay in the lab, the same penalty charged. Each pair
    reports its chosen path's ratio to the reference and its excess over
    it, split into the topology's share — the shortest over the formed
    links against the reference — and the choice's share — the chosen path
    against that shortest. The penalty is a lab's parameter; its default is
    calibrated by measurement.
3.  **A segment no chosen path joins is noise.** The objective is none: a
    segment that no pair's chosen path joins in the settled network costs
    state and earns nothing. A segment chosen only after a failure is a
    backup, judged by the failure's scenario (decision 5): what it buys is
    a better interim path than the other segments offer, for as long as a
    replacement takes to surface without it.
4.  **Cutting any one link does not split the network.** Removing any single
    formed link leaves the formed links connecting every node, and the
    cut's scenario shows every pair reaching again.
5.  **Changes are scenarios, each measured end to end.** After settling, a
    lab changes its environment: a link cut and later restored, a delay
    that changes. Each scenario measures the time until the network detects
    the change; the interim path — the best the segments present at the
    change still offer — graded as decision 2 grades a path; the time until
    every pair reaches again; the time until the best path the changed
    links allow surfaces among the segments, the replacement surfacing; the
    time until the link set settles again; and the link changes on the way.
6.  **Degradation is swept, and every level settles.** A lab steps one
    link's loss rate from none to total and back down, holding each level
    until the network settles or a time limit runs out. At every level it
    reports whether the link's verdict and the link stand; the verdict
    changes and link changes the level causes; the chosen paths that still
    cross the link and the loss they inherit; and every pair's reachability
    and path cost. The objective is a response that settles at every level:
    the link set and the chosen paths stop changing, never alternating
    between keeping and dropping the link. The sweep reports the loss at
    which the network drops the link on the way up, the loss at which it
    takes the link back on the way down, and the band between them.
7.  **Quality is benchmarked; reachability gates.** The measures beyond
    decision 1 grade how well a network serves, not whether it works, and
    the reference may lie beyond any design's reach: they run on demand as
    benchmarks, each reported across repeated runs and compared between
    designs, and none fails a lab. Reachability (decision 1) is the one
    property the labs assert in every run.

### Positive consequences

*   Labs judge what traffic gets, with one yardstick shared by all of them,
    and a change to selection, beaconing, or path choice is compared on the
    same measures everywhere.
*   The reference comes from a lab's own delays, so no design grades
    itself.
*   State and churn are counted where they accrue; link counts stop
    standing in for cost.
*   The split between the topology's share and the choice's share says
    which layer a gap belongs to.
*   Failures and changes are judged, not only steady states, and a backup
    segment's worth is measured rather than argued.
*   A degraded link's handling is known: the loss at which the network
    drops it, the loss at which it takes it back, and whether any level
    sets the network oscillating.

### Negative consequences

*   A lab must know every pair's delay and read every node's chosen paths
    and segments, and the path layer must report which segments a chosen
    path joins.
*   The penalty is a judgment, not a measurement: a heavy one favors fewer
    transits, and so more links, and its default stays open until measured.
*   Benchmarks run on demand, so a regression in quality shows only when
    someone runs them, and each takes minutes of wall time: a sweep holds
    every level until it settles, and random loss needs repeated runs to
    read.
*   Reachability over the chosen path fails in some runs today — a stale
    segment leads a pair over a link already gone — so the labs assert it
    once stale segments stop being chosen.

## Pros and cons of the options

### Link-level assertions

*   Good, because they exist, run fast, and need nothing the labs lack.
*   Bad, because links are not what traffic rides: a link set settles with
    pairs detouring 23 times their direct delay, or with one link holding
    the network together.
*   Bad, because link counts misstate cost: the sparser link sets held more
    segments.

### Bespoke measures per lab

*   Good, because each lab measures what its scenario stresses.
*   Bad, because measures that differ cannot compare a design change across
    labs, and each lab re-derives its references and its costs.

### Paths against a global reference

*   Good, because it grades what traffic gets against what the delays
    allow, independently of the design under test.
*   Good, because one judgment serves every lab.
*   Bad, because it needs the global view and the segments each chosen path
    joins, and it computes more than a link check.

### Direct delay

*   Good, because it needs no computation.
*   Bad, because a relay can beat a pair's direct delay where delays break
    the triangle inequality, and forwarding costs nothing under it: a path
    crossing five nodes grades like one crossing none.

### Shortest over the formed links

*   Good, because it isolates the choice: what the segments and the ranking
    miss of what the topology allows.
*   Bad, because it grades the topology against itself: a topology that
    detours every pair passes.

### Global shortest with a transit penalty

*   Good, because it is the best any topology could serve, and it charges
    forwarding.
*   Bad, because the penalty's value is a judgment that colors every ratio;
    it stays a parameter.

### Stored segments

*   Good, because counting is trivial.
*   Bad, because a segment's worth is its use: a store can be small and
    unused or large and every entry chosen.

### Unchosen segments as noise

*   Good, because it targets the state that earns nothing, and it tells a
    selection policy what to stop keeping.
*   Bad, because a backup is unchosen until a failure, so its worth waits
    on the failure's scenario.

### Failures alone

*   Good, because a cut is decisive and quick to measure.
*   Bad, because it never shows what the network does with a link it can
    neither trust nor give up: whether it keeps the link, drops it, or
    alternates.

### One loss level

*   Good, because it measures a degraded link's handling at the cost of one
    scenario.
*   Bad, because it reads one point of a response that matters most at its
    threshold: it cannot show where the network drops a link, where it takes
    the link back, or whether a band between them alternates.

### A swept loss rate

*   Good, because it maps the whole response: the loss at which the network
    drops a link, the loss at which it takes it back, and any level at which
    it oscillates.
*   Bad, because it holds every level until it settles, and random loss
    needs repeated runs.

### Bounds in every run

*   Good, because a regression in any measure fails the change that causes
    it.
*   Bad, because a measure of quality has no correct value: a bound sits
    where today's design lands, failing a change that trades one measure
    for a better other, or sits loose enough to catch nothing; and the
    scenarios cost minutes in every run.

### Benchmarks

*   Good, because each measure keeps its whole distribution, two designs
    compare on every measure at once, and the labs that gate every change
    stay fast.
*   Bad, because a regression in quality shows only when the benchmarks
    run.
