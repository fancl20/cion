# Select neighbors by marginal utility

This proposal implements the policy half of
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md):
the comparator the formation loop decides with. The instruments already
stand — [proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md)
landed the loop itself speaking ADR-0008's peer-relative comparator,
[proposal 0012](/docs/proposals/0012-bfd-liveness-and-two-route-comparator.md)
moved its measurement onto SCMP echo over two routes beside BFD's verdict,
and
[proposal 0040](/docs/proposals/0040-enumerate-composed-paths-with-their-facts.md)
landed the enumerated path facts and the query helpers the new comparator
reads. What lands here is the decision computed from them: tiers derived
from the window's sample map, one utility test that admission and
retirement both read, promotion's four cases, retirement's guards, the
least-harm eviction at the cap, and the stranded dialer below the floor.
The link store, the establishment paths, the generation swaps, and every
instrument stay as they are; the wire gains nothing.

[TOC]

## Summary

`RunSelection` decides by the peer's own round trip
([selection.go](/pkg/modules/topology/impl/measured/selection.go)): a
candidate is promoted when its direct median beats the SCMP echo over the
freshest path to the same peer by `PromotionRatio`, sustained two windows;
a neighbor retires when its direct median durably loses to that baseline by
`DemotionRatio`, or its verdict stays down, three windows and never below a
floor of established entries; and at the cap a sustained winner displaces
`worstNeighbor` — the slowest direct sample, a down neighbor more so. The
comparator's questions ADR-0017 asks are answered beside it by helpers no
loop reads yet ([queries.go](/pkg/modules/topology/impl/measured/queries.go)):
`freshest`, `routeCount`, `tierPrice`. The change:

*   Tiers derived every window from the sample map: the measured peers
    walked sorted by direct round trip, a peer opening a new tier when its
    round trip exceeds twice the median of the current one — `TierGap`, a
    code constant. A tier is a decision label local to the node, recomputed
    each window, never exchanged.
*   The window's enumeration held per peer. The probe already enumerates
    once inside `freshest`; the enumeration is kept rather than
    discarded — the baseline echo rides the freshest clean candidate, and
    the tier's route counts and declared prices read the rest. Each
    established neighbor gains one excluded measurement per window: the
    enumeration to
    its tier's members minus the link, the freshest clean survivor echoed.
*   A tier's facts, one helper: its up links — verdict-up links to
    members — its baseline, the fastest member echo; its price,
    `tierPrice` over the members' candidates; its route count,
    `routeCount`; and its
    strandedness, no live route into it. A live route crosses neither a
    signaled interface nor a local verdict-down link: a flagged candidate
    or one over the node's own dead interface is last-resort forwarding,
    not redundancy, and counting either would overcount routes — the one
    error that errs toward under-protection, where every blind spot the
    ADR accepts errs toward over-protection.
*   Promotion admits four cases, one establishment per window: below the
    floor of up links, reachability alone; a stranded tier, a reachable
    member at once, no streak; a single-route tier, a second member within
    the demotion ratio of the price, sustained; and any tier whose price a
    candidate beats by the promotion ratio, sustained. At the cap every
    admission requires an eviction that qualifies under retirement.
*   Retirement guards before it prunes: the floor counts up links only —
    retirement's floor changes with it, from established entries — and a
    cut-critical link, whose exclusion leaves its tier without a live
    route, never retires.
    Past the guards, a link whose verdict stays down across the sustained
    window retires, and a link whose excluded baseline leaves its tier
    served no worse than the demotion ratio above the price retires as
    useless — measured each window, never a remembered value.
    `worstNeighbor` and the peer-relative `good` retire from the code.
*   The cap evicts the least harm: the retirement-qualified neighbor whose
    exclusion moves its tier's baseline least; when none qualifies, no
    promotion happens.
*   Below the floor, a stranded node dials what it knows: with no
    reachable candidate from the directory, the joiner's dials re-dial the
    rendezvous addresses the table already holds, dead entries included.

## Motivation

ADR-0017 decides; the loop still speaks the comparator it supersedes. The
peer-relative test asks what a direct link to a peer buys *at the peer*,
and the ADR's context names why that converges wrong: within a region the
composed paths are already short, so every cheap intra-regional link passes
the promotion ratio, while the long bridge — whose round trip is the
network's worst — is the first the cap displaces, for `worstNeighbor`
ranks by cost and cost is not harm. The same ranking holds the partition
stable once a cut empties: the composed paths that priced the links are
gone with the cut, so no path baseline answers, `good` returns false, and
nothing reaches across — the stranded tier the ADR's promotion reads as
its strongest evidence is, in the code's reading, no evidence at all.

The demotion floor has the same wound from the other side: it counts
established entries, so a link the verdict marks down holds the floor it
contributes nothing to — ADR-0017 counts up links, a down link being no
redundancy whatever its entry's state.

None of the replacement is new machinery. The loop already measures
every peer every window — neighbor, candidate, and demoted neighbor
alike — by the two carriers 0012 split; the probe already enumerates
composed routes to each peer and discards all but the freshest; and
0040's helpers answer the comparator's questions over exactly that
enumeration. What is missing is the derivation that classes the
samples — tiers — and the policy that reads route counts and prices
instead of one peer's baseline: the wiring, not the instrument.

### Goals

*   Tier derivation from the window's sample map, per decision 3: the
    sorted walk, the twice-the-median gap as `TierGap`, recomputed every
    window, local to the node, two nodes free to disagree.
*   The tier's facts computed each window from the store, the verdicts,
    and the per-peer enumerations: up links, measured baseline, price over
    declared sums, route count saturating at two, strandedness over live
    routes alone.
*   Promotion's four cases with their own evidence rules — reachability
    below the floor, no streak for the stranded tier, sustained evidence
    for the priced cases — one establishment per window, the ADR's order.
*   Retirement with its guards: the floor counting up links, the
    cut-critical never retiring, sustained-down and useless retirements
    measured each window on the excluded baseline.
*   Least-harm eviction at the cap, over the same qualification
    retirement reads, so displacement cannot evict a link the policy must
    immediately re-recruit.
*   The stranded dialer: re-dialing held rendezvous addresses, retired
    entries included, when the directory names no reachable candidate.
*   The excluded measurements at the loop's own cadence, inside the
    evaluation window, on the probe socket the loop already owns.

### Non-goals

*   No new instrument, message, or wire change: the loop reads facts
    proposal 0040 landed and constants it already keeps; `Enumerate`
    stays fact-only, and no policy moves into the path layer.
*   No change to the sweep, establishment, the rendezvous acceptor's
    admission, the directory, or the generation swaps — membership
    changes land exactly as they do today.
*   No new run arguments: the tier gap, the ratios, and the windows are
    code constants, per ADR-0017's almost-zero-config reading.
*   No coordinated cuts, no global view: the guarantees stay node-local,
    the ADR's accepted consequence.
*   No NAT traversal and no operator-declared regions — the rejected
    options stay rejected.

## Proposal

### The window's measurements

The window keeps its shape — sweep, probe, declare, decide — and its
probes keep their carriers: the direct side by SCMP echo over the one-hop
path for an established neighbor and by the rendezvous echo for a
candidate, a demoted neighbor a candidate again. What changes is what the
probe keeps. `freshest` already enumerates every composed route to the
peer and returns one; the window holds the enumeration beside the sample.
The baseline echo rides the freshest *clean* candidate — a candidate
crossing a signaled interface is the wrapper's last resort, never the
comparator's route — and no clean candidate leaves the baseline
unmeasured for the window rather than measured over a route the network
would not serve. The members' enumerations are the tier's raw material:
the same candidates feed the route counts, the declared prices, and the
stranded determination.

Each established neighbor gains one excluded measurement: the enumeration
to its tier's members with the link excluded — the hard filter 0040
defined, never the cache's last resort — echoed over the freshest clean
survivor. That one measurement answers three questions: the useless test
(the survivor's round trip against the tier's price), cut-criticality (no
survivor and no other up link in the tier), and the eviction ranking (how
far the exclusion moves the baseline). The probes cross the survivors, not
the questioned link, and run at the loop's cadence on its own socket, in
the evaluation window — measurement stays the selector's instrument, at
the selection loop's pace, per the owner split. The window's work stays
bounded by what the loop already touches — one enumeration per measured
peer, one excluded enumeration per established neighbor, the cap holding
the neighbors — the per-window clustering and comparison the
non-scalable-by-choice driver admits.

`declare` is untouched: the neighbor's direct round trip halved remains
the declaration the next beacons carry.

### Tiers from the sample map

The window's samples — every peer the directory names and the scope
filter passes, measured or not — class into tiers by direct round trip:
walked ascending, a peer joins the current tier when its round trip is at
most `TierGap` times the median of that tier's members and opens the next
when it exceeds it. Unmeasured peers class into none; a peer with only a
path baseline and no direct answer is not placed. The median is over the
current tier's members as walked, the walk is order-stable among equals,
and the labels are local: recomputed every window, keyed by nothing
stable, exchanged with no one — decision labels the policy reads, never
protocol state.

### A tier's facts

One helper turns a tier into what the rules read:

*   **Up links** — the tier's established links, to members, whose
    verdicts are up. A down link is not the tier's redundancy and not its
    route count's first term.
*   **Baseline** — the fastest composed-path round trip among the
    members: the minimum of their baseline echoes. Zero when none
    answered.
*   **Price** — `tierPrice(baseline, candidates)` over the members'
    enumerations: the measured baseline where an echo exists, the doubled
    declared sums where none does, an undeclared edge pricing nothing.
    Zero when nothing prices the tier, and no priced rule fires on it.
*   **Routes** — `routeCount(upLinks, candidates)`: the up links plus a
    clean composed path into a member traversing none of them, a second
    only edge-disjoint from the first, saturated at two.
*   **Stranded** — no live route: no up links and no clean composed
    candidate into any member. A crossing candidate is not a route here
    for the same reason it is not the baseline's carrier, and a candidate
    crossing the node's own verdict-down interface is neither — the store
    and the verdicts name the local interfaces, the candidate's `Links`
    name what it traverses, and the intersection drops the dead.

### Promotion admits four cases

The cases run in the ADR's order, and the first that fires establishes
one link — every link change reshapes segments network-wide, so the
window's budget is one establishment, as today.

1.  **Below the floor.** Fewer up links than `NeighborFloor`: the fastest
    reachable candidate, no utility test. Reachability outranks latency,
    and the floor already counts up links — this case is today's, kept.
2.  **A stranded tier.** A tier with no live route and a reachable
    member: that member — the fastest by direct sample — is promoted at
    once, no streak. This is the clause that keeps every cut transient:
    no composed path resolves into the tier, so the in-band request of
    `establishLink` finds no route, and the rendezvous establishment it
    already falls through to is the establishment that reaches where no
    path does.
3.  **A single-route tier.** A tier whose route count is one admits a
    second: a member whose direct round trip is no worse than
    `DemotionRatio` times the tier's price, sustained `PromoteWindows` —
    redundancy purchased at a bounded latency price.
4.  **A beaten baseline.** A tier whose price a candidate beats by
    `PromotionRatio` — direct round trip under the ratio of the price —
    admits it, sustained `PromoteWindows`, the sustained winner the
    fastest direct sample among qualifiers.

Only a classed, reachable peer promotes: an unmeasured peer carries no
label to compare and no sample to compare with. At the cap, every case
requires an eviction that qualifies under retirement — the next
section's rules; the floor case and the stranded case included, for the
cap bounds the set at every instant. Streaks damp as they do today:
sustained windows of the same evidence, reset when evidence breaks,
spent and erased by retirement, so a peer whose utility durably earns a
link is proposed again however often it was demoted before.

### Retirement guards before it prunes

Two guards, then two rules, and the floor holds at every instant —
however many links go bad in one window, up links retire only down to the
floor.

*   **The floor.** Up links only. A link the verdict marks down is no
    redundancy and never blocks another's retirement; an up link retires
    only while up links exceed the floor.
*   **Cut-critical.** A link whose exclusion leaves its tier without a
    live route — the excluded enumeration returns no clean survivor and
    the tier holds no other up link — never retires, whatever its
    latency. The bridge survives on measured merit; healing is
    promotion's work, never the last route's removal.

Past the guards:

*   **Down.** A link whose verdict stays down across `DemoteWindows`
    consecutive windows retires — the monitor's own hysteresis inside a
    window, the streak across them. Its recovery path is re-establishment:
    the peer remains a candidate the window measures by rendezvous echo,
    and a peer that answers is promotable again at once under the floor
    or stranded cases.
*   **Useless.** A link whose excluded baseline serves its tier no worse
    than `DemotionRatio` times the tier's price, sustained `DemoteWindows`,
    retires — the survivor measured each window, never a remembered
    value. An excluded enumeration that resolves a clean survivor the
    echo cannot answer leaves the test unmeasured for the window and the
    streak intact but unextended: no evidence, no retirement.

The useless rule and promotion's cases 3 and 4 read the same price with
hysteresis between the thresholds — one test serving both directions,
each correcting the other's estimation error, the feedback loop decision
2 depends on.

### The cap evicts the least harm

At the cap, an admission first evicts: the victim is the
retirement-qualified neighbor — past both guards and meeting a
retirement rule's test this window, the sustained-down streak for a dead
link, the useless test for a live one — whose exclusion moves its tier's
baseline least, the smallest distance from the excluded baseline to the
tier's price, ties to the slower direct sample. When none qualifies, no
promotion happens and the cap stands. Eviction and retirement qualify
the same neighbors against the same measurements, so the
intra-regional mesh — whose exclusion changes nothing — retires first
and the bridge — whose exclusion strands a tier — is not eligible at
all.

### A stranded node dials what it knows

The joiner's dial loop dials entries still aimed at a rendezvous and
skips the retired. ADR-0017 decision 8 widens it: when the window's
probe found no reachable candidate from the directory, the next dial
pass re-dials the rendezvous addresses the table already holds, retired
entries included — the one address a stranded node independently holds
is worth more than an empty or expired directory snapshot. An answered
re-dial revives the entry as a candidate — the state flip and the
recorded sides — and the candidate sweep settles it by the peer's
evidence, exactly as it settles a joiner's. An unanswered one costs a
UDP round trip and changes nothing.

### What changes shape

`TierGap` joins the constants; the ratios and windows keep their names
and values, read against the tier's price instead of the peer's
baseline. `measurement` keeps its two fields and the enumeration lands
beside the samples; the probe seam the tests inject grows to carry the
per-peer candidates and the excluded measurements. `promote`, `demote`,
`good`, and `worstNeighbor` are replaced by the cases, guards, and rules
above — the store writes, the `Changed` callback, and the generation
swap they trigger unchanged.

## Test plan

*   **Unit, tiers:** the sorted walk — a peer within the gap joins, one
    past twice the median opens a new tier, an unmeasured peer classes
    into none; the median recomputes as a tier grows; equal samples are
    stable across recomputation.
*   **Unit, facts:** the baseline is the fastest member echo; the price
    takes the measured baseline over declared sums, a declared sum where
    no echo answered, and nothing when neither prices; the route count
    reads the tier's up links and clean candidates — a crossing
    candidate and one over a local down interface count as no route, and
    a tier with only those strands.
*   **Unit, promotion:** below the floor the fastest reachable candidate
    establishes, no test; a stranded tier establishes a reachable member
    in the same window, no streak, and the establishment rides the
    rendezvous path when no route resolves; a single-route tier admits a
    second within the demotion ratio of the price, sustained, and
    rejects one outside it; a candidate beating the price by the
    promotion ratio admits, sustained; a flapping one never; one
    establishment per window across cases; an unpriced tier promotes
    nothing.
*   **Unit, retirement:** the floor counts up links — a down link
    retires where the old established-entry floor would have held it,
    and an up link never retires at the floor; a cut-critical link never
    retires however slow or useless; sustained-down retires at the streak
    and resets on recovery; the useless test measures the excluded
    baseline each window — a remembered value never substitutes, an
    unanswered survivor extends no streak — and the price the test reads
    is the same price promotion read the same window.
*   **Unit, the cap:** a promotion at the cap evicts the qualified
    neighbor whose exclusion moves its baseline least, ties to the
    slower sample; a bridge whose exclusion strands its tier is not
    eligible and blocks the promotion; none qualifying means no
    promotion; the displaced candidate's own evidence rules still apply.
*   **Integration, the line:** the harness's three-node line — kill B,
    C linked to B alone, and every route from C to A crosses the dead
    link: the tier holding A strands, C promotes A within the window by
    the rendezvous establishment, and the dead link retires once the new
    segments serve the tier.
*   **Integration, equilibrium:** a small regional mesh joined by one
    slow bridge, every node at the cap, a fast candidate appearing
    inside a region — the eviction lands on the intra-regional link
    whose exclusion moves nothing, and the bridge survives on measured
    merit; a cut that empties the bridge's tier strands it and heals by
    the stranded clause while the cap's eviction takes a dead or
    intra-regional link, never the bridge.
*   **Negative:** a candidate that answers no probe is never promoted
    however favorable its tier's declared prices; a misstated
    declaration moves no measured baseline and strands no tier the
    enumerations serve; the quiet window — no verdict edges, no streak
    thresholds met, no cap pressure — changes nothing.
