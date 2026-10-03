# Form the Topology with Measured Neighbor Utility

*   Status: proposed
*   Date: 2026-10-03

[TOC]

## Context and problem statement

A CION node owns its link set. The underlay is UDP/IP, so a link is a
connected socket pair the node chooses, and every reachable,
directory-listed peer is a candidate for one. Owning the link set means
continuously answering three questions. Whether each established link
is alive — the question the network's forwarding rests on, asked every
interval of every link. Whether each link is worth having — the
comparator's question. And whether a candidate would be worth
establishing — the comparator's question asked of a peer no path and no
interface reach yet. It also means the policy that turns those answers
into topology: joining the network, learning candidates, admitting
links bilaterally, selecting under a resilience floor, and applying
changes to a forwarding plane built to serve immutable generations.

Worth having needs a definition that survives geography. A link's cost
is its round trip; its contribution is what the composed paths cannot
do without it — reach into the region beyond the peer at better
latency, or a route those paths do not provide. A policy that ranks
links by cost converges on dense regional meshes: within a region the
composed paths are already short, so cheap links pass any promotion
ratio, while the long links that bridge regions are the first the cap
displaces. Worse, once a cut empties, the composed paths that priced
the links are gone with it, so a cost-ranked policy holds no rule that
reaches across — the partition is stable. Resilience therefore belongs
inside the comparison itself: what a link adds — latency into its
region, and independent routes — is the quantity the comparator
measures, and the same quantity shields the bridges from displacement.
The region beyond a peer is not configuration either: the loop already
measures every peer every window, latency classes fall out of those
measurements, and the path database already holds the hop-by-hop
identity — ISD-AS and interface IDs — of every composed path, so
whether two routes share a link is a local computation.

The drafts CION implements supply instruments for two of the three
questions. The data plane draft assigns link failure detection to BFD
(Section 6.1): sessions between neighboring routers carried on one-hop
paths, silence past an interval marking the link down in both
directions, the session itself watching for recovery, and the SCMP
interface-down notification (Section 6.2) telling sources while their
own probes stay authoritative. SCMP echo measures round trips over
paths — the instrument the path library already carries as the ping
machinery — and one-hop paths between neighbors (control plane draft,
Section 5) give it a route to every established link. For the third
question the drafts configure neighbors out of band (control plane
draft, Section 2.2.5), and CION's rendezvous exchange fills that
silence: a plain underlay round trip to a peer's advertised rendezvous
address, where no path and no interface exist yet.

This record consolidates the topology design: the formation policy —
measured selection by marginal utility with a resilience floor, joining
with two arguments, a core-served directory, generated local state,
generational replacement — and the instruments that feed it, drawn from
the drafts wherever the drafts define one. The ownership of those
instruments — what the node owes its neighbors, what its policy chooses
for itself — is the companion decision of
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md).

## Decision drivers

*   **Almost-Zero Config:** Joining is an act of the joining node: two
    run arguments and generated local state, with topology description
    and secret material kept out of every file. Regions are derived
    from measurements, never named by an operator.
*   **Resilience by Construction:** A cut is a transient the mechanism
    heals, not an equilibrium it maintains; no node's own action
    strands a region it can still reach, and a node holds enough up
    links that a single failure leaves it connected.
*   **Utility over Latency:** A link is earned by what it adds — reach
    the composed paths serve poorly, or redundancy they lack — and
    priced by the same quantity in both directions, admission and
    retirement.
*   **Measurement over Description:** Links and regions alike are
    earned by evidence — the posture beaconing took for paths, applied
    to the topology itself.
*   **Spec-Native Instruments:** Where the drafts define an instrument
    — BFD for liveness, SCMP echo for measurement, service resolution
    for endpoint discovery — the node speaks the drafts' instrument.
    CION designs its own where the drafts hand the question to
    out-of-band configuration.
*   **Instruments by Owner:** Liveness is a service the node owes its
    neighbors and runs for every serving link whatever its topology
    policy; measurement is the selector's own instrument, run at the
    selection loop's cadence. The owner decides where the instrument
    runs.
*   **Operator Sovereignty:** Which links a node accepts and whose
    traffic it transits are the operator's decisions, visible and
    restrictable; a node appears in paths only through AS entries it
    signed (ADR-0004).
*   **Trust Continuity:** The WebPKI bootstrap channel, TRC-anchored
    chains, and authenticated control channels stay as they are.
*   **Single Binary, One Node per AS:** One process owns its links.
*   **Non-Scalable by Choice:** Mechanisms acceptable at CION's target
    scale — probing candidates, directory fan-out from a core,
    per-window clustering and pairwise path comparison — are in
    bounds.

## Considered options

How link failure is detected:

*   **BFD per the Drafts:** The data plane draft's inter-router
    sessions (Section 6.1).
*   **Liveness from Measurement Arrivals:** The measurement stream's
    arrival and silence double as the failure signal.
*   **Admission-Time Probing Only:** The comparator gates membership;
    runtime state observes the link only through the measurements
    selection already makes.

What carries the comparator's measurements:

*   **SCMP Echo over Two Routes:** One-hop paths to each neighbor for
    the direct side, the freshest resolved path to the same destination
    for the baseline.
*   **A Dedicated Probe Protocol:** A purpose-built periodic probe
    with its own cadence and payload.
*   **Liveness-Protocol Timestamps:** The liveness stream carries the
    selector's timestamps beside its own work.

How candidates are measured before a link exists:

*   **The Rendezvous Echo:** A plain underlay round trip to the
    candidate's advertised rendezvous address.
*   **Path-Borne Echo:** Echo over the composed paths the candidate is
    compared against.

What the comparator measures:

*   **Peer-Relative Latency:** The direct round trip against the
    composed paths to the same peer.
*   **Marginal Utility:** What adding or removing the link changes for
    the destinations beyond the peer — the latency of the freshest
    route into the peer's region, and the count of independent routes
    there.
*   **Coordinated Cuts:** A coordinator computes the network's cuts and
    assigns each node protected links.

How redundancy is judged:

*   **The Floor Alone:** Neighbor degree, not routes.
*   **Route Counts from the Path Database:** Up links plus pairwise
    edge-disjoint composed paths.
*   **Operator-Declared Regions:** Configured classes the policy
    balances across.

What a missing baseline means:

*   **No Evidence:** A candidate without a path baseline is unpromotable
    above the floor.
*   **A Stranded Tier:** No path resolving into a peer's region is
    itself the strongest promotion evidence.

What displacement at the cap evicts:

*   **The Slowest Sample:** The neighbor with the worst direct round
    trip.
*   **The Least Harm:** The neighbor whose exclusion changes neither
    latency nor route count anywhere the policy can measure.

## Decision outcome

Chosen options: **BFD per the drafts** for liveness, **SCMP echo over
two routes** for measurement, **the rendezvous echo** for candidates,
selection by **marginal utility** with redundancy as **route counts
from the path database**, a missing baseline read as **a stranded
tier**, and displacement evicting **the least harm** — realized as
follows:

1.  **The link set is the node's own decision, continuously revised.**
    Every directory-listed, reachable peer is a candidate. The node
    keeps a link for what it adds beyond the peer, always retains at
    least two up links so a single failure leaves it connected while
    replacement earns its way in, caps its link count to bound
    beaconing fan-out, and changes links only on sustained evidence —
    every link change reshapes segments network-wide, so stability
    trades against optimality deliberately. The comparator measures
    every peer every evaluation window — neighbor, candidate, and
    demoted neighbor alike — so a peer whose utility durably earns a
    link is proposed again however often it was demoted before, and
    the floor and the cap bound the set at every instant. Link roles
    still emerge from beacon flow (ADR-0004).
2.  **Utility is the comparator, and one test serves both directions.**
    A link's utility is what its presence or absence changes for the
    destinations beyond the peer: the latency of the freshest composed
    route into the peer's tier, and the count of independent routes
    there. Promotion asks whether adding the link improves either;
    retirement asks whether removing it changes neither. What the
    peer's own round trip measures is cost, and the comparator prices
    contribution. The exact latency delta is measurable only once the
    link exists, so promotion decides on the tier-relative estimate
    and retirement corrects on the link's own windows — the two rules
    form a feedback loop, which is why precision in each matters less
    than agreement between them.
3.  **Tiers are derived every window from the sample map.** A tier is
    a latency class of the peers the window measured: walking them
    sorted by direct round trip, a peer opens a new tier when its
    round trip exceeds twice the median of the current one. A tier's
    baseline is the fastest composed-path round trip among its
    members, unreachable when none resolves. Tiers are decision labels
    local to the node, recomputed each window, never protocol state
    and never exchanged; two nodes may draw different boundaries, and
    nothing depends on their agreeing.
4.  **Route counts come from the path database.** A link's identity is
    the `(ISD-AS, interface ID)` pair the interface-down cache already
    keys on, and a composed path's link set is the walk the
    interface-down skip already makes over its segment entries
    (`/pkg/scion/provider.go`, `crossesFrom`). The routes into a tier
    are its up links plus a composed path into the tier that traverses
    none of them; a second path counts only when edge-disjoint from
    the first; the count saturates at two. Two blind spots are
    accepted: segments the node has not learned can only undercount
    routes, which errs toward over-protection, and links disjoint on
    the graph may share fate on the underlay — same fiber, same
    facility — which no beacon carries.
5.  **Promotion admits four cases, one establishment per window.**
    Below the floor of up links, reachability alone: the fastest
    reachable candidate, no utility test. A tier no composed path
    resolves into is stranded: a reachable member is promoted at once,
    no streak — the clause that keeps every cut transient, for the
    rendezvous establishment reaches where no path does. A tier with a
    single route admits a second whose round trip is no worse than the
    demotion ratio above the tier baseline, on sustained evidence. A
    tier whose baseline a candidate beats by the promotion ratio
    admits it on sustained evidence. At the cap, any admission
    requires an eviction that qualifies under retirement.
6.  **Retirement guards before it prunes.** The floor counts up links
    only — a link the verdict marks down is no redundancy, whatever
    its entry's state. A link whose exclusion leaves its tier without
    a route is cut-critical and never retires, whatever its latency.
    Past the guards, two retirements: a link whose verdict stays down
    across the sustained window retires; and a link whose exclusion
    leaves a route into its tier no worse than the demotion ratio
    above the tier baseline retires as useless — measured each window
    on the excluded baseline, the interface-down skip resolving the
    paths that avoid the link, never a remembered value.
7.  **The cap evicts the least harm.** At the cap the victim is the
    retirement-qualified neighbor whose exclusion moves the tier
    baseline least; when none qualifies, no promotion happens. The
    bridge survives on measured merit — its exclusion strands a tier
    — while the intra-regional mesh, whose exclusion changes nothing,
    retires first.
8.  **Below the floor, a stranded node dials what it knows.** With no
    reachable candidate from the directory, the joiner's dials re-dial
    the rendezvous addresses the table already holds, dead entries
    included. The one address a stranded node independently holds is
    worth more than an empty or expired directory snapshot.
9.  **Joining takes two arguments, and identity is generated local
    state.** A joiner is given one existing node's underlay address and
    the core's domain: the address seeds the first link, the domain
    authenticates the enrollment and the TRC fetch over the WebPKI
    bootstrap channel — a joiner cannot otherwise know which domain is
    correct, so the domain is an argument for core and non-core alike.
    The founding core takes its domain alone; a restarting node takes
    neither, identity coming from local state and neighbors from the
    running network. The node's ISD-AS, forwarding key, and AS keys
    are created on first start and persisted with the trust material;
    the ISD-AS is self-picked from the private ranges, and enrollment
    is the gatekeeper that rejects collisions and strangers.
10. **First contact is the rendezvous exchange, and the rendezvous
    exchange is the candidate probe.** Every node listens on its
    advertised rendezvous address. The exchange is a plain underlay
    round trip — a nonce-bearing request, a matching reply — beneath
    SCION, bounded by return-routability checks and admission limits,
    with admission policy the acceptor's: open within those limits by
    default, restrictable to allowlisted ISD-ASes. For a joiner with
    no composed path the exchange is also the establishment, seeding
    the link store entry; for the selection loop it is the candidate
    measurement — the direct round trip to the peer's public address,
    taken where no path and no interface exist, which is what makes it
    an honest measurement of the hypothetical link rather than of the
    paths it would compete with. Everything after first contact rides
    authenticated channels.
11. **A core-served directory informs selection.** Once enrolled, each
    node publishes its ISD-AS, control and rendezvous addresses over
    its own channel, authenticated by its TRC-anchored chain; the core
    aggregates and serves the directory, and entries expire without
    refresh. The core is the rendezvous, never the authority over what
    is true — the trust and availability posture of enrollment and
    ADR-0005's gateway directory.
12. **Every established link carries a BFD session.** Per the data
    plane draft (Section 6.1): the node answers its peers' sessions
    and initiates its own, BFD control packets in the drafts' SCION
    framing carried on the one-hop path of each serving link. Silence
    past the session's window marks the link down in both directions,
    and the session keeps running while the link is down, which is how
    recovery is seen. The session's own timers — the transmission
    interval and the detect multiplier — are the link's liveness
    constants.
13. **The verdict is reversible runtime state within a generation.**
    A link the session marks down stops forwarding at once: the data
    plane drops traffic destined to it and answers sources with the
    rate-limited SCMP interface-down signal (Section 6.2), beaconing
    pauses on the interface, and the floor counts the link out — a
    down link is no redundancy, so sustained down state meets
    retirement once the guards are past. Answers returning mark the
    link up again: a state flip and its notification, with the
    interface ID, the link addresses, and the serving generation all
    intact. Both edges are hysteresed, so a lossy link settles rather
    than flaps. A source that receives the interface-down signal sets
    aside paths crossing that interface for a short window — its own
    probes remain the authority and the received signal a prompt to
    re-probe, which is the drafts' own posture: notifications are
    optional and rate-limited, and endpoints detect failures by their
    own means.
14. **SCMP echo measures both sides of the comparator.** The direct
    side echoes over the one-hop path to each neighbor; the baseline
    echoes over the freshest resolved path to the same destination —
    one instrument read over two routes, each route chosen for the
    question it answers. The selection loop drives both at its own
    cadence, the ping machinery as an internal service, and the
    comparator reads the two round trips against each other.
    Measurement cadence belongs to the selector alone, free of the
    liveness timers.
15. **Membership changes ride generational replacement.** Interface
    IDs are allocated at establishment, unique among live links, and
    held back after retirement while unexpired segments elsewhere may
    reference them. Removal is graceful: the node withdraws beaconing
    from the link and expiration retires the segments (ADR-0004, which
    adds no revocation). The forwarding substrate's configuration is
    immutable while serving: a data plane is built with a link set and
    serves until retired, a topology change gracefully retires the
    serving instance and brings up its replacement, and each link's
    underlay address is part of the link's state, bound identically by
    every generation, so peers observe a brief pause while the control
    plane survives the replacement untouched. The up/down verdict of
    the preceding point is the one mutable edge — state the substrate
    reads at egress.
16. **Instruments split by owner.** Liveness is owed: the BFD sessions
    and the verdicts they feed run in the node core, for every serving
    link, whatever the topology application is doing — a neighbor's
    detection of the node depends on the node answering, which makes
    answering a service of the node itself. Measurement is chosen: the
    echo prober runs in the topology application beside the selection
    loop it feeds, at the cadence the loop wants.
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
    draws the boundary this split implies.
17. **Consent is the operator's, and the scope is chosen.** Appearing
    in paths requires signing one's own AS entries; accepting links
    and propagating beacons remain the operator's choices, and direct
    links reduce dependence on others' transit. Nodes behind address
    translation join but cannot be joined; their floor is met from
    publicly reachable candidates, and NAT traversal is out of scope.
    The comparison metric is utility against the candidate's tier.
    The constants — session timers, hysteresis margins, probe cadences,
    the negative-cache window, the tier gap — are code constants; two
    run arguments remain, and almost-zero-config stays almost.

### Positive consequences

*   Every instrument the drafts define, the node speaks as the drafts
    define it: liveness, failure signaling, and measurement behave on
    CION links as the specs describe SCION links behaving.
*   Liveness is independent of policy: detection and answering run for
    every serving link whatever the topology application does, so the
    forwarding plane keeps its failure detection through any
    application failure or absence.
*   One measurement instrument serves both of the comparator's inputs,
    over two routes chosen for the question, at a cadence the selector
    owns.
*   Health and membership move at two deliberate timescales — a verdict
    flip within a generation, a damped change across generations — so a
    flapping link costs a state flip and its notification, while the
    segment structure stays stable.
*   First contact is one exchange with three uses — acquaintance,
    candidate measurement, and a joiner's establishment — and
    everything after it rides authenticated channels.
*   Regional meshes joined by protected bridges are the equilibrium of
    local decisions: intra-region links retire first because their
    exclusion changes nothing, and bridges survive because theirs
    strands a tier.
*   Cuts heal within windows at the first node that sees a reachable
    member of the stranded tier — the stranded-tier promotion rides
    the rendezvous establishment that bypasses paths.
*   Promotion and retirement share one utility test, so displacement
    cannot evict a link the policy must immediately re-recruit, and
    the path database's hop identity informs policy through the walk
    the interface-down skip already makes — no new wire exchange and
    no new state.
*   Zero config is intact: tiers derive from measurements the loop
    already takes, and no constant becomes an argument.

### Negative consequences

*   Two periodic streams cross each established link — the liveness
    session and the measurement probes — with independent timers and
    constants.
*   BFD is protocol work new to the node: RFC 5880 control sessions in
    the drafts' SCION framing, with the drafts' SHOULD-level
    obligations on answering and initiating.
*   The candidate measurement and the neighbor measurement differ in
    carrier and target — an underlay round trip to the rendezvous
    address, then path-borne echoes to the link address — so admission
    rests on a proxy the established link's own measurements confirm or
    correct.
*   Liveness and measurement can disagree — a link may forward while
    its round trips disappoint — and each reading is honored for its
    own question: the verdict gates forwarding, the measurement gates
    membership.
*   The evaluation window does real work: clustering the sample map,
    resolving excluded baselines, comparing path link sets — bounded
    by the non-scalable-by-choice driver.
*   The excluded-baseline measurement adds probes per window, crossing
    the very links whose redundancy it questions.
*   The resilience guarantees are node-local: a coordinated two-sided
    retirement can still empty a cut for the windows the heal takes,
    and route counts see the graph, not the underlay.
*   Promotion decides on an estimate it can verify only after
    establishment, so a link whose measured utility disappoints costs
    its establishment and a damped retirement.

## Pros and cons of the options

### BFD per the drafts

*   Good, because it is the instrument the data plane draft prescribes
    for exactly this question, carried on the same one-hop paths the
    node already speaks, with failure semantics the SCMP machinery
    expects.
*   Good, because it runs beneath policy: a session exists for every
    serving link whatever the topology application chooses.
*   Bad, because it is a second periodic stream per link and a session
    state machine with timers of its own.
*   Bad, because BFD answers liveness alone; every utility-driven
    decision needs a measurement beside it.

### Liveness from measurement arrivals

*   Good, because one stream would answer both questions — arrival is
    liveness, round trip is latency.
*   Bad, because the measurement stream belongs to the selector, so its
    cadence and its failures become the forwarding plane's health
    signal — policy owns mechanism.
*   Bad, because the drafts already separate the two questions with two
    instruments, each with its own owner.

### Admission-time probing only

*   Good, because selection stays the only machinery, with no runtime
    state and no new constants.
*   Bad, because a link that dies after establishment stays a member
    until sustained evidence accumulates, and the floor counts it.
*   Bad, because the data plane forwards into a dead link with nothing
    watching it.

### SCMP echo over two routes

*   Good, because one drafts-native instrument measures both comparator
    inputs, and the path library already carries it as the ping
    machinery.
*   Good, because cadence and payload are the selector's alone.
*   Bad, because the direct side rides a one-hop path that exists only
    after establishment — candidates need a second carrier.

### A dedicated probe protocol

*   Good, because cadence, payload, and evolution are free of every
    other concern.
*   Bad, because it is a third periodic protocol crossing the link
    beside the drafts' two, saying what they already say.

### Liveness-protocol timestamps

*   Good, because the liveness stream already crosses the link every
    interval, and timestamps are small.
*   Bad, because measurement cadence is then pinned to the liveness
    timers, and the owed instrument carries the selector's payload.

### The rendezvous echo

*   Good, because it reaches where no path and no interface exist — the
    candidate's advertised address on the underlay — and doubles as the
    joiner's establishment.
*   Good, because the nonce-matched reply proves return routability of
    the address a link would bind toward.
*   Bad, because it measures a proxy — the rendezvous address rather
    than the link address — and it is unauthenticated until
    establishment rides the authenticated channels.

### Path-borne echo

*   Good, because it reuses the echo machinery end to end.
*   Bad, because a probe over the composed path measures the baseline
    against itself, and the comparison it exists to inform degenerates.

### Peer-relative latency

*   Good, because one destination, one ratio, one comparison is the
    smallest policy that earns links by measurement at all.
*   Good, because the baseline is a single echo over a single resolved
    path.
*   Bad, because the peer's own round trip is a proxy for the
    destinations that matter, and within a region the proxy is
    trivially beatable.
*   Bad, because ranking candidates and victims by raw round trip
    evicts the bridge first — the slowest link is often the only one.

### Marginal utility

*   Good, because it prices a link by what traffic beyond the peer
    experiences, which is the quantity the network actually serves.
*   Good, because promotion and retirement are the same test with
    hysteresis between the thresholds, and each corrects the other's
    estimation error.
*   Bad, because the exact delta is measurable only after the link
    exists, so admission rests on a tier-relative estimate.

### Coordinated cuts

*   Good, because global cut structure is the true object of the
    resilience question.
*   Bad, because it needs a coordinator and a topology description —
    the two things measured selection exists to be rid of.
*   Bad, because the coordinator is itself a partitioning failure mode.

### The floor alone

*   Good, because degree is local, cheap, and needs no path state.
*   Bad, because two links into one region satisfy it while every route
    to the rest of the network rides a single bridge.

### Route counts from the path database

*   Good, because edge-disjointness is fully determined by data the
    node already holds, verifies, and walks for another purpose.
*   Good, because ignorance errs toward over-protection — unseen
    segments undercount routes, never overcount them.
*   Bad, because the graph is not the underlay; shared fate below the
    link layer counts as redundancy.

### Operator-declared regions

*   Good, because the operator knows the deployment's geography and its
    failure domains.
*   Bad, because description replaces measurement — the posture this
    policy exists to hold.
*   Bad, because another run argument arrives and almost-zero-config
    stops being almost.

### No evidence

*   Good, because refusing to act on what it cannot compare is the
    conservative reading of a missing baseline.
*   Bad, because the absence of every route is the strongest comparison
    there is, and reading it as silence leaves an emptied cut unhealed.

### The slowest sample

*   Good, because the slowest link is the costliest beacon fan-out to
    keep, and the ranking needs no extra measurement.
*   Bad, because cost is not harm: the slowest link is often the only
    bridge, and nothing in the ranking asks.

### The least harm

*   Good, because eviction and retirement qualify the same neighbors,
    and the victim's exclusion is checked against the routes it
    carries.
*   Bad, because harm is measured on excluded baselines — more probes
    per window, and a wrong measurement protects a useless link one
    retirement-window longer.
