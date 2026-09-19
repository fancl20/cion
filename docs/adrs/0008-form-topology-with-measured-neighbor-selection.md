# Form the Topology with Measured Neighbor Selection

*   Status: accepted
*   Supersedes:
    [ADR-0006](/docs/adrs/0006-form-topology-with-measured-neighbor-selection.md)
*   Date: 2026-09-16

[TOC]

## Context and problem statement

A CION node owns its link set. The underlay is UDP/IP, so a link is a
connected socket pair the node chooses, and every reachable,
directory-listed peer is a candidate for one. Owning the link set means
continuously answering three questions. Whether each established link
is alive — the question the network's forwarding rests on, asked every
interval of every link. Whether each link is worth having — the
comparator's question, a direct round trip measured against the
composed paths to the same destination. And whether a candidate would
be worth establishing — the comparator's question asked of a peer no
path and no interface reach yet. It also means the policy that turns
those answers into topology: joining the network, learning candidates,
admitting links bilaterally, selecting with a resilience floor, and
applying changes to a forwarding plane built to serve immutable
generations.

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

This ADR consolidates the topology design: the formation policy —
measured selection with a redundancy floor, joining with two
arguments, a core-served directory, generated local state, generational
replacement — and the instruments that feed it, drawn from the drafts
wherever the drafts define one. The ownership of those instruments —
what the node owes its neighbors, what its policy chooses for itself —
is the companion decision of
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md).

## Decision drivers

*   **Almost-Zero Config:** Joining is an act of the joining node: two
    run arguments and generated local state, with topology description
    and secret material kept out of every file.
*   **Resilience by Construction:** Redundancy is an invariant the node
    maintains itself; no single neighbor failure partitions a node that
    can help it.
*   **Measurement over Description:** Links are earned by evidence —
    the posture beaconing took for paths, applied to the topology
    itself.
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
    scale — probing candidates, directory fan-out from a core — are in
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

The formation policy frame — measured selection with a redundancy
floor, one bootstrap neighbor argument, a core-served directory,
generated local state, the WebPKI domain argument, a self-picked
enrollment-gated ISD-AS, and generational replacement — stands as
decided; the option analysis that chose it is the record of the
superseded ADR.

## Decision outcome

Chosen options: **BFD per the drafts** for liveness, **SCMP echo over
two routes** for measurement, and **the rendezvous echo** for
candidates, over the standing formation policy — realized as follows:

1.  **The link set is the node's own decision, continuously revised.**
    Every directory-listed, reachable peer is a candidate. The node
    keeps a direct link when it is meaningfully faster than the
    composed paths to the same destination, always retains at least two
    neighbors so a single failure leaves it connected, caps its link
    count to bound beaconing fan-out, and changes links only on
    sustained evidence — every link change reshapes segments
    network-wide, so stability trades against optimality deliberately.
    The comparator measures every peer every evaluation window —
    neighbor, candidate, and demoted neighbor alike — so a peer whose
    direct round trip durably beats its baseline is proposed again
    however often it was demoted before, and the floor and the cap
    bound the set at every instant. Link roles still emerge from beacon
    flow (ADR-0004).
2.  **Joining takes two arguments, and identity is generated local
    state.** A joiner is given one existing node's underlay address and
    the core's domain: the address seeds the first link, the domain
    authenticates the enrollment and the TRC fetch over the WebPKI
    bootstrap channel — a joiner cannot otherwise know which domain is
    correct, so the domain is an argument for core and non-core alike.
    The founding core takes its domain alone; a restarting node takes
    neither, identity coming from local state and neighbors from the
    running network. The node's ISD-AS, forwarding key, and AS keys are
    created on first start and persisted with the trust material; the
    ISD-AS is self-picked from the private ranges, and enrollment is
    the gatekeeper that rejects collisions and strangers.
3.  **First contact is the rendezvous exchange, and the rendezvous
    exchange is the candidate probe.** Every node listens on its
    advertised rendezvous address. The exchange is a plain underlay
    round trip — a nonce-bearing request, a matching reply — beneath
    SCION, bounded by return-routability checks and admission limits,
    with admission policy the acceptor's: open within those limits by
    default, restrictable to allowlisted ISD-ASes. For a joiner with no
    composed path the exchange is also the establishment, seeding the
    link store entry; for the selection loop it is the candidate
    measurement — the direct round trip to the peer's public address,
    taken where no path and no interface exist, which is what makes it
    an honest measurement of the hypothetical link rather than of the
    paths it would compete with. Everything after first contact rides
    authenticated channels.
4.  **A core-served directory informs selection.** Once enrolled, each
    node publishes its ISD-AS, control and rendezvous addresses, and a
    reachability class over its own channel, authenticated by its
    TRC-anchored chain; the core aggregates and serves the directory,
    and entries expire without refresh. The core is the rendezvous,
    never the authority over what is true — the trust and availability
    posture of enrollment and ADR-0005's gateway directory.
5.  **Every established link carries a BFD session.** Per the data
    plane draft (Section 6.1): the node answers its peers' sessions and
    initiates its own, BFD control packets in the drafts' SCION framing
    carried on the one-hop path of each serving link. Silence past the
    session's window marks the link down in both directions, and the
    session keeps running while the link is down, which is how recovery
    is seen. The session's own timers — the transmission interval and
    the detect multiplier — are the link's liveness constants.
6.  **The verdict is reversible runtime state within a generation.** A
    link the session marks down stops forwarding at once: the data
    plane drops traffic destined to it and answers sources with the
    rate-limited SCMP interface-down signal (Section 6.2), beaconing
    pauses on the interface, and the redundancy floor counts the link
    out — sustained down state meets selection exactly as the loop
    treats an infinitely slow neighbor. Answers returning mark the link
    up again: a state flip and its notification, with the interface ID,
    the link addresses, and the serving generation all intact. Both
    edges are hysteresed, so a lossy link settles rather than flaps. A
    source that receives the interface-down signal sets aside paths
    crossing that interface for a short window — its own probes remain
    the authority and the received signal a prompt to re-probe, which
    is the drafts' own posture: notifications are optional and
    rate-limited, and endpoints detect failures by their own means.
7.  **SCMP echo measures both sides of the comparator.** The direct
    side echoes over the one-hop path to each neighbor; the baseline
    echoes over the freshest resolved path to the same destination —
    one instrument read over two routes, each route chosen for the
    question it answers. The selection loop drives both at its own
    cadence, the ping machinery as an internal service, and the
    comparator reads the two round trips against each other.
    Measurement cadence belongs to the selector alone, free of the
    liveness timers.
8.  **Membership changes ride generational replacement.** Interface
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
    the preceding points is the one mutable edge — state the substrate
    reads at egress.
9.  **Instruments split by owner.** Liveness is owed: the BFD sessions
    and the verdicts they feed run in the node core, for every serving
    link, whatever the topology application is doing — a neighbor's
    detection of the node depends on the node answering, which makes
    answering a service of the node itself. Measurement is chosen: the
    echo prober runs in the topology application beside the selection
    loop it feeds, at the cadence the loop wants.
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
    draws the boundary this split implies.
10. **Consent is the operator's, and the scope is chosen.** Appearing
    in paths requires signing one's own AS entries; accepting links and
    propagating beacons remain the operator's choices, and direct links
    reduce dependence on others' transit. Nodes behind address
    translation join but cannot be joined; their redundancy floor is
    met from publicly reachable candidates, which the reachability
    class identifies, and NAT traversal is out of scope. The comparison
    metric is latency to the candidate. The constants — session timers,
    hysteresis margins, probe cadences, the negative-cache window — are
    code constants; two run arguments remain, and almost-zero-config
    stays almost.

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
*   Bad, because BFD answers liveness alone; every latency-driven
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
