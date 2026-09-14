# Form the Topology with Measured Neighbor Selection

*   Status: proposed
*   Date: 2026-09-14

[TOC]

## Context and problem statement

CION presents itself as "almost zero config", yet every node carries a
configuration file whose heart is hand-written topology: the interface list
names each neighbor's underlay address and ISD-AS, paired manually on both
endpoints, beside the node's own ISD-AS and forwarding key written as literals.
Adding or removing a neighbor is a coordinated edit and restart on both sides,
and the topology is frozen between restarts. Nothing maintains connectivity
resilience either: a node whose only neighbor fails is partitioned until an
operator intervenes.

The rest of the system no longer needs the file. Discovery greetings already
learn neighbors and relay the core's endpoint; link roles emerge from beacon
flow rather than configuration
([ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md));
paths are discovered, verified, and composed without topology input; and
[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md) already
moved application secrets out of the configuration file. What remains static is
the link set itself — and it is static in name only: the underlay is UDP/IP, so
an interface is a connected socket to a chosen peer, not a physical fact. Every
pair of reachable nodes is a potential direct link; the interface list is a
topology policy an operator maintains by hand, when the node is the party that
can measure which links are worth having.

This ADR decides how the link set comes to exist and persist: how a node joins,
how nodes learn of candidate peers, how links are established and admitted, how
a node decides which to keep, and what remains of configuration when the file
is gone.

## Decision drivers

*   **Almost-Zero Config:** The README's founding claim. Joining must be an act
    of the joining node, not a coordination ceremony across operators; no
    topology description, and no secret material, in any file.
*   **Resilience by Construction:** No single node failure may disconnect a
    node from the network; redundancy must be an invariant the node maintains
    itself, not a property operators plan for.
*   **Operator Sovereignty:** Which links a node accepts and whose traffic it
    transits remain the operator's decisions, visible and restrictable; a node
    appears in paths only through AS entries it signed (ADR-0004).
*   **Measurement over Description:** The network already discovers paths and
    measures nothing but them; topology should follow the same principle —
    links earned by evidence, not declared.
*   **Trust Continuity:** No new trust anchors. The WebPKI bootstrap channel,
    TRC-anchored chains, and authenticated control channels stay exactly as
    they are.
*   **Single Binary, One Node per AS:** One process owns its links; no
    provisioning service exists or is wanted.
*   **Non-Scalable by Choice:** Mechanisms acceptable only at CION's target
    scale — probing candidates, directory fan-out from a core — are in bounds.

## Considered options

How the neighbor set is determined:

*   **Configured Interfaces:** Today's interface list, edited and restarted on
    both endpoints.
*   **Full Mesh:** Every node establishes a direct link to every other node.
*   **Measured Selection with a Redundancy Floor:** Each node continuously
    selects neighbors by comparing direct links against its composed paths,
    keeping at least two.
*   **Core-Assigned Topology:** The core computes and assigns each node's
    neighbors.

How a node joins the network:

*   **Neighbor List in a File:** Today's arrangement.
*   **One Bootstrap Neighbor Argument:** The joining node is given a single
    existing node's underlay address at start.

How nodes learn of candidate peers:

*   **Core-Served Directory:** Nodes publish their addresses to the core, which
    serves the directory to every node.
*   **Peer Gossip:** Nodes relay peer information among themselves.
*   **Greeting Relay Only:** No new mechanism; peers are learned only from
    what neighbors choose to relay.

How identity and secrets originate:

*   **Configuration Literals:** The ISD-AS and forwarding key written in the
    file, as today.
*   **Generated Local State:** Created on first start, persisted beside the
    trust material, stable across restarts.

How the first trust exchange is authenticated:

*   **WebPKI Domain Argument:** The joining node is given the core's domain,
    authenticating the enrollment and TRC fetch against the WebPKI channel as
    today.
*   **Trust on First Use:** The joining node pins the core's certificate or TRC
    fingerprint on first contact and verifies it out of band later.

How a new ISD-AS is chosen:

*   **Self-Picked, Enrollment-Gated:** The node picks its own ISD-AS from the
    private ranges; enrollment is the gatekeeper that rejects collisions and
    strangers.
*   **Core-Assigned:** The core allocates the ISD-AS during enrollment.

How a link change reaches the data plane:

*   **Live Mutation:** Links are added to and removed from the serving data
    plane.
*   **Generational Replacement:** The serving data plane is gracefully
    retired and replaced by one built with the new link set.

## Decision outcome

Chosen options: **measured selection with a redundancy floor**, **one
bootstrap neighbor argument**, a **core-served directory**, **generated local
state**, the **WebPKI domain argument**, a **self-picked, enrollment-gated
ISD-AS**, and **generational replacement** of the data plane on link changes —
realized as follows:

1.  **The link set is the node's own decision, continuously revised.** An
    interface is an overlay edge the node chooses, not a physical fact; every
    directory-listed, reachable peer is a candidate. The node adds, retains,
    and removes links based on measured benefit and a resilience invariant.
    Link roles still emerge from beacon flow (ADR-0004); what becomes dynamic
    is the membership of the link set.
2.  **Generated local state replaces the configuration file.** The node's
    ISD-AS, forwarding key, and AS keys are created on first start and
    persisted with the trust material; bind addresses and the state directory
    are run arguments with defaults. The forwarding key needs no coordination:
    each AS MACs its own hop fields, so the key never leaves the node —
    ADR-0005's "no secrets in the configuration file" applied to the last
    remaining one.
3.  **Joining takes two things: a neighbor's underlay address and the core's
    domain.** The address seeds the first link; the domain authenticates the
    enrollment and TRC fetch over the unchanged WebPKI bootstrap channel — a
    joiner cannot otherwise know which domain is correct, so the domain is an
    argument for core and non-core alike. The founding core takes its domain
    alone; the domain names its ACME-managed certificate, with certificate
    files remaining the offline fallback. A restarting node takes neither:
    identity comes from local state and neighbors from the running network.
4.  **Links are established bilaterally and admitted by policy.** A link exists
    only by agreement of both endpoints, each allocating its own interface ID.
    Between nodes that composed paths already reach, the request rides the
    mutually authenticated control channel. For first contact, every node
    listens for rendezvous on its advertised underlay address, bounded by
    return-routability checks and admission limits. Admission policy is the
    acceptor's: open within those limits by default, restrictable to
    allowlisted ISD-ASes — the successor of the enrollment allowlist. The
    joiner's first rendezvous is the only unauthenticated exchange in the
    system; everything after it rides authenticated channels.
5.  **A core-served node directory informs selection.** Once enrolled, each
    node publishes its ISD-AS, control and rendezvous addresses, and a
    reachability class over its own channel, authenticated by its TRC-anchored
    chain; the core aggregates and serves the directory, and entries expire
    without refresh. The directory shares the trust and availability posture
    of enrollment and ADR-0005's gateway directory: the core is the
    rendezvous, never the authority over what is true.
6.  **Selection is measurement with a redundancy floor and damping.** A node
    probes a candidate link before committing to it and keeps a direct link
    when it is meaningfully faster than the composed paths to the same
    destination. It always retains at least two neighbors, so no single node
    failure partitions it; below that floor, reachability outranks latency and
    any reachable candidate will do. It caps its link count to bound beaconing
    fan-out, and it changes links only on sustained evidence — every link
    change re-shapes segments network-wide, so stability is traded against
    optimality deliberately.
7.  **Interfaces are runtime state over generational data planes.** Interface
    IDs are allocated at establishment, unique among live links, and not
    reused while unexpired segments elsewhere may still reference them.
    Removal is graceful: the node withdraws beaconing from the link and
    expiration retires the segments — no revocation exists or is added
    (ADR-0004). The forwarding substrate itself is never mutated: a data
    plane is built with an immutable link set and serves until retired, and a
    topology change gracefully retires the serving instance and brings up
    its replacement with the new link set. Each link's underlay address is
    part of the link's state and is bound identically by every generation,
    so peers observe a brief pause rather than a re-acquaintance, and the
    control plane — trust, beaconing, connections — survives the replacement
    untouched. The data plane is asked for nothing new beyond the graceful
    shutdown.
8.  **Consent is unchanged.** Appearing in paths still requires signing one's
    own AS entries; accepting links and propagating beacons remain the
    operator's choices, and direct links reduce dependence on others' transit.
    The selection heuristic itself depends on multi-hop paths existing — on
    some transit consent in the network — which is the same posture
    ADR-0004 took.
9.  **Scope boundaries.** Nodes behind address translation join but cannot be
    joined; their redundancy floor is met from publicly reachable candidates,
    which the reachability class identifies. NAT traversal is out of scope.
    The comparison metric is latency to the candidate; richer benefit models
    are deferred with the policy work ADR-0004 already deferred. Two run
    arguments remain — "almost" zero config stays almost.

### Positive consequences

*   Joining is node-local: one address, one domain, no coordination with any
    other operator, and a topology change replaces a data plane generation,
    not the node.
*   Single-node failure never partitions a node that can help it: the floor
    drives re-selection on its own, the same self-maintaining posture as the
    chain lifecycle.
*   Topology follows experience — shortcut links appear where multi-hop
    detours cost, and detours retire when direct links win — growing path
    diversity where it pays, which is ADR-0001's founding driver.
*   The configuration file disappears entirely, taking its secret material
    with it; identity is generated where it is used and persisted where the
    trust material already lives.
*   No new trust anchors: admission builds on enrollment, the directory on
    the existing authenticated channels, and the first contact on the same
    WebPKI-anchored fetch as today.
*   The forwarding substrate never mutates while serving: topology change
    becomes the retirement and replacement of a component whose lifecycle is
    already build, serve, and discard — the ordinary startup path, exercised
    at every node start and reusable for recovering a wedged data plane.
*   The directory removes the last reason operators exchange addressing
    information by hand, extending what ADR-0005's gateway directory began.

### Negative consequences

*   Every topology change restarts the forwarding substrate: a bounded loss
    burst while the serving data plane retires and its replacement binds —
    borne by all traffic, not only the change that caused it — per-link
    counters reset with each generation, and a replacement supervisor is new
    lifecycle code to get right.
*   Link changes propagate as network-wide segment churn; damping means
    suboptimal links persist by design, and the floor can keep a link no
    measurement would justify.
*   First-contact admission is unauthenticated at the underlay, bounded by
    rendezvous limits and the requirement that candidates enroll within a
    window; operator curation of neighbor identity gives way to admission
    policy.
*   The directory deepens the core's centrality — already accepted for trust
    and issuance, now extended to peer awareness.
*   Recovery from neighbor loss is bounded by greeting timeout and segment
    expiry, not revoked; stale segments can attract traffic to a withdrawn
    link until they age out.
*   Nodes behind NAT cannot serve as a redundancy floor for each other, and
    zero config is approached, not reached: two arguments and the core's
    public TCP ports for ACME remain.

## Pros and cons of the options

### Configured interfaces

*   Good, because the topology is exactly what the operator wrote — no
    surprises, no measurement, immediate determinism.
*   Good, because neighbor identity is curated by both endpoints before any
    packet flows.
*   Bad, because every membership change is a coordinated edit and restart on
    two machines — the ceremony CION exists to avoid.
*   Bad, because the file carries secret material and duplicates state the
    trust database already owns.

### Full mesh

*   Good, because every pair speaks directly: minimum latency, maximum path
    diversity, and no selection logic at all.
*   Good, because resilience is trivial — losing any one neighbor changes
    nothing.
*   Bad, because link count grows with the square of the network while
    beaconing fan-out grows with it — unacceptable beyond a handful of
    operators, and CION is non-scalable by choice, not by accident.
*   Bad, because it maximizes transit surface for traffic that never needed a
    direct link, working against sovereignty rather than for it.

### Measured selection with a redundancy floor

*   Good, because links exist where measurement justifies them: the same
    evidence-driven posture as beaconing, applied to the topology itself.
*   Good, because the floor makes single-failure resilience an invariant the
    node maintains, not an outcome operators plan for.
*   Good, because joining and healing are node-local acts; no coordination
    crosses operator boundaries.
*   Bad, because selection, probing, and damping are new control-plane
    machinery with tuning knobs that must remain constants.
*   Bad, because link changes must land on a running node — as replacement
    bursts or live changes — which is why the selection is damped.

### Core-assigned topology

*   Good, because one planner sees the whole graph and could optimize
    globally.
*   Bad, because the core becomes the routing authority, contradicting the
    decentralized control ADR-0001 adopted and concentrating what ADR-0003
    already accepted for trust into perpetual topology control.
*   Bad, because every membership change funnels through the core — the same
    single point, now on the growth path of the network.

### Neighbor list in a file

*   Good, because it needs no protocol at all.
*   Bad, because it is the status quo this ADR retires: paired edits,
    restarts, and frozen topology.

### One bootstrap neighbor argument

*   Good, because a single address is the least a joiner can be given and the
    least an operator can hand over; everything else the node learns.
*   Good, because it degrades gracefully — any existing node can serve as the
    entry point, not just the core.
*   Bad, because the given node must accept a first contact it did not
    initiate, from a peer it cannot yet authenticate.

### Core-served directory

*   Good, because it reuses the trust and availability posture of enrollment
    and the gateway directory: authenticated publishing, core as rendezvous.
*   Good, because a new node becomes visible to everyone through one
    publish — no peer-to-peer consistency to design.
*   Bad, because the core's centrality extends to peer awareness, and the
    directory is only as fresh as its refresh cadence.

### Peer gossip

*   Good, because topology view survives core unavailability and needs no
    rendezvous point.
*   Bad, because it is a new consistency protocol — propagation, expiry,
    convergence — for a network whose trust already anchors at the core.
*   Bad, because unauthenticated strangers cannot be told from stale entries
    without re-deriving what the directory gets from enrollment for free.

### Greeting relay only

*   Good, because it invents nothing; greetings already carry endpoint
    addresses.
*   Bad, because greetings travel only on existing links: a node can never
    learn of a peer it does not already neighbor, which is precisely the
    information selection needs.

### Configuration literals

*   Good, because the identity is chosen deliberately and visible in one
    place.
*   Bad, because secrets in a configuration file are ADR-0005's rejected
    pattern, and ISD-AS literals collide only at runtime anyway.

### Generated local state

*   Good, because identity originates where it is used, survives restarts
    through the same persistence as the trust material, and never transits a
    file an operator might commit.
*   Bad, because a wiped state directory means a new identity — the node's
    old ISD-AS departs the network with its keys.

### WebPKI domain argument

*   Good, because it changes nothing about trust: the bootstrap channel, the
    ACME-managed certificate, and the authenticated fetch of the TRC work as
    they already do.
*   Good, because the domain is a TLS identity the joiner must be told
    regardless — no derivation or guesswork could make it trustworthy.
*   Bad, because the core needs a real domain and public TCP ports for the
    challenges; offline deployments fall back to certificate files.

### Trust on first use

*   Good, because it asks for no domain at all: a fingerprint pinned at first
    contact suffices.
*   Bad, because the first contact is then exactly the moment an impostor is
    cheapest — the joiner has no anchor yet — and the operator's out-of-band
    verification becomes an unenforced habit.
*   Bad, because it introduces a second trust model beside the WebPKI channel
    the architecture already commits to.

### Self-picked, enrollment-gated ISD-AS

*   Good, because it keeps allocation decentralized — the node names itself,
    and the network's certificate authority is the collision and admission
    gate, the same gate enrollment already staffs.
*   Good, because it matches the CSR pattern: keys and identity originate
    with the requester, never issued from the center.
*   Bad, because a colliding or squatting pick is only rejected at enrollment,
    and the private ranges are large enough that a retry is cheap but not
    impossible to need.

### Core-assigned ISD-AS

*   Good, because allocation cannot collide by construction.
*   Bad, because it makes the core the naming authority — one more authority
    beside issuance, against the grain of the CSR-based enrollment design.
*   Bad, because the assignment must survive restarts and re-enrollment as
    state the core owns, complicating recovery from exactly the failures the
    redundancy floor exists for.

### Live mutation

*   Good, because only the affected link changes; every other link's traffic
    continues without pause.
*   Good, because changes take effect with no loss window at all.
*   Bad, because forwarding state becomes mutable on the serving path — a new
    concurrency surface in the component whose correctness matters most, and
    against the grain of a data plane that today refuses modification of a
    running instance outright.
*   Bad, because the underlay must learn to admit and retire connections
    while serving, a capability nothing else has ever asked of it.

### Generational replacement

*   Good, because forwarding state stays immutable: the data plane keeps its
    build-serve-discard lifecycle, and the mutable topology state lives
    entirely in the control plane, off the forwarding path.
*   Good, because the replacement path is the ordinary startup path — what
    every node start exercises — and the same mechanism later recovers a
    wedged data plane for free.
*   Good, because the data plane is asked for nothing but the graceful
    shutdown it should already owe any operator.
*   Bad, because every change restarts every link, not only the changed one:
    all traffic bears a brief loss burst for a single topology decision.
*   Bad, because link addresses must stay stable across generations for peers
    not to re-acquaint, and per-generation counters are lost unless carried.
