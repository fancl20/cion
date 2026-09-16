# Keep a Minimal Node Core and Move Everything Else to Apps

*   Status: proposed
*   Supersedes:
    [ADR-0007](/docs/adrs/0007-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
*   Date: 2026-09-16

[TOC]

## Context and problem statement

CION's node has grown by accretion: what began as ADR-0001's collapsed
data plane and control service gained trust bootstrap (ADR-0003),
beaconing (ADR-0004), an application seam (ADR-0005), a resident
WireGuard application (proposal 0006), and the topology machinery —
rendezvous first contact, an in-band link service, a node directory,
and a selection loop (proposal 0008). Each addition was wired where the
previous one had been wired, and the packages stopped naming their
contents: protocol subset, deployment policy, and connection glue in
one tree, a reviewer holding CION's choices and the drafts'
requirements in the same file, an operator replacing one and touching
the other, and the node assembly unable to run without every piece,
because nothing drew the line between what a node *is* and what a node
*does by choice*.

The seams for a cleaner answer already exist, each built by an earlier
decision: ADR-0005's application seam (`pkg/scion`) lets a process
become path-aware beside the control plane; proposal 0006 established
the resident application — its own keys, its own state, its own service
socket — as the shape of optional node functionality; proposal 0008
made the link store the single source of topology truth with a
generation supervisor that applies every change to it; and
[ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
split the link instruments by owner — liveness a service the node owes
its neighbors, measurement the selector's own tool. What is missing is
the decision those seams point at: an enumeration of the irreducible
node, a rule for what lives beside it as a shared library, and a rule
for what lives under an application.

This ADR decides that boundary.

## Decision drivers

*   **Almost-Zero Config:** The default node boots to a working,
    self-selecting topology with two arguments.
*   **Mechanism over Policy:** The node owns *how* a topology change is
    applied — the store, the generation swap, the stable link
    addresses — and applications own *which* changes are worth making.
*   **Reviewability:** The core reads as the SCION subset CION
    implements, reviewable against the drafts alone.
*   **Spec-Native Core:** Every protocol the core speaks is the
    drafts': forwarding and SCMP, BFD liveness, beaconing, the
    authenticated control channel and its service resolution.
*   **No New Trust Anchors:** The node's keys stay with the node;
    applications speak through the assembly's sockets and senders.
*   **Single Binary, One Node per AS:** Apps are loadable components of
    one process; the boundary is packaging and ownership.
*   **Operator Sovereignty:** An operator who wants a deliberate,
    static topology gets it as a policy choice, keeping the generated
    identity and state the rest of the node relies on.

## Considered options

How the boundary between the node and its optional machinery is drawn:

*   **Assembly Wiring:** Every capability is wired directly into the
    node assembly, its library parts living where they were first
    needed.
*   **Minimal Core, Shared Libraries, and Apps:** Enumerate the
    irreducible node; keep pure libraries shared by core and apps; move
    everything else under applications — the topology machinery
    becoming the default-loaded application, with a file-backed
    provider as the static alternative.
*   **External Plugin Process:** The topology decider runs as a
    separate process that writes a configuration the node watches and
    reloads.

## Decision outcome

Chosen option: **minimal core, shared libraries, and apps** — with the
boundary drawn by three tests:

> **If removing a capability still leaves a forwarding, beaconing,
> enrolling SCION AS, it is policy — and policy lives under an app. If
> two providers could implement it differently, it is policy — and
> policy lives under an app. And if the rest of the network depends on
> a node providing it whatever the node's own policy, it is core
> nonetheless — a service the node owes the network, not a choice it
> makes.**

The core is mechanism the drafts and the neighbors define; apps are
policy deployments choose; shared libraries are the vocabulary both
speak. Realized as follows:

1.  **The node core is enumerated, and frozen at that enumeration.** A
    CION node is, at minimum:
    *   the data plane (`pkg/dataplane`) — one immutable generation
        serving at a time, the per-link up/down state of ADR-0008, and
        the SCMP failure signaling its egress check originates;
    *   the link store and the generation supervisor that apply a
        topology to it;
    *   the BFD sessions on every serving link and the health monitor
        that reduces their arrivals to ADR-0008's verdicts — liveness
        owed by every node however its topology is decided, feeding the
        data plane's link state and the beaconer's interface pauses;
    *   the SCMP echo responder, answering every peer that baselines
        against the node;
    *   the SCION-native control endpoint — HTTP/3 over QUIC over
        SCION paths, peers authenticated by their chains against the
        TRC — serving the drafts' services: segment creation,
        registration, and lookup, trust material and chain renewal, and
        the enrollment lifecycle. Peer control endpoints resolve
        through the drafts' service discovery (control plane draft,
        Section 5) — a service-resolution request to the peer's control
        service address, carried on a one-hop path — and the ISD core
        is reached the same way, over the reversed up segment beaconing
        supplies, addressed to the core's control service;
    *   the beaconing loops of ADR-0004.

    `pkg/controlplane` holds exactly this enumeration.
2.  **Shared libraries serve core and apps alike, run no loops of their
    own, and hold no policy.** These are `pkg/scion` — the connection,
    address, and path provider of ADR-0005's application seam;
    `pkg/links` — the neighbor table as the single source of topology
    truth, holding the identity facts whichever provider learns:
    neighbor ISD-AS, interface IDs, link and rendezvous addresses; the
    peer-identity middleware of the SCION-native channel; and the trust
    and path databases. The moment one of these grows a policy decision
    or a lifetime loop, it has become an app and must move.
3.  **The topology machinery of ADR-0008 is an application — the
    measured provider — loaded by default.** The rendezvous acceptor,
    the joiner's dials, the node directory, the in-band link service,
    the selection loop, and the SCMP echo prober that measures its
    direct sides and baselines compose the topology application from
    the same libraries. The acceptor carries its admission policy with
    it, which is where that policy belongs: that strangers may dial the
    socket is mechanism, who may dial it is policy. Neighbor identity
    lands in the store, written by whichever provider establishes the
    link, and the beaconer reads it there. Loading the measured
    provider is what makes a node zero-conf, and it is the default
    because almost-zero-config is the founding claim.
4.  **A file provider is the static alternative, and providers are
    exclusive.** It reads a link-set file — neighbor ISD-AS, underlay
    addresses, optional interface ID — and reconciles it into the
    store: named entries are established, the operator vouching for
    them as configured interfaces once did; entries absent from the
    file retire. The file carries links alone — identity, keys, and
    bind addresses stay with the node — a policy artifact for
    deliberate deployments: labs, CI rigs, reproducible tests. A node
    runs exactly one provider, because two deciders writing the same
    entries is flapping by construction. Exclusivity is per node, under
    the operating assumption that one operator runs an ISD, so provider
    choice is uniform within it; cross-ISD provider mixing is deferred
    with the cross-ISD questions.
5.  **Identity completion is provider-aware.** A first start's ISD is
    a provisional draw; the measured provider completes it with the
    network's from a rendezvous reply, the file provider from a
    neighbor's ISD-AS in the file. Both paths keep `ia` literals out of
    every file.
6.  **Apps expose their services through the assembly, by the two
    mechanisms the node already has.** Control services mount on the
    endpoint's mux as interfaces — the link and directory services when
    the measured provider loads, mounting none when it does not.
    Data-plane services keep sockets of their own: an app binds its
    SCION socket and registers it as a service with the assembly, which
    re-registers it with every data-plane generation — the pattern the
    WireGuard application's mesh socket already follows. Apps that
    speak per-link — the echo prober's one-hop paths — send through
    assembly-provided senders, so the node's keys stay with the node.
    The dependency direction is one-way: apps import the core and the
    shared libraries.

### Positive consequences

*   The core is the SCION subset CION implements: a reviewer holds the
    drafts beside it and the whole core at once, and every protocol a
    serving link carries from the core — forwarding, SCMP, BFD,
    beaconing, the control channel — is the drafts' own.
*   Liveness, forwarding, and the drafts' services run whatever the
    topology policy: an application that fails or is declined degrades
    the node locally, and the node keeps answering its neighbors.
*   Topology policy is swappable without touching the node: the
    measured provider and the file provider are two implementations of
    one seam, and a third — an operator's own — needs no core change to
    exist.
*   Static topologies are a first-class choice for deliberate
    deployments, with the store and the generation swap applying a file
    exactly as they apply a measurement.
*   Applications gain a clear contract — land decisions in the store,
    register services through the assembly, hold your own keys and
    state — that the WireGuard application already satisfies and new
    ones can follow from day one.
*   The minimal core is small enough to stabilize: its churn is the
    drafts' churn.

### Negative consequences

*   The default node still loads the measured provider, so "minimal" is
    a property of the packaging and the review surface, and the default
    footprint carries the full topology machinery.
*   The liveness and measurement carriers on the wire arrive with
    ADR-0008, so a running network upgrades its peers together — a
    coordinated step.
*   Provider interfaces and two more packages to keep coherent, and a
    refactor of just-landed code to get there.
*   The exclusivity rule holds a node to one provider; an operator
    wanting one pinned link beside measured ones gets a policy the
    providers do not express yet.
*   In-process apps share the node's supervision: a panicking or exited
    app loop is absorbed and logged — the node serves on, degraded —
    and nothing restarts it.
*   The seams are conventions as much as types: review is what keeps a
    future capability from being wired into the core and re-blurring
    the boundary this ADR draws.

## Pros and cons of the options

### Assembly wiring (status quo)

*   Good, because it is already built, tested, and working, and a node
    that always runs everything needs no loading logic.
*   Bad, because the packages name nothing: the drafts' services and
    CION's policy sit together, and the tree cannot say which is which.
*   Bad, because policy is welded to mechanism: replacing a heuristic
    means touching the node assembly, and a deliberate static topology
    has no expression at all.

### Minimal core, shared libraries, and apps

*   Good, because the boundary follows a rule — mechanism versus
    policy, owed versus chosen — rather than where the last contributor
    happened to be working.
*   Good, because it inherits the joints earlier decisions built: the
    application seam, the resident application, the store with its
    supervisor, and ADR-0008's ownership split.
*   Good, because the file provider restores deliberate topologies as a
    policy artifact, with the identity and secrets staying generated
    and local.
*   Bad, because it costs a refactor of working code, an interface to
    document, and — with ADR-0008's carriers — a coordinated wire
    upgrade for a running network.

### External plugin process

*   Good, because process isolation contains a crashing decider and
    allows an independent release cadence.
*   Bad, because it re-imports a serialized topology artifact as the
    interface, a watcher and a reload path beside the store's
    notifications, and two sources of truth that can diverge.
*   Bad, because it draws a new trust boundary: the decider must either
    hold the node's keys — becoming the node — or command it through an
    authorization the architecture has no anchor for.
*   Bad, because the decider's probes ride the node's own sockets — BFD
    on the link's own underlay, echo on one-hop paths MACed with the
    forwarding key — so an external prober needs a second SCION stack
    beside the first.
