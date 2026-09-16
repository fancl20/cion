# Keep a Minimal Node Core and Move Everything Else to Apps

*   Status: superseded by
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
*   Date: 2026-09-16

[TOC]

## Context and problem statement

CION's node has grown the way successful nodes do: by accretion. What
began as [ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md)'s
collapsed data plane and control service gained trust bootstrap
([ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md)),
beaconing
([ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)),
an application seam
([ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md)),
a resident WireGuard application
([proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md)),
and most recently the topology machinery of
[ADR-0006](/docs/adrs/0006-form-topology-with-measured-neighbor-selection.md)
— rendezvous first contact, an in-band link service, a node directory,
and a selection loop
([proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md)).
Each addition was wired where the previous one had been wired: into the
node assembly and, for its library parts, into `pkg/controlplane`.

The result is a package that no longer names one thing. `pkg/controlplane`
holds the SCION-native channel and the drafts' services — segment
creation, registration, and lookup, trust material, chain renewal —
beside beaconing and enrollment, beside CION's own discovery greetings,
and beside the whole of the measured-selection machinery, none of which
is a SCION concept at all. A reader cannot tell from the tree which
parts are the protocol subset CION reimplements and which are CION's own
policy layered on top of it; an operator cannot replace one without
touching the other; and the node assembly cannot run without every
piece, because nothing draws the line between what a node *is* and what
a node *does by choice*.

The seams for a cleaner answer already exist, each built by an earlier
decision: ADR-0005's application seam (`pkg/scion`) lets a process
become path-aware without the control plane; proposal 0006 established
the resident application — its own keys, its own state, its own service
socket — as the shape of optional node functionality; and proposal 0008
made the link store the single source of topology truth with a
generation supervisor that applies every change to it. What is missing
is the decision those seams point at: an enumeration of the irreducible
node, a rule for what lives beside it as a shared library, and a rule
for what lives under an application.

This ADR decides that boundary.

## Decision drivers

*   **Almost-Zero Config:** the default node boots to a working,
    self-selecting topology with two arguments. No reorganization may
    make the default experience worse than that.
*   **Mechanism over Policy:** the node should own *how* a topology
    change is applied — the store, the generation swap, the stable link
    addresses — and nothing about *which* links are worth having. Policy
    that can differ between deployments is policy that can be swapped.
*   **Reviewability:** `pkg/controlplane` should read as the SCION
    subset CION implements plus its greeting glue, and nothing more; a
    reviewer of the core should not need to hold CION's topology policy
    in their head.
*   **No New Trust Anchors:** nothing in the split may move the node's
    keys across a boundary or introduce a second authority over the
    node's decisions.
*   **Single Binary, One Node per AS:** apps are loadable components of
    one process, not separately deployed services; the boundary is
    packaging and ownership, not process topology.
*   **Operator Sovereignty:** an operator who wants a deliberate,
    static topology — a lab, a CI rig, a reproducible test — should get
    it as a policy choice, without giving up the generated identity and
    state the rest of the node relies on.

## Considered options

How the boundary between the node and its optional machinery is drawn:

*   **Assembly Wiring (Status Quo):** every capability is wired directly
    into the node assembly and its library parts live where they were
    first needed, `pkg/controlplane` foremost.
*   **Minimal Core, Shared Libraries, and Apps:** enumerate the
    irreducible node; keep pure libraries shared by core and apps; move
    everything else under applications — the topology machinery
    becoming the default-loaded application, with a file-backed provider
    as the static alternative.
*   **External Plugin Process:** the topology decider runs as a separate
    process that writes a configuration the node watches and reloads.

## Decision outcome

Chosen option: **minimal core, shared libraries, and apps** — with the
boundary drawn by three tests:

> **If removing a capability still leaves a forwarding, beaconing,
> enrolling SCION AS, it is not core. If two providers could implement
> it differently, it is policy — and policy lives under an app. And if
> the rest of the network depends on a node providing it whatever the
> node's own policy, it is core nonetheless — a service the node owes
> the network, not a choice it makes.**

The core is mechanism; apps are policy; shared libraries are the
vocabulary both speak. Realized as follows:

1.  **The node core is enumerated, and frozen at that enumeration.** A
    CION node is, at minimum: the data plane (`pkg/dataplane`) — one
    immutable generation serving at a time; the link store and the
    generation supervisor that apply a topology to it; the SCION-native
    control endpoint — HTTP/3 over QUIC over SCION paths, peers
    authenticated by their chains against the TRC — serving the drafts'
    services (segment creation, registration, and lookup, trust
    material, chain renewal) and the enrollment lifecycle; the beaconing
    loops of ADR-0004; discovery — the greeting stream, the neighbor
    map, and the core-endpoint relay, CION's own but owed by every node
    however its topology is decided; and the SCMP echo responder, the
    one capability that moves the other way — out of
    [proposal 0005](/docs/proposals/0005-path-library-and-scion-ping.md)'s
    ping application and into the core — because every node's selection
    baseline is an echo its peers must answer: a node that could
    decline the responder silently disables the comparator on every
    neighbor, and the responder has no policy surface to swap; it
    answers everyone. `pkg/controlplane` slims to exactly this: the
    channel, the drafts' services, discovery, and enrollment.
2.  **Shared libraries serve core and apps alike, run no loops of their
    own, and hold no policy.** These are `pkg/scion` — the connection,
    address, and path provider of ADR-0005's application seam;
    `pkg/links` — the neighbor table as the single source of topology
    truth; the peer-identity middleware of the SCION-native channel; and
    the trust and path databases. The moment one of these grows a policy
    decision or a lifetime loop, it has become an app and must move.
3.  **The topology machinery of ADR-0006 becomes an application — the
    measured provider — loaded by default.** The rendezvous acceptor,
    the joiner's dials, the node directory, the in-band link service,
    and the selection loop move out of `pkg/controlplane` and the node
    assembly into a topology application composed of the same
    libraries — the acceptor carrying its admission policy with it,
    which is where that policy belongs: that strangers may dial the
    socket is mechanism, who may dial it is policy. Nothing about them
    changes; their packaging does. Loading it is what makes a node
    zero-conf, and it is the default because almost-zero-config is the
    founding claim.
4.  **A file provider is the static alternative, and providers are
    exclusive.** It reads a link-set file — neighbor ISD-AS, underlay
    addresses, optional interface ID — and reconciles it into the store:
    named entries are established, the operator vouching for them as the
    old configured interfaces did; entries absent from the file retire.
    The file never carries identity, keys, or bind addresses — it is a
    policy artifact, not the retired configuration file reborn — and a
    node runs exactly one provider, because two deciders writing the
    same entries is flapping by construction. This deliberately
    narrows ADR-0006's founding "no topology description, and no secret
    material, in any file" from an absolute to the default path: what
    returns is description as a declared policy for deliberate
    deployments, carrying no secret and playing no part in a default
    join. Exclusivity is per node, under a stronger operating
    assumption: one operator runs an ISD, so provider choice is uniform
    within it — a core on the file provider never strands measured
    members of its own ISD, because there are none to strand.
    Cross-ISD provider mixing is deferred with the cross-ISD questions.
5.  **Identity completion is provider-aware.** A first start's ISD is a
    provisional draw; the measured provider completes it with the
    network's from a rendezvous reply, the file provider from a
    neighbor's ISD-AS in the file. Neither path puts an `ia` literal in
    any file.
6.  **Apps expose their services through the assembly, by the two
    mechanisms the node already has.** Control services mount on the
    endpoint's mux as interfaces — the link and directory services when
    the measured provider loads, mounting none when it does not.
    Data-plane services keep sockets of their own: an app binds its
    SCION socket and registers it as a service with the assembly,
    which re-registers it with every data-plane generation — the
    pattern the WireGuard application's mesh socket, and the directory
    its core serves, already follow and keep following. The dependency
    direction is one-way: apps import the core and the shared
    libraries, never the reverse.

### Positive consequences

*   `pkg/controlplane` becomes what its name promises: the SCION subset
    CION implements, reviewable without CION's policy in view.
*   Topology policy is swappable without touching the node: the measured
    provider and the file provider are two implementations of one seam,
    and a third — an operator's own — needs no core change to exist.
*   Static topologies return as a first-class choice for labs, CI, and
    reproducible tests, without re-importing coordinated identity files
    or restart ceremonies: the store and the generation swap apply a
    file exactly as they apply a measurement.
*   Applications gain a clear contract — land decisions in the store,
    register services through the assembly, hold your own keys and state
    — that the WireGuard application already satisfies and new ones can
    follow from day one.
*   The minimal core is small enough to stabilize: its churn is the
    drafts' churn, not the policy's.

### Negative consequences

*   The default node still loads the measured provider, so "minimal" is
    a property of the packaging and the review surface, not of the
    default footprint.
*   Two more packages and an interface to keep coherent, and a refactor
    of just-landed code to get there — behavior-neutral, but reviewable
    only as a move.
*   The exclusivity rule means a node cannot mix decided and measured
    links; an operator wanting one pinned link beside measured ones gets
    a policy the providers do not express yet.
*   In-process apps share the node's supervision, not a process fence:
    a panicking or exited app loop is absorbed and logged — the node
    serves on, degraded — but nothing restarts it; this is the residue
    of declining the plugin option's isolation.
*   The seams are conventions as much as types: nothing but review stops
    a future capability from being wired into the core and re-blurring
    the boundary this ADR draws.

## Pros and cons of the options

### Assembly wiring (status quo)

*   Good, because it is already built, tested, and working.
*   Good, because a node that always runs everything needs no loading
    logic — there is nothing to choose.
*   Bad, because `pkg/controlplane` names nothing: the drafts' services,
    CION's greetings, and CION's topology policy sit in one package, and
    the tree cannot say which is which.
*   Bad, because policy is welded to mechanism: replacing the selection
    heuristic with anything else means touching the node assembly, and a
    deliberate static topology has no expression at all.

### Minimal core, shared libraries, and apps

*   Good, because the boundary is decided by a rule — mechanism versus
    policy — rather than by where the last contributor happened to be
    working.
*   Good, because it inherits, rather than invents: the application seam
    (ADR-0005), the resident application (proposal 0006), and the store
    with its supervisor (proposal 0008) are the joints it separates
    along.
*   Good, because the file provider restores deliberate topologies as a
    policy artifact without restoring the retired configuration file's
    identity and secrets.
*   Bad, because it costs a refactor of working code and an interface
    more to document, and because the default node's behavior is
    unchanged — the win is structural, not functional.

### External plugin process

*   Good, because process isolation contains a crashing decider and
    allows an independent release cadence.
*   Bad, because it re-imports what ADR-0006 retired: a serialized
    topology artifact as the interface, a watcher and a reload path
    beside the store's notifications, and two sources of truth that can
    diverge.
*   Bad, because it draws a new trust boundary: the decider must either
    hold the node's keys — becoming the node — or command it through an
    authorization the architecture has no anchor for.
*   Bad, because the decider's probes cannot leave the node: greeting
    liveness, chain evidence, and echoes over one-hop paths all ride the
    node's own sockets, so an external prober needs a second SCION stack
    — the "second protocol beside the first" ADR-0006 rejected.
