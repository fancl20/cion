# Discover Paths with Spec-Aligned Beaconing

*   Status: accepted
*   Date: 2026-09-12

[TOC]

## Context and problem statement

CION's data plane already forwards multi-hop SCION paths: the processor in
`pkg/dataplane/processor.go` verifies hop-field MACs with the AS forwarding
key, chains SegIDs, advances the path metadata, and crosses over between path
segments; egress is driven entirely by the packet's hop fields, so no routing
table exists or is needed. Directly connected neighbors discover each other by
exchanging greetings, and since
[ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md) every
node can hold TRC-anchored certificate chains and reach its neighbors' control
services over one-hop SCION paths.

Nothing in the system creates or distributes path segments, however. The
segment RPCs (`SegmentCreationService`, `SegmentRegistrationService`,
`SegmentLookupService`) are mounted but unimplemented
(`pkg/controlplane/trustservice.go`), and only the two-node test hand-crafts a
two-hop path (`pkg/dataplane/twonode_test.go`). Consequently, no packet
can travel beyond a direct neighbor — there is no source of end-to-end
paths — and nodes without a direct link to the core cannot enroll, the case
ADR-0003
deferred to multi-hop paths.

This ADR decides the architecture of the path layer: how path segments come to
exist (exploration), how they are stored (the path segment database), how they
are published (registration), and how they are consumed (lookup and the
control-plane transport). The decision builds on
[ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md),
[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md), and ADR-0003, and
follows
[`draft-dekater-scion-controlplane`](/docs/specs/draft-dekater-scion-controlplane.txt)
for every wire format and inter-AS mechanism it touches.

## Decision drivers

*   **Spec Alignment:** Path segments, their signatures, and the RPCs that
    carry them follow the SCION control-plane draft, keeping CION's artifacts
    consumable by reference tooling and keeping the data plane (already
    spec-compliant) unchanged.
*   **Operator Sovereignty:** An AS appears in a path only through AS entries
    it signed itself; declining transit must be possible and visible.
*   **Almost-Zero Config:** Nodes are configured with links and a core domain
    today; the path layer must not require operators to describe the topology
    they are building.
*   **Single Binary, One Node per AS:** The beaconing, registration, and
    lookup roles of the reference implementation's separate services collapse
    into the CION node.
*   **Incremental Delivery:** The design must build on the one-hop control
    transport and the trust material that exist today, not replace them.
*   **Non-Scalable by Choice:** CION targets small multi-operator networks, so
    mechanisms whose only purpose is internet-scale tractability are cut.

## Considered options

How paths are discovered:

*   **Spec-Aligned Beaconing:** Cores originate path-construction beacons
    (PCBs), each on-path AS appends a signed AS entry and forwards the beacon
    to its neighbors, per control plane draft Section 2.
*   **Link-State Flooding:** Every node floods its links; each node computes
    paths locally over the accumulated topology graph.
*   **Core-Computed Paths:** The core maintains the topology and computes and
    distributes complete end-to-end paths on demand.

How path segments are stored:

*   **Two Stores, Two Lifetimes:** An in-memory beacon store for candidate
    PCBs and a persistent path database for registered segments, per the
    draft's separation of candidate storage (Section 2.3.2) from path
    databases (Section 4).
*   **One Persistent Store:** Candidate PCBs and registered segments in a
    single durable database.
*   **All In-Memory:** Both stores volatile; a restarted node waits one
    beaconing period to rebuild.

How link roles are known:

*   **Emergent Link Roles:** Parent, child, and core roles derive from beacon
    flow and the trust material; no link type is configured.
*   **Three Declared Tiers:** Read a routing hierarchy out of the TRC's role
    sets — cores above `ASTypeAuthoritative` above `ASTypeNormal` — with
    beacons flowing strictly down the tiers.
*   **Same-Type Links as Peering:** Links between same-type ASes carry no
    beacons and serve as peering shortcuts.
*   **Configured Link Types:** A per-interface `linkType` field (core, parent,
    child, peer) in the node configuration.
*   **Static Topology:** A configured graph of the whole network.

How consumers obtain end-to-end paths:

*   **In-Node Path Provider:** One abstraction resolves a destination ISD-AS
    into an end-to-end SCION path; the control transport and, later, endhost
    exposure consume it.
*   **Per-Consumer Store Access:** Each consumer (transport, enrollment,
    endhost API) queries the path database and combines segments itself.
*   **Endhost Proxy Now:** The node translates plain local traffic into SCION
    packets over computed paths as part of this milestone.

## Decision outcome

Chosen options: **spec-aligned beaconing**, **two stores with different
lifetimes**, **emergent link roles**, and an **in-node path provider**,
realized as follows:

1.  **Exploration by beaconing.** Cores originate PCBs on their links, each
    carrying a fresh segment information with a cryptographically random
    16-bit segment ID and a creation timestamp (control plane draft, Section
    2.2.1). Every receiving AS appends an AS entry binding its ISD-AS, the
    ingress and egress interface IDs, and the next AS, signed with its AS
    certificate chain through the existing trust signer; the entry's hop
    field is MACed with the data-plane forwarding key, the same MAC
    algorithm the processor already verifies (dataplane draft, Section
    4.1). Beacons travel between neighboring control services over the
    existing QUIC/SCION channel — one-hop paths, as greetings do today —
    and are forwarded on every external interface except the one they
    arrived on and except interfaces whose neighbor the TRC names as a
    core — beacons never travel toward a core, which drops any beacon
    containing itself and needs no up segment, so the trust material
    that verifies beacons also prunes the upward sends a pure flood
    would make. The draft's PCB selection policies (Section 2.3.3)
    collapse to a fixed bounded set; no policy engine, no per-policy
    configuration.
2.  **Authenticated reception.** The beacon handler verifies each AS entry's
    signature against TRC-anchored chains with the existing verifier, checks
    that the announcing neighbor matches the interface's configured neighbor
    ISD-AS (the enforcement ADR-0003 promised for the first signed
    control-plane message), and drops beacons whose AS entries contain the
    local ISD-AS (loop prevention). Accepted beacons enter the beacon store.
3.  **Two segment stores with different lifetimes.** The beacon store holds
    candidate PCBs and is in-memory: it is write-heavy, valid for one
    beaconing period at a time, and rebuilt by the next period's beacons
    after a restart. The path database holds registered up, down, and core
    segments and is persistent, following the trust DB pattern — a pure
    interface, a bbolt implementation, and shared contract tests — in a
    dedicated package beside `pkg/trust`. Segments are stored in CION-owned
    domain types wrapping the vendored `proto/control_plane` messages; the
    reference implementation's `pathdb` and beacon-server packages stay
    unvendored. A newly registered segment replaces the stored segment with
    the same identity (originating core, segment ID, creation timestamp);
    segments are evicted when their timestamp-relative expiration passes, on
    access and by a periodic sweep. There is no revocation mechanism in this
    milestone; expiration bounds staleness.
4.  **Link roles without link-type configuration.** A link's roles are not
    configured; they emerge from beacon flow. A core originates beacons on
    all of its links; an interface a beacon arrives on is the node's parent
    side, and interfaces beacons are propagated to are child sides; a link
    between two cores — identifiable through the TRC, which names the ISD's
    cores — is a core link, carrying core beacons in both directions.
    Parent-child direction on a link between two non-core ASes is therefore
    decided by which side can reach a core and deliver beacons. Intra-ISD
    peering is not representable — no signal distinguishes a shortcut from
    a parent-child link — and cross-ISD links, peering by elimination
    where not core-to-core, are out of scope while CION is single-ISD
    (ADR-0003). Valley freedom follows
    structurally: a non-core never receives a beacon originated below it,
    and paths combine only up, core, and down segments.
5.  **Registration per the draft.** Non-cores periodically terminate selected
    PCBs — appending a final AS entry with unset next AS and egress
    interface, signed (Section 4.1.1) — into up segments, kept in the local
    path database (Section 4.1.2), and down segments, registered with the
    control service of the core that originated the PCB (Sections 4.1.3 and
    4.3). Cores likewise terminate core beacons into core segments in their
    own path database (Section 4.2). Intervals are code defaults, not
    configuration.
6.  **Lookup and the in-node path provider.** The node implements the
    draft's source-AS segment-request handler (Section 5.2.2): up segments
    from the local path database, core and down segments fetched from the
    core's control service with expiry-aware caching, wildcards expanded as
    specified. One in-node provider composes up, core, and down segments
    into end-to-end paths and is the only consumer seam: it generalizes
    today's one-hop `SCIONConn`, carrying control RPCs over the reversed
    freshest up segment — which exists from beaconing alone, so reaching
    the core has no bootstrap cycle — and completes ADR-0003's deferred
    enrollment of nodes not directly linked to the core.
7.  **Transit consent.** An operator consents to transit by propagating
    beacons; refusing to propagate leaves the node's links usable for its
    own traffic but keeps it out of other ASes' paths. Sovereignty rests on
    the signatures: no AS entry exists that the node did not sign. A
    configuration kill-switch for propagation is future hardening.
8.  **Scope boundary.** Endhost-facing path exposure — a local path API or a
    UDP proxy answering the internal underlay's requirement that hosts send
    SCION-structured packets — is deferred to a follow-up that consumes the
    same provider. The data plane needs no change.

### Positive consequences

*   The data plane, the hardest component, stays as it is; the milestone is
    purely control-plane work over interfaces that already exist.
*   No new configuration; provider relationships organize themselves from
    connectivity.
*   Wire formats, signatures, and RPCs follow the draft, so segments remain
    inspectable by reference tooling and the design composes toward
    multi-core ISDs.
*   Transit sovereignty is cryptographic, not configurational.
*   Stores stay small at CION's target scale, and the persistent store uses
    the established bbolt and contract-test pattern.

### Negative consequences

*   Path availability trails topology changes by up to one beaconing and
    registration period — inherent to beaconing, aggravated here by the
    fixed selection policy.
*   Link roles cannot be pinned: with multiple candidate parents, the node
    keeps all their segments instead of a preferred provider, and an
    intra-ISD peering relationship cannot be expressed at all.
*   Propagating on every non-ingress interface that does not lead to a
    TRC-named core is still flooding at heart among non-core ASes; it is
    acceptable only because CION is non-scalable by design.
*   The in-memory beacon store makes a restarted node dependent on the next
    beaconing period before it can register or serve paths.
*   Without revocation, a path segment remains usable until its hop fields
    expire; a link failure propagates only through expiration and fresh
    registrations.

## Pros and cons of the options

### Spec-aligned beaconing

*   Good, because segments arrive already signed hop by hop, which is exactly
    the sovereignty property ADR-0001 demands.
*   Good, because the vendored protobuf and crypto libraries already carry
    the PCB and segment messages and MAC algorithms.
*   Good, because exploration reuses the one-hop control channel; no new
    transport is invented.
*   Bad, because it brings the most moving parts of the options: origination,
    propagation, reception, termination, registration, and lookup.

### Link-state flooding

*   Good, because it is conceptually simpler: one flood, local path
    computation, no registration step.
*   Bad, because paths computed locally have no per-AS signatures, so transit
    consent would have to be re-invented beside the computation.
*   Bad, because it diverges from the draft's segment model, orphaning the
    vendored message types and the data plane's expectation of MACed hop
    fields.

### Core-computed paths

*   Good, because one writer of paths means no distributed consistency
    questions at all.
*   Bad, because the core becomes the routing authority, contradicting
    ADR-0001's decentralized control driver.
*   Bad, because every topology change funnels through the core, the same
    single point ADR-0003 already accepts for trust and no more.

### Two stores, two lifetimes

*   Good, because each store gets the durability its contents deserve:
    candidate PCBs are disposable by construction, registered segments serve
    lookups across restarts.
*   Good, because it mirrors the draft's own separation, keeping CION's
    vocabulary aligned with the specification's.
*   Bad, because two stores are more code than one.

### One persistent store

*   Good, because a single database and schema is less code.
*   Bad, because candidate PCBs churn every beaconing period, writing
    throwaway data durably for no benefit.

### All in-memory

*   Good, because it is the least code and the fastest.
*   Bad, because a restarted core serves no down segments until every node
    re-registers, and a restarted non-core must re-derive its up segments
    before it can reach the core.

### Emergent link roles

*   Good, because the configuration stays what it is today: links and a core
    domain.
*   Good, because roles derive from signed beacons, so they cannot disagree
    with the paths the network actually built.
*   Bad, because roles are observed, not declared: an operator cannot pin a
    preferred parent or declare a peering link.

### Three declared tiers

*   Good, because direction would be known statically from trust material
    the node already holds, eliminating upward and lateral beacon sends
    entirely.
*   Bad, because `ASTypeAuthoritative` is a core in ADR-0002's model — a
    second flavor of core, not a middle tier — so this redefines the type,
    hanging a routing hierarchy on certificates whose meaning is voting
    rights.
*   Bad, because a depth-capped hierarchy forbids chains of providers
    (core—B—C), this milestone's own motivating topology, although the
    draft's parent-child links chain without bound.

### Same-type links as peering

*   Good, because same-type neighbors at the same depth are exactly the
    peering shape, and the rule needs no new configuration.
*   Bad, because type equality does not imply lateral position: in
    core—B—C, B and C are both `ASTypeNormal`, yet the link must carry
    beacons or C has no path to the core at all.
*   Bad, because core↔core links — including authoritative↔authoritative —
    are core links that core beaconing depends on.
*   Bad, because pruning the lateral beacon exchange between redundant
    neighbors discards the path diversity that path-aware endpoints exist
    to choose from.

### Configured link types

*   Good, because declared roles are deterministic and support peering links
    from day one.
*   Bad, because every link gains a field that must be consistent across both
    endpoints, for a benefit that only materializes with peering or provider
    preferences.

### Static topology

*   Good, because a full graph makes every question answerable locally.
*   Bad, because it violates the almost-zero-config driver outright; CION
    nodes are supposed to know their neighbors, not the network.

### In-node path provider

*   Good, because composition (up + core + down, reversal, expiry) is written
    once and every consumer — transport, enrollment, later endhosts — gets
    identical paths.
*   Good, because it is the natural seam to generalize the existing one-hop
    transport without changing its callers.
*   Bad, because endhost exposure still needs a follow-up; the provider alone
    does not make local applications path-aware.

### Per-consumer store access

*   Good, because each consumer could tailor its combination strategy.
*   Bad, because segment composition duplicated per consumer invites
    divergence in the one place correctness matters most.

### Endhost proxy now

*   Good, because local applications would immediately gain multi-hop paths
    without knowing SCION exists.
*   Bad, because it entangles this milestone with the endhost addressing
    question — how plain local traffic is mapped into SCION endpoints —
    which is orthogonal to discovering paths and unblocked the moment the
    provider
    exists.
