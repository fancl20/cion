# CION architecture

CION is a single-binary implementation of the SCION architecture in which one
node is one Autonomous System (AS). This document describes the components of
a node and how they interact; the reasoning behind every boundary lives in
the [decision records](/docs/README.md) under `/docs/adrs/`, and the
[security model](/docs/design/security.md) states the trust these components
assume and enforce.

[TOC]

## The system in one view

A CION network is a set of nodes, one per AS, run by different operators and
linked pairwise over a UDP/IP underlay. Each node forwards packets whose path
is carried in the packet itself — no node holds a routing table — and the
endpoint, not the network, chooses the path its traffic takes. A node joins
with two facts, one neighbor's address and the core's domain, and needs
nothing else: identity is generated locally, paths are discovered, links are
earned by measurement, and plain hosts are served through an embedded
gateway. CION is non-scalable by choice: it targets small multi-operator
networks and cuts every mechanism whose only purpose is internet scale
([ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md)).

## Design principles

*   **One node per AS, one binary** — the reference architecture's separate
    services collapse into a single unprivileged process.
*   **Path awareness** — a sender selects among the network's paths for its
    own reasons, without network-side configuration.
*   **Operator sovereignty** — an AS appears in a path only through entries
    it signed itself
    ([ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)).
*   **Almost-zero config** — defaults are open; restriction is something a
    deployment opts into.
*   **Spec-native mechanisms** — where the SCION drafts define an
    instrument, the node speaks it
    ([ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)).
*   **Mechanism in the core, policy in apps** — what the network depends on
    whatever the node's own policy is core, a service owed; what deployments
    could differ on is policy under an application
    ([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)).

## The components

The dependency direction is one-way: applications and policy import the
core, never the reverse.

### The node core

The core is what the rest of the network depends on, whatever the node's own
policy chooses.

*   **Data plane** — forwards SCION packets over the underlay by the path
    each packet carries. It is built with an immutable link set and serves
    until retired; the only state that changes while serving is each link's
    up or down verdict.
*   **Control endpoint** — speaks the control services to neighbor nodes:
    beaconing, segment registration and lookup, trust material, and service
    resolution, beside the per-link liveness sessions and the monitor that
    turns their verdicts.
*   **Trust engine** — holds and issues the network's trust material: the
    TRC, certificate chains, and their renewal.
*   **Neighbor table** — the one source of truth about links; every data
    plane generation is built from its snapshot.
*   **Path database** — the registered path segments a node keeps.

### Shared libraries

Libraries carry the vocabulary both sides of the node's boundary speak; they
run no loops of their own and hold no policy.

*   **SCION library** — the application seam: the socket that carries
    datagrams over SCION paths, and the path provider that composes
    end-to-end paths from discovered segments.
*   **Segment types** — the vocabulary of beacons and signed entries.
*   **Bootstrap channel** — the core's certificate management and the
    joiner's first verified fetch of it.
*   **Peer identity** — the verified chain's identity, shared as middleware
    by every authenticated channel.

### Applications and policy

*   **Topology application** — owns the node's link policy: rendezvous, the
    node directory, and the selection loop. It loads by default; a static
    file-driven alternative exists for deliberate deployments
    ([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)).
*   **Gateway** — serves plain hosts as WireGuard clients and carries their
    traffic over SCION paths, with internet egress on exit nodes
    ([ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md)).
*   **Ping** — the network's probe, and the selection loop's measuring
    instrument.
*   **Enrollment policy** — the authorizers a core can gate a joiner's first
    issuance with
    ([ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)).

## How the components interact

The data plane forwards by the packet's own path, so the control plane's
work is making paths exist and keeping links real. The two meet at the path
provider and the neighbor table.

### Trust and enrollment

The founding core self-issues the TRC and anchors it in the WebPKI through
its domain. A joiner's first fetch of the core is the only WebPKI-anchored
exchange; enrollment then issues the chain that authenticates everything the
node says thereafter, and renewal is automatic. First issuance is the
admission gate, where enrollment policy — if a deployment selects one —
decides on the verified facts of the exchange.

### Path discovery

Cores originate beacons; each AS on the way appends a signed entry of its
own and forwards the beacon to its neighbors, which verify every entry
against the TRC. Receiving nodes keep candidates briefly, then terminate
selected beacons into segments — up segments kept locally, down segments
registered with the originating core — where they persist in the path
database until they expire. The path provider composes registered segments
into end-to-end paths and is the single seam every consumer uses: the control
endpoint's own transport rides it, and applications reach it through the
SCION library's socket.

### Topology and liveness

The topology application meets candidate peers at the rendezvous exchange —
first contact, admission probe, and a joiner's establishment in one — and
learns of them from the core-served node directory. Admitted links enter the
neighbor table; the selection loop then measures every peer and keeps a
direct link only while it beats the composed-path alternative, holding a
resilience floor and changing slowly, because every change reshapes paths
network-wide. Membership changes land as generation swaps: the new data
plane is built from the neighbor table's snapshot and the old one retires.
Liveness runs beside the policy: a session per link feeds the monitor, whose
verdict stops forwarding on a dead link and resumes it on recovery — a state
flip within the same generation, faster and reversible where membership
changes are damped.

### Endhost service

Hosts are ordinary WireGuard clients of their node's internal address. The
gateway carries host-to-host traffic over SCION paths between gateways, and
internet-bound traffic through an exit node. A host exercises path choice by
choosing which of its provisioned destinations to send through, one key per
path choice.

## See also

*   [CION security model](/docs/design/security.md) — the trust these
    components assume and enforce.
*   [Decision records](/docs/README.md) — the ADR corpus under `/docs/adrs/`
    this design descends from, and the workflow that maintains it.
*   [README](/README.md) — the project's goal and scope.
