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
earned by measurement, and hosts are tailnet clients — one login against the
core's coordination endpoint serves the network's life, every node an
offered internet exit. CION is non-scalable by choice: it targets small
multi-operator networks and cuts every mechanism whose only purpose is
internet scale
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
*   **Mechanism in the core, seams in modules, services in apps** — what the
    network depends on whatever the node's own policy is core, a service
    owed; where an implementation could differ is a module; what a node
    offers beyond itself is an application
    ([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md),
    [ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)).

## The components

The dependency direction is one-way: modules and applications import the
core and the libraries, never the reverse.

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

### Modules

Modules are the parts of the node where an implementation could differ —
its pluggable surface
([ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)). Each
declares a kind, and the kind fixes the selection: storage is bound by the
composition root, policy and the source by the operator's run arguments.

*   **Trust database** — storage: where trust material persists.
*   **Path database** — storage: where registered segments persist.
*   **Neighbor table** — storage: where the one source of truth about
    links persists; every data plane generation is built from its
    snapshot.
*   **Enrollment authorizer** — policy: who is admitted, joiner node or
    host; `--trust.enroll-auth` selects exactly one method
    ([ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)).
*   **Topology source** — source: where topology decisions come from; the
    measured provider by default — loading it is what makes a node
    zero-conf — the file provider when `--topology.link-set` names a
    link-set.

### Applications

Applications are what a node offers beyond itself, enumerated in one
closed table — the one place that answers what a node can be. The
`--applications` run argument selects among them: unset loads what the
run arguments already imply — the zero-conf default — and a list, the
empty one included, states the combination deliberately; one that cannot
load refuses the boot with the fix named
([ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)).

*   **WireGuard** — carries host and mesh traffic over SCION paths between
    nodes ([ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md)).
*   **SOCKS** — internet egress as a service on the overlay: every node
    serves it by default at its own tailnet address, and the destination a
    client names is the exit it uses
    ([ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)).
*   **Coordination** — the network's headscale, minimal by decision: hosts
    join by logging in with a standard tailnet client against the core's
    coordination endpoint, registration asks the admission seam, and the
    registry distributes by the directory
    ([ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)).
*   **Ping** — the network's probe, and the selection loop's measuring
    instrument.

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

The topology source meets candidate peers at the rendezvous exchange —
first contact, admission probe, and a joiner's establishment in one — and
learns of them from the core-served node directory. Admitted links enter the
neighbor table; the selection loop then measures every peer and keeps a
direct link only while it beats the composed-path alternative, holding a
resilience floor and changing slowly, because every change reshapes paths
network-wide. Membership changes land as generation swaps: the new data
plane is built from the neighbor table's snapshot and the old one retires.
Liveness runs beside the source: a session per link feeds the monitor, whose
verdict stops forwarding on a dead link and resumes it on recovery — a state
flip within the same generation, faster and reversible where membership
changes are damped.

### Endhost service

Hosts are tailnet clients of their node: they join by logging in against
the core's coordination service and run no CION software. The tunnel
carries the tailnet alone — no default route is advertised — and internet
reachability is a service every node offers by default at its own tailnet
address: the exit a flow uses is the destination it names
([ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)).
Host-to-host and exit traffic alike cross the SCION mesh between nodes. A
join completes at the directory's fetch cadence.

## See also

*   [CION security model](/docs/design/security.md) — the trust these
    components assume and enforce.
*   [Decision records](/docs/README.md) — the ADR corpus under `/docs/adrs/`
    this design descends from, and the workflow that maintains it.
*   [README](/README.md) — the project's goal and scope.
