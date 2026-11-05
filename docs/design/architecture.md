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
with two facts, one neighbor's address and the core's identity, and needs
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

Each kind of component sits beneath a roof of its own — `pkg/core`,
`pkg/libs`, `pkg/modules`, and `pkg/apps` — whose walk test checks the
roof's shape and its import rule. The dependency direction is one-way:
modules and applications import the core and the libraries, never the
reverse.

### The node core

The core is what the rest of the network depends on, whatever the node's own
policy chooses.

*   **Data plane** — forwards SCION packets over the underlay by the path
    each carries, control traffic first
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)). Each
    generation serves a fixed link set until retired; a link's verdict,
    locator, and observed source change in place, and a link that keeps its
    addresses keeps its observed source in the next generation.
*   **Control endpoint** — speaks the control services to neighbor nodes
    over the SCION-native channel: beaconing, segment registration and
    lookup, trust material, and service resolution.
*   **Liveness** — a BFD session on every serving link, and the monitor
    that keeps the sessions across data plane generations and turns their
    arrivals into each link's up or down verdict.
*   **Trust engine** — holds and issues the network's trust material: the
    TRC, certificate chains, and their renewal, and runs the procedures that
    keep it current: the chain's lifecycle, the rotation watch, and the
    founder's decision on submitted TRC updates.
*   **Bootstrap channel** — the core's certificate management and the
    joiner's first verified fetch of it.

### Shared libraries

Libraries carry the vocabulary both sides of the node's boundary speak; they
run no loops of their own and hold no policy.

*   **SCION library** — the socket that carries datagrams over SCION paths,
    and the path provider that composes paths from discovered segments and
    holds each destination's lease, the path every flow to it rides
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)).
*   **SCION RPC** — the SCION-native channel: HTTP/3 over QUIC riding SCION
    paths, peers authenticated by their chains against the TRC, and the
    drafts' service resolution.
*   **Segment types** — the vocabulary of beacons and signed entries.
*   **Underlay** — the facts of the UDP/IP network beneath SCION that the
    data plane shares with the sockets.
*   **Peer identity** — the verified chain's identity, shared by every
    authenticated channel.
*   **State files** — the state directory's files, written whole: a reader
    or a crash sees the old content or the new.
*   **Node bus** — the node's events: a component publishes the state it
    owns, and the components that depend on it subscribe to its changes or
    read its last event
    ([ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)).

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
    host, and what the founder votes on; `--trust.enroll-auth` selects
    exactly one method
    ([ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)):
    by source address, admitting nodes alone, or from the operator's chat
    or passkey console
    ([ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md)),
    whose auth keys admit hosts, each key naming its host's node
    ([ADR-0023](/docs/adrs/0023-admit-every-host-by-a-key-that-names-its-node.md)).
*   **Membership** — policy: how a node's admission binds it
    network-wide; `--trust.membership` selects exactly one method, the same
    on every node: the founder method by default, under which a node's
    membership is the newest chain the founder issued for its key, or none,
    under which every chain stands as its own membership
    ([ADR-0034](/docs/adrs/0034-verify-each-chains-membership-and-remove-cores-at-once.md)).
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
    nodes ([ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md)),
    and relays each host's sessions with other nodes
    ([ADR-0024](/docs/adrs/0024-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md)).
*   **Egress** — every node's internet exit by default: the node's netstack
    ends the TCP and UDP flows a host sends through it and opens them again
    from the node's own sockets, and serves the node's own tailnet address
    ([ADR-0024](/docs/adrs/0024-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md)).
*   **Mihomo** — the mihomo proxy provider each node serves its hosts at its
    own tailnet address: one tailnet client instance per exit, so a host's
    mihomo chooses its exit per flow.
*   **Coordination** — the network's headscale, minimal by decision: hosts
    join by logging in with a standard tailnet client and an auth key
    against the core's coordination endpoint, registration asks the
    admission seam, the host's address comes from the node its key names,
    and the registry distributes by the directory
    ([ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)).
*   **Portal** — the operator's passkey console, which the founding core
    serves beneath `/admin/` beside the portal admission method it pairs
    with: it decides the method's node and vote asks, mints its auth keys,
    each naming a node, lists the nodes and hosts, releases hosts, and
    removes nodes and cores
    ([ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md)).
*   **Ping** — the network's probe: it measures the paths the SCION
    library's picks and leases and the topology selection ask about, and
    each chooses by its records
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)).

## How the components interact

The data plane forwards by the packet's own path, so the control plane's
work is making paths exist and keeping links real. The two meet at the path
provider and the neighbor table.

### Trust and enrollment

The founding core self-issues the TRC and anchors it in the WebPKI through
its identity. A joiner's first fetch of the core is the only WebPKI-anchored
exchange; enrollment at the founding core then issues the chain that
authenticates everything the node says thereafter. First issuance is the
admission gate, where enrollment policy — if a deployment selects one —
decides on the verified facts of the exchange, and it binds the node's
ISD-AS to its key. Every core's root is in the TRC, and renewal is
automatic at any of them: a node renews on its current chain over the
authenticated channel, and a core renews its own chain itself
([ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md)). A peer's
chain passes a handshake only where a membership binds its ISD-AS to its
key: a chain the founder issued, which each node renews at the founder and
presents beside any other chain it holds
([ADR-0034](/docs/adrs/0034-verify-each-chains-membership-and-remove-cores-at-once.md)).
Removing a node frees its name, so its membership lapses; removing a core
also drops it from the TRC by the founder's vote alone, and the nodes
holding its chains fall back on their memberships. A node pins a TRC update
only once the founder signed it.

### Path discovery

Cores originate beacons; each AS appends a signed entry and forwards them,
and receivers verify every entry against the TRC. A node sends each
neighbor, among the routes it can take, each core's cheapest route, backups,
and each link's cheapest route
([ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md)), and
registers its own selection: up segments locally, down segments at the
originating core. The path provider composes segments into end-to-end paths,
the one seam every consumer uses, the control endpoint's transport included.

### Topology and liveness

The topology source meets candidate peers at the rendezvous exchange — first
contact, admission probe, and a joiner's establishment in one — and learns
of them from the directory of each scope the node is in: a node groups its
links by the host each peer sees it at, and the groups that links join form
a scope. Each node signs its own entry in each of its directories; linked
nodes flood new entries to each other and exchange summaries to catch up,
each entry only over the links of its scope
([ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)).
It reaches a candidate that reports itself undialable, such as a node behind
a NAT, by punch instead: over a request both chains authenticate, each side
learns its socket's reflexive address from a dialable neighbor in the
scope and sends toward the other's.
Admitted links enter the neighbor table; the selection loop then measures
every peer and keeps a link for what it adds into the region beyond its peer
— a cheaper route or an independent one, judged by the end that dialed the
link — holding a resilience floor and changing slowly, because every change
reshapes paths network-wide. Membership changes land as generation swaps:
the new data plane is built from the neighbor table's snapshot and the old
one retires. Liveness runs beside the source: a session per link feeds the
monitor, whose verdict stops forwarding on a dead link and resumes it on
recovery — a state flip within the same generation, faster and reversible
where membership changes are damped. The node publishes its link state on
its bus whenever the table, a verdict, or a link's observation changes:
beaconing, path composition, the sockets, and the topology source read the
links there.

### Endhost service

Hosts are tailnet clients of the node their auth key names: they log in
against the core's coordination service and run no CION software. A host's
netmap makes every node an exit peer, and the host's own node relays its
sessions with the others over SCION, unopened
([ADR-0024](/docs/adrs/0024-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md)).
Host-to-host traffic crosses the SCION mesh. A join completes at the
directory's fetch cadence.

## See also

*   [CION security model](/docs/design/security.md) — the trust these
    components assume and enforce.
*   [Decision records](/docs/README.md) — the ADR corpus under `/docs/adrs/`
    this design descends from, and the workflow that maintains it.
*   [README](/README.md) — the project's goal and scope.
