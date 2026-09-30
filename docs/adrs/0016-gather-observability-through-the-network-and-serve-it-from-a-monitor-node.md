# Gather Observability Through the Network and Serve It from a Monitor Node

*   Status: draft
*   Date: 2026-09-30

[TOC]

## Context and problem statement

The node counts and cannot be read. The data plane declares six counter
families — input, output, processed, dropped packets, and bytes
(`pkg/dataplane/metrics.go`) — built from the global meter provider, but no
SDK provider is installed, so every `Add` lands in the API's no-op and a
deployment running the daemon reads none of them; beside them, the fast
path's discards return their disposition unnamed at every log level.
[Proposal 0017](/docs/proposals/0017-expose-metrics-and-log-discards.md)
turns the local instruments on — the provider, the level, the capped
discard lines — and serves them on a plain HTTP listener, loopback by
default.

Two properties of this network leave that listener unread. First, the
channels a node answers are SCION-native: the control endpoint is HTTP/3
over QUIC over SCION paths, peers authenticated by their chains against
the TRC, and the underlay sockets carry the drafts' forwarding and
liveness alone. A node behind an unmapped underlay — the common shape in
a multi-operator network — is reachable by no scraper that pulls over
plain HTTP; the loopback listener presupposes a collector co-located with
every node. The proposal's own reasoning names the gap and stops at it:
a scraper is not a peer. True of a Prometheus, and false of a scraper
that is itself a node — an application resident on one holds a chain,
and no consideration was given to one.

Second, the operator's question is the network's, not the node's:
traffic per node and per link, the topology graph, the enrollment state —
answers spread across every node, each invisible from the others.
Proposal 0017 makes per-neighbor volumes the node operator's own business
with the loopback bind as the access boundary, which places a
network-wide view outside the design by construction, not as a cost.

And the destination is not the network's to host. An observability
backend — OpenObserve, or any store that ingests OTLP — is a separate
deployment speaking plain HTTP on an underlay address, placed by
resource and reachability rather than by role; unlike the coordination
service it has no claim on the core, and the mesh cannot route a node's
request to it. Whatever gathers visibility must therefore terminate at a
node that fronts the backend.

What exists to build on:

*   The control endpoint's application mounts, served behind the
    peer-identity middleware (`pkg/controlplane`, `pkg/peeria`) — an
    authenticated HTTP channel to every node, riding paths the mesh
    already routes; today the measured provider's link and directory
    services are the only contributors.
*   The node directory: every enrolled node publishes its entry to the
    core each minute, entries expire after five, and every node's
    fetched copy is already the network's aggregated view
    (`pkg/modules/topology/impl/measured/directory.go`).
*   The state a dashboard needs in process: chain presence reads
    enrollment (`pkg/trust`), and the link store with the monitor's BFD
    verdicts read the topology's nodes and edges (`pkg/links`,
    `pkg/controlplane`).
*   The SCMP traceroute the drafts define and the core already serves —
    router-alert slow paths answering with the hop's ISD-AS and
    interface, replies DRKey-authenticated (`pkg/dataplane`) — while the
    sender side beside SCMP echo (`pkg/scion`) does not exist; the
    prober's shape is the ping application's (`pkg/apps/ping`).
*   [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)'s
    closed table, where a resident enters by an entry alone, bound to no
    role unless it says so.

This record decides how visibility travels, where it converges, and who
may read it.

## Decision drivers

*   **Gathered Through the Network:** visibility rides the SCION mesh —
    no underlay reachability assumption, no per-node public listener, no
    scraper the network cannot authenticate.
*   **Almost-Zero Config:** loading one application on one node makes
    the network observable; nothing per-node is configured for
    visibility's sake beyond what a formed node already runs.
*   **Collector at a Designated Node:** the backend is a deployment the
    operator places — not the network's to host, and not a privilege of
    whichever node holds the core role.
*   **Mechanism over Policy:** which node gathers, where the data lands,
    and who may read per-neighbor volumes are decisions stated at seams,
    not defaults inherited from a listener's bind address.
*   **Minimal Core** ([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)):
    observability is policy — a resident application. The core keeps
    what the drafts define, and the drafts' SCMP traceroute replies are
    already among it.
*   **Standard Handoff:** the network's obligation ends at OTLP and a
    status view; storage, dashboards, and alerting are the external
    layer's, chosen per deployment.

## Considered options

How visibility travels:

*   **Per-Node Pull:** a plain-HTTP metrics listener on every node —
    proposal 0017's shape — and a scraper that reaches each.
*   **Node Push:** every node ships its instruments to the backend
    directly, over OTLP.
*   **In-Band Gathering:** coarse status rides the directory
    publication, full counters are read from the control endpoint,
    latency and path truth ride SCMP traceroute — converged at a monitor.

Where gathering terminates:

*   **The Core:** the coordination precedent — the one node every member
    reaches, holding the aggregated stores.
*   **A Designated Node:** the monitor as an ordinary resident,
    loadable on any node, with the backend beside it.

Who may read the instruments:

*   **Node-Local:** the loopback bind is the boundary — proposal 0017's
    stance.
*   **Membership-Scoped:** any chain-holding network member may read
    through the authenticated channel.

## Decision outcome

Chosen options: **in-band gathering**, **a designated node**,
**membership-scoped reads** — realized as follows:

1.  **The monitor is a resident application, bound to no role.** An
    entry in ADR-0014's table without `CoreOnly` and without
    requirements; loading it by name is what designates the collector.
    Its own run arguments name the backend's OTLP endpoint and its
    cadences. The backend — OpenObserve or another store — runs beside
    the monitor or is reachable from it; nodes never address it, for the
    mesh cannot route to it and it authenticates no chains. The monitor
    is the SCION-native front: it reads what the network serves and
    pushes what the backend ingests.
2.  **Coarse status rides the directory publication.** Additive fields
    on `node.v1.Entry`: enrollment with chain expiry, per-link state
    with the monitor's BFD verdicts, counter totals, and a report
    sequence with its time. Publication stays on the existing minute
    cadence with its five-minute expiry, so the fetched set — already on
    every node — becomes the network's status view, and the topology
    graph's nodes and edges derive from it wherever the monitor runs.
    Freshness is the publication cadence; the fields carry state, not
    series.
3.  **Full counters are read from the control endpoint.** The SDK meter
    provider is installed with a reader served at an application mount
    behind the peer-identity middleware, and the monitor scrapes peers
    over SCION paths on its own cadence. This record re-scopes proposal
    0017: its provider install, its log level, and its capped discard
    lines stand as the enabling half; its loopback listener is
    superseded by the mount. Reading on demand keeps a node's egress at
    zero until a reader asks, and the cardinality that leaves a node is
    bounded by the reader's scrape. Membership is the boundary: an
    instrument served through the authenticated channel is readable by
    any network member, and per-neighbor volumes are the network's
    shared business — the multi-operator boundary this record chooses,
    superseding the proposal's loopback stance.
4.  **Latency and path truth ride the drafts' traceroute.** The sender
    side joins SCMP echo in the shared libraries — a request with the
    router alert on a chosen hop, its reply read back by identifier —
    and the monitor probes the paths in the segment store at a minutes
    cadence. Every reply names the answering hop's ISD-AS and interface,
    so per-hop latency attributes to links and the observed forwarding
    sequence cross-checks the link store against the data plane's truth.
    Selection keeps its own measures
    ([ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)'s
    ownership split): this channel is diagnosis and verification, not a
    selector input.
5.  **The network ends at handoff.** The monitor pushes OTLP to the
    named backend and serves a JSON status view — nodes and edges with
    enrollment, verdicts, latency, and volume — for whatever renders it:
    the backend's own dashboards, or a graph panel over the status view.
    The node network hosts no dashboards and stores no history. The
    backend is a sibling deployment, never a vendored or linked
    dependency — its license must not reach this tree (OpenObserve's
    AGPL-3.0 beside this project's Apache-2.0).

### Positive consequences

*   A network becomes observable by loading one application on one node:
    every channel rides paths the mesh already routes, so unmapped
    underlays change nothing.
*   Gathering is not a role privilege: any operator may load a monitor
    against their own backend, for the status view is every node's
    already and the instruments are membership-readable.
*   No wire protocol is invented — two channels exist today and the
    third is the drafts' own; the widest new surface inside the node is
    the traceroute sender.
*   The backend stays a deployment choice — OpenObserve today, another
    store later — because the monitor owns the egress format, not the
    storage.
*   The core is untouched: no owed service is added and no boundary
    moves; the drafts' traceroute replies were already the core's to
    serve.

### Negative consequences

*   Per-neighbor volumes become network-visible — a policy change from
    the loopback stance, owned here: an operator joining accepts that
    members see what members carry.
*   Unenrolled nodes are invisible beyond their absence: publication
    waits for a chain and the mount answers chains — the bootstrap
    window keeps no instruments.
*   Coarse freshness is the directory's minute cadence, and
    full-fidelity history exists only where a monitor and a backend run:
    between cadences and without them, the network is as unreadable as
    today.
*   The vendored tree grows the SDK provider with the exporter that
    serves the reader; the monitor's scrapes add control-plane load that
    grows with nodes and cardinality.
*   Traceroute probing spends the data plane's slow path per hop and
    must respect SCMP rate limiting — the minutes cadence is a budget,
    not a taste.

## Pros and cons of the options

### Per-node pull

*   Good, because the instruments are served the way the ecosystem
    already scrapes, beside the process that counts.
*   Bad, because it presupposes a scraper co-located with every node or
    an underlay path to each — the thing a NAT'd multi-operator mesh
    withholds — and aggregation then needs per-operator exports of data
    the loopback stance calls the operator's own.
*   Bad, because the listener authenticates no one: the bind address is
    the whole of the access control.

### Node push

*   Good, because one egress per node over a standard protocol needs no
    scraper state anywhere, and OTLP backends ingest it natively.
*   Bad, because the backend sits on the underlay — unreachable from
    the mesh — so a SCION-native relay appears regardless, now carrying
    every node's egress whether or not anything reads it.
*   Bad, because instruments alone answer none of the status questions —
    enrollment, topology, link verdicts arrive by a second channel
    regardless.

### In-band gathering

*   Good, because it rides channels the network already authenticates
    and routes, reading on demand, and status, instruments, and path
    truth meet at a monitor that already holds the directory's view.
*   Bad, because it is the widest surface inside the node — directory
    fields, a mount, a traceroute sender, a resident application — where
    the listener would have been one bind.

### The core

*   Good, because the coordination precedent holds: the one node every
    member reaches, already hosting the aggregated stores.
*   Bad, because visibility would acquire both a single point and a
    role privilege the architecture never gave it — and the backend is
    placed by resource and reachability, not by role; a core already
    carrying coordination, enrollment, and the directory is the least
    free host for it.

### A designated node

*   Good, because the monitor follows ADR-0014's shape exactly — loaded
    by name wherever the operator placed the backend — and several may
    load, since the channels are readable by any member.
*   Bad, because designation is an operational choice to document, and
    nothing gathers by default: a network whose operator loads no
    monitor keeps today's blindness.

### Node-local reads

*   Good, because per-neighbor volumes stay the node operator's own
    business, and nothing about who reads needs deciding.
*   Bad, because the network's view — the want that started this —
    cannot exist, and aggregation reduces to per-operator exports across
    an underlay that cannot reach.

### Membership-scoped reads

*   Good, because the authenticated channel already names the reader by
    chain: membership is a boundary the network states and enforces, and
    every operator may gather their own view.
*   Bad, because a member sees every member's neighbor volumes — the
    accepted cost of a shared view, and the reason the boundary is
    decided here rather than inherited.
