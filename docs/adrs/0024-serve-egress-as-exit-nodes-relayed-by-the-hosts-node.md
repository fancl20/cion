# Serve Egress as Exit Nodes Relayed by the Host's Node

*   Status: proposed
*   Date: 2026-10-24

[TOC]

## Context and problem statement

[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)
made internet egress a SOCKS service at every node's own tailnet address and
kept the netmap to the tailnet: a host chooses its exit by the address it
sends a flow to, and the tunnel carries no default route. The record named
its costs — transparent tunneling ceases, every flow pays a proxy handshake
before its first byte, UDP datagrams carry the SOCKS header — and hosts pay
them. A mihomo host chains a SOCKS outbound over its tailnet outbound: every
TCP flow waits out its handshake with the exit and then two more round trips
of SOCKS negotiation across the mesh before its first byte, every UDP
association holds a TCP connection beside it, and an application that speaks
no SOCKS — or a client line's own exit-node setting — reaches no internet at
all.

The tailnet client lines carry their own egress control: a client selects
one peer as its exit node, and its default routes go there. ADR-0012
declined it partly because an exit route "rides a client setting the network
neither sets nor verifies." Since capability version 122 the client lines
report that setting: a client names its selected exit in the map request it
sends after each change. The report trails the selection rather than
carrying it. The client re-points its default routes at the selected peer's
WireGuard key first, and whatever ends that key carries the host's internet
traffic. To a standard client an exit is a key it encrypts to, and a key
never moves between the peers a netmap names.

Under
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)'s
peer model a host's netmap holds one peer — its node — so the only exit a
client could select is the node it already reaches. Offering every node as
an exit makes every node a peer under a key the host encrypts to, and the
host reaches only its own node: its sessions start at that node's
host-facing endpoint, and the client lines never relay toward a
WireGuard-only peer through DERP. The client lines also send a destination
to the peer whose own addresses name it before they consult routes, so a
node's address belongs to the one peer that should receive its traffic.

A tailnet client resolves the names its applications dial through a resolver
of its own: the one the netmap names for its selected exit or, with none
named, the resolver of the system it runs on. SOCKS never asked it — a name
travelled to the exit inside the request — and the netmap names no resolver
today.

What exists to build on: the host's node already receives every datagram the
host sends; the SCION underlay already carries WireGuard datagrams between
nodes within the overlay's budget — an inner packet of 1280 bytes with
WireGuard's overhead and a worst-case SCION header inside 1500; every node's
key and serving address already ride the directory; and the netstack egress
the exit model built before ADR-0012 ended flows to any destination and
opened them again from the node's own sockets.

A tailnet client selects one exit at a time, so a host choosing its exit per
flow runs one client per exit, each its own login — written by hand, the
per-host configuration ADR-0011 set out to remove. The portal mints reusable
keys that each name a node
([ADR-0023](/docs/adrs/0023-admit-every-host-by-a-key-that-names-its-node.md)),
and mihomo can fetch a provider of outbounds through an outbound it already
holds and amend every entry before use.

This ADR decides how a host selects its exit, how the selection reaches the
exit, where exit traffic leaves, where its names resolve, and how per-flow
choice is offered.

## Decision drivers

*   **Standard Clients, Unmodified:** egress is the client lines' own
    exit-node selection — the vendor's and mihomo's — and the clients'
    behavior is a fixed input: nothing CION needs may depend on changing a
    client.
*   **No Negotiation per Flow:** a flow's first byte waits for its own
    handshake alone, and UDP travels as datagrams.
*   **The Mesh Carries Egress:** exit traffic crosses SCION paths between
    nodes, never the internet between host and exit.
*   **Only the Exit Reads Egress:** a host's internet traffic is readable
    where it leaves the network and nowhere on the way — protection end to
    end, the security model's stance.
*   **The Choice Stays in the Client:** which exit serves a flow is the
    client's data plane; the network keeps no per-host exit that could
    disagree with it.
*   **Unprivileged Node:** egress adds no kernel state and no capability.
*   **Per-Flow Choice Without Per-Host Configuration:** a host chooses its
    exit per flow without anyone writing a client per exit.
*   **Almost-Zero Config:** exits work with nothing configured, and every
    default is a working one.

## Considered options

How a selection reaches its exit:

*   **SOCKS per Destination:** ADR-0012 as it stands.
*   **Exit Identities on the Host's Node:** the host's node holds one
    WireGuard identity per exit, and the identity a host selects tells its
    node where to forward over the mesh.
*   **The Reported Exit's Label on the Node's Peer:** the host's node is its
    one exit-capable peer; control moves the label of the exit the client
    last reported onto it, and the node forwards by a registry field.
*   **Every Node a Peer, Relayed by the Host's Node:** each node is a peer
    under its own key, and the host's node forwards the host's datagrams for
    another node's key to that node unopened.
*   **Direct Tunnels:** each node is a peer at its own public endpoint, and
    the host's session crosses the internet to its exit.

Where exit traffic leaves:

*   **A Netstack Egress:** flows end in-process and leave from the node's
    own sockets.
*   **Kernel Forwarding:** the node routes and masquerades.

Where exit traffic's names resolve:

*   **The Client's Own Resolver:** the netmap names none, and a client
    resolves where it runs.
*   **Public Resolvers Through the Exit:** the netmap names public
    resolvers, and a client's queries leave through its selected exit.
*   **The Exit's Own Resolver:** each exit answers DNS at its own address
    with the resolver its host system uses.

How per-flow choice is offered:

*   **SOCKS per Flow:** the status quo.
*   **One Login, Cloned:** client instances share one login's state.
*   **Generated Instances:** each node serves its hosts a provider listing
    one client instance per exit.

## Decision outcome

Chosen options: **every node a peer, relayed by the host's node**, **a
netstack egress**, **public resolvers through the exit**, and **generated
instances** — realized as follows:

1.  **Every node is a peer under its own key.** A host's netmap names its
    own node as today and every other node beside it, each under its own
    WireGuard key, with its serving address — its slice's first — as its one
    address, and offering the exit routes. The host's own node keeps the
    hosts' addresses. A host selects an exit with its client's exit-node
    setting, by a node's serving address or name; with none selected, the
    tunnel carries the tailnet, and each node's address reaches that node.
    This narrows ADR-0011's decision 4, the netmap holding one peer, and
    ADR-0023's decision 3 with it, to the one peer holding the hosts.
2.  **The host's node relays, unopened.** Every peer's endpoint is the host's
    own node's host-facing endpoint. The node forwards each datagram that
    belongs to another node's session — a handshake by the MAC its initiator
    keyed to the responder's public key, every later message by the
    session's receiver index — over the SCION underlay to that node, and that
    node's answers back to the host, adding nothing to either. The host's
    session ends at the exit node, so the host's own node relays ciphertext.
    Relayed datagrams ride the underlay outside the mesh tunnels: the host's
    session already authenticates and encrypts them, and nesting would break
    the overlay's budget.
3.  **Every node serves every host.** A node accepts a session from any host
    the directory holds. Its answers to a host that reached it by relay
    leave through that session when they come from the node's own address or
    its egress; any other tailnet traffic toward the host keeps crossing the
    mesh to the host's own node, as today.
4.  **Exits end flows in-process.** A node's egress ends the TCP and UDP
    flows a host sends to the internet and opens them again from the node's
    own sockets, under ADR-0012's flow bounds and idle expiry, and ICMP echo
    relays. The client lines admit an exit only with both default routes, so
    the exit routes cover IPv6, and an exit drops IPv6: egress is IPv4. Every
    node offers by default, as ADR-0012's service did; a node whose
    applications leave the egress out still appears as an exit and carries
    nothing.
5.  **Names resolve through the exit.** A run argument names the public
    resolvers a node uses — Google's 8.8.8.8 and 8.8.4.4 by default — and
    any application that resolves a name asks them. The netmap names the
    founding core's resolvers for every exit, as the resolvers a client uses
    while that exit is selected: a client's queries leave through its exit
    like any other flow, and names resolve from the exit's region. With no
    exit selected, a client keeps its own resolver.
6.  **The reported exit is observed, not obeyed.** The coordination service
    records each host's reported exit beside its presence, for the
    operator's view, and nothing routes by it.
7.  **Per-flow choice is generated.** An application on every node serves,
    at the node's own address and on the tailnet alone, a mihomo proxy
    provider listing one tailnet client instance per exit, each with its own
    state and its exit selected. A host logs in once without an exit and
    fetches the provider through that login. The client injects into every
    instance one reusable key naming the host's node — the node never holds
    the key — so each instance registers as a host of its own on that node,
    and the client chooses among them per flow.
8.  **SOCKS retires.** The exits and the generated instances replace it
    whole: ADR-0012's service, its listener, and the delivery of each node's
    address to it are removed in the same landing. This record supersedes
    ADR-0012.

### Positive consequences

*   Any application and any client line reaches the internet: the vendor's
    clients select an exit from their own menus, and mihomo selects per flow
    among the generated instances.
*   A flow's first byte waits for its own handshake alone; UDP travels as
    plain datagrams; ICMP echo returns.
*   Only the exit reads a host's internet traffic: the host's own node
    relays ciphertext, where today it reads the SOCKS traffic it forwards.
*   The host's node no longer decrypts and re-encrypts egress, and exit
    traffic stays on SCION paths between nodes.
*   No key is derived, no directory entry grows, and the registry holds no
    per-host exit; a switch takes effect in the client's data plane at once.
*   Every node's address reaches that node directly.
*   Names resolve from the exit's region with nothing configured, and an
    operator can name other resolvers in one place.
*   Per-flow choice needs no hand-written client: the provider follows the
    directory as exits come and go.

### Negative consequences

*   A relay joins the nodes' data path outside the mesh tunnels, with
    failure modes of its own: the host's node keeps a table of the sessions
    it relays, and a restart loses it — relayed sessions resume only after
    their next handshake.
*   Every node holds every host, state that grows with hosts times nodes and
    is affordable only at the small scale the network targets.
*   A relayed datagram fills the overlay's budget exactly as a mesh datagram
    does: the relay can add no header, now or later.
*   Per-flow choice costs one login per exit per device, each holding an
    address of its node's slice of 253. Instances of a vanished exit stay
    registered until released, and the reusable key that admits them admits
    anyone holding it.
*   A tailnet client resolves through its own resolver, which the client
    lines drive at four upstream exchanges per name — A and AAAA, each over
    UDP and TCP at once — where SOCKS resolved once at the exit. An
    IPv4-only instance halves it and caching spares repeats; nothing removes
    it.
*   A third party answers every name a client resolves through an exit —
    Google, unless the operator names other resolvers — and sees the exit's
    address beside each one.
*   IPv6 egress stays absent, and a client handed an AAAA answer tries IPv6
    first and waits out its own fallback.
*   CION depends on more of the client lines' behavior — exit selection over
    WireGuard-only peers, routing by a peer's own addresses first, the fields
    that tell a client an exit serves no DNS proxy of its own — a standing
    compatibility commitment verified against both lines.
*   A vendor client selects one exit at a time; per-flow choice is mihomo's
    alone, and SOCKS-aware applications on other clients lose theirs with
    SOCKS.
*   ADR-0012's cost on unreachable UDP stands: a host whose UDP cannot reach
    its node has no tunnel, for the client lines never relay toward a
    WireGuard-only peer through DERP.

## Pros and cons of the options

### SOCKS per destination

*   Good, because it is built, and one login serves every exit.
*   Bad, because every flow pays the negotiation, UDP pays a header and a
    control connection, and only SOCKS-aware applications reach the
    internet.
*   Bad, because the host's node reads the traffic it forwards.

### Exit identities on the host's node

*   Good, because exit traffic rides the mesh tunnels that exist, and the
    identity a host selects tells its node the exit.
*   Bad, because every node derives and publishes an identity per exit,
    holds a device for each, and decrypts and re-encrypts egress it can
    read.
*   Bad, because each exit's peer needs an address nothing else routes, a
    label beside the real one.

### The reported exit's label on the node's peer

*   Good, because one identity serves every exit, and the node's change is
    the smallest.
*   Bad, because the choice becomes registry state that lags the client: a
    switch drops traffic until the netmap follows, and a node other than the
    core learns it a directory fetch later — the mutable exit ADR-0012
    rejected, now written by the client's own protocol.
*   Bad, because it rests on a label moving between peers, which the client
    lines tolerate and nowhere promise.

### Every node a peer, relayed by the host's node

*   Good, because every exit is the node itself, under the key it already
    has, and the host's session ends there.
*   Good, because the netmap names each node by its own address, and the
    client's exit setting needs nothing more.
*   Bad, because it costs a relay outside the mesh tunnels, and every host
    at every node.

### Direct tunnels

*   Good, because it needs no relay: the host's session goes straight to its
    exit.
*   Bad, because egress leaves the mesh for the internet between host and
    exit, and every host must reach every exit's endpoint.

### A netstack egress

*   Good, because it is the machinery ADR-0012's service already runs,
    unprivileged.
*   Bad, because every TCP flow ends at the exit and starts again, a
    congestion loop of the exit's own.

### Kernel forwarding

*   Good, because a flow crosses the exit untouched, one loop end to end.
*   Bad, because the node needs the capability to route and masquerade, and
    kernel state to keep.

### The client's own resolver

*   Good, because it costs nothing.
*   Bad, because names resolve by the resolver of the system the client runs
    on — the wrong region for the exit, every name seen where the client
    runs.

### Public resolvers through the exit

*   Good, because names resolve from the exit's region with no new service,
    and one run argument names the resolvers every application uses.
*   Bad, because a third party answers every name by default, and AAAA
    answers send clients after IPv6 the exit drops.

### The exit's own resolver

*   Good, because the exit's own resolver answers, no third party sees the
    names, and AAAA questions can be answered empty.
*   Bad, because every exit runs a resolver service beside its egress.

### SOCKS per flow

*   Good, because one login serves every exit.
*   Bad, because it keeps every cost of SOCKS per destination.

### One login, cloned

*   Good, because one registration serves every instance.
*   Bad, because instances sharing an identity on any node starve one
    another silently, and the client lines treat a cloned key as a mistake.

### Generated instances

*   Good, because each instance is an ordinary login, and the provider
    follows the directory.
*   Bad, because each instance is a registration and an address, and the
    client runs one tailnet engine per exit.
