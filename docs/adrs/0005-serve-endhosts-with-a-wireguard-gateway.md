# Serve Endhosts with a WireGuard Gateway

*   Status: accepted
*   Date: 2026-09-13

[TOC]

## Context and problem statement

CION's control plane discovers, verifies, and distributes path segments, and an
in-node path provider composes them into end-to-end SCION paths
([ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)).
Only the node's own control traffic consumes those paths, however. The data
plane's internal underlay requires hosts to submit SCION-structured packets
(`pkg/dataplane/udpip.go`), no local path API exists to produce them, and no
application-facing consumer has ever been built. The founding driver of
[ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md) — clients dynamically
selecting routing paths — is therefore unmet: there is no client that could
select anything.

ADR-0004 drew its scope boundary exactly here: endhost-facing path exposure
was deferred to "a follow-up consuming the same provider," with the data plane
needing no change. The provider now exists. This ADR decides how endhosts
obtain paths, how plain hosts without any SCION knowledge reach the network,
what carries their traffic between nodes, what forwards it between the
tunnels, and how the resulting key material is distributed.

## Decision drivers

*   **Standard Clients:** Hosts must reach the network with ordinary,
    widely deployed client software; SCION knowledge must not be a
    prerequisite for using CION.
*   **Path Choice for Clients:** Choosing a path — through a different
    operator, a different region — must be an action the endhost can take;
    which choices exist to choose among is the operator's to provision.
*   **Implementation Economy:** Proven components are consumed, not
    reimplemented: WireGuard for tunnels, gVisor's netstack for flow
    termination. What the node writes is a destination table and a splice —
    not a TCP/IP stack, not a packet NAT. Custom logic is reserved for what
    only CION has: SCION paths.
*   **Almost-Zero Config and Single Binary:** No new daemon, no per-host
    SCION setup, no secrets in the configuration file, no per-peer tunnel
    configuration copied between operators; the gateway lives in the CION
    binary like everything else, and runs unprivileged — no TUN devices, no
    network-administration capabilities.
*   **SCION as a Pure Forwarding Layer:** SCION forwards packets; it does not
    protect them. Protection is an end-to-end concern of the application
    riding the network. The network layer assumes no protection role and
    accretes no key material for one.
*   **Operator Sovereignty:** What transits or egresses an AS is the
    operator's decision, visible in their own configuration.
*   **Incremental Delivery:** The milestone consumes the ADR-0004 provider
    seam; the data plane is untouched.

## Considered options

How endhosts obtain paths:

*   **In-Process Path Library:** The node's applications link a library that
    resolves routes through the provider and speaks SCION sockets directly.
*   **Local Path API Service:** A daemon on the node answers path queries
    over a local socket, in the role of the reference implementation's
    endhost daemon.
*   **Per-Consumer Store Access:** Each consumer queries the path database
    and composes segments itself. (Rejected already by ADR-0004.)

How plain hosts enter the network:

*   **Embedded WireGuard Gateway:** The node terminates WireGuard tunnels from
    standard client software and forwards the decrypted packets over SCION.
*   **Transparent UDP Proxy:** The node maps local UDP ports to remote
    (ISD-AS, port) pairs and translates datagrams one to one.
*   **SCION-Aware Client Library:** Hosts run applications linked against a
    SCION socket library, the model of the reference implementation's
    endhost stack.

What the WireGuard tunnel connects:

*   **Node-to-Node Mesh over SCION:** Every node runs WireGuard; tunnels run
    between nodes, carried by the SCION transport; hosts are clients of their
    local node.
*   **Host-to-Exit End-to-End:** The host's tunnel extends untouched through
    the local node to the exit it selected; the local node only relays
    datagrams.
*   **Local Termination with Plain Transit:** The local node terminates host
    tunnels and forwards plain IP over SCION.

How a host selects an exit:

*   **Peer Key per Exit on a Shared Port:** One public UDP port serves all
    exits; the host's public key — configured under one exit's device —
    selects the exit, the shared socket demultiplexing by peer lookup.
*   **Listen Port per Exit:** One WireGuard listen port per offered exit; the
    port the client dials is the exit it gets.
*   **Destination-Based Routing:** One tunnel endpoint; the destination
    overlay address or the node's default route decides the exit.
*   **Per-Exit Server Key Pairs:** One node key pair per exit; the key the
    client peers with selects the exit.

How WireGuard key material is distributed:

*   **Local Generation with a Core-Published Directory:** Each node generates
    its WireGuard key pair locally and publishes the public key — with its
    gateway port and overlay subnet — to the core during enrollment; nodes
    fetch the directory from the core.
*   **Core-Issued Key Pairs:** The core generates and hands out private keys,
    as it hands out certificate chains.
*   **Static Configuration:** Every operator configures every peer's public
    key by hand.

What forwards between the tunnels:

*   **Kernel TUNs and Policy Routing:** Every device sits on a kernel TUN;
    the node provisions addresses, per-exit routing tables and rules, IP
    forwarding, and nftables masquerading.
*   **In-Process Routing with Netstack Egress:** Devices sit on in-process
    packet pipes; a destination table routes the overlay, and exits proxy
    internet flows through gVisor's netstack.

## Decision outcome

Chosen options: an **in-process path library**, an **embedded WireGuard
gateway** built as a **node-to-node mesh over SCION** with **one shared
host-facing port, the peer's key selecting its exit**, key material
**generated locally and published through a core-served directory**, and
**forwarding in-process with netstack-serviced egress** — realized as
follows:

1.  **The path library is the provider seam, not a new abstraction.** A
    SCION socket already carries datagrams over provider-supplied SCION
    paths and reverses arrival paths for replies; the path provider already
    resolves them. The library is the two of them in a package of their
    own, with the control plane as their first consumer — and the gateway,
    or any future in-process application, links it directly. No path API
    daemon exists; an application on a CION node is part of the node's
    process, and linking the library is how it becomes path-aware.
2.  **WireGuard runs on every node; tunnels connect nodes.** The gateway is
    an application in the SCION network, embedded in the CION binary — and
    behaves like one: it consumes the path library and the trust engine as
    any future application would, and owns its key and directory state. The
    binary embeds wireguard-go; a node's mesh peers are the other nodes'
    gateways,
    reached over the SCION network through a transport (`conn.Bind`)
    implemented on the SCION socket: every outgoing datagram is carried by a
    SCION packet over a provider-resolved path, and everything WireGuard
    contributes — peer authentication by public key, handshakes, retransmit,
    roaming, replay filtering — is inherited rather than reimplemented. One
    SCION socket on a fixed gateway port serves all of a node's mesh devices;
    an incoming datagram is delivered to whichever device holds the sender's
    public key as a peer, so the peer lookup demultiplexes the shared socket.
3.  **The gateway forwards in userspace; the node holds no kernel state.**
    Mesh and host devices sit on in-process packet pipes instead of kernel
    TUNs, and an in-process router moves packets between them: each host
    peer's /32 goes to its host device, each directory peer's subnet to its
    mesh device — longest prefix first — and everything else to the exit
    whose device decrypted the packet. Internet egress is flow-level
    proxying through gVisor's netstack: the exit terminates TCP flows — the
    host completes its handshake with the exit — and splices each to an
    outbound connection from the node's own address; a UDP flow maps to one
    socket with the addresses rewritten, the socket itself the reply
    mapping; echo ICMP is relayed per identifier; other IP protocols are
    dropped. Flow state is bounded and expired by idleness. A gateway node
    needs nothing but unprivileged UDP sockets — no TUN device, no
    network-administration capability, nothing provisioned.
4.  **Hosts are standard WireGuard clients of their local node on one shared
    port, one device per exit.** All host-facing devices share a single
    public UDP port and the node's key pair; a datagram arriving on it is
    delivered to every device, and the one whose peer table holds the
    sender's public key completes the handshake — the same peer-lookup
    demultiplexing the mesh socket performs. Each host public key is
    configured under exactly one exit, with its overlay address; WireGuard
    drops handshakes from keys the node has not configured, so host
    membership and each host's exit are the operator's list. A host keeps
    one peer configuration per key — the local node's public key, one
    address, the shared port — and chooses among its provisioned exits by
    choosing which of its keys it sends with; a host needing several exits
    at once runs several interfaces, one key each.
5.  **Exit selection is the router's default.** Traffic decrypted by the
    host-facing device of exit X is routed by the in-process table, whose
    default points at the tunnel to X; remote overlay subnets, as longer
    prefixes, win over the default and go direct. WireGuard's
    longest-prefix peer selection carries the same rule inside each tunnel.
    Replies find their device by the peer's address: each host address is
    configured under exactly one exit's device as its /32, so no subnet
    splitting exists.
6.  **One WireGuard key pair per node, generated locally, published through
    the core.** The key pair is created on first start and persisted in the
    application's own state, apart from the AS keys; it never appears in
    the configuration file. The gateway publishes its public key, gateway
    port, and overlay subnet to the core over its own authenticated
    channel — presenting the node's certificate chain, verified against
    the TRC, so the publishing ISD-AS is identified and a node cannot
    publish for another — on a cadence it owns, beginning once enrollment
    has produced the chain. The core node's gateway application stores the
    directory in its own store and serves it to every node, which refreshes
    it periodically and creates tunnels for peers as they appear. The core
    never generates or holds a private WireGuard key: issuing private keys
    would let it read all node-to-node traffic silently, a trust regression
    the certificate enrollment flow (CSRs from locally generated keys)
    deliberately avoids.
7.  **SCION remains a pure forwarding layer.** The node-to-node protection
    the mesh provides is an application choosing to protect itself, not a
    network service: WireGuard is the gateway's transport, and its
    confidentiality is a side effect of the implementation economy that
    motivated it. Nothing in the data plane, the control plane, or the trust
    architecture learns a WireGuard key or owes the gateway an obligation.
    Hosts that want protection beyond their access tunnel and the mesh have
    the same option every internet application has: end-to-end protection of
    their own.
8.  **Scope stays minimal.** Only host-initiated flows exist (the exit's
    flow proxying returns replies; nothing is published to the internet);
    host membership is the static per-node peer list, not control-plane
    distribution; one path per destination at a time — the freshest,
    resolved from local state, refreshed on expiry or error — with no policy
    engine, following ADR-0004. Overlay addressing is IPv4; the tunnel MTU
    is a code constant sized so an inner packet plus the WireGuard, UDP/IP,
    and SCION header stacks fits a standard 1500-byte MTU, enforced by the
    router.

### Positive consequences

*   Any host with a standard WireGuard client can use CION and choose its
    path by choosing which of its provisioned keys it sends with; no SCION
    software is ever installed on a host, and one UDP port serves everyone.
*   The single binary runs unprivileged — no TUN device, no
    network-administration capability, nothing to provision — deployable
    anywhere an unprivileged process runs, containers and shared hosts
    included.
*   The node's new code is device lifecycle, the SCION transport, directory
    plumbing, an overlay destination table, and the exit's flow splice;
    WireGuard, gVisor's netstack, and the operating system's outbound
    sockets do the rest.
*   Forwarding is entirely in-process, so tests exercise the production
    router and proxy rather than a simulated kernel leg; and netstack's
    endpoint mode leaves the node itself able to join the overlay later —
    in-process applications with real sockets over CION paths.
*   WireGuard supplies on the mesh leg exactly what SCION deliberately does
    not: authenticated, confidential tunnels between nodes, with no new
    protocol of our own.
*   Peer discovery is the core's directory: a new node's tunnel reaches every
    node without any operator copying keys or subnets between machines.
*   The gateway introduces no new trust anchor: keys are the application's
    own local state, publishing is authenticated by the node's TRC-anchored
    certificate chain over the gateway's own channel, and the directory
    rides the application's own store and channel.
*   The data plane, the SCION transport, and the provider are reused
    unchanged.

### Negative consequences

*   TCP through an exit is two spliced connections, not one: RTT, congestion
    control, and retransmission are per leg, and the two halves need not
    agree on MTU or options.
*   Only TCP, UDP, and echo ICMP traverse an exit; other IP protocols are
    dropped, and other ICMP is best-effort.
*   The exit's flow bounds, idle expiry, and echo mapping are CION's code —
    a new bug surface where a NAT appliance's was — and about 4 MB of
    vendored gVisor joins the module.
*   Overlay traffic leaves the operating system's tooling behind: no
    `tcpdump` or `iptables` on gateway devices, counters and logs instead.
*   The access node terminates its hosts' tunnels and can read their
    traffic; the mesh protects only the node-to-node leg. Both are inherent
    to the model; applications with stronger needs protect themselves
    end-to-end.
*   A device-per-exit and device-per-peer fan-out multiplies wireguard-go
    devices, and every handshake on the shared ports is decrypted by each
    device before one claims it; acceptable only because CION is
    non-scalable by design.
*   Exit choice is provisioned: a host cannot use an exit its operator has
    not configured for one of its keys, and a host that wants a new choice
    needs a new key provisioned on the node.
*   Host membership is manual: every host public key is configured on its
    node by hand until a later milestone distributes it.
*   Flow state at the exit ties a flow to one exit: mid-flow exit switching
    or exit failure drops the flow.
*   One path at a time per destination: diversity exists across exits
    (keys), not within one exit's traffic.

## Pros and cons of the options

### In-process path library

*   Good, because it is ADR-0004's plan executed: the provider is the only
    consumer seam, and every consumer gets identical paths.
*   Good, because there is no daemon to operate, no IPC protocol to define,
    and no second composition of segments to get wrong.
*   Bad, because non-linked applications cannot use it; the WireGuard
    gateway exists precisely to serve them.

### Local path API service

*   Good, because a stable local API serves arbitrary processes, not just
    in-process consumers.
*   Bad, because it invents a protocol the SCION drafts do not define, for
    an audience — arbitrary local processes — that CION's one-process-per-AS
    model does not have.
*   Bad, because it is a second composition seam beside the provider.

### Transparent UDP proxy

*   Good, because it is small and needs no crypto at all.
*   Bad, because it forwards datagrams, not flows: arbitrary TCP or ICMP
    through a plain UDP port mapping is not serviceable, and every
    application protocol needs its own mapping.

### SCION-aware client library

*   Good, because it is the reference architecture's model and the most
    direct expression of path awareness.
*   Bad, because it puts SCION software on every host, violating the
    standard-client driver; CION's hosts are plain.

### Embedded WireGuard gateway

*   Good, because WireGuard is widely deployed, audited, and present in
    every operating system a host is likely to run.
*   Good, because wireguard-go embeds as a library with a swappable
    transport, and its datagram orientation tolerates path rotation and
    reordering under an established flow.
*   Bad, because the node owns device lifecycle and a forwarding story, not
    just sockets.

### Node-to-node mesh over SCION

*   Good, because peer authentication between nodes is WireGuard's, not a
    new mechanism beside the TRC-anchored control plane.
*   Good, because handshakes, retransmit, roaming, and replay filtering are
    inherited from WireGuard rather than designed here.
*   Bad, because a device per peer and per exit multiplies state.

### Host-to-exit end-to-end

*   Good, because the access node cannot read user traffic, and the local
    node is a trivial relay.
*   Bad, because every host's public key must reach every exit — a
    network-wide membership distribution with no control-plane home.
*   Bad, because one client configuration across exits forces a shared exit
    key pair that any exit can impersonate.

### Local termination with plain transit

*   Good, because it keeps origin nodes unprivileged and adds no
    node-to-node crypto to explain.
*   Bad, because node-to-node datagrams would ride SCION bare — no peer
    authentication, roaming, or replay filtering — and the node would owe
    all of that machinery itself instead of inheriting WireGuard's.

### Peer key per exit on a shared port

*   Good, because one UDP port serves every host and every exit: one
    firewall rule, one client endpoint, no port-to-exit convention to
    document.
*   Good, because the demultiplexing is the peer lookup the mesh socket
    already performs — one pattern, used twice.
*   Good, because replies route by the peer's /32 on its exit's device; the
    subnet-split policy of the port model disappears.
*   Bad, because exit choice is provisioned per key: a host cannot dial an
    unprovisioned exit, where a port choice needs nothing on the node.

### Listen port per exit

*   Good, because a port is the one selector every WireGuard client already
    has, and any offered exit is usable with no per-host provisioning.
*   Good, because it needs no protocol: the mapping lives in the node's
    configuration and the router's per-exit defaults.
*   Bad, because the node opens and documents one port per exit, and reply
    routing needs the overlay subnet split into one source range per exit.

### Destination-based routing

*   Good, because routing by destination address is the familiar mental
    model with no policy-routing rules to provision.
*   Bad, because the exit then follows from the destination, not the user's
    choice: two hosts cannot reach the same destination through different
    exits without address gymnastics.

### Per-exit server key pairs

*   Good, because each exit is then cryptographically distinct, and a shared
    port demultiplexes naturally by which key decrypts.
*   Bad, because the client's peer configuration changes per exit — the node
    public key itself — which is exactly the fiddly client experience the
    shared key pair avoids.

### Local generation with a core-published directory

*   Good, because secrets never leave the node, matching the CSR-based
    enrollment pattern exactly.
*   Good, because the directory removes all peer configuration between
    operators, and the TRC-anchored channel authenticates who published
    what.
*   Bad, because the core is the directory's availability point, like it
    already is for enrollment.

### Core-issued key pairs

*   Good, because distribution is one flow with no publishing step.
*   Bad, because the core would hold every private key and could silently
    read all node-to-node traffic — the single point of trust ADR-0003
    already accepted for issuance, now extended to perpetual interception.

### Static configuration

*   Good, because it needs no protocol work at all.
*   Bad, because every membership change copies keys and subnets between
    operators by hand, the manual ceremony ADR-0003 removed for certificates
    and CION exists to avoid.

### Kernel TUNs and policy routing

*   Good, because the operating system's forwarding and NAT are proven at
    internet scale, and overlay traffic stays visible to the system's own
    tools — `tcpdump`, `iptables` — on the gateway devices.
*   Good, because the gateway itself implements no forwarding at all.
*   Bad, because every node needs a TUN device and `CAP_NET_ADMIN`, and the
    node must provision — or instruct an operator to provision — addresses,
    routing tables, rules, forwarding, and NAT, with a degraded mode
    wherever the privileges are missing.

### In-process routing with netstack egress

*   Good, because the node runs unprivileged and provisions nothing: the
    almost-zero-config driver is complete even where no
    network-administration privilege exists.
*   Good, because the overlay router is a destination table rather than an
    IP stack, and the internet leg terminates flows in a reusable userspace
    stack rather than a bespoke packet NAT.
*   Good, because the forwarding path is entirely in-process and therefore
    entirely testable.
*   Bad, because TCP through an exit is two spliced connections,
    non-TCP/UDP protocols are dropped, and flow bounds, expiry, and ICMP
    handling become the node's own code.
*   Bad, because overlay traffic leaves the operating system's tooling
    behind, and about 4 MB of vendored gVisor joins the module.
