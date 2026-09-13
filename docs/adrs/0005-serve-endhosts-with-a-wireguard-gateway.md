# Serve Endhosts with a WireGuard Gateway

*   Status: accepted
*   Date: 2026-09-12

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
what carries their traffic between nodes, and how the resulting key material
is distributed.

## Decision drivers

*   **Standard Clients:** Hosts must reach the network with ordinary,
    widely deployed client software; SCION knowledge must not be a
    prerequisite for using CION.
*   **Path Choice for Clients:** Choosing a path — through a different
    operator, a different region — must be an action the endhost can take;
    which choices exist to choose among is the operator's to provision.
*   **Implementation Economy:** Where the operating system already forwards,
    routes, and translates packets, the node must not reimplement it in
    userspace. Custom code is reserved for what only CION has: SCION paths.
*   **Almost-Zero Config and Single Binary:** No new daemon, no per-host
    SCION setup, no secrets in the configuration file, no per-peer tunnel
    configuration copied between operators; the gateway lives in the CION
    binary like everything else.
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

## Decision outcome

Chosen options: an **in-process path library**, an **embedded WireGuard
gateway** built as a **node-to-node mesh over SCION** with **one shared
host-facing port, the peer's key selecting its exit**, key material
**generated locally and published through a core-served directory** —
realized as follows:

1.  **The path library is the provider seam, not a new abstraction.**
    `controlplane.SCIONConn` already carries datagrams over provider-supplied
    SCION paths and reverses arrival paths for replies; `controlplane.
    PathProvider` already resolves them. The gateway — and any future
    in-process application — consumes both directly. No path API daemon
    exists; an application on a CION node is part of the node's process, and
    linking the library is how it becomes path-aware.
2.  **WireGuard runs on every node; tunnels connect nodes.** The CION binary
    embeds wireguard-go. A node's mesh peers are the other nodes' gateways,
    reached over the SCION network through a transport (`conn.Bind`)
    implemented on the SCION socket: every outgoing datagram is carried by a
    SCION packet over a provider-resolved path, and everything WireGuard
    contributes — peer authentication by public key, handshakes, retransmit,
    roaming, replay filtering — is inherited rather than reimplemented. One
    SCION socket on a fixed gateway port serves all of a node's mesh devices;
    an incoming datagram is delivered to whichever device holds the sender's
    public key as a peer, so the peer lookup demultiplexes the shared socket.
3.  **The operating system forwards between tunnels.** Each device sits on a
    kernel TUN. Routes for remote overlay subnets point at their tunnels, so
    overlay traffic between nodes is kernel forwarding; an egress node
    enables IP forwarding and masquerades overlay traffic to the public
    internet, so exit traffic and its conntracked replies are kernel
    forwarding too. The node provisions TUN devices, addresses, routes,
    forwarding, and NAT rules itself, and logs the exact commands as
    instructions where it lacks the privileges to run them. The gateway
    implements no routing, address translation, or flow table of its own.
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
5.  **Exit selection is policy routing.** Traffic decrypted by the
    host-facing device of exit X enters the kernel on that device's TUN and
    is routed by a per-exit routing table whose default route points at the
    tunnel to exit X; remote overlay subnets, as longer prefixes, win over
    the default and go direct. WireGuard's longest-prefix peer selection
    carries the same rule inside each tunnel. Replies find their device by
    the peer's address: each host address is configured on exactly one
    exit's device and routed by its /32, so no subnet splitting exists.
6.  **One WireGuard key pair per node, generated locally, published through
    the core.** The key pair is created on first start and persisted in the
    state directory beside the AS keys; it never appears in the
    configuration file. During enrollment — and re-enrollment — a node
    publishes its public key, gateway port, and overlay subnet to the core
    over the SCION-native channel, where the peer's verified certificate
    chain identifies the publishing ISD-AS; a node cannot publish for
    another. The core stores the directory beside the trust material and
    serves it to every node, which refreshes it periodically and creates
    tunnels for peers as they appear. The core never generates or holds a
    private WireGuard key: issuing private keys would let it read all
    node-to-node traffic silently, a trust regression the certificate
    enrollment flow (CSRs from locally generated keys) deliberately avoids.
7.  **SCION remains a pure forwarding layer.** The node-to-node protection
    the mesh provides is an application choosing to protect itself, not a
    network service: WireGuard is the gateway's transport, and its
    confidentiality is a side effect of the implementation economy that
    motivated it. Nothing in the data plane, the control plane, or the trust
    architecture learns a WireGuard key or owes the gateway an obligation.
    Hosts that want protection beyond their access tunnel and the mesh have
    the same option every internet application has: end-to-end protection of
    their own.
8.  **Scope stays minimal.** Only host-initiated flows exist (the NAT
    returns replies; nothing is published to the internet); host membership
    is the static per-node peer list, not control-plane distribution; one
    path per destination at a time — the freshest, resolved from local state,
    refreshed on expiry or error — with no policy engine, following
    ADR-0004. Overlay addressing is IPv4; the tunnel MTU is a code constant
    sized so an inner packet plus the WireGuard, UDP/IP, and SCION header
    stacks fits a standard 1500-byte MTU.

### Positive consequences

*   Any host with a standard WireGuard client can use CION and choose its
    path by choosing which of its provisioned keys it sends with; no SCION
    software is ever installed on a host, and one UDP port serves everyone.
*   Nearly all forwarding, return-path, and NAT behavior is the operating
    system's, proven at internet scale, instead of bespoke gateway logic; the
    node's new code is device lifecycle, the SCION transport, directory
    plumbing, and OS provisioning.
*   WireGuard supplies on the mesh leg exactly what SCION deliberately does
    not: authenticated, confidential tunnels between nodes, with no new
    protocol of our own.
*   Peer discovery is the core's directory: a new node's tunnel reaches every
    node without any operator copying keys or subnets between machines.
*   The gateway introduces no new trust anchor: keys are local state beside
    the AS keys, publishing is authenticated by the TRC-anchored control
    channel, and the directory rides the existing trust database pattern.
*   The data plane, the SCION transport, and the provider are reused
    unchanged.

### Negative consequences

*   Every node needs a privileged TUN device and `CAP_NET_ADMIN` — not just
    egress nodes — and test environments must provide them or skip the tests
    that need them.
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
*   NAT state ties flows to one exit: mid-flow exit switching or exit
    failure drops the flow.
*   One path at a time per destination: diversity exists across exits
    (ports), not within one exit's traffic.

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
*   Bad, because the node must run and configure real devices and TUNs
    instead of just sockets.

### Node-to-node mesh over SCION

*   Good, because tunnels on TUN devices hand routing, return paths, and NAT
    to the kernel: the largest part of a gateway's work disappears.
*   Good, because peer authentication between nodes is WireGuard's, not a
    new mechanism beside the TRC-anchored control plane.
*   Bad, because every node needs TUN privileges, and a device per peer and
    per exit multiplies state.

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
*   Bad, because the node must itself route between the decrypted traffic
    and the SCION transport — learned overlay routes, per-exit forwarders,
    reply mapping — exactly the bespoke forwarding this ADR's economy driver
    exists to avoid.

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
    configuration and the kernel's per-exit routing tables.
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
