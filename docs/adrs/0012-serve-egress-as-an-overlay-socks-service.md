# Serve Egress as an Overlay SOCKS Service

*   Status: draft
*   Date: 2026-09-22

[TOC]

## Context and problem statement

[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md) gave
hosts a path choice and made it a provisioning act: every host public key is
configured under exactly one exit's device, traffic decrypted by exit X's
device routes by the table's default into X's tunnel, and a host chooses "by
choosing which of its keys it sends with." The costs were accepted in the
record itself — exit choice is provisioned, a new choice needs a new key, a
device-per-exit fan-out multiplies state and makes every shared-port handshake
decrypt per exit, and flow state ties each flow to one exit.

The deeper gap is that the endhost holds no routing decision. The founding
driver of
[ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md) — clients dynamically
selecting routing paths — currently has no client-side expression at all, and
the exit is the granularity a user actually feels: it decides which operator
sees the flow, which region it leaves from, what the destination observes.
Meanwhile everything else about reachability already travels by directory: a
node's key and overlay subnet appear as it joins, and peers learn them without
ceremony. The one thing a host cannot discover is where egress is offered, and
the one decision left in the application's configuration file is the one the
client is best placed to make.

What exists to build on: the mesh directory, authenticated by the trust
fabric and fetched on cadence; the egress itself, whose UDP mapping — one
socket per flow, the socket the reply mapping — is already the shape of a
relay; and ADR-0005's own observation that netstack's endpoint mode leaves the
node able to join its own overlay with in-process sockets — the seam an
in-overlay service needs.

This ADR decides how a host selects its egress, what carries the service, and
what the host tunnel carries. Host membership is
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)'s subject;
NAT traversal remains the deferred milestone
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md) left
it. Nothing here depends on either.

## Decision drivers

*   **Client Path Choice:** Exit selection is the endhost's routing action:
    per flow, switchable at runtime, with no operator ceremony per choice.
    ADR-0001's founding driver, taken at exit granularity.
*   **Standard Clients:** Hosts stay plain WireGuard clients; no CION
    software is required on a host. Richness a host adds on top — per-app
    rules, latency preferences — is optional client territory, never a
    prerequisite.
*   **One Configuration for the Network's Life:** A host's tunnel — the
    node's key, its own address, the shared port — survives new exits and
    changed choices unchanged.
*   **Mechanism over Policy:** Which exits exist is mechanism the directory
    distributes; which exit serves a flow is the client's policy. The node
    holds neither.
*   **Protocol over Presets:** The egress service speaks a standard, audited
    protocol rather than a bespoke wire format, and UDP remains first class —
    no UDP encapsulated in TCP.
*   **Unprivileged Node:** The service adds no kernel state and no new
    capability; it runs on sockets the node already holds.
*   **Operator Sovereignty:** What egresses an AS is its operator's offer —
    visible, withdrawable — with admission riding enrollment, per ADR-0009's
    operating assumption that one operator runs an ISD.
*   **Scope Stays Minimal:** No per-host egress policy, no naming service;
    the membership and NAT-traversal milestones stay where they are.

## Considered options

How a host selects its egress:

*   **Provisioned Exit per Key:** Keep ADR-0005's assignment — the operator
    configures each host key under one exit's device.
*   **Mutable Exit in the Directory:** A host's entry carries a changeable
    exit that a side channel re-points, and the node re-routes the host's
    default.
*   **Egress as an Overlay Service:** Egress nodes serve a proxy protocol at
    an overlay address; the destination a client sends to is the exit it
    uses.

What carries the service:

*   **HTTP CONNECT:** A TCP-only proxy at the overlay address.
*   **A Bespoke Egress Protocol:** A CION-defined service protocol.
*   **SOCKS5 with UDP ASSOCIATE:** RFC 1928, both commands.

What the host tunnel carries:

*   **Overlay Plus a Default Exit:** Keep 0.0.0.0/0 semantics — the local
    node remains an implicit exit for hosts that route everything through
    the tunnel.
*   **Overlay Only:** Internet egress exists solely as the advertised
    service; the router has no default.

## Decision outcome

Chosen options: **egress as an overlay service**, carried by **SOCKS5 with
UDP ASSOCIATE**, with the host tunnel carrying **the overlay only** —
realized as follows:

1.  **Egress nodes serve SOCKS5 on their own overlay address.** A node
    running egress holds the first address of its overlay subnet — the
    node's own overlay address — and the router delivers traffic addressed
    to it to an in-process SOCKS listener, the same delivery a host's /32
    receives to its device. The listener binds the overlay only; no egress
    socket is internet-facing. CONNECT splices TCP flows and UDP ASSOCIATE
    relays UDP flows through the egress machinery that exists — flow bounds
    and idle expiry unchanged, outbound legs from the node's own address as
    today. This is the minimal case of the future ADR-0005 noted: the node
    joining its own overlay with in-process sockets.
2.  **The dialect is pinned.** The listener offers no authentication method
    beyond none — overlay reachability is the admission, since hosts exist
    only through enrollment and one operator runs an ISD. A UDP ASSOCIATE
    reply carries the exit's true overlay address; a client must never be
    asked to guess its relay. The relay answers the association peer's
    arrival address, its lifetime is the association's TCP connection, and
    fragmented datagrams are refused. Nothing relays UDP inside TCP. The
    SOCKS UDP header costs ten bytes of an overlay datagram to an IPv4
    destination; the payload budget an application should assume — 1242
    bytes over the tunnel MTU of 1280 — follows from it.
3.  **The directory advertises egress.** A node's entry gains an egress
    mark, and the serving address is the advertising node's own overlay
    address, so nothing rides the entry beyond the subnet it already
    carries. Offering egress is a run argument, as the egress flag is
    today; withdrawal is the mark's disappearance. Every node — and through
    it every host — learns the offer from the directory it already
    fetches.
4.  **Exit selection is the client's destination decision.** The per-exit
    host devices, the per-exit table defaults, and the `exits` and `exit`
    configuration fields are deleted; a host peer is a public key and an
    address. One host key, one device, one client configuration serve every
    advertised exit: the exit a flow uses is which overlay service the flow
    is sent to — an application's proxy setting, or a local rule-based
    front-end a host may run for per-application or latency-aware choice.
    Switching exits changes no state anywhere in the network. A standard
    WireGuard client reaches the service the same way any client does: a
    tunnel whose allowed IPs cover the overlay, and applications pointed at
    the exit's address.
5.  **The host tunnel carries the overlay; egress is a service, not a
    default.** A host's peer allowed IPs name the overlay, not 0.0.0.0/0;
    internet-destined packets arriving from a host are dropped. No implicit
    exit exists, the router's table has no default, and internet
    reachability is exactly the advertised services. The echo-ICMP relay
    retires with the default it served.
6.  **The trust shape is unchanged.** SOCKS exchanges ride inside the host's
    tunnel and the mesh — the same on-path readers ADR-0005 acknowledged,
    and no new one. The offer is the advertisement: an egress node serves
    the hosts the directory admits to the overlay, and finer per-host
    egress policy is declined — with one operator per ISD it would be
    ceremony without a threat model.

### Positive consequences

*   The endhost holds a routing action at last: exit choice is per flow,
    runtime-switchable, and discovered rather than provisioned — the
    founding driver's first client-side expression.
*   One host configuration serves the network for its life: exits appear and
    vanish by advertisement, and no host, node configuration, or key changes
    with a choice.
*   The application's configuration loses its exit surface entirely, and the
    device-per-exit fan-out and shared-port handshake multiplication it
    caused are deleted with it.
*   Egress gains a protocol boundary in RFC 1928 — standard, audited,
    implemented everywhere — replacing per-exit WireGuard state with
    destination addressing.
*   UDP keeps flow semantics without TCP encapsulation; the relay is the UDP
    mapping the egress already was, now addressed by its client.
*   The node stays unprivileged and unchanged in its sockets: the service is
    one listener and the machinery it already runs.

### Negative consequences

*   Transparent internet tunneling ceases: a host routing 0.0.0.0/0 through
    the tunnel reaches the overlay only, and internet access requires
    SOCKS-aware applications or a local forwarder. The plainest clients pay
    the most for the choice this record buys.
*   Internet ICMP is gone: SOCKS carries TCP and UDP, and the echo relay it
    replaces had no protocol to inherit it.
*   Every flow pays a proxy handshake before its first byte, and UDP
    datagrams carry the SOCKS header.
*   An egress node serves every enrolled host alike; per-host egress
    restriction has no mechanism, by the same single-operator assumption
    [ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
    rides.
*   The subnet's first address becomes load-bearing: it is the node's own,
    and a peer configuration that assigns it to a host collides with a
    service.

## Pros and cons of the options

### Provisioned exit per key

*   Good, because it is built, tested, and needs no protocol work.
*   Good, because exit policy sits with the operator, where ADR-0005 placed
    operator sovereignty.
*   Bad, because the host's action is a provisioning echo rather than a
    routing decision: fixed per key rather than per flow, not switchable at
    runtime, and a new choice is a new key on the node.
*   Bad, because it costs the device-per-exit fan-out and multiplies every
    shared-port handshake across exits.

### Mutable exit in the directory

*   Good, because the tunnel configuration never changes and the routing
    follows machinery the directory already runs.
*   Bad, because the choice leaves the host: a side channel speaks for it,
    per host rather than per flow, and the network re-points a default it
    can no longer claim not to hold.
*   Bad, because it adds a writable per-host knob the operator now owns — a
    second membership surface beside the peer list.

### Egress as an overlay service

*   Good, because the destination is the one selector every client can
    already express: per flow, runtime-switchable, and costing no network
    state.
*   Good, because it converts exit policy from node configuration into
    client routing — the side of the boundary ADR-0001 wanted it on.
*   Bad, because it costs a service: an address, a listener, a protocol —
    and the transparency a default route gave.

### HTTP CONNECT

*   Good, because it is the simplest proxy protocol a client can speak.
*   Bad, because it is TCP-only, and UDP parity fails at the first DNS or
    QUIC flow.

### A bespoke egress protocol

*   Good, because it could carry ICMP and express CION concepts natively.
*   Bad, because a new wire format is a new audit surface, and every client
    of the service is software this project wrote — the standard-client
    driver forfeited exactly where it matters.

### SOCKS5 with UDP ASSOCIATE

*   Good, because RFC 1928 is standard, audited, and implemented everywhere;
    any SOCKS-capable application becomes a client with no CION involvement.
*   Good, because UDP ASSOCIATE matches the egress's existing UDP mapping
    one to one — the mechanism was already this protocol's shape.
*   Bad, because it carries no ICMP and no authentication, and its UDP leg
    costs a header and a rendezvous TCP connection per association.

### Overlay plus a default exit

*   Good, because the plainest clients keep transparent internet with
    nothing to learn.
*   Bad, because the default is an exit choice the network makes for the
    host — the provisioned model surviving inside the service model.
*   Bad, because two egress paths are two behaviors to secure, test, and
    explain.

### Overlay only

*   Good, because one mechanism serves all egress, and no hidden default can
    disagree with the advertised set.
*   Good, because the router's table loses its last policy and the host peer
    loses its last exit-coupled field.
*   Bad, because a host that cannot speak to a proxy has no internet
    reachability at all.
