# Serve Egress as an Overlay SOCKS Service

*   Status: accepted
*   Date: 2026-09-26

[TOC]

## Context and problem statement

[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md) gave
hosts a path choice and made it a provisioning act: every host public key was
configured under exactly one exit's device, traffic decrypted by exit X's
device routed by the table's default into X's tunnel, and a host chose "by
choosing which of its keys it sends with." The costs were accepted in the
record itself — exit choice provisioned, a new choice a new key, a
device-per-exit fan-out multiplying state and shared-port handshakes, flow
state tied to one exit.
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
retired that whole boundary at its landing: hosts are tailnet clients,
membership is a registration the one admission seam answers, the per-exit
devices and the `exits` and `exit` fields are deleted, the host default went
with them, and the host space renumbered into the tailnet range.

What that landing left open is this record's reason: the tunnel carries the
tailnet and nothing else — no default route is advertised, internet
reachability through the tunnel is not a property of the join — and the
egress machinery stands unfed, the netstack and its flow bounds built for an
exit no path reaches. The endhost still holds no routing decision. The
founding driver of
[ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md) — clients dynamically
selecting routing paths — has no client-side expression at all, and the exit
is the granularity a user actually feels: it decides which operator sees the
flow, which region it leaves from, what the destination observes.

What exists to build on: the directory, which distributes node entries —
key, slice, host endpoint — and host entries beside them on one
authenticated `List`; the netmap, the client's whole configuration, which
already carries every allocated host /32 as a single-IP route the client
lines hold unconditionally; the egress itself, whose UDP mapping — one
socket per flow, the socket the reply mapping — is already the shape of a
relay, and whose netstack leaves the node able to join its own overlay with
in-process sockets; and the client, whose applications name destinations
freely.

This ADR decides how a host selects its egress, what carries the service,
and what the netmap carries. Membership is ADR-0011's, landed; NAT traversal
is the client's own, and the relay fallback's limit is carried below among
the consequences.

## Decision drivers

*   **Client Path Choice:** Exit selection is the endhost's routing action:
    per flow, switchable at runtime, with no operator ceremony per choice.
    ADR-0001's founding driver, taken at exit granularity.
*   **Standard Clients:** Hosts stay the tailnet clients ADR-0011 admitted —
    the vendor's line or a compatible one — and no CION software is required
    on a host. Richness a host adds on top — per-app rules, latency
    preferences — is optional client territory, never a prerequisite.
*   **One Login for the Network's Life:** A host's login — the one
    configuration its client holds — survives new exits and changed choices
    unchanged.
*   **Mechanism over Policy:** Which exits exist is mechanism the directory
    distributes; which exit serves a flow is the client's policy. The node
    holds neither.
*   **Protocol over Presets:** The egress service speaks a standard, audited
    protocol rather than a bespoke wire format, and UDP remains first class —
    no UDP encapsulated in TCP.
*   **Unprivileged Node:** The service adds no kernel state and no new
    capability; it runs on sockets the node already holds.
*   **Operator Sovereignty:** What egresses an AS is its operator's offer —
    this record makes every node offer by default, adds nothing to the
    directory entry the offer rides, and leaves the offer's surface, which
    applications a node runs, to the applications architecture record to
    come — with admission riding the seam, per ADR-0009's operating
    assumption that one operator runs an ISD.
*   **Scope Stays Minimal:** No per-host egress policy, no naming service;
    membership is ADR-0011's landed subject and stays closed here.

## Considered options

How a host selects its egress:

*   **Provisioned Exit per Key:** Restore ADR-0005's assignment — each host
    pinned to one exit by configuration.
*   **Mutable Exit in the Directory:** A host's entry carries a changeable
    exit that a side channel re-points, and the node re-routes the host's
    default.
*   **Egress as an Overlay Service:** Egress nodes serve a proxy protocol at
    a tailnet address; the destination a client sends to is the exit it
    uses.

What carries the service:

*   **HTTP CONNECT:** A TCP-only proxy at the tailnet address.
*   **A Bespoke Egress Protocol:** A CION-defined service protocol.
*   **SOCKS5 with UDP ASSOCIATE:** RFC 1928, both commands.

What the netmap carries:

*   **Tailnet Plus a Default Exit:** Advertise a default route in the
    netmap — every host's client makes its node an implicit exit for traffic
    routed nowhere finer.
*   **Tailnet Only:** Internet egress exists solely as the advertised
    service; the map carries no default.

## Decision outcome

Chosen options: **egress as an overlay service**, carried by **SOCKS5 with
UDP ASSOCIATE**, with the netmap carrying **the tailnet only** — realized as
follows:

1.  **Egress nodes serve SOCKS5 on their own tailnet address.** A node
    running egress holds the first address of its slice of the tailnet
    range — the node's own address, the netstack's claim, which the
    allocator never issues to a host — and traffic addressed to it is
    delivered in-process to a SOCKS listener through the same netstack the
    egress stands on: the minimal case ADR-0005 noted, the node joining its
    own overlay with in-process sockets. The listener binds the tailnet
    only; no egress socket is internet-facing. CONNECT splices TCP flows and
    UDP ASSOCIATE relays UDP flows through the egress machinery that exists
    — flow bounds and idle expiry unchanged, outbound legs from the node's
    own address as today.
2.  **The dialect is pinned.** The listener offers no authentication method
    beyond none — tailnet reachability is the admission, since hosts exist
    only through registration at the one seam. A UDP ASSOCIATE reply carries
    the exit's true tailnet address; a client must never be asked to guess
    its relay. The relay answers the association peer's arrival address, its
    lifetime is the association's TCP connection, and fragmented datagrams
    are refused. Nothing relays UDP inside TCP. The SOCKS UDP header costs
    ten bytes of a tailnet datagram to an IPv4 destination; the payload
    budget an application should assume — 1242 bytes over the client's
    default tunnel MTU of 1280 — follows from it.
3.  **The netmap carries the serving addresses; every node serves.**
    Nothing new rides the directory entry: the serving address is the
    first address of the slice the entry already carries, and every
    node's own address joins the routed addresses as one more single-IP
    route, the same form the allocated host /32s already take and the client
    lines route unconditionally — a covering prefix would sit behind the
    client's route-all preference, a preference no host of this network is
    asked to hold. Every node offers by default; the surface that would
    withhold the offer — which applications a node runs — is the
    applications architecture record's to draw, and this record accepts
    the default-on exposure until then. The mesh needs nothing new: the
    slice routing that carries a destination to its node's mesh device
    already carries the serving address within it. Every client learns
    the address from the map it already holds.
4.  **Exit selection is the client's destination decision.** One login, one
    netmap serve every advertised exit: the exit a flow uses is which
    tailnet address the flow is sent to — an application's proxy setting,
    or a local rule-based front-end a host may run for per-application or
    latency-aware choice. Switching exits changes no state anywhere in the
    network. A standard tailnet client reaches the service the way it
    reaches any host: the map carries the address, and applications point
    at it.
5.  **The netmap carries the tailnet; egress is a service, not a default.**
    No default route is advertised — the shape ADR-0011's landing already
    carries, the tunnel holding the tailnet alone — and this record keeps
    it on its own ground: a destination no slice claims counts unroutable,
    no implicit exit exists, and internet reachability is exactly the
    advertised services. The echo-ICMP relay retires with the default it
    served.
6.  **The trust shape is unchanged.** SOCKS exchanges ride inside the host's
    tunnel and the mesh — host to node the client's own WireGuard, node to
    node the SCION underlay — the same on-path readers ADR-0011 carries,
    and no new one. The offer is the advertisement: an egress node serves
    the hosts the registry admits to the tailnet, and finer per-host egress
    policy is declined — with one operator per ISD it would be ceremony
    without a threat model.

### Positive consequences

*   The endhost holds a routing action at last: exit choice is per flow,
    runtime-switchable, and discovered rather than provisioned — the
    founding driver's first client-side expression.
*   One login serves the network for its life: exits appear and vanish by
    advertisement, and no host, node configuration, or key changes with a
    choice.
*   No exit state returns to the node: the device-per-exit fan-out and the
    shared-port handshake multiplication are deleted at ADR-0011's landing,
    and this record adds none back — an address, a listener, and the
    machinery the node already runs.
*   Egress gains a protocol boundary in RFC 1928 — standard, audited,
    implemented everywhere — with destination addressing in place of any
    per-exit WireGuard state.
*   UDP keeps flow semantics without TCP encapsulation; the relay is the UDP
    mapping the egress already was, now addressed by its client.
*   The node stays unprivileged and unchanged in its sockets.

### Negative consequences

*   Transparent internet tunneling ceases: a host reaches the tailnet only,
    and internet access requires SOCKS-aware applications or a local
    forwarder. The plainest clients pay the most for the choice this record
    buys.
*   Internet ICMP is gone: SOCKS carries TCP and UDP, and the echo relay it
    retires had no protocol to inherit it.
*   Every flow pays a proxy handshake before its first byte, and UDP
    datagrams carry the SOCKS header.
*   An egress node serves every admitted host alike; per-host egress
    restriction has no mechanism, by the same single-operator assumption
    [ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
    rides.
*   The slice's first address is load-bearing twice over: the node's own,
    and the address the service answers on — renumbering a slice moves the
    service, and the address is never the operator's to repurpose.
*   The service's reachability is the tunnel's reachability: the vendored
    client line refuses DERP sends to wireguard-only peers, so under
    ADR-0011's peer model a host on a network where UDP to its node cannot
    pass has no relay path, no tunnel, and therefore no egress — the
    node-side bridge leg stands landed, and the host-side leg is the cost
    this boundary carries.

## Pros and cons of the options

### Provisioned exit per key

*   Good, because the model was built and tested, and could be restored
    without protocol work.
*   Good, because exit policy sits with the operator, where ADR-0005 placed
    operator sovereignty.
*   Bad, because the host's action is a provisioning echo rather than a
    routing decision: fixed per key rather than per flow, not switchable at
    runtime, and a new choice is a new assignment on the node.
*   Bad, because it costs the device-per-exit fan-out and multiplies every
    shared-port handshake across exits.

### Mutable exit in the directory

*   Good, because the login never changes and the routing follows machinery
    the directory already runs.
*   Bad, because the choice leaves the host: a side channel speaks for it,
    per host rather than per flow, and the network re-points a default it
    can no longer claim not to hold.
*   Bad, because it adds a writable per-host knob the operator now owns — a
    second membership surface beside the registry.

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

### Tailnet plus a default exit

*   Good, because the plainest clients keep transparent internet with
    nothing to learn.
*   Bad, because the default is an exit choice the network makes for the
    host — the provisioned model surviving inside the service model.
*   Bad, because a default route is an exit route the client lines carry
    only for the exit node they select, so the implicit exit rides a
    client setting the network neither sets nor verifies.
*   Bad, because two egress paths are two behaviors to secure, test, and
    explain.

### Tailnet only

*   Good, because one mechanism serves all egress, and no hidden default can
    disagree with the advertised set.
*   Good, because the map keeps the shape ADR-0011 drew — the tailnet,
    single-IP routes, no route-all preference asked of any host.
*   Bad, because a host that cannot speak to a proxy has no internet
    reachability at all.
