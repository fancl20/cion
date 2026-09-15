# Address the gateway by SCION services

This proposal retires the gateway's fixed ports: the mesh transport and the
directory become SCION services, addressed by service value instead of
underlay port, beside [proposal
0006](/docs/proposals/0006-wireguard-gateway-application.md)'s application
in `pkg/apps/wireguard`. The data plane already owns the whole service
model — discovery registers the CS service and its greetings are delivered
by it — so the change is the path library learning to *name* a service
destination, the gateway registering its sockets as backends, and the
directory entries shedding the reachability data senders no longer need.

[TOC]

## Summary

The path library's `Addr` gains a service destination beside its underlay
address; `Conn.WriteTo` serializes a `HostTypeSVC` destination the
destination AS's router translates to a registered backend, the way it
delivers discovery's greetings to the CS service today. The gateway
registers its mesh socket under a CION-private service value in its own AS
and binds an ephemeral port; the mesh's configured endpoints name the peer
by ISD-AS and service, and directory entries shrink to ISD-AS, public key,
and overlay subnet — proposal 0006's implementation had to add the peer's
underlay address to entries because a fixed-port destination still needed
it; a service destination needs nothing. The core's directory socket
likewise binds an ephemeral port under its own service value, the
publishing client dials the core by ISD-AS and service, and `GatewayPort`
and `DirectoryPort` leave the code. Sessions roam to arrival addresses as
in proposal 0006; the service address is the rendezvous.

## Motivation

ADR-0005's implementation followed the drafts the way a port follows a
service: `GatewayPort` beside `EndpointPort`, the peer's underlay address
beside its key in the directory entry, the port rewrite in the node
assembly's directory route. SCION itself never works this way — services
are named by a service value the last router resolves into a local
backend, and the sender carries no reachability data at all. CION's data
plane implements exactly this for the CS service; proposal 0006 simply
could not use it, because the path library's address names a peer only by
ISD-AS and underlay address. Closing that gap removes the ports, the
underlay field in every directory entry, the entry-field gap proposal
0006's implementation history records, and the fixed-port collision class
the tests worked around — and gives the service model's anycast to any
future multi-socket node for free.

### Goals

*   Extend `pkg/scion`'s `Addr` and `Conn.WriteTo` to a service
    destination: an `addr.SVC` beside the ISD-AS, serialized as a
    `HostTypeSVC` destination address, delivered by the receiving AS's
    internal link to the registered backend and to no port the sender
    names.
*   Keep every existing consumer of the address unchanged: replies derive
    from a received packet's source host — always an ordinary IP — and
    the service field is zero for them.
*   Register the gateway's mesh socket as a service in its own AS, the
    socket on an ephemeral port; the configured mesh endpoint becomes
    "isd-as,service"; directory entries carry ISD-AS, public key, and
    overlay subnet only, with proposal 0006's stored entries decoded and
    their retired fields ignored.
*   Serve the core's directory as a service the same way, dial it from
    every other node by ISD-AS and service, and delete `GatewayPort` and
    `DirectoryPort` from `pkg/controlplane/transport.go`.
*   Preserve the session behavior of proposal 0006: the service address
    carries handshakes and keepalives until a peer's first arrival, and
    roamed arrival addresses with their reversed paths carry the session
    thereafter.

### Non-goals

*   Moving the control endpoint off `EndpointPort`, or discovery off its
    port: those are the drafts' own services and proposal 0004's
    machinery, and their underlay addresses ride the discovery greeting
    rather than a directory.
*   Multicast service values (the SVC flag's upper bit) and load-aware
    backend selection — the data plane's `Services` map already picks
    randomly among backends; CION's one node per AS makes the question
    moot.
*   Host-facing configuration: hosts are plain internet clients dialing a
    UDP port; the shared `listenPort` is the internet side of the node,
    not a SCION service, and stays.
*   Changes to WireGuard session management, the directory's cadence, the
    router, or the egress — they consume addresses, they do not name them.
*   A service registry protocol: registration is the node assembly
    handing the application its own provider, the same call discovery
    makes.

## Proposal

### Service destinations in the path library

`Addr` gains a `Service addr.SVC` field beside `Addr netip.AddrPort`; the
zero value means the destination is an underlay address, so every address
a receive path derives — the reversed arrival paths replies ride — is
unchanged. `Conn.WriteTo` builds the SCION destination host from the
service value when one is set, with `SetDstAddr(addr.HostSVC(...))`, the
serialization discovery's greetings already use. The inner UDP destination
port is not consulted on service delivery — the receiving internal link
takes the port from the registration — so the library writes zero and the
wire stays honest about carrying no port. A packet whose service has no
registered backend fails the receiving router's resolution, which answers
SCMP destination unreachable; as in proposal 0006, that exposure stays a
non-goal — the sender sees an unanswered send, WireGuard retransmits, and
the publish loop retries.

### A private service range

The drafts' registry names the low values (DS `0x0001`, CS `0x0002`, the
wildcard `0x0010`), and the SVC type's top bit is the multicast flag.
CION's own services take a private slice above both:
`0x7ff1` through `0x7fff`, with the constants living beside the
application that owns them — `SvcGateway` (`0x7ff1`) and `SvcDirectory`
(`0x7ff2`) in `pkg/apps/wireguard`. They are CION's convention the way
`proto/gateway/v1` is: the drafts define no gateway service, so the values
are ours to allocate and document.

### The mesh as a service

Every node's gateway registers its mesh socket — bound to an ephemeral
port — under `SvcGateway` in its own AS at startup, beside the host-facing
socket that keeps its configured port. The configured mesh endpoint
becomes "isd-as,gateway": `ParseEndpoint` reads the service name, the
handshake's first datagram resolves a path to the peer's ISD-AS and
addresses the service, and the peer's router delivers to the registered
backend. From the first received packet the peer's endpoint roams to its
arrival address exactly as in proposal 0006 — an underlay address and a
reversed path — and the session rides it; the service address is what the
persistent keepalive returns to when no arrival has been seen and what a
restarted peer's fresh registration heals toward. The cookie digest
endpoint methods compute carries the service value in place of the
address. Directory entries lose `gateway_port` and `underlay`: a peer is
its ISD-AS, its key, and its subnet.

### The directory as a service

The core node's gateway registers its directory socket under
`SvcDirectory` and binds an ephemeral port; every other node dials the
core by ISD-AS and service, so the node assembly's directory route
collapses to the core's ISD-AS with a provider path — the underlay
endpoint address and the port rewrite go. Stored entries from proposal
0006 decode with their retired fields ignored, the same leniency the
store's JSON round-trip already has. `GatewayPort` and `DirectoryPort`
leave `pkg/controlplane/transport.go`; `EndpointPort` stays, beside the
discovery port.

### Registration and node wiring

The gateway's `Config` gains a registration callback —
`RegisterSvc func(svc addr.SVC, port uint16) error` — that the node
assembly implements over the data plane's provider, the same `AddSvc`
discovery calls; `Close` deregisters. Startup order is unchanged: the
mesh socket binds and registers after the path provider exists, the core's
directory socket beside it; nothing serves before `Run`.

## Test plan

*   **Unit tests:** the service-destination header — `WriteTo` serializes
    a `HostTypeSVC` destination and the receiving internal link delivers
    to the registered backend's port, with no backend yielding the
    router's unreachable path; the endpoint string's round trip with the
    service name and its malformed forms; the cookie digest over a service
    endpoint; directory entries without port or underlay round-tripping
    through the store and the wire, and proposal 0006-shaped stored
    entries decoding with their retired fields ignored.
*   **Integration tests:** proposal 0006's proofs re-run unchanged on
    service addresses — the nodes publish and fetch the directory through
    the core's service, mesh handshakes ride it, and the host-to-host
    echo and internet egress flows carry as before — with the directory
    assertions on entries of the new shape.
*   **Negative tests:** a service with no registered backend fails the
    send and the publish loop retries rather than erroring; a stale
    entry's retired fields change nothing; an unparseable endpoint string
    is refused at configuration.

## Implementation history

*   Path library: `Addr.Service` beside the underlay address, the zero
    value meaning underlay so every receive-derived address is unchanged;
    `WriteTo` serializes the service destination with `SetDstAddr` and a
    zero inner UDP destination port. The string form of a service
    destination is `isd-as,svc:xxxx` — the numeric value, since the
    library knows no names — and the SCION-native channel's URL authority
    (`PeerAuthority`) rides it, so the directory client dials the core by
    authority the way it always has.
*   Application: the constants live in `pkg/apps/wireguard` as `SvcGateway`
    and `SvcDirectory`, with the name table the IPC endpoint string reads
    (`"isd-as,gateway"`) — `ParseEndpoint` refuses a name the table does
    not hold, underlay forms included. The mesh devices' IPC drops
    `listen_port` outright: the shared socket owns an ephemeral port no
    device names. `Config.RegisterSvc` gained a sibling `UnregisterSvc`
    for `Close`'s deregistration — one callback cannot express both
    directions over the provider's `AddSvc`/`DelSvc`.
*   Directory: the wire entry's retired fields left `proto/gateway/v1`
    outright — `overlay_subnet` renumbered to 3, nothing reserved, since no
    deployment ever carried proposal 0006's numbering — while the store's
    JSON decode keeps ignoring the retired keys a proposal-0006 state
    directory may hold, a re-publish replacing an old-shape entry wholesale.
    The node assembly's `registerSvc` derives the registration's host from
    the control address, the host its `scionConn` binds, so the router's
    resolution meets the socket the application bound.
*   Tests: the service header's wire form and the two-node delivery with
    its reply beside the unanswered send to an unregistered service; the
    authority round trip over both forms and the publish-side dial that
    fails rather than hangs when no backend answers; the endpoint string's
    round trip with its malformed forms and the cookie digest carrying the
    service value; the store's leniency toward proposal 0006's shape; and
    the registration lifecycle around `New`/`Close`. The integration proofs
    re-ran unchanged on the service addresses.
