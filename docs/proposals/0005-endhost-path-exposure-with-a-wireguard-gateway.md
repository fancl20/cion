# Implement endhost path exposure with a WireGuard gateway

This proposal outlines the implementation of the endhost layer decided in
[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md): the
path library consuming the ADR-0004 provider, an embedded WireGuard gateway
whose node-to-node tunnels ride SCION, the core-published peer directory,
per-exit host ports with policy routing, and internet egress through NAT. The
data plane is untouched.

[TOC]

## Summary

Every path CION discovers is consumed by nothing but the node's own control
traffic, and the internal underlay accepts only SCION-structured packets, so
no application can use the network. This proposal builds the consumer: a
`pkg/gateway` embedding wireguard-go, where hosts are standard WireGuard
clients of their local node, nodes tunnel to each other through a WireGuard
transport (`conn.Bind`) implemented on the SCION socket over provider paths,
and the operating system forwards between the tunnels — kernel routing for
overlay traffic, kernel NAT at egress nodes. Nodes publish their gateway
public keys through the core's control endpoint, authenticated by the
TRC-anchored channel, so tunnels to new peers need no configuration copied
between operators. A host's public key selects its exit: one shared host-facing
port serves every exit, demultiplexed by peer lookup.

## Motivation

ADR-0004 deferred endhost exposure to a follow-up consuming the same
provider; the provider now exists, and ADR-0005 decides the shape. The
founding driver of ADR-0001 — clients dynamically selecting routing paths —
has never had a client: nothing produces SCION-structured packets for an
application, and no application-facing consumer of `PathProvider` exists.
WireGuard supplies what the access side needs (standard clients, peer
authentication, confidentiality to the node) while the node-to-node tunnels
hand routing, return paths, and NAT to the kernel, leaving the node's own
code to the one thing only CION has: SCION paths.

### Goals

*   Embed wireguard-go in the CION binary behind the node's configuration,
    with the node's WireGuard key pair generated locally on first start and
    persisted in the state directory, never in the configuration file.
*   Carry node-to-node WireGuard over SCION: a `conn.Bind` on a SCION socket
    that resolves a provider path per sent datagram and refreshes it on
    expiry or error, so an established tunnel tolerates path rotation.
*   Publish (ISD-AS, public key, gateway port, overlay subnet) to the core
    during enrollment — the publisher identified by its verified certificate
    chain — and serve the directory to every node, which maintains one mesh
    device per directory peer.
*   Terminate hosts on one device per exit behind a single public UDP port,
    all sharing the node's key pair, each host public key configured under
    exactly one exit, so the peer lookup demultiplexes the shared socket and
    reply traffic routes by the peer's address to its exit's device.
*   Provision the operating system from the binary: TUN devices, addresses,
    per-exit routing tables and rules, IP forwarding, and masquerading at
    egress nodes; where privileges are missing, log the exact commands as
    instructions instead of failing.
*   Reuse `controlplane.SCIONConn` and `controlplane.PathProvider` unchanged
    as the path library — the same seam a future in-process application
    consumes.

### Non-goals

*   Distributing host membership: host public keys stay a static per-node
    list until a later milestone.
*   Host-to-exit end-to-end tunnels (the local node relaying without
    terminating) — considered and rejected in ADR-0005.
*   Core-generated private keys: the core serves public keys only; secrets
    never leave the node.
*   Inbound connectivity from the internet: only host-initiated flows and
    their NAT replies exist; no port publishing.
*   A userspace IP stack (`gvisor` netstack or equivalent): kernel TUN and
    routing are the forwarding engine, with the privilege requirement
    accepted.
*   IPv6 overlay addressing, multipath or metric-based path selection, and
    gateway metrics — one freshest path per destination, following ADR-0004's
    fixed-policy stance.
*   SCMP exposure beyond using errors as a path-refresh trigger.
*   Changes to the data plane, the control plane's segment machinery, or the
    trust architecture's artifacts.

## Proposal

### The gateway package

`pkg/gateway` holds the milestone: WireGuard key handling (`LoadOrCreateKey`,
following `pkg/trust/keys.go`), device lifecycle, the SCION transport, the
directory client, OS provisioning, and the run loop. It consumes
`controlplane` types and is wired in `cmd/cion/main.go` after
`setupControlPlane` — the gateway needs the trust engine (for the publishing
channel), the enrollment lifecycle (to publish after each successful pass),
and the path provider (for every sent datagram). The node runs a gateway only
when its configuration has one; the milestone adds no always-on component.

`GatewayPort` (30045, beside `EndpointPort` in `pkg/controlplane/transport.go`
and the discovery port) is the fixed SCION port every node's mesh transport
listens on, so a peer's directory entry — ISD-AS, public key, subnet — is all
a node needs to reach it.

### The mesh transport: a WireGuard bind over SCION

wireguard-go separates the WireGuard protocol from its usual UDP transport
through the `conn.Bind` interface; implementing that interface over a
`controlplane.SCIONConn` bound to the internal underlay on `GatewayPort`
gives node-to-node tunnels carried by SCION packets:

*   `Send` resolves the peer endpoint `Addr{IA, Addr, Path}` with
    `PathProvider.LocalPath` — local state only, never a fetch inside a send
    — caching the freshest path per peer and re-resolving when the cached
    path's hops near expiry or a send fails. `SCIONConn.WriteTo` already
    serializes a full SCION packet over a supplied path; replies already
    reverse arrival paths.
*   `Receive` reads datagrams from the shared socket and delivers each to
    every mesh device. All devices share the node's key pair, so each can
    decrypt a handshake, but only the device whose peer table contains the
    sender's public key completes it; data packets match a session on exactly
    one device. The wasted decryption on foreign devices is bounded by
    handshake frequency and CION's scale.
*   WireGuard's persistent keepalive, set to a code constant, keeps sessions
    and paths warm enough that path rotation is exercised rather than
    discovered at first use.

The bind is also the milestone's seam for the path library: it is a worked
example of an in-process SCION application built on `SCIONConn` and the
provider, the pattern a future application repeats without gateway
machinery.

### Mesh devices and the peer directory

The node runs one wireguard-go mesh device per directory peer, each on its
own TUN, all configured with the node's key pair. A peer's `AllowedIPs` are
its overlay subnet; when the peer is one of this node's configured exits,
`0.0.0.0/0` is added so the device's default-routed traffic (Section
"Routing and egress") finds a peer for any destination. WireGuard's
longest-prefix peer selection keeps subnet traffic direct to its node while
everything else flows to the exit.

The directory is served by a new ConnectRPC service on the control endpoint,
backed by a new bucket in the trust DB following the trust DB pattern (pure
interface, bbolt implementation, shared contract tests):

*   `Publish(entry)` records the publisher's gateway entry. The RPC rides
    the SCION-native mTLS channel (`controlplane.PeerClient`), so the peer's
    verified chain identifies the ISD-AS; the claimed entry is ignored in
    favor of the authenticated one, and a node cannot publish for another.
    Any node may publish to the core; the core serves `List()` to everyone.
*   The enrollment loops (`pkg/controlplane/lifecycle.go`) publish the entry
    after each successful pass — enrollment renews daily, which is also a
    reasonable directory refresh rate — and a periodic refresh constant
    re-fetches the directory between enrollments.
*   A node diffs each fetched directory against its devices: new peers gain
    a mesh device; departed peers lose theirs. A fresh node's tunnels come
    up as soon as its first enrollment publishes its entry and its first
    fetch returns the others.

The service is CION's first own protobuf API — the vendored
`proto/control_plane` services belong to the SCION drafts, and a directory is
not among them. A small `proto/gateway/v1` package with generated ConnectRPC
code joins the module (generated files vendored like the rest).

### Host-facing devices and the shared port

Every host-facing device listens behind one public UDP port — hosts are
plain internet clients with a single endpoint to reach. The port's socket is
shared the way the mesh socket is: a dispatcher delivers each datagram to
every device, and the device whose peer table holds the sender's public key
completes the handshake — handshakes fan out across devices (each shares the
node's key pair and can decrypt), data packets match a session on exactly
one, and the cost is bounded by handshake frequency at CION's scale.

Each host public key is configured under exactly one exit's device with its
overlay address, and WireGuard drops handshakes from keys the node has not
configured — membership and each host's exit are the operator's list. Reply
routing needs no subnet split: the peer's /32 route points at its exit's
device, so traffic decrypted by device X returns to device X by destination.
A host chooses among its provisioned exits by choosing which of its keys it
sends with; a host needing several exits at once runs several interfaces,
one key each. Ordinary hosts run one.

### Routing and egress

The binary provisions the OS and keeps the provisioning matched to the
devices (routes are added and withdrawn as the directory changes):

*   Main table: each host peer's /32 via its exit's host device TUN; each
    peer node's subnet via its mesh TUN.
*   Per-exit table, selected by an `ip rule` on the ingress host TUN: the
    overlay prefixes plus a default route via the exit peer's mesh TUN.
*   Egress nodes enable IP forwarding and masquerade overlay traffic out of
    the default interface, so internet replies return by conntrack state to
    the origin's mesh TUN, and the main table carries them to the host
    device.

Provisioning runs through the system's networking utilities (TUN via
`ioctl`/netlink, routes and NAT via `ip`/`nft`); where a step needs
privileges the process lacks, the gateway logs the exact command as an
operator instruction and continues degraded — the same posture the control
plane takes toward missing reachability, and the state tests can assert
without privileges by checking the generated commands.

### Addressing and MTU

Overlay addressing is IPv4, one operator-assigned subnet per node, host
addresses assigned within it by the peer configuration. The TUN MTU is a
code constant of 1280: an inner packet of 1280 bytes plus WireGuard's data
overhead (~32), the outer IPv4 and UDP headers (28), and a worst-case SCION
header stack (~156 for a long composed path) stays within a standard
1500-byte MTU.

### Configuration and node wiring

```json
"gateway": {
  "subnet": "10.64.1.0/24",
  "listenPort": 51820,
  "egress": true,
  "exits": ["20-ff00:0:3"],
  "peers": [
    {"publicKey": "...", "address": "10.64.1.10", "exit": "20-ff00:0:3"}
  ]
}
```

`subnet` is the node's overlay; `listenPort` is the shared host-facing UDP
port; `egress` marks an internet exit; `exits` lists the offered exit
ISD-ASes; `peers` lists host public keys, addresses, and each peer's exit
(validated: addresses inside the subnet, exits configured, one exit per
key). A host's client configuration is the node's public key, one address,
and the shared port; the key it sends with selects the exit.

Startup in `cmd/cion/main.go` extends proposal 0004's: after the path
provider exists, the gateway loads or creates its key, binds the mesh socket
on `GatewayPort`, starts the directory client (first fetch deferred until
enrollment publishes this node's entry), creates host devices for configured
exits, and provisions the OS. The enrollment lifecycle gains the publish
step. Shutdown withdraws routes and closes devices.

## Test plan

*   **Unit tests:** key load-or-create persistence; the bind's path caching,
    per-peer endpoint resolution, and refresh on expiry and error; directory
    handlers record the authenticated ISD-AS and reject mismatches, and the
    trust DB bucket round-trips entries with contract tests beside the
    existing ones; configuration validation (peer addresses inside the
    subnet, exits configured, one exit per key, the listen port free); route
    and rule
    generation against the expected command sequences; provisioning emits
    instructions rather than failing without privileges.
*   **Integration tests:** extending `pkg/controlplane/network_test.go`'s
    topology harness — two nodes publish and fetch the directory, mesh
    devices handshake over the SCION transport, and an in-process
    wireguard-go client (host) exchanges ICMP through node A's host device,
    the mesh, and node B's delivery to its own in-process host; with
    privileges available, an egress node NATs a host's traffic to a
    loopback "internet" service and returns the reply. Tests requiring TUN
    or `CAP_NET_ADMIN` skip with a logged reason when the environment lacks
    them, following the de-flaked port-bound test style.
*   **Negative tests:** a handshake from a public key no device holds is
    dropped, and one configured under another exit completes only on that
    exit's device; a publish claiming another ISD-AS is recorded under the
    authenticated one; a directory entry without a reachable path queues
    refresh and logs rather than erroring the gateway; an oversized inner
    packet is not sent (MTU enforced at the TUN); a departed directory peer
    loses its device and routes.

## Implementation history
