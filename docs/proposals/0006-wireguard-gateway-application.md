# Implement the WireGuard gateway application

This proposal outlines the gateway of
[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md): a
WireGuard application in the SCION network — `pkg/apps/wireguard`, beside
[proposal 0005](/docs/proposals/0005-path-library-and-scion-ping.md)'s ping
in the `pkg/apps` namespace — that serves plain hosts. Hosts are standard
WireGuard clients of their local node; tunnels between nodes ride SCION
paths over the path library; an in-process router forwards between the
tunnels; internet egress flows through gVisor's netstack; and the
application distributes its peers' keys through a directory the core node's
application serves.

[TOC]

## Summary

A `pkg/apps/wireguard` application embedding wireguard-go serves plain
hosts: hosts are standard WireGuard clients of their local node, nodes
tunnel to each other through a WireGuard transport (`conn.Bind`)
implemented on the path library's SCION socket, and an in-process router
forwards between the tunnels — mesh and host devices sit on in-process
packet pipes, and a destination table routes the overlay — while internet
egress is flow-level proxying through gVisor's netstack. The application
publishes its public key to the directory the core node's application
serves — authenticated by TRC-anchored certificate chains — so tunnels to
new peers need no configuration copied between operators. A host's public
key selects its exit: one shared host-facing port serves every exit,
demultiplexed by peer lookup. A gateway node holds unprivileged UDP sockets
and its own state, and nothing else.

## Motivation

ADR-0005's standard-clients driver sets the bar: hosts reach the network
with ordinary, widely deployed client software, and SCION knowledge is
never a prerequisite. With paths discovered end to end (ADR-0004) and
consumable by applications (proposal 0005's library and ping), the founding
driver of ADR-0001 — clients dynamically selecting routing paths — becomes
an action a host takes: choosing which of its provisioned keys to send
with. WireGuard supplies the access side (standard clients, peer
authentication, confidentiality on the access leg), gVisor's netstack
terminates the internet leg, in-process packet pipes keep the operating
system out of the forwarding path, and the application's own code stays on
the one thing only CION has: SCION paths.

### Goals

*   Embed wireguard-go behind the node's configuration, with the node's
    WireGuard key pair generated locally on first start and persisted in
    the application's own state, never in the configuration file.
*   Carry node-to-node WireGuard over SCION: a `conn.Bind` on the path
    library's socket that resolves a provider path per sent datagram and
    refreshes it on expiry or error, so an established tunnel tolerates
    path rotation.
*   Publish (ISD-AS, public key, gateway port, overlay subnet) over the
    application's authenticated channel — the publisher identified by its
    verified certificate chain, on a cadence the application owns — and
    serve the directory to every node, which maintains one mesh device per
    directory peer.
*   Terminate hosts on one device per exit behind a single public UDP port,
    all sharing the node's key pair, each host public key configured under
    exactly one exit, so the peer lookup demultiplexes the shared socket
    and reply traffic routes by the peer's address to its exit's device.
*   Forward in userspace: mesh and host devices on in-process packet pipes,
    an in-process router between them — host peers' /32s to their devices,
    directory peers' subnets to theirs longest-prefix first, everything
    else to the exit whose device decrypted the packet — and the overlay
    MTU enforced by the router; the application runs on unprivileged UDP
    sockets.
*   Service internet egress by terminating flows in gVisor's netstack: an
    exit completes a host's TCP handshake itself and splices the flow to an
    outbound connection from the node's own address, maps each UDP flow to
    one rewritten socket, relays echo ICMP per identifier, drops other IP
    protocols, and bounds and expires flow state by idleness.

### Non-goals

*   Distributing host membership: host public keys stay a static per-node
    list until a later milestone.
*   Host-to-exit end-to-end tunnels — rejected in ADR-0005's options.
*   Core-generated private keys: the core serves public keys only; secrets
    stay on the node.
*   Inbound connectivity from the internet: host-initiated flows and their
    proxied replies exist; no port publishing.
*   Kernel forwarding and packet NAT — rejected in ADR-0005's options; the
    router stays in-process and the egress terminates flows.
*   IP protocols beyond TCP, UDP, and echo ICMP through an exit: the rest
    are dropped, and ICMP other than echo is best-effort.
*   IPv6 overlay addressing, multipath or metric-based path selection, and
    gateway metrics — one freshest path per destination, following
    ADR-0004.
*   SCMP exposure beyond using errors as a path-refresh trigger.
*   A separate process: the application is embedded in the CION binary.
*   Changes to the data plane, the control plane's segment machinery, or
    the trust architecture's artifacts.

## Proposal

### The wireguard application

`pkg/apps/wireguard` holds the milestone, the second resident of the
`pkg/apps` namespace proposal 0005 opens: WireGuard key handling
(`LoadOrCreateKey`, following `pkg/trust/keys.go` into the application's
own state), device lifecycle, the SCION transport, the directory client
and — on the core — the directory server, the in-process router, the
netstack egress, and the run loop. The application consumes the path
library (`pkg/scion`, proposal 0005) for every sent datagram and the trust
engine to authenticate directory peers by certificate chain; it holds its
own sockets, storage, and loops. `cmd/cion/main.go` starts it after
`setupControlPlane` when the node's configuration has a gateway section;
the milestone adds no always-on component.

`GatewayPort` (30045, beside `EndpointPort` in
`pkg/controlplane/transport.go` and the discovery port) is the fixed SCION
port every node's mesh transport listens on, so a peer's directory entry —
ISD-AS, public key, subnet — is all a node needs to reach it.
`DirectoryPort` (30046, beside `GatewayPort`) is where the core node's
application serves the directory; proposal 0005's ping needs no port of
the row — SCMP echo rides the endhost port and the echo identifier.

### The mesh transport: a WireGuard bind over SCION

wireguard-go separates the WireGuard protocol from its usual UDP transport
through the `conn.Bind` interface; implementing that interface over the
path library's `Conn` bound to the internal underlay on `GatewayPort`
gives node-to-node tunnels carried by SCION packets:

*   `Send` resolves the peer endpoint `Addr{IA, Addr, Path}` with
    `PathProvider.LocalPath` — local state only, never a fetch inside a
    send — caching the freshest path per peer and re-resolving when the
    cached path's hops near expiry or a send fails. `Conn.WriteTo`
    serializes a full SCION packet over a supplied path; replies reverse
    arrival paths.
*   `Receive` reads datagrams from the shared socket and delivers each to
    every mesh device. All devices share the node's key pair, so each can
    decrypt a handshake, but only the device whose peer table contains the
    sender's public key completes it; data packets match a session on
    exactly one device. The wasted decryption on foreign devices is bounded
    by handshake frequency and CION's scale.
*   WireGuard's persistent keepalive, set to a code constant, keeps
    sessions and paths warm enough that path rotation is exercised rather
    than discovered at first use.

The bind consumes the path library exactly as proposal 0005's ping does —
the second worked example of an application on a CION node, and the one
future tunneling applications copy.

### Mesh devices and the peer directory

The node runs one wireguard-go mesh device per directory peer, each on its
own in-process pipe, all configured with the node's key pair. A peer's
`AllowedIPs` are its overlay subnet; when the peer is one of this node's
configured exits, `0.0.0.0/0` is added so the device's default-routed
traffic (Section "The in-process router") finds a peer for any destination.
WireGuard's longest-prefix peer selection keeps subnet traffic direct to
its node while everything else flows to the exit.

The directory is the application's own service — a ConnectRPC server on
`DirectoryPort`, served by the core node's application and stored in its
own bbolt file, following the trust DB's pattern of a pure interface and
shared contract tests:

*   `Publish(entry)` records the publisher's gateway entry. The channel is
    the application's own mTLS over SCION — the control endpoint's
    machinery consumed as a library, presenting the node's certificate
    chain — so the peer's verified chain identifies the ISD-AS; the
    claimed entry is ignored in favor of the authenticated one, and a node
    can only publish its own entry. Any node may publish to the core; the
    core serves `List()` to everyone.
*   The application owns its cadence: publication retries until enrollment
    has produced the node's chain, re-publishes on a constant (enrollment
    renews daily, a reasonable rate), and a refresh constant re-fetches the
    directory between.
*   A node diffs each fetched directory against its devices: new peers
    gain a mesh device; departed peers lose theirs. A fresh node's tunnels
    come up as soon as its first publish lands and its first fetch returns
    the others.

The service is CION's first own protobuf API — the vendored
`proto/control_plane` services belong to the SCION drafts, and a directory
is not among them. A small `proto/gateway/v1` package with generated
ConnectRPC code joins the module (generated files vendored like the rest).

### Host-facing devices and the shared port

Every host-facing device listens behind one public UDP port — hosts are
plain internet clients with a single endpoint to reach. The port's socket
is shared the way the mesh socket is: a dispatcher delivers each datagram
to every device, and the device whose peer table holds the sender's public
key completes the handshake — handshakes fan out across devices (each
shares the node's key pair and can decrypt), data packets match a session
on exactly one, and the cost is bounded by handshake frequency at CION's
scale.

Each host public key is configured under exactly one exit's device with its
overlay address, and WireGuard drops handshakes from keys the node has not
configured — membership and each host's exit are the operator's list.
Reply routing needs no subnet split: the peer's /32 route points at its
exit's device, so traffic decrypted by device X returns to device X by
destination. A host chooses among its provisioned exits by choosing which
of its keys it sends with; a host needing several exits at once runs
several interfaces, one key each. Ordinary hosts run one.

### The in-process router

wireguard-go exchanges a device's plaintext packets through its device
interface, and a kernel TUN is only that interface's usual implementation;
the gateway provides userspace implementations instead — packet pipes — so
the node holds no kernel state for the overlay: no TUN device, no
addresses, no routing tables or rules, no forwarding, no NAT. An
in-process router moves packets between the pipes by destination:

*   Each host peer's /32 goes to its host device, and each directory
    peer's subnet to its mesh device — longest prefix first, so remote
    overlay subnets win over any default and go direct.
*   Everything else goes to the exit whose device decrypted the packet:
    traffic from exit X's host device defaults to X's mesh device — exit
    selection is the router's default — and traffic decrypted by a mesh
    device for no overlay destination has reached the exit this node
    offers and enters the netstack egress (next section).
*   Replies find their device by the peer's address — each host address is
    configured under exactly one exit's device as its /32, so no subnet
    splitting exists — and WireGuard's longest-prefix peer selection
    carries the same rule inside each tunnel.
*   The router enforces the overlay MTU: an inner packet larger than the
    constant is dropped, never sent, since no kernel TUN exists to do it.

The table is rebuilt as the directory and the peer list change — routes
appear and disappear in process state, with nothing in the operating system
to keep matched. Overlay traffic accordingly leaves the operating system's
tooling behind — no `tcpdump` or `iptables` on gateway devices — so the
gateway exposes counters and logs instead.

### Internet egress through gVisor's netstack

An exit services internet flows by terminating them, not by translating
packets. Default-routed packets enter an embedded gVisor netstack (about
4 MB vendored into the module) over a link endpoint the router feeds;
flows terminate on the overlay addresses, and the gateway splices each to
traffic from the node's own sockets:

*   **TCP:** the exit terminates the flow — the host completes its
    handshake with the exit, not the destination — and the gateway splices
    it to one outbound connection dialed from the node's own address, each
    direction a copy between the legs. RTT, congestion control, and
    retransmission are per leg, and the halves need not agree on MTU or
    options.
*   **UDP:** a flow maps to one outbound socket with the addresses
    rewritten; the socket itself is the reply mapping.
*   **Echo ICMP** is relayed per identifier; other IP protocols are
    dropped, and ICMP other than echo is best-effort toward the flow it
    names.

Flow state is bounded by a code constant and expired by idleness, and a
flow lives and dies on one exit: mid-flow exit switching or exit failure
drops it. Nothing is published to the internet — the egress dials out only
in response to a host's flow and returns its replies. Netstack's endpoint
mode doubles as the seam for the node itself to join the overlay later —
in-process applications with real sockets over CION paths.

### Addressing and MTU

Overlay addressing is IPv4, one operator-assigned subnet per node, host
addresses assigned within it by the peer configuration. The overlay MTU is
a code constant of 1280: an inner packet of 1280 bytes plus WireGuard's
data overhead (~32), the outer IPv4 and UDP headers (28), and a worst-case
SCION header stack (~156 for a long composed path) stays within a standard
1500-byte MTU. The router enforces the constant.

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
port; `egress` marks an internet exit — the node runs the netstack egress
only when set; `exits` lists the offered exit ISD-ASes; `peers` lists host
public keys, addresses, and each peer's exit (validated: addresses inside
the subnet, exits configured, one exit per key). A host's client
configuration is the node's public key, one address, and the shared port;
the key it sends with selects the exit.

Startup in `cmd/cion/main.go` extends proposal 0004's: after the path
provider exists, the application loads or creates its key, binds the mesh
socket on `GatewayPort`, starts the directory client and its publish loop
(publication begins once enrollment has produced the node's chain),
creates host devices for configured exits, and starts the router and —
when `egress` is set — the netstack egress; on the core it also serves the
directory on `DirectoryPort`. Shutdown closes the devices and expires the
flow state; no operating-system provisioning exists to undo.

## Test plan

*   **Unit tests:** key load-or-create persistence; the bind's path
    caching, per-peer endpoint resolution, and refresh on expiry and
    error; directory handlers record the authenticated ISD-AS and reject
    mismatches, the application's directory store round-trips entries with
    contract tests beside the existing ones, and the publish loop retries
    until the node's chain exists; configuration validation (peer
    addresses inside the subnet, exits configured, one exit per key, the
    listen port free); router lookups — longest prefix, the
    per-decryption default, reply routing by host /32, oversized inner
    packets dropped — and the egress's TCP splice (a host handshake
    completing at the exit, bytes flowing both legs), UDP mapping and
    reply rewriting, echo ICMP per identifier, dropped protocols, and flow
    bounds with idle expiry.
*   **Integration tests:** extending `pkg/controlplane/network_test.go`'s
    topology harness — proposal 0005's ping verifies the paths between the
    two nodes first; then the nodes publish and fetch the directory, mesh
    devices handshake over the SCION transport, and an in-process
    wireguard-go client (host) exchanges ICMP through node A's host
    device, the mesh, and node B's delivery to its own in-process host; an
    egress node proxies a host's TCP or UDP flow to a loopback "internet"
    service and returns the reply. The production router and egress run
    in-process, so the tests exercise them directly — unprivileged UDP
    sockets carry everything.
*   **Negative tests:** a handshake from a public key no device holds is
    dropped, and one configured under another exit completes only on that
    exit's device; a publish claiming another ISD-AS is recorded under the
    authenticated one; a directory entry without a reachable path queues
    refresh and logs rather than erroring the gateway; an oversized inner
    packet is dropped by the router; a non-TCP/UDP/echo-ICMP packet
    entering an exit is dropped; a departed directory peer loses its
    device and its router entries.

## Implementation history
