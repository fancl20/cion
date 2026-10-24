# Serve egress as exit nodes relayed by the host's node

This proposal implements
[ADR-0024](/docs/adrs/0024-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md):
every node joins a host's netmap as a peer under its own key and serving
address, offering the exit routes; the host's node relays the host's
WireGuard datagrams for another node's key to that node over the SCION
underlay; an egress application ends exit flows on a netstack; the netmap
names public resolvers for every exit; an exits application serves each
node's hosts a mihomo proxy provider of per-exit client instances; and the
SOCKS application retires.

[TOC]

## Summary

A host's netmap holds one peer today — its node, under the node's key, every
routed /32 in its `Addresses` and `AllowedIPs`, `Cap` at the served
capability version, no hostinfo, no resolver
([netmap.go](/pkg/apps/coordination/netmap.go)). The node's host device
holds the hosts the node owns and no other
([app.go](/pkg/apps/wireguard/app.go)), its router takes no default
([router.go](/pkg/apps/wireguard/router.go)), and internet egress is the
SOCKS application at the node's own address
([socks](/pkg/apps/socks/app.go)).

The plan:

*   `--dns.resolvers` names the resolvers a node's applications use,
    `8.8.8.8` and `8.8.4.4` by default;
*   the netmap names every node as a peer beside the host's own, each an
    exit, and names the founding core's resolvers for every exit;
*   the coordination application records each host's reported exit beside
    its presence, and the console shows it;
*   the WireGuard application relays, at its host-facing port, every
    datagram that belongs to another node's session, over a new SCION
    service, and serves every host in the directory;
*   the router hands non-tailnet destinations arriving from the host device
    to the egress, and delivers what the node's own services produce to any
    host through the host device;
*   the egress application ends exit flows on a tuned netstack that also
    serves the node's own address;
*   the exits application serves `GET /mihomo` at the node's own address;
*   the SOCKS application, its client, and its lab are removed.

## Motivation

ADR-0024 decides the boundary; this plan grounds it in the packages that
carry it. The client behavior it rests on is fixed and measured against the
vendored client line: a client sends its default routes to the selected
exit peer's key; it sends a destination to the peer whose `Addresses` name
it before it consults routes; a WireGuard-only exit peer with `Cap` 26 or
above is taken to serve a DNS proxy of its own, and one below 26 without
hostinfo crashes the client; with `Cap` 0, hostinfo, and
`ExitNodeDNSResolvers`, the client resolves through the named resolvers
while that exit is selected, and keeps its own resolver otherwise.

### Goals

*   A host's netmap names every node, each under its own key with its
    serving address as its one address, each an exit, and the host's own
    node keeps the hosts' addresses.
*   A host selects any node as its exit — by serving address or name —
    and its internet traffic leaves there, relayed unopened by its own
    node; with no exit selected, each node's serving address reaches that
    node.
*   A client resolves names through the configured resolvers while an exit
    is selected, and the queries leave through that exit.
*   The core's console shows each host's reported exit.
*   A host fetches, through a login without an exit, a provider listing
    one client instance per exit.
*   The SOCKS application, its listener, and its lab are gone.

### Non-goals

*   No per-node resolvers in the netmap: every exit carries the founding
    core's.
*   No IPv6 egress, no kernel forwarding, no relay over DERP.
*   No routing by the reported exit.
*   No relaying of a handshake an exit node initiates toward a host:
    relayed sessions begin at the host, as every host session does.
*   No release of the instances of a vanished exit; the console's release
    stands as the remedy.
*   No change to any client.

## Proposal

### The resolvers argument

The run command registers `--dns.resolvers`, a list of IP addresses,
default `8.8.8.8,8.8.4.4`, beside `--applications`
([run.go](/cmd/cion/run.go)); an entry that is not an IP address refuses the
boot naming it. `NodeConfig` carries it, and the applications' environment
gains `Resolvers []netip.Addr`
([apps.go](/pkg/apps/apps.go),
[applications.go](/internal/services/applications.go)). Two applications
read it:

*   the coordination application, which names the founding core's
    resolvers in every netmap;
*   the WireGuard application's relay presence, which resolves the relay's
    name through them — a `net.Resolver` whose dial goes to the resolvers'
    port 53 — unless the harness pins the relay's address.

### The netmap

`netmap` builds one peer per directory node that holds a slice:

*   **The host's own node** keeps its key, ID, endpoint, and DERP region.
    Its `Addresses` are the registry's hosts' /32s and the node's own
    serving address, the other nodes' serving addresses moving to their own
    peers; its `AllowedIPs` are the same plus `0.0.0.0/0` and `::/0`.
*   **Every other node** is a peer under its own key, its stable ID derived
    from that key as the host node's is, and its node ID derived from its
    ISD-AS, so a node keeps one ID for its life and a key never moves
    between IDs. Its one address is its serving address; its `AllowedIPs`
    are that /32, `0.0.0.0/0`, and `::/0`; its endpoint is the host node's
    host-facing endpoint, or none under `RelayOnly`.
*   **Every peer** carries `IsWireGuardOnly`, a `Name` of its ISD-AS with
    each `:` written as `-`, beneath the tailnet's domain, hostinfo naming
    the node, `Cap` 0, `Online`, and `ExitNodeDNSResolvers` listing the
    configured resolvers.

A node whose applications leave the egress out still appears as an exit,
and its exit carries nothing. `Created` and `LastSeen` take the stream's
opening time, so the stream's comparison resends on change alone; today they
stamp every rebuild, and every connected host re-applies its netmap on each
tick. The doc comments naming the SOCKS offer are rewritten for the exits.

### The reported exit

`observe` records the request's `Hostinfo.ExitNodeID` beside the hostname
and operating system ([presence.go](/pkg/apps/coordination/presence.go)),
lite requests included, and `Presence` gains `Exit addr.IA`: the node whose
stable ID the host reported, zero for none or for an ID no node holds. The
console's host listing carries it beside the connection state
([portal.go](/pkg/apps/portal.go),
[api.go](/pkg/apps/portal/api.go)), and the page shows it.

### The relay

The host socket's reader classifies each datagram by WireGuard's own
message type before the host device sees it
([hostbind.go](/pkg/apps/wireguard/hostbind.go)):

*   **An initiation** goes to the host device when its `mac1` verifies under
    the node's own key; otherwise it is relayed to the node under whose key
    it verifies, found among the directory's node keys, and the relay
    records the host's endpoint and sender index against that node. An
    initiation verifying under no key drops.
*   **A response, a cookie reply, or a transport message** from a host is
    relayed when its receiver index names a session the relay recorded, and
    goes to the host device otherwise.
*   **A datagram from a node** — arriving on the relay socket — is a
    response, a cookie reply, or a transport message for one of the node's
    hosts: the relay records the node's sender index of a response and
    writes the datagram to the endpoint its receiver index recorded, from
    the shared port. An initiation from a node drops — relayed sessions
    begin at the host.

The relay table expires an entry after three minutes of silence, WireGuard's
rejection time, and a host's later handshake replaces its endpoint, so a
roaming host's relayed sessions recover at their next handshake. Nothing is
added to a relayed datagram: it rides the SCION underlay at the size a mesh
datagram does.

The relay socket is a SCION connection of the node, registered under a new
service value `SvcHostRelay` (`0x7ff3`) in the private slice the mesh and
directory services share ([app.go](/pkg/apps/wireguard/app.go)), and it
sends to a node on the path the mesh socket's route pick holds for it
([bind.go](/pkg/apps/wireguard/bind.go), [route.go](/pkg/apps/wireguard/route.go)).
On the exit side, a datagram arriving on the relay socket enters the host
device through its bind with a relay endpoint naming the relaying node —
the shape the DERP presence's endpoint already has
([derpbridge.go](/pkg/apps/wireguard/derpbridge.go)) — and the bind's sends
to a relay endpoint ride the relay socket back. The counters gain
`relayed_datagrams_total` and `relay_drops_total`
([counters.go](/pkg/apps/wireguard/counters.go)).

### Every node serves every host

`applyHostEntries` programs every host the directory holds on the host
device, each with its /32, not the owned alone; the router's host table
keeps the owned for forwarded packets. The router's drains split by
arrival:

*   **from the host device**, a non-tailnet destination goes to the default
    delivery the egress installs, and the rest routes as today;
*   **from a mesh device**, a non-tailnet destination counts unroutable, as
    today;
*   **from the node's own services** — `Route` — a destination any host of
    the directory holds goes to the host device, whose peer table picks the
    session, and the rest routes as today.

`Router` gains `DeliverDefault(deliver func(pkt []byte)) func()`, installed
by the egress for as long as it runs.

### The egress application

`pkg/apps/egress` is the node's netstack: an IPv4 NIC, promiscuous and
spoofing, claiming the node's own address through `Deliver` and the
default through `DeliverDefault`, its TCP tuned as the SOCKS netstack's is.
It ports the netstack egress the SOCKS landing retired — `egress.go` and
`echo.go` beneath `pkg/apps/wireguard` before commit `d746db3`:

*   a TCP forwarder dials a non-tailnet destination from the node's own
    sockets under the dial timeout, then completes the host's handshake and
    splices, and refuses a tailnet destination no listener holds;
*   a UDP forwarder maps each flow to one socket of the node's own, the
    socket the reply mapping;
*   echo ICMP relays on the unprivileged ICMP socket, and drops where the
    system offers none;
*   flow bounds, idle expiry, and the dial timeout are the SOCKS
    application's constants, moved.

`Listen(port uint16) (net.Listener, error)` binds a listener at the node's
own address for a borrower. The entry is `egress`, requiring `wireguard`,
loading wherever the WireGuard application loads.

### The exits application

`pkg/apps/exits` borrows the egress's listener on port 80 and the WireGuard
application's directory, and serves `GET /mihomo`: a JSON document, which a
YAML reader reads as YAML, holding a `proxies` list of one entry per node
that holds a slice, the host's own node included:

```json
{"proxies": [{
  "name": "1-ff00:0:110",
  "type": "tailscale",
  "control-url": "https://cion.example",
  "exit-node": "100.64.0.1",
  "state-dir": "cion/1-ff00_0_110",
  "udp": true,
  "ip-version": "ipv4"
}]}
```

The control URL is the founding core's HTTPS origin, the harness's
placement standing in through the relay placement. The state directory is
derived from the exit's ISD-AS, so a refetch keeps every instance's login.
The entry is `exits`, requiring `egress`. A client's configuration names
the host's base login, the provider through it, and the key injected into
every instance:

```yaml
proxies:
  - name: cion
    type: tailscale
    control-url: https://cion.example
    auth-key: <reusable key naming the host's node>
    state-dir: cion/base
proxy-providers:
  cion-exits:
    type: http
    url: http://<the host's node's serving address>/mihomo
    proxy: cion
    interval: 3600
    override:
      override-expr:
        - '.auth-key = "<the same key>"'
```

### SOCKS retires

`pkg/apps/socks`, its entry ([socks.go](/pkg/apps/socks.go)),
`internal/socksclient`, and the SOCKS lab
([socks_test.go](/internal/testnetwork/socks_test.go)) are removed; the
table becomes `wireguard`, `coordination`, `egress`, `exits`, `voting`,
`portal`, and `--applications socks` refuses as unknown. The texts naming
SOCKS — the host port's help, `WireguardArguments`, the netmap's comments —
are rewritten.

### The documentation

The architecture overview's applications list replaces SOCKS with the
egress and the exits, and its endhost section describes exits relayed by
the host's node ([architecture.md](/docs/design/architecture.md)). The
implementing commit flips ADR-0024 to accepted and ADR-0012 to superseded
by ADR-0024.

## Test plan

*   **Unit, the resolvers argument (decision 5):** the default parses to
    `8.8.8.8` and `8.8.4.4`; a non-address entry refuses the boot naming
    it; the environment carries the list.
*   **Unit, the netmap (decisions 1 and 5):** a two-node registry gives the
    host its node, with the hosts' and its own addresses and the exit
    routes, and the other node under its own key, its serving address
    alone, the exit routes, and the host node's endpoint; every peer
    carries `Cap` 0, hostinfo, a name, and the resolvers; node IDs and
    stable IDs hold across rebuilds, and a rebuild without change resends
    nothing.
*   **Unit, the reported exit (decision 6):** a lite request naming a
    node's stable ID records that node; an unknown ID records none; the
    console's listing carries it.
*   **Unit, the relay (decision 2):** an initiation verifying under the
    node's key reaches the host device; one verifying under another node's
    key is relayed to it, and that node's response returns to the host's
    endpoint with the sender index recorded; transport messages follow
    the recorded indices both ways; an unknown index reaches the host
    device; an initiation from a node and one verifying under no key drop
    and count; an idle entry expires; a relayed datagram leaves byte for
    byte as it arrived.
*   **Unit, every host (decision 3):** the host device holds every
    directory host; a packet the node's own services produce for a host
    another node owns enters the host device; a non-tailnet destination
    from the host device reaches the default delivery, and from a mesh
    device counts unroutable.
*   **Unit, the egress (decision 4):** the ported flows — TCP splice with
    refusal told by reset, UDP mapping, the flow bound, the idle sweep,
    echo relay — and the TCP tuning; a tailnet destination no listener
    holds is refused; an IPv6 packet never enters.
*   **Unit, the exits (decision 7):** the document lists one instance per
    node with a slice, with the exit's serving address, a state directory
    stable across fetches, IPv4 only, and the core's origin; the listener
    answers on the node's own address alone.
*   **Integration, the exits lab (decisions 1 to 7):** the core and a leaf,
    a tsnet host on the leaf:
    *   with no exit selected, the host reaches the core's serving address
        through the leaf's relay, and the leaf's relay counter rises;
    *   with the core selected by its serving address, TCP and UDP echoes
        to a loopback internet return through the core;
    *   with the leaf selected, the echoes return through the leaf;
    *   with `--dns.resolvers` naming a loopback lab resolver, the host's
        query reaches it from the selected exit's sockets;
    *   the core's presence names the selected exit;
    *   the host fetches the provider through the tailnet and lists both
        nodes.
*   **Integration, SOCKS retired (decision 8):** the applications table
    refuses `socks`; the coordination labs' joins and echoes hold unchanged.

## Implementation history
