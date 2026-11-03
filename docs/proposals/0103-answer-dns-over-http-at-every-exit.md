# Answer DNS over HTTP at every exit

This proposal grounds on
[ADR-0024](/docs/adrs/0024-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md)'s
decision 5: while a client selects an exit, its queries leave through that
exit like any other flow, and names resolve from the exit's region. On a
tsnet client neither holds: one leg of each query leaves outside the tunnel,
and whichever leg answers first decides the name. Every exit's peer offers a
DNS proxy on the client lines' peer API, and the egress serves it as DNS
over HTTP at the node's own address, from the node's own resolvers, so each
query travels inside the tunnel and leaves from the exit. The decision names
the founding core's resolvers for every exit, where each exit now asks its
own; the difference is recorded here alone.

[TOC]

## Summary

Today:

*   **The netmap names resolvers.** Every exit's peer carries
    `ExitNodeDNSResolvers` listing the founding core's `--dns.resolvers`,
    beside `Cap` 0 and hostinfo naming its node alone
    ([netmap.go](/pkg/apps/coordination/netmap.go)). A client that selects
    an exit forwards its queries to those addresses.
*   **The client asks over two legs.** For a query that reaches the
    client's forwarder over TCP — the local API's `QueryDNS` asks so — the
    forwarder starts a UDP exchange and a TCP exchange with each resolver at
    once and takes the first answer (`send` in `net/dns/resolver`). The TCP
    leg dials through `UserDial`, which follows the exit route.
*   **The UDP leg leaves outside the tunnel.** A tsnet client's UDP socket
    is not the tunnel's. On the vendored line under Linux it is the system's
    own: `packetListener` returns `stdNetPacketListener`, for
    `initListenConfig` is set only in the macOS and iOS network extension
    builds. On mihomo's line it comes from the packet listener mihomo hands
    its tsnet server. Neither follows an exit route, so a name can resolve
    from the client's own region, and the query is seen outside the exit.
*   **The lab cannot tell.** In the exits lab the UDP leg goes to a
    documentation address nothing answers, so the TCP leg wins: a probe at
    the lab's resolvers counted three queries over TCP and none over UDP.
    The lab checks the answer and the resolvers the client names, not the
    transport ([exits_test.go](/internal/testnetwork/exits_test.go)), as
    [proposal 0069](/docs/proposals/0069-serve-egress-as-exit-nodes-relayed-by-the-hosts-node.md)'s
    history records.

The client lines carry a path inside the tunnel. An exit that can proxy DNS
becomes the client's resolver at its peer API — the HTTP service a client
finds at a peer's address and the port its hostinfo names — under
`/dns-query`, and the client sends each query there as DNS over HTTP:
RFC 8484's messages and methods over plain HTTP, through the tunnel. No CION
exit offers one today.

The plan:

*   the egress serves the node's HTTP at port 80 of its own address, the
    mihomo application's provider mounted on it beside DNS over HTTP, which
    answers from the node's own resolvers;
*   every exit's peer names that port as its peer API and offers a DNS
    proxy, `Cap` staying 0, and the home node's peer lists its serving
    address first;
*   the netmap's resolvers leave it;
*   the exits lab checks that each exit answers over HTTP from its own
    resolver.

## Motivation

Decision 5 holds only while a client's queries ride the tunnel like its
other flows. A leg on sockets that follow no exit route breaks both of its
promises silently, and it does so on tsnet, which every mihomo instance the
mihomo application lists runs on.

The client facts the plan rests on, read in the vendored client
(`tailscale.com` v1.102.5) and the same on mihomo's line:

*   **Which exit proxies.** The client takes a peer to proxy DNS when its
    `Cap` is 26 or above, or when its hostinfo lists a `peerapi-dns-proxy`
    service at a port of 1 or above (`peerCanProxyDNS` in `ipn/ipnlocal`);
    the service's grammar asks for port 1.
*   **Precedence.** While such an exit is selected, the client's default
    resolver is the exit's peer API base with `/dns-query` appended, unless
    the map names resolvers for use with an exit, which CION's never does;
    the peer's `ExitNodeDNSResolvers` go unread (`dnsConfigForNetmap`). With
    no exit selected, nothing changes.
*   **The URL.** For a client holding an IPv4 address, as every CION host
    does, the base is `http://`, the first single-IP IPv4 address in the
    peer's `Addresses` (`nodeIP`), and the port of its `peerapi4` service
    (`peerAPIBase`, `peerAPIPorts`). Without the port the URL is the bare
    `/dns-query`, which the forwarder cannot send: an earlier experiment
    with `Cap` 26 saw such queries answer SERVFAIL.
*   **The transport.** The forwarder POSTs the query as
    `application/dns-message` with the peer API's HTTP client, takes a 200
    answer of exactly that type, and turns a 5xx into SERVFAIL (`sendDoH`).
    The client dials a peer's address through tsnet's netstack
    (`dialPeerAPI`, `UseNetstackForIP`), and through the TUN on a client
    with one, so the query never takes UDP and never leaves outside the
    tunnel.
*   **The budget.** The client bounds a forwarded query at ten seconds
    (`dnsQueryTimeout`), and the client lines' own peer API proxy bounds
    its exchange at five (`handleDNSQuery`).

### Goals

*   While a client selects an exit, every query it forwards travels to that
    exit inside the tunnel, as DNS over HTTP, and no leg leaves the client
    outside it.
*   Each exit answers from its own resolvers, asked from its own sockets, so
    names resolve from its region.
*   The exits lab proves both for each exit it selects.
*   The netmap names no resolver.

### Non-goals

*   No change to any client.
*   No DNS over TLS or QUIC, and no TLS on the proxy: the host's WireGuard
    session already ends at the exit, and the host's node relays it
    unopened.
*   No cache at the exit: each query is one exchange with the resolvers,
    which keep caches of their own.
*   No per-host resolvers or policy: an exit answers every host from the
    same resolvers.
*   No change to the answers: AAAA questions pass as asked, though the
    egress carries no IPv6.
*   No proxy for a client without an exit selected: it keeps its own
    resolver, as decision 5 has it.

## Proposal

### The DNS proxy

The egress serves the proxy: it owns the node's own address and the sockets
an exit's flows leave from, and a client's DNS through an exit is part of
the exit. It takes over the node's HTTP at `egress.HTTPPort`, port 80 of its
own address: once the address is claimed, Run binds the port and serves one
HTTP server there until Run stops, the proxy mounted at `/dns-query`.

*   **One port, mounted.** `Listen` gives way to `Mount(pattern string,
    handler http.Handler)`, the shape `MountHTTPS` and `MountControlEndpoint`
    already take ([apps.go](/pkg/apps/apps.go)). The mihomo application
    mounts `GET /mihomo` on the egress's server instead of serving a
    listener the egress lends ([app.go](/pkg/apps/mihomo/app.go)), and the
    egress mounts the proxy itself. The proxy therefore stands wherever the
    egress runs, whichever applications its node loads, while the netmap
    offers it at every exit: decision 4 already has a node without the
    egress appear as an exit that carries nothing, its DNS now included. A
    client's other requests to a peer API — Taildrop's among them — meet
    paths the server holds none of. Not 53: a resolver's port promises DNS's
    own wire format.
*   **The handler.** `/dns-query` takes both of RFC 8484's forms: POST with
    an `application/dns-message` body, and GET with the message in the `dns`
    parameter as unpadded base64url. The message is a query of one
    question, at most 65535 bytes, DNS's own bound over TCP. A body past the
    bound answers 413, a `dns` parameter decoding past it 414, a POST of
    another type 415, a message that is no query of one question 400, and
    any other method 405. An answer returns as 200, of type
    `application/dns-message`, under the query's ID, whatever its response
    code.
*   **The bounds.** An exchange runs at most five seconds — the bound the
    client lines' own proxy keeps, half the client's — and one that expires
    or fails answers 502, which the client turns into SERVFAIL. Each
    exchange holds a place among the egress's flows while it runs, so the
    flow bound caps queries and flows together, and a query past it answers
    503 at once. The server reads a request within ten seconds and closes a
    connection idle for two minutes; the client's transport closes an idle
    connection after 90 seconds, so the client ends it first and no POST
    meets a connection the server has closed.
*   **The exchange.** The proxy asks the resolvers the egress entry hands it
    — the node's `--dns.resolvers`, `Environment.Resolvers` — each at port
    53, from the node's own sockets. It sends the query over UDP from one
    fresh socket to every resolver at once, as the relay presence does,
    resends it each second until an answer or the bound, and takes the first
    datagram from a resolver asked whose ID and question match. It asks
    under an ID of its own, drawn at random, and restores the query's in the
    answer, for RFC 8484 asks its clients to send ID 0. A truncated answer
    is asked again over TCP, the resolvers tried in order, and a failed
    retry returns the truncated answer. With the list empty the proxy asks
    the nameservers `/etc/resolv.conf` names, read at each exchange — the
    system's resolver, which an empty list already means to the relay
    presence — and none named or none readable answers 502. The harness's
    internet maps the exchange's legs as it maps a flow's.
*   **Reachability.** The listener is a netstack endpoint at the node's own
    address, with no socket of the system's: only what the router delivers
    to that address from the tailnet reaches it. Every host may ask any
    exit's proxy, as every host may select any exit. No party off the
    tailnet reaches it, and an answer returns on the asking connection
    inside the tunnel, so the proxy reflects nothing at a third party.

### Each exit's own resolvers

Decision 5 names the founding core's resolvers for every exit; each exit now
asks its own. Every node defaults to Google's 8.8.8.8 and 8.8.4.4, so the
two differ only where an operator names a node's resolvers apart from the
core's, and there each exit answers from the resolvers its own operator
named. What the decision promises is what this delivers: a client's queries
leave through its exit, and names resolve from the exit's region. The
resolvers stay the ones a run argument names, and the proxy resolves
nothing itself: it adds the transport the client lines take to an exit.

### The netmap

`peer` and `netmap` change ([netmap.go](/pkg/apps/coordination/netmap.go)):

*   **Every peer** carries hostinfo naming its node and two services,
    `peerapi4` at port 80 and `peerapi-dns-proxy` at 1. `Cap` stays 0:
    the services claim the proxy alone, where a capability version would
    vouch for every behavior up to it. The client lists the port as the
    peer's peer API, and its other uses of one — Taildrop, Taildrive — need
    capabilities no CION map grants.
*   **The home node's peer** lists its serving address first and the hosts'
    /32s after it, sorted. The client takes the first IPv4 address as the
    peer API's host, and a host of any node whose slice sorts below the home
    node's sorts ahead of the home node's serving address. Every other
    peer's one address is its serving address already.
*   **The resolvers leave:** `ExitNodeDNSResolvers`, `exitResolvers`, and
    `Config.Resolvers`. A client never reads the list while its exit
    proxies DNS, and each exit asks its own resolvers. `Config.PeerAPIPort`
    carries the port in their place, handed over from the egress's
    `HTTPPort` by the coordination entry
    ([coordination.go](/pkg/apps/coordination.go)): the coordination
    package, requiring the WireGuard application alone, imports no egress.

The comments naming the resolvers are rewritten for the proxy. ADR-0024's
standing commitment to the client lines' behavior moves with it: from the
fields that told a client an exit serves no DNS proxy to the services that
offer one and the address its peer API takes.

### The entries and their comments

The egress entry hands the egress the environment's resolvers
([egress.go](/pkg/apps/egress.go)), and the mihomo entry mounts the provider
through the egress it borrows ([mihomo.go](/pkg/apps/mihomo.go)). The comments
on the resolvers —
`Environment.Resolvers` ([apps.go](/pkg/apps/apps.go)) and
`NodeConfig.Resolvers` ([config.go](/internal/services/config.go)) — name
the proxy beside the relay presence, and those on the harness's internet
name the exchange's legs beside a flow's.

### The documentation

The architecture overview's endhost section says a host's names resolve
through its exit's DNS proxy, from the exit's own resolvers
([architecture.md](/docs/design/architecture.md)).

### Compatibility

A founding core on this binary offers every exit's proxy at once. An exit on
the previous binary serves port 80 for the provider alone, so it answers the
proxy's path with a 404, and a client selecting it gets SERVFAIL until the
node upgrades. A node on this binary under a core on the previous one is asked
nothing, for the old netmap names the core's resolvers. A network upgrades
its nodes first and its founding core last.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/apps/egress` | The node's HTTP server, `Mount`, and the DNS proxy |
| `pkg/apps/mihomo` | The provider mounted on the egress's server |
| `pkg/apps/coordination` | The peers' services and order; no resolvers |
| `pkg/apps` | The entries' resolvers, port, and mount |
| `internal/services` | The resolvers' comment |
| `internal/testnetwork` | The exits lab's DNS check |

## Test plan

*   **Unit, the proxy (decision 5):** in the egress's host lab, a host's
    POST to the own address's port 80 is answered from a stub resolver
    reached through the harness's internet, under the query's ID and of
    type `application/dns-message`, the stub having seen another ID; a GET
    with `dns` is answered likewise; a truncated answer is asked again over
    TCP and returns whole; with one resolver silent the other answers; a
    lost datagram is resent; an answer with another ID or question is
    passed over; a silent upstream answers 502 once the bound passes; the
    malformed forms answer 400, 405, 413, 414, and 415; at the flow bound a
    query answers 503 at once; with no resolvers the exchange asks the
    nameservers of a resolv.conf the test names; the proxy answers at the
    own address once the address is claimed.
*   **Unit, the mount:** a handler mounted on the egress answers at the
    own address's port 80 once the address is claimed, and the exits
    application's provider answers there through its mount.
*   **Unit, the netmap (decision 5):** every peer carries `Cap` 0, hostinfo
    naming its node, `peerapi4` at the configured port, `peerapi-dns-proxy`
    at 1, and no resolvers; every peer's first address is its serving
    address, the home node's too when another node's host sorts below it,
    the rest sorted; an unchanged registry rebuilds an equal map.
*   **Unit, the entries:** the egress's configuration carries the
    environment's resolvers, and the coordination application's the
    egress's port.
*   **Integration, the exits lab (decision 5):** every node's
    `--dns.resolvers` names the lab's resolver — the harness names none,
    which would leave each proxy the system's — and each node's harness
    internet maps it onto the node's own, which counts the queries it takes
    over UDP and over TCP. With each exit selected:
    *   `QueryDNS` names the exit's peer API,
        `http://<serving address>:80/dns-query`, as the name's one
        upstream — a resolver the client's forwarder sends to by HTTP alone,
        dialing the exit's tailnet address through the tunnel;
    *   the answer is that exit's resolver's, which the lab's address
        reaches only through that node's harness internet;
    *   that exit's resolver counts the query over UDP, the proxy's leg, and
        neither resolver counts one over TCP, the transport the host's
        tunnel leg reaches them by today.

## Implementation history
