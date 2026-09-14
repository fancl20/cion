# Implement the path library and a SCION-native ping application

This proposal outlines the application seam of
[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md): the
path library — the SCION socket and path resolution an application on a CION
node links to become path-aware — given a package of its own, and proven by
the first application: a SCION-native ping for end-to-end testing. The
WireGuard gateway application that serves plain hosts follows as
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md).

[TOC]

## Summary

Applications on a CION node are in-process consumers of a path library: they
link it, resolve a path, and their packets ride the network. The library's
pieces exist today inside `pkg/controlplane` — `SCIONConn` and `Addr` in
`transport.go`, `PathProvider` in `provider.go` — so importing them imports
the control plane entire: trust, enrollment, beaconing. This proposal moves
the seam into `pkg/scion` — the socket (`Conn`), the path resolver
(`PathProvider`), and the address (`Addr`) — with the control plane
importing the package beside applications and behavior unchanged. On the
library stands `pkg/apps/ping`, first resident of a `pkg/apps` namespace for
applications embedded in the CION binary: a SCMP-echo ping exchanged over
provider-resolved paths, with a responder on a fixed port and a pinger
exposed as a `cion ping` subcommand and as an in-process entry for tests —
the network's first end-to-end proof by a real application, and the
end-to-end check every later milestone's tests begin with.

## Motivation

ADR-0001's founding driver — clients dynamically selecting routing paths —
requires clients, and the network has none: the provider's only consumer is
the node's own control traffic. ADR-0005's first decision names the seam
through which a client appears: linking the path library in-process — no
path API daemon, no second composition of segments. The seam exists as
types; this milestone makes it an import. Two deliverables close it: a
library package applications can consume narrowly, and a first application
that exercises the whole chain — segment discovery, path composition,
packet carriage, arrival-path reversal — between two nodes. Ping is that
application: the network's classic health probe, deliberately the smallest
scope that proves the seam — resolve the freshest path, send SCMP echo
requests, match replies, report.

### Goals

*   Extract the path library into `pkg/scion`: `Conn` (today
    `controlplane.SCIONConn` in `pkg/controlplane/transport.go`) — `WriteTo`
    serializes a full SCION packet over the supplied path and replies
    reverse arrival paths — together with `Addr` and its configuration; and
    `PathProvider` (today `pkg/controlplane/provider.go`), its `Lookup`
    dependency narrowed from the lookup service to the down-segment function
    `Path` calls. The control plane imports the package and keeps its
    behavior; the moved types' tests move with them.
*   SCMP echo as application traffic: echo request and reply construction
    and parsing over the vendored slayers types, with identifiers matching
    the underlay ports the data plane already demultiplexes by
    (`pkg/dataplane/dataplain.go`'s `getDstPortSCMP`).
*   `pkg/apps/ping`, the first resident of the `pkg/apps` namespace: a
    responder serving echo replies on a fixed port, and a pinger — per-reply
    RTT, the reply's path hops, a loss summary — as a `cion ping`
    subcommand and as an in-process entry point.
*   The end-to-end integration: pinger and responder on two nodes of the
    topology harness, requests over a composed multi-segment path, replies
    over the reversed arrival path.

### Non-goals

*   A path API daemon or local query service — ADR-0005 chose in-process
    linking.
*   Gateway concerns — tunnels, host termination, directories, egress —
    which are proposal 0006's milestone.
*   SCMP beyond echo request and reply; traceroute.
*   Path selection policy — the freshest path per destination, following
    ADR-0004. Multipath, metrics, and streaming or monitoring APIs.
*   Changes to the data plane or the trust architecture's artifacts; the
    control plane changes by importing the library.

## Proposal

### The path library

`pkg/scion` is the node's SCION library, the seam ADR-0005 describes with a
home of its own:

*   `Conn` — the SCION socket, moved from `controlplane.SCIONConn`.
    `WriteTo` serializes a full SCION packet over the path in the
    destination `Addr`; `ReadFrom` returns the payload and the arrival
    `Addr`, whose path is the reversed arrival path, so a reply addressed
    with it returns by the road it came by. A `Conn` binds the internal
    underlay on a UDP port of the node's control address — the construction
    `setupControlPlane`'s `scionConn` helper performs today
    (`cmd/cion/main.go`), port 0 for an ephemeral one.
*   `PathProvider` — moved with its fields: the local ISD-AS, the path
    database of up segments, the `Bootstrap` and `Cores` functions, and
    `Lookup` as the narrowed down-segment function. `LocalPath` resolves
    from local state only — the variant safe to call inside a dial; `Path`
    fetches down segments with expiry-aware caching and composes.
*   `Addr{IA, Addr, Path}` — moved.

The control plane imports the package for its endpoint, peer, and core
clients, with `EndpointPort` staying on the control plane's own socket;
applications import the package alone. Where the library meets the vendored
`scionproto` slayers, import aliases keep the two `scion` names apart.

### SCMP echo

The data plane already carries SCMP and delivers echo traffic to internal
sockets by identifier: `getDstPortSCMP` reads the echo identifier as a
destination port (`pkg/dataplane/dataplain.go`). The library builds on it —
a `Conn` sending an echo request stamps its own port as the identifier, so
the reply returns to it — and adds the request and reply constructors and
parsers over the slayers types the data plane already decodes
(`slayers.SCMPTypeEchoRequest`, `slayers.SCMPEcho`).

### The ping application

`pkg/apps/ping` opens the `pkg/apps` namespace with the shape every later
application — proposal 0006's gateway included — repeats: a package
consuming `pkg/scion` and the node's wiring.

*   The responder serves echo replies on the node's endhost port
    (`dataplane.EndhostPort`, 30041): one `Conn` bound to the control
    address's host, each request answered on its reversed arrival path.
    The port is the data plane's, not an application constant:
    `getDstPortSCMP` delivers echo requests to the endhost port of the
    destination host — SCMP has no per-application port — and replies to
    the port in the echo identifier. A fixed `PingPort` beside
    `EndpointPort` would never receive a request.
*   The pinger resolves the destination with `PathProvider.Path`, sends a
    count of requests at a fixed interval with sequence numbers, matches
    replies by identifier and sequence, and reports per-reply RTT, the
    reply's path hops, and a loss summary; the path is re-resolved on
    expiry or error and the run continues.
*   `cion ping` — `cion -config node.json ping 20-ff00:0:2,[addr]` —
    assembles the transport pieces the configuration describes (internal
    link, path database, provider) and runs the pinger; the in-process form
    serves tests and embedded use identically.

### Node wiring

`cmd/cion/main.go` gains the `ping` subcommand beside the daemon path, and
constructs its sockets through `pkg/scion` where it today names
`controlplane.SCIONConn`; the daemon's startup order is otherwise as
proposal 0004 left it.

## Test plan

*   **Unit tests:** the extraction is a refactor — the moved `Conn` and
    `PathProvider` tests pass against the new package, with the narrowed
    lookup covered by an injected function; echo request and reply
    round-trip through the constructors and parsers; the identifier equals
    the sending socket's port; RTT accounting and the loss summary.
*   **Integration tests:** the topology harness of
    `pkg/controlplane/network_test.go` — a responder on node B and a pinger
    on node A: requests ride a composed up/down path, replies ride the
    reversed arrival path, and the reported hops name the traversed
    segments; a path expiring mid-run is re-resolved and the run continues.
*   **Negative tests:** a destination with no resolvable path returns an
    error rather than hanging; an unknown ISD-AS is reported unreachable;
    the subcommand with a missing configuration fails with the
    configuration error.

## Implementation history

*   Library: `pkg/scion` holds the socket (`Conn`, from
    `controlplane.SCIONConn`), the address (`Addr`), and the resolver
    (`PathProvider`, its `Lookup` narrowed from the lookup service to the
    down-segment function); the moved types' tests moved with them, the
    control plane imports the package with its behavior otherwise
    unchanged, and import aliases (`spath` for the vendored
    `slayers/path/scion`) keep the two `scion` names apart where they meet.
*   SCMP echo: request and reply constructors and parsers beside the UDP
    datagram path on the same socket — `WriteEchoRequestTo` stamps the
    socket's own port as the identifier, `ReadEchoFrom` returns the
    message with the reversed arrival path — with the SCMP checksum
    computed on send and, like the data plane, not verified on receipt.
*   Application: `pkg/apps/ping` — a responder bound to the endhost port
    (see above for why not a `PingPort`; the sample configurations' internal
    links moved from 30041 to 30042 so the responder's bind does not
    collide) and a pinger as a library entry (`ping.Run`) and the `cion
    ping` subcommand, which rides the node's full assembly in place of
    serving. Both were exercised against two real processes.
*   Provider: one gap the first consumer surfaced — a down segment whose
    origin core is the local node is itself the complete route (cores hold
    no up segments to compose before it) — is resolved in `Path`, so
    `cion ping` works from a core node.
*   Lookup: an empty down-segment fetch is no longer cached for the TTL —
    a fetch racing the destination's first registration otherwise left the
    route poisoned for a minute.
*   Composed paths: the end-to-end proof runs on a fork topology (core
    between two leaves). On a line, the composed route to the middle node
    revisits it mid-path, and the routers reject a packet whose destination
    ISD-AS is local before the path's last hop — legal path syntax, but
    not carriage the (upstream) forwarding check permits; revisiting
    compositions are a path-selection concern for a later milestone.
*   Tests: the moved socket and parse tests, echo wire round trip and
    exchange over one hop, provider resolution and expiry with an injected
    lookup, a crafted-segment expiry that re-resolves mid-run and recovers,
    the fork-topology composed ping with per-reply hops and RTT, the loss
    summary with the responder down, the unreachable destination, and the
    subcommand's target parsing and missing-configuration errors.