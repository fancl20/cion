# File the SCION-native channel as a library

This proposal implements
[ADR-0020](/docs/adrs/0020-file-the-scion-native-channel-as-a-library.md):
the SCION-native channel moves from `pkg/core/controlplane` to a library,
`pkg/libs/scionrpc`, which reads the node's credentials through an
interface of its own. The control service's composition and peer client
stay. Identifiers keep their names; the channel's two configurations take
the credentials and the AS key where they took the trust engine, and no run
argument, wire message, store format, or behavior changes.

[TOC]

## Summary

The channel spans five files of the control plane's package, about 530
lines, with 430 lines of tests:

*   [server.go](/pkg/core/controlplane/server.go): `ServeHTTP3`, which
    serves HTTP/3 on a SCION socket and answers the drafts' service
    resolution on it, and `Mount`, a handler an application serves on the
    endpoint.
*   [peerclient.go](/pkg/core/controlplane/peerclient.go): `NewSCIONClient`
    and its `PeerClientConfig`, the dial over the channel, and
    `PeerAuthority`, which names a peer.
*   [mtls.go](/pkg/core/controlplane/mtls.go): `EndpointTLS` and its
    `EndpointTLSConfig`, the bootstrap channel beside the TRC-anchored
    mutual TLS.
*   [resolution.go](/pkg/core/controlplane/resolution.go):
    `ResolveService`, the resolution's client.
*   [transport.go](/pkg/core/controlplane/transport.go): `EndpointPort`,
    beside the package's document.

`RemoteUnderlay` reads a request's remote address beside the trust service
([trustservice.go](/pkg/core/controlplane/trustservice.go)), and the
segment service's arrival-interface check reads the same context key
([segmentservice.go](/pkg/core/controlplane/segmentservice.go)). The TLS
reads the trust engine's chain, key, and anchor pool. Outside the package,
the voting and WireGuard applications, the topology contract, and its file
and measured providers import the control plane in production for these
alone; the assembly uses them beside the control service.

## Motivation

ADR-0020 files the channel among the libraries, so that an application or
module that speaks it no longer imports the control service.

### Goals

*   The channel lives in `pkg/libs/scionrpc` with its tests, and the
    library imports no core package.
*   No application or module imports the control plane in production.
*   The control plane reads a request's remote address through the library,
    and its production sources no longer import quic-go's HTTP/3 package.

### Non-goals

*   The control service stays in the control plane: the drafts' services,
    `ControlPlane`, `Services`, `NewServer`, `Client`, and `PeerClient`.
*   No identifier changes name, and the trust engine's API is unchanged.
*   The applications' and the topology contract's configurations keep the
    trust engine, and hand the channel its credentials and key.
*   The bootstrap channel's client keeps its own HTTP/3 client: it verifies
    the core's WebPKI certificate, not a chain against the TRC.
*   No roof check gains a rule: ADR-0020 decides none.
*   The two-node fixture the tests copy is not consolidated across
    packages.

## Proposal

### The library

`pkg/libs/scionrpc` holds the channel:

*   `scionrpc.go`: the package's document, `EndpointPort`, `Mount`, the
    `Credentials` interface, and the readers of a request's remote address.
*   `serve.go`: `ServeHTTP3` and the socket's demultiplexer, which answers
    service resolution, from `server.go`.
*   `client.go`: `NewSCIONClient`, `PeerClientConfig`, and `PeerAuthority`,
    from `peerclient.go`.
*   `mtls.go`, as it is but for the credentials, and `resolution.go`, as it
    is.

`Credentials` declares what the TLS reads: `Chain`, the node's chain, and
`AnchorPool`, the TRC anchors peers' chains verify against.
`*trust.Engine` satisfies it unchanged. `EndpointTLSConfig` and
`PeerClientConfig` carry `Credentials` and `Key`, the AS key, where they
carried `Engine`.

`RemoteAddr` returns the SCION address a request's connection carries,
read off the context key quic-go's HTTP/3 server sets, or nil when the
context carries none; `RemoteUnderlay` reads its underlay address through
it. ADR-0020 lists `RemoteUnderlay` alone: the second reader lets the
segment service read the arrival interface without the key.

The package's document states what the library is: the drafts' RPC over
HTTP/3 (QUIC) riding SCION paths (control plane draft, Section 1.7), peers
authenticated by their chains against the TRC, and the drafts' service
resolution answered beside it (control plane draft, Section 5).

### The control plane

The control service stays as it is. `PeerClient` takes the library's
`PeerClientConfig` and dials through `NewSCIONClient`, and `Services`
carries its mounts as `scionrpc.Mount`. The trust service's admission facts
and rate cap, and the segment service's arrival interface, read the remote
address through the library. With `EndpointPort` gone, `transport.go` holds
the package's document alone: the document moves atop `server.go`, stating
that the package is the control service the endpoint serves over the
channel, and `transport.go` goes.

### The importers

The voting and WireGuard applications, the topology contract, and its file
and measured providers import `scionrpc` for what they imported the control
plane for. The WireGuard directory's TLS and the two directory clients'
dials hand over the engine as the credentials and its key beside it. The
assembly does the same for the endpoint's TLS and the peer client
([node.go](/internal/services/node.go),
[controlplane.go](/internal/services/controlplane.go)), and imports both
packages.

### The tests

*   `mtls_test.go` and `resolution_test.go` move to the library,
    `server_test.go` moves as `serve_test.go`, and the authority's and the
    dial's episodes leave `transport_test.go` for `client_test.go`. They
    stay internal tests, for they read the package's unexported state.
*   The library's `fixtures_test.go` declares what they took from the
    control plane's tests: a copy of the two-node data-plane fixture on a
    loopback host of its own, `127.0.0.131`; the ISD-ASes; a founder on
    `trusttest`; and the trust database's opener.
*   The resolution episode served its peer's endpoint with the control
    plane's trust service; in the library it serves the endpoint with the
    channel alone, for the resolution's answer needs no handler.
*   The control plane keeps its fixture for the enrollment episodes, which
    serve the trust service over the channel; `transport_test.go` becomes
    `node_test.go`.
*   New episodes cover the readers: `RemoteAddr` and `RemoteUnderlay` with
    and without the context key, and the arrival-interface check refusing a
    request without a remote address or an arrival interface.

### The documents

The architecture overview's libraries gain the channel, and its control
endpoint speaks the control services over it. ADR-0020 flips to accepted.

The change lands in one commit.

## Test plan

*   **Fidelity:** the moved tests pass in the library unchanged but for the
    credentials and the resolution episode's endpoint; the control plane's,
    the applications', the providers', and the assembly's tests pass with
    the new qualifier; and the integration labs pass unmodified.
*   **The credentials:** the TLS episodes hand the library trust engines,
    so the interface is checked against the type the node passes.
*   **The readers:** the trust service's authorizer and rate-cap episodes
    and the voting application's source episode, which set quic-go's
    context key themselves, pass through the library's reader, and the new
    episodes pin both readers and the arrival-interface check.
*   **The boundary:** the libraries' import check passes with the new
    member, which imports no core package; in production, the control
    plane's only importer is the assembly, and the control plane imports
    quic-go's HTTP/3 package no more.

## Implementation history
