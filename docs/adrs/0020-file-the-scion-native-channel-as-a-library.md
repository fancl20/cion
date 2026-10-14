# File the SCION-Native Channel as a Library

*   Status: accepted
*   Date: 2026-10-14

[TOC]

## Context and problem statement

[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
enumerates the SCION-native control endpoint as a core item — "HTTP/3 over
QUIC over SCION paths, peers authenticated by their chains against the TRC
— serving the drafts' services" — and files the channel's peer-identity
middleware as a library, "the piece both sides of the node's boundary
speak". The rest of the channel lives in the control plane's package:
serving HTTP/3 on a SCION socket, with the drafts' service resolution
answered on the same socket; dialing a peer's endpoint; the TLS that
authenticates peers against the TRC; the authority encoding that names a
peer; the endpoint's port; and the handlers applications mount on the
endpoint. The channel realizes the control-plane draft's communication
protocol (Section 1.7) and control service discovery (Section 5); the
package's other files realize the draft's beaconing, registration, and
lookup (Sections 2 to 4) and the services that answer them.

Applications and modules speak the channel from there. The WireGuard
application serves its directory over it and dials its core's; the measured
provider dials its peers' directories and mounts its services on the
control endpoint; the voting application names its core's endpoint and
reads a submission's source; the topology contract declares its mounts in
the channel's type. In production, each imports the control plane for the
channel alone, and the dial's own document calls it "the control endpoint's
client machinery as a library".

The channel cannot move to the libraries as it is:
[ADR-0018](/docs/adrs/0018-file-every-package-under-the-roof-of-its-kind.md)
lets a library import only libraries and module contracts, and the
channel's TLS reads the node's chain, its key, and the TRC anchors from the
trust engine, a core package. Upstream keeps its counterparts as libraries
outside its control service — `pkg/snet/squic`, `pkg/connect`, and
`private/svc` — with the TLS verifier beside its trust library.

This ADR decides where the SCION-native channel lives.

## Decision drivers

*   **Libraries Are the Shared Vocabulary:** what core and applications
    share, with no loops of its own and no policy, is a library.
*   **Importers Depend on What They Use:** an application or module that
    speaks the channel imports the channel, not the control service.
*   **Each Package Reviews Against Its Sections:** the control plane's
    package reads against the control-plane draft's beaconing,
    registration, and lookup, and the channel against the draft's
    communication protocol and service discovery.
*   **The Control Service Stays Whole:** the drafts' services, the server
    that composes them, and the client that calls them share a package.
*   **Mechanical Moves:** identifiers keep their names, and no behavior
    changes.

## Considered options

*   **A Library, `scionrpc`:** the channel in `pkg/libs/scionrpc`, reading
    the node's credentials through an interface.
*   **A Sixth Core Member:** the channel in a core package of its own,
    importing trust as today.
*   **The Whole Transport:** the channel, the server that composes the
    drafts' services, and the peer client that calls them leave the control
    plane together.
*   **Stay Put:** the channel remains in the control plane's package.

## Decision outcome

Chosen option: **a library, `scionrpc`** — realized as follows:

1.  **The SCION-native channel moves to `pkg/libs/scionrpc`,** its
    identifiers keeping their names:
    *   serving HTTP/3 on a SCION socket, with the drafts' service
        resolution answered on the same socket (`ServeHTTP3`), and the
        resolution's client (`ResolveService`);
    *   dialing a peer's endpoint (`NewSCIONClient` and its
        `PeerClientConfig`), and the authority that names the peer
        (`PeerAuthority`);
    *   the endpoint's TLS: the bootstrap channel's WebPKI certificate
        beside the TRC-anchored mutual TLS (`EndpointTLS` and its
        `EndpointTLSConfig`);
    *   the endpoint's port (`EndpointPort`) and the handlers applications
        mount on the endpoint (`Mount`);
    *   the reader of a request's remote address (`RemoteUnderlay`).
2.  **The control service stays in the control plane.** The drafts'
    services, the composition that serves them with the mounts
    (`ControlPlane`, `Services`, `NewServer`), and the peer client the
    beaconer and the lookup call (`Client`, `PeerClient`) ride the library:
    the control plane imports it, never the reverse.
3.  **The channel declares the credentials it reads.** The chain it
    presents and the TRC anchors it verifies peers against come through an
    interface the library declares and `*trust.Engine` satisfies, and the AS
    key comes beside it. The library imports no core package, as ADR-0018's
    sixth decision requires.
4.  **Applications and modules import the library, not the control
    plane.** The WireGuard and voting applications, the topology contract,
    and its providers speak the channel through `scionrpc`; in production,
    the assembly alone imports the control plane.
5.  **The libraries gain a member.** This extends the libraries ADR-0018's
    first decision lists. The control endpoint stays the core item ADR-0009
    enumerates: the node serves it with the control plane's server over the
    library's channel, as the channel rides the SCION library's socket.
6.  **The landed records stand as written.** The map below translates
    their links at HEAD.

| Before | After |
|---|---|
| `pkg/core/controlplane/mtls.go` | `pkg/libs/scionrpc` |
| `pkg/core/controlplane/resolution.go` | `pkg/libs/scionrpc` |
| `ServeHTTP3` and `Mount` in `pkg/core/controlplane/server.go` | `pkg/libs/scionrpc` |
| `NewSCIONClient`, `PeerClientConfig`, and `PeerAuthority` in `pkg/core/controlplane/peerclient.go` | `pkg/libs/scionrpc` |
| `EndpointPort` in `pkg/core/controlplane/transport.go` | `pkg/libs/scionrpc` |
| `RemoteUnderlay` in `pkg/core/controlplane/trustservice.go` | `pkg/libs/scionrpc` |

### Positive consequences

*   No application or module imports the control plane in production: each
    imports the channel it speaks.
*   The control plane's package reads against the control-plane draft's
    beaconing, registration, and lookup, and the channel's against its
    communication protocol and service discovery.
*   The channel's TLS can be tested with credentials of the test's own
    making.

### Negative consequences

*   The TLS configuration and the dial take the credentials and the key in
    two fields where they took the engine in one.
*   The assembly's, the applications', and the modules' references change
    their package qualifier, and the channel's tests need fixtures of their
    own.
*   Upstream keeps its TLS verifier beside its trust library; CION's stays
    with the channel, behind the interface.

## Pros and cons of the options

### A library, `scionrpc`

*   Good, because it files the channel where ADR-0009 files its middleware,
    among the vocabulary both sides speak, as upstream keeps its
    counterparts.
*   Good, because importers depend on the channel alone.
*   Bad, because the library cannot import trust: the credentials cross an
    interface, and the key a field of its own.

### A sixth core member

*   Good, because the move is mechanical: the engine stays the TLS's input.
*   Bad, because applications would import a core package for shared
    vocabulary, and the core would gain a member that is no engine.
*   Bad, because the core walk, ADR-0018's first decision, and the
    architecture overview would change again.

### The whole transport

*   Good, because the control plane would keep the drafts' services and
    loops alone.
*   Bad, because the control service would leave its package: the server
    composes the control plane's services, and the beaconer and the lookup
    call the peer client.
*   Bad, because the server could no longer read the mounts off the
    services' composition and would take them as an argument of their own.

### Stay put

*   Good, because nothing moves.
*   Bad, because every application and module that speaks the channel keeps
    importing the control service.
