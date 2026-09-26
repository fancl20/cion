# Serve the coordination endpoint from the node

This proposal grounds on
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md):
the core's WebPKI identity — certmagic behind `--domain`, certificate files
as the offline fallback — is core machinery, the anchor a joiner's first
fetch verifies against, whatever apps the core loads; and apps expose their
services through the assembly, not by taking ports of their own. It moves
the coordination endpoint of
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
onto that ground: the application stops owning the HTTPS listener and
contributes its handlers to a server the node assembly owns — the one
server that holds port 443, presents the identity, and answers the ACME
TLS-ALPN challenge beside whatever protocols the mounted apps speak. No
client sees a difference; the record ADR-0011 drew — the endpoint rides
the core's WebPKI identity — stands, and this narrowing is recorded here
alone.

[TOC]

## Summary

What exists is a fork with an app in one of its arms. The core assembles
its identity two ways, keyed on whether the run arguments name a wireguard
configuration — the proxy for "the coordination application will load"
(`internal/services/controlplane.go`): `webpki.PrepareTLSCert` when
coordination serves, handing the application a shared `tls.Config` to
clone, and `webpki.ManageTLSCert` when it does not, standing a dedicated
TLS-ALPN challenge listener on 443. The coordination application owns the
listener in the first arm: it clones the configuration, advertises
`acme-tls/1` beside `http/1.1` itself — the ALPN name that carries an
ACME probe's handshake to certmagic's challenge certificate — binds, and
serves (`pkg/apps/coordination/app.go`).

The costs are structural. The fork keys the core's TLS behavior on an
app's presence, and apps are optional by ADR-0009's design. The challenge
contract is split across packages: the library owns the need, the
application owns the advertisement, and forgetting the name breaks
issuance at runtime with nothing at assembly refusing it. And the
maintenance loop and the application's bind start as concurrent
goroutines, so a first issuance whose probe beats the bind rides certmagic's
retry backoff to convergence.

This proposal lands one path. The node prepares the identity on every
core and owns the HTTPS server built on it: the server's TLS advertises
`http/1.1` and `acme-tls/1`, its settings stay stream-friendly, and its
handlers are whatever the assembled apps contribute. The coordination
application hands the assembly its three surfaces — `/key`, `/ts2021`,
`/derp` — and keeps its keys, its state, its noise machine, and its relay
conversations; the listener, the TLS configuration field, and the serving
loop retire. A core whose apps mount nothing degenerates to the challenge
answerer the dedicated listener was; a core with static certificate files
and no internet-facing app binds nothing, as it does not today.

## Motivation

Port 443 is the node's port already, in both arms of the fork. The ACME
challenge must be answered there whatever the core serves beside it, so
the non-coordination arm binds it with a bare handshake listener and the
coordination arm binds it with the application — the fork decides which
code holds a port the core requires either way. An identity the network
depends on, whatever the node's own policy loads, is ADR-0009's own
definition of core; the serving of that identity's challenge belongs with
it.

The assembly contract already covers this shape. ADR-0009: "apps expose
their services through the assembly, by the two mechanisms the node
already has" — control services mount on the endpoint's mux as
interfaces, and data-plane services register their own sockets with the
assembly. The topology provider's `Mounts()` feeding the endpoint's mux
is the in-repo precedent. The coordination listener is a third mechanism
invented beside them; conforming it to the first retires the invention
rather than adding a fourth.

The brittleness compounds toward the future the design intends. The
`WireguardConfig != ""` test is a proxy — coordination loads because the
core holding the directory store implies the service, today — and every
future internet-facing application would face the same negotiation for
the port or grow another fork arm. Optional apps cannot be optional while
the core's TLS path branches on their presence.

Two defects of the current split repair themselves in the move. The ALPN
advertisement joins the machinery that needs it: whoever owns certmagic
owns the challenge, one name in one place, no cross-package contract to
remember. And the bind becomes synchronous structure — the assembly binds
443 before it launches the maintenance loop — where today the two start
as racing goroutines.

### Goals

*   One identity path on the core: `PrepareTLSCert` and the node-owned
    server; `ManageTLSCert` and the dedicated challenge listener
    (`serveTLSALPN01`) retire.
*   The node's HTTPS server: assembled by the node from the shared
    identity, advertising `http/1.1` and `acme-tls/1`, carrying whatever
    handlers the loaded apps contribute, with settings that hold
    long-lived streams — a read-header timeout alone, as the coordination
    server's are today.
*   The coordination application contributes handlers: the `TLS`
    configuration field retires, the application exposes its surfaces for
    mounting, and it keeps its own keys, state, and `Close`; its `Run` —
    whose body was the bind and serve — retires with the listener.
*   The bind decision is the node's own fact: bind when the identity is
    ACME-managed or an app contributed handlers; a static-file identity
    on a core whose apps mount nothing binds nothing.
*   The integration harness's placement override stands: the coordination
    address, its loopback bind, and its pinned certificate keep their
    semantics, consumed by the node's bind instead of the application's.
*   No client-visible change on the wire.

### Non-goals

*   No HTTP/3 or HTTP/2 on the internet surface: the client protocol's
    upgrade and the relay's both ride HTTP/1.1, and the server grows no
    protocol beyond what the mounted apps speak.
*   No second internet-facing application and no general mounting
    framework: one consumer exists today, and the pattern generalizes
    when a second app lands — not before.
*   No change to the SCION control endpoint, its HTTP/3 channel, or the
    service registration the data plane generations carry.
*   No egress movement: [ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)
    keeps its subject and its draft stands.
*   No ADR re-decision: ADR-0011's boundary — the endpoint rides the
    core's WebPKI identity, hosts are plain internet clients — is
    untouched, and no record is edited; the narrowing lives in this
    proposal alone.

## Proposal

### The node owns the HTTPS port

`pkg/webpki` grows the serving half of the identity it already prepares.
The bare challenge listener — a TLS listener whose handshakes answer and
whose connections carry nothing — generalizes into the node's HTTPS
server: the same clone of the shared configuration with `http/1.1` and
`acme-tls/1` beside the `GetCertificate` that answers both, bound to the
address the assembly names, serving the handler the assembly built. The
seam is one function in the library's present shape — prepare the
identity, then serve it, with the HTTP-01 listener on port 80 standing
as it does. The library keeps its altitude: no policy, no handlers of
its own, the challenge and the mounted app's protocols beside each other
inside one TLS configuration.

The settings the shared server carries are the stream-friendly ones the
coordination server carries today — a read-header timeout and nothing
beside. This is a contract of the surface, not an implementation detail:
the netmap poll and the relay conversations are long-lived connections a
server-level write timeout would cut, and the node's server now holds
them for every mounted app.

### The coordination application contributes its surfaces

The application assembles as it does — keys load or create in its own
state, the DERP server stands on its node key, the noise machine on its
machine key — and hands the assembly its HTTP surface instead of a
server: the `/key` fetch, the `/ts2021` upgrade, and the `/derp` relay,
one handler, the mux the assembly mounts it at. The `TLS` field of its
configuration retires with the clone it carried; `Run` retires with the
bind and serve it was; `Close` keeps its work — the relay's connected
clients — and the assembly releases the application before the
WireGuard application whose store it borrows, as it does today.

The wildcard-address refusal moves with the bind: refusing an address
whose published endpoint no host could dial is a fact about the
internet-facing listener, and it becomes the node's check at the address
it binds — the message standing as it does.

### One path through the assembly

The fork in `assembleEndpoint` retires. Every core prepares the identity
and holds the certificate manager; after the applications assemble, the
node knows the handlers it carries; at `start` it binds the HTTPS server
synchronously — the address resolved, the listener held — and only then
launches the certificate maintenance loop, so a first issuance's probe
finds the port answered by structure rather than by retry. The bind
decision is the node's own: the ACME-managed identity binds for the
challenge alone when no app contributes handlers, the mounted handlers
bind beside it when one does, and a static-file identity on a core whose
apps mount nothing leaves the port unbound, as the tree behaves today.

The integration harness's override keeps its meaning: the coordination
placement names the address the node binds and the certificate the relay
advertises, its loopback and pinned certificate standing in for the
domain and the WebPKI, consumed one assembly phase earlier than the
application that consumed it before.

## Test plan

*   **Unit, the server:** a TLS client offering `acme-tls/1` completes
    its handshake against the node's server with certmagic's challenge
    certificate served from the cache — the challenge answered on the
    mounted server, no dedicated listener; a plain HTTP/1.1 request
    reaches a mounted handler; a static-file identity with no mounted
    handlers binds nothing; the bind returns with the port held, so the
    maintenance loop launches against a listening server.
*   **Unit, the application:** the three surfaces answer over an
    externally assembled server — the key fetch, the upgrade into the
    noise channel, a relay probe; `Close` retires the relay's connected
    clients; no `TLS` field remains for a caller to set.
*   **Integration:** the coordination and admission suites stand as
    their episodes run them — the vendored client engine joins through
    the login, receives its netmap, completes the handshake within one
    fetch cadence, and exchanges traffic through the mesh — with the
    node serving the endpoint; the harness placement override answers
    on its loopback address with its pinned certificate as before.
*   **Negative:** a wildcard control address refuses the boot at the
    bind with the published-endpoint message; no mounted handlers and a
    static-file identity leave port 443 unbound; a long-lived map poll
    under a slow consumer is not cut by a server timeout.

## Implementation history
