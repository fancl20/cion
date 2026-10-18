# Bind the default control address on every interface

This proposal grounds on [ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
— the measured topology whose loading "is what makes a node zero-conf" — and
extends [proposal 0028](/docs/proposals/0028-learn-the-external-address-from-rendezvous.md)
from the published side of the address to the bound side. The control
address's default becomes the wildcard, every socket binds it — the founding
core's HTTPS included — and every establishment records the observed host
where a claim names none, so a real deployment names no address the host
could derive itself. The per-host control address — the one run argument
left — retires, through the bare-host grammar
[proposal 0060](/docs/proposals/0060-accept-a-bare-host-in-the-address-run-arguments.md)
lands beside this seam.

[TOC]

## Summary

Proposal 0028 split what a node binds from what it publishes: every socket
binds the control host, the directory entry publishes the learned external
host at the fixed ports, and the founding core publishes its identity's
address. A real host nevertheless still names its own address, for three
reasons:

*   The default binds the loopback
    ([config.go](/internal/services/config.go)) — unusable off-host.
*   A wildcard bind poisons the link table. Link sockets are allocated on
    the control host in the 31000 band, and the establishment records the
    *claimed* address verbatim as the peer's remote — the rendezvous
    request's claim and the reply's answer
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)),
    the in-band link reply's answer
    ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go))
    — so a wildcard-bound node teaches its peers to dial `0.0.0.0:31xxx`.
*   The founding core's HTTPS bind refuses the wildcard outright
    ([https.go](/internal/services/https.go)).

Four moves retire the per-host address:

*   **The observed host over the unnamed claim.** The claim's host when it
    names one — today's behavior, verbatim — else the host the exchange
    already observed: the acceptor records the request's observed source
    host under the claim's port, and the dialer records the reply's source
    host the same way, beside the in-band reply's dial host. The exchange's
    own return-routability has already proved the observed address answers;
    the port belongs to the claim, the socket that will receive.
*   **The wildcard binds everywhere.** The HTTPS refusal drops — its
    published endpoint names the identity, not the bind host, and the CA's
    challenges want 443 on every interface. The service registrations
    deliver to a concrete local host instead of the wildcard.
*   **Publications never carry a wildcard.** The fallback publication —
    the control host before anything is learned — publishes nothing
    instead, exactly the founder's unresolved name; the WireGuard host
    endpoint gains the published-host split the node directory already
    has, instead of publishing its bind host.
*   **The default flips.** `DefaultControl` becomes the bare wildcard
    host, the port arriving by the derivation
    [proposal 0060](/docs/proposals/0060-accept-a-bare-host-in-the-address-run-arguments.md)
    already reads; the help it restated says the wildcard binds every
    interface of its family.

## Motivation

The zero-conf goal is ADR-0017's own first driver — "two run arguments and
generated local state" — and the two arguments a joiner still truly needs
are the neighbor's address and the core's identity. The control address is
not one of them: it names a fact about the host the host knows better than
its operator, and naming it wrong is silent in the worst direction. A
loopback default binds every socket where no peer can reach it; a copied
address from another host's notes binds nothing; a cloud host whose NIC
carries a private address behind a one-to-one mapping binds correctly but
only by luck of the operator knowing the mapping's inside address.

The published side already learns itself. Every rendezvous dial observes
the mapped source, the learned host persists beside the identity, and the
entry publishes it at the fixed ports — the claim's only remaining reader
that matters off-host is the link table's remote, and the exchange observes
that too, on both sides, without using it. What the claim holds over the
observation is the port: the observed port belongs to the dial's ephemeral
socket, closed with the dial, while the claim names the link socket's port
in the band. Host from the observation, port from the claim — the fact each
side actually holds.

The boundary 0028 drew stands: no hole is punched and no mapping is kept
alive. A wildcard bind publishes truthfully through a one-to-one mapping
and a public NIC alike; a node behind address and port translation joins
but cannot be joined, exactly as before.

### Goals

*   `DefaultControl` is the IPv4 wildcard; a node on a publicly addressed
    host boots with no `--control`, binds every interface, and is joinable.
*   The claim rule: a claim with a host records verbatim, a claim without
    one records the observed host under the claim's port — the acceptor by
    the request's source, the dialer by the reply's source, the in-band
    establishment by the host it dialed.
*   The founding core binds the wildcard at the HTTPS port; the refusal
    and its check retire.
*   The wildcard publishes nowhere: the fallback publication holds until a
    host is learned, and the WireGuard entry's host endpoint carries the
    published host.
*   The service registrations carry a concrete local host.

### Non-goals

*   No NAT traversal: 0028's boundary stands untouched.
*   No wire change: the reply already echoes the observed source; the
    recorded-claim preference is node policy. A mixed-version pair — a
    wildcard-bound node against an unupgraded acceptor — records the
    wildcard verbatim at the old peer and never proves out; upgrade
    ordering, not protocol.
*   No dual-stack default: `0.0.0.0` binds IPv4, an IPv6-only host names
    `[::]` or its own address through the same grammar, and the published
    entry keeps its one host.
*   No advertised-address argument: 0028's non-goal stands; the learned
    host and the identity cover the cases.
*   No change to `--internal`: the loopback default is correct everywhere,
    for the internal address is the local path between the node's sockets
    and its data plane, invisible off-host by design.

## Proposal

### The claim and the observation

One rule at every site that records a peer's link address: *the claim's
host when it names one, the observed host when it does not, the claim's
port always.*

The acceptor side. The rendezvous acceptor's admission
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go))
records the request's `LinkAddr` both when it mints a candidate and when a
claim retargets one; the handler already holds the request's observed
source, the address it replies to, and the rule applies it: an unspecified
claim's port on the observed host. A concrete claim — the lab nodes' named
loopback addresses, a static link-set's pinned locals, any deliberate
bind — records verbatim, exactly as today, so nothing that works changes.

The dialer side. `RendezvousEcho`'s reply read discards the datagram's
source; it keeps it, returning the observed address beside the reply. The
joiner's dials — the bootstrap exchange, the join loop, the stranded
revivals ([provider.go](/pkg/modules/topology/impl/measured/provider.go))
— and the selection loop's establishment
([selection.go](/pkg/modules/topology/impl/measured/selection.go)) record
the reply's `LinkAddr` under the same rule: the reply's source host when
the answer's host is unspecified. The reply leaves the acceptor's
rendezvous socket, bound beside every other socket on the control host, so
its source is the acceptor's routable host on the path the dial already
proved.

The in-band arm. The establishment's in-band request
([selection.go](/pkg/modules/topology/impl/measured/selection.go)) rides a
composed path to the peer's published control address, and the reply's
`LocalAddr` ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go))
is the peer's claim; under the rule, an unspecified claim's port records
on the host the requester dialed — the published host both fixed ports and
the link band sit on.

### The binds

`httpsBindAddr`'s refusal
([https.go](/internal/services/https.go)) retires. Its reason — the
published endpoint would name an address no host could dial — belonged to a
tree where the endpoint published the bind host; the published coordination
endpoint names the identity now, the certificates maintain under it, and
the ACME challenges the node already answers want port 443 held on every
interface, which is what a wildcard bind holds. The harness placement
override stands.

The rendezvous acceptor, the endpoint conn, the allocation in the link
band, and the WireGuard listen socket already bind whatever the control
host names; a wildcard binds every interface of its family and sends with
the kernel's per-route source, which is the address the observation
teaches. The local `Local` values stay bind values — a generation rebinds
them, the data plane receives on them — and only the copies that cross to
a peer take the rule above.

The service registrations — the control service and the applications'
backends ([dataplane.go](/internal/services/dataplane.go)) — name the
delivery address the data plane's internal link forwards to. A wildcard
there delivers by the operating system's wildcard-means-loopback
convention, which is no contract; when the control host is unspecified the
registrations carry the internal address's host instead, the loopback the
internal link already sends from and every wildcard-bound receiver covers.

### The publications

The measured provider's fallback
([provider.go](/pkg/modules/topology/impl/measured/provider.go)) returns
the control host when nothing is learned; under a wildcard bind it returns
the zero address instead, and the publish loop's existing unresolved-host
path holds the publication for the retry — the same treatment the founding
core's unresolved name already gets
([directory.go](/pkg/modules/topology/impl/measured/directory.go)). A
first start always learns before it could publish: the bootstrap dial
precedes assembly, and a restart loads the persisted host.

The WireGuard application's own entry
([directory.go](/pkg/apps/wireguard/directory.go)) publishes its bind host
as the host-facing endpoint — the one published surface 0028's split never
reached, wrong today for any node whose public face differs from its bind.
The application environment gains the published-host resolver beside the
control host, and the entry's endpoint resolves it at each publication:
the learned host, else the bind host when it names one, else the entry
publishes nothing and the cadence retries. The resolver is the provider's
own, so both publications answer with one host.

### The default and the family

`DefaultControl` becomes the bare wildcard host — the constant naming the
host alone, its port derived where the resolution already derives it — and
the flag's help, which
[proposal 0060](/docs/proposals/0060-accept-a-bare-host-in-the-address-run-arguments.md)
restated around the bare form, says the wildcard binds every interface of
the family. The founding core's domain
resolution keeps its family filter for a control host that names one — the
answer must share the bind's family, the sockets receiving what the
published address draws — and for a wildcard, which names none, the
resolver's first answer publishes.

`--internal` and its loopback default are untouched.

### The documents

ADR-0017's decision 10 draws the exchange as a round trip beneath SCION
bounded by return-routability — the observed host is that bound's own
fact, applied where the claim was silent. The architecture overview's
rendezvous paragraph and
[security.md](/docs/design/security.md)'s first-contact bullet stand as
written: the exchange's posture is unchanged, and binding every interface
exposes doors that were already the boundary — the nonce check and the
admission caps at the rendezvous, mutual authentication at the endpoint,
the enrollment gate behind both.

The change lands in one commit.

## Test plan

*   **The rule:** the acceptor records an unspecified claim's port on the
    observed host and a concrete claim verbatim; the dialer records the
    reply's answer under the same rule, the echo returning the observed
    source; the in-band reply records on the dialed host for an
    unspecified claim.
*   **The binds:** a node resolves and boots with the wildcard default —
    the constant's bare form through the resolution's derivation — and
    every socket binds it; the founder's HTTPS binds where today's refusal
    fired, and the refusal's episode flips to the bind's.
*   **The publications:** a wildcard fallback publishes nothing until a
    host is learned, then the learned one; the WireGuard entry's endpoint
    follows the resolver — learned host, concrete bind, else held.
*   **The registrations:** the service map carries the internal host under
    a wildcard control address and the control host otherwise; the
    internal link delivers to it.
*   **The proofs:** the integration suites pass unmodified — every lab
    node names its own loopback address, a concrete claim the rule keeps
    verbatim — and one episode binds two assembly nodes wildcard and links
    them through their observed addresses, the founder's HTTPS serving the
    coordination surfaces beside them.

## Implementation history

None yet.
