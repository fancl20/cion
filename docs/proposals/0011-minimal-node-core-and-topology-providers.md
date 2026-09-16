# Implement the minimal node core and the topology providers

This proposal implements
[ADR 0007](/docs/adrs/0007-keep-a-minimal-node-core-and-move-everything-else-to-apps.md):
the node core is enumerated and frozen, `pkg/controlplane` slims to the
SCION subset it implements plus its greeting glue, and everything else
moves — the topology machinery of
[ADR-0006](/docs/adrs/0006-form-topology-with-measured-neighbor-selection.md)
becomes the measured provider, an application loaded by default; a file
provider reads a link-set as the static alternative; providers are
exclusive and identity completion is provider-aware; the peer-identity
middleware extracts into a package of its own; and the SCMP echo
responder crosses from the ping application into the core, the one
capability that moves the other way.

[TOC]

## Summary

`pkg/controlplane` keeps the channel (`transport`, `server`, `mtls`,
`tls`, the clients), the drafts' services (segment, trust, lookup), the
enrollment lifecycle, beaconing, and discovery — nothing else. The
rendezvous acceptor, the in-band link service, the node directory, and
the selection loop of
[proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md)
move, unchanged and with their tests and constants, into
`pkg/apps/topology`, taking the joiner's dials, seeding, and bootstrap
dial with them from the node assembly; the peer-identity middleware
(`peeria.go`) extracts into `pkg/peeria`, where the endpoint, the
topology services, and the WireGuard directory share it. Between the
assembly and the machinery stands a provider seam of three moments —
complete a first start's provisional identity, mount the endpoint's
services, run the loops — with two implementations:
`topology.Zeroconf`, loaded by default, and `topology.File`, selected
by `--link-set`, which reads a JSON link-set — neighbor ISD-AS, the link's
two underlay addresses, an optional interface ID — and reconciles it
into the store the way the old configured interfaces worked: named
entries established by the operator's vouch, entries absent from the
file retired, every change a data plane generation swap the supervisor
already performs. The endpoint's `Services` takes the handlers a loaded
provider serves as mounts behind the peer middleware, mounting none
when none are loaded; the echo responder moves out of
[proposal 0005](/docs/proposals/0005-path-library-and-scion-ping.md)'s
ping application into the node's assembly, leaving the pinger the
application's whole surface.

## Motivation

ADR 0007 decides the boundary; this proposal draws it in packages. The
ground is already prepared: proposal 0006 established the resident
application and the service-socket registration the generation
supervisor replays on every swap, `Services` already nil-checks the
optional handlers it mounts, the supervisor applies any store write as
a generation swap whatever wrote it, and the joiner's machinery sits in
the node assembly exactly where it was wired. What remains is the
enumeration made visible: the moves themselves, the seam between the
assembly and the machinery, the file provider — the one piece that is
new behavior rather than repackaging — and the responder's promotion,
which the ADR's third test owes to the network.

### Goals

*   Slim `pkg/controlplane` to the channel, the drafts' services,
    discovery, and enrollment: move `rendezvous.go`, `linkservice.go`,
    `directory.go`, and `selection.go` with their tests, their
    constants, and the Link and Directory client stubs they own; the
    drafts' stubs stay in `Client`.
*   Extract the peer-identity middleware into `pkg/peeria`
    (`Authenticate`, `AuthenticatedIA`), imported by the endpoint, the
    topology application's services, and the WireGuard directory — the
    ADR's shared-library enumeration made importable, and the second of
    its two new packages.
*   Define the provider seam — complete a first start's identity, mount
    endpoint services, run loops — and load exactly one provider: the
    measured provider by default, the file provider when `--link-set`
    names a file; the two selectors refuse to combine, and a non-core's
    first start satisfies its neighbor requirement from whichever is
    loaded.
*   Move the joiner's machinery into the measured provider: the
    bootstrap rendezvous dial that completes identity, `seedNeighbors`,
    and the `runJoinDials` loop, with `bootstrapIdentity`'s dialing and
    `selectionConfig` following; the assembly calls the provider's
    completion step before its phases, as it calls `loadIdentity`
    before them.
*   Implement the file provider: a JSON link-set parsed with
    `json.RejectUnknownMembers` (the WireGuard configuration's
    discipline), reconciled on start and on change into the store;
    identity completed offline from the first entry's ISD.
*   Mount app services through the assembly: `Services.Link` and
    `Services.Directory` become a `Mounts` list of pattern/handler
    pairs the loaded provider supplies, wrapped in the peer middleware
    beside the drafts' services — `pkg/controlplane` learns no
    `proto/node/v1` type, and the file provider mounts none.
*   Promote the SCMP echo responder into the core as an unexported loop
    in the node assembly, socket and behavior unchanged; `pkg/apps/ping`
    keeps the pinger alone.

### Non-goals

*   Behavior changes to the moved machinery: constants, RPC shapes,
    admission rules, and pacing move verbatim; `proto/node/v1` is
    untouched, and the existing integration proofs must pass unmodified.
*   Mixing providers or switching at runtime: one provider per process
    lifetime, per the ADR's exclusivity rule; a deliberate topology
    beside measured links remains the policy the providers do not
    express.
*   Cross-ISD provider mixing or any cross-ISD behavior — deferred with
    the ADR's uniform-operator scope.
*   Identity, keys, or the node's bind addresses in the link-set file:
    the entries carry per-link underlay addresses only, and the node's
    own `ia` appears in no file, per the ADR.
*   File watching beyond a constant modification-time poll; no reload
    signals, no API, no operator tuning.
*   Placing [proposal
    0010](/docs/proposals/0010-probe-driven-link-health.md)'s health
    monitor on either side of the boundary: it consumes discovery's
    greetings and the store, lands beside them, and depends on nothing
    this proposal moves.
*   Touching the WireGuard application beyond its import of
    `pkg/peeria`: its own sockets and directory stay as they are, per
    the ADR's second mounting mechanism.

## Proposal

### The core that remains

`pkg/controlplane` after the move, file for file: `transport.go` (the
endpoint port), `server.go` (`Services`, `NewServer`, `ServeHTTP3`),
`mtls.go` and `tls.go` (the channel's TLS, WebPKI bootstrap included),
`client.go`, `peerclient.go`, and `remote.go` (the channel's clients),
`segmentservice.go`, `trustservice.go`, and `lookup.go` (the drafts'
services), `beacon.go` and `beaconstore.go` (the beaconing loops),
`lifecycle.go` (enrollment), and `discovery.go` (greetings, the
neighbor map, the core-endpoint relay). The assembly's phases rename to
what they hold — `assembleLinks` becomes discovery's assembly alone —
and `controlplane.MaxNeighbors` follows the selection loop into the
topology application, where its remaining consumers (the acceptor's and
the link service's caps) live.

`Services` loses its `Link` and `Directory` fields and gains what the
ADR's sixth point names: the handlers a loaded app serves, as
interfaces. Concretely a `Mounts []Mount` of pattern/handler pairs —
the provider builds its connect handlers and returns them; `NewServer`
wraps each in the peer middleware and mounts it beside the drafts'
services, mounting none when the list is empty. The control plane thus
learns no `proto/node/v1` type and cannot depend on what loads beside
it; the dependency direction stays one-way.

### The peer-identity middleware

`peeria.go` moves to `pkg/peeria` unchanged: `Authenticate` wrapping a
handler in chain verification against the TRC, `AuthenticatedIA`
extracting the verified ISD-AS. Its importers follow — the endpoint,
the topology application's link and directory services, and the
WireGuard directory, which today reaches both through `pkg/controlplane`
and keeps reaching `ServeHTTP3` and `EndpointTLS` there, as an app may
import the core. The middleware is the piece both sides speak; giving
it a package makes the ADR's shared-library enumeration — `pkg/scion`,
`pkg/links`, `pkg/peeria`, `pkg/trust`, `pkg/pathdb` — visible in the
tree.

### The provider seam

The seam has three moments, because identity completes before the node
assembles and services mount while it does:

1.  **Complete.** Before the phases, on a first start only: the measured
    provider dials `--neighbor`'s rendezvous claiming the zero ISD-AS
    and adopts the answer's ISD; the file provider adopts the first
    entry's ISD offline. The founding core persists its draw at once
    under either provider. The assembly calls this step where it calls
    `bootstrapIdentity` today, and persists what returns.
2.  **Mount.** At endpoint assembly: the provider returns the handlers
    it serves — link and directory under the measured provider, nothing
    under the file provider — and the assembly passes them into
    `Services.Mounts`.
3.  **Run.** At start: the provider's loops — the acceptor, the join
    dials, the directory's publish and fetch, the selection sweep —
    under the node's loop supervision like every other background
    service, one panic absorbed and logged, not the process's.

The seam is one interface in `pkg/apps/topology`, implemented twice in
that package: `topology.Zeroconf` — the measured provider, named for
the claim that loading it is what makes a node zero-conf — and
`topology.File`. The assembly selects by run arguments and refuses
`--neighbor` beside `--link-set`, since a seeded rendezvous dial and a
vouched static link set are two providers' worth of topology. A
non-core's first-start neighbor requirement is satisfied by either — a
`--neighbor` under the measured provider, a non-empty link-set under
the file provider.

The measured provider's construction follows the WireGuard
application's pattern: a `Config` the assembly fills with the pieces
the machinery consumes — the link store, the peer client, the path
provider, a connection factory, the discovery neighbor map, the
evidence check against the trust DB, the core route, the pacing
constants, and the change notification — so the application imports
the core and the shared libraries, never the reverse.

### The measured provider

Everything moves verbatim: the rendezvous acceptor with its
return-routability checks and rate caps, the joiner's dials and
seeding, the node directory (the core's store and service, every
node's publish and fetch loops), the in-band link service, and the
selection loop with its constants and its probe sockets. Loading it is
the default because almost-zero-config is the founding claim; nothing
about it changes but its import path. The store keeps its writers and
the supervisor its role: a promotion, a rendezvous claim, or a file
reconciliation all land as writes, and the generation swap that
applies them is the one the assembly already performs.

### The file provider

The link-set is JSON, parsed with `json.RejectUnknownMembers` so a
retired field fails loudly, one object per link:

| Field | Role | Meaning |
| :--- | :--- | :--- |
| `ia` | required | The neighbor's ISD-AS — the vouch. A non-core first start completes its own ISD from the first entry's. |
| `local` | required | The link's local underlay address, pinned — bound by every generation as an allocated address is. |
| `remote` | required | The neighbor's link underlay address the socket connects to. |
| `interface` | optional | The local interface ID; allocated monotonically when absent. |

Both underlay addresses are pinned because the pairing must be
writable on both ends: the acceptor that would exchange allocated
addresses belongs to the measured provider, so a static link has no
handshake — each node's file names the other's address, exactly the
retired interface list's pairing, minus its identity, keys, and the
node's bind arguments, which stay run arguments. Reconciliation runs on
start and on a constant modification-time poll: an entry named in the
file is established — the operator vouches, no candidate window, no
evidence check — with its addresses and optional interface ID; an entry
absent from the file retires, its interface ID held back by the store's
existing rule; an unchanged file writes nothing. Greetings still flow
over the pinned sockets — discovery is core — so liveness, neighbor
adoption, and beaconing treat a static link exactly as a measured one,
including a peer that stays silent: the entry stands because the
operator vouched, while discovery's freshness and the beaconer's
timeout treat it as gone.

Identity completes offline, per the ADR: the first entry's ISD with
the node's drawn AS, persisted before the phases assemble. The
entries therefore carry completed ISD-ASes — a founding core's draw is
final at once, so a static lab starts its founding node first, or any
node whose name is already final; the ordering is the file provider's
one operational ceremony.

### The responder's promotion

`ping.Responder` moves out of `pkg/apps/ping` into the node assembly as
an unexported loop: same socket (the control address's host, the
endhost port), same behavior (a reply on each reversed arrival path),
started beside the control-plane loops as today. The ADR's third test
puts it there — every node's selection baseline is an echo a peer must
answer, and a responder a node could decline to run silently disables
the comparator on its neighbors — and SCMP echo's read/write stays in
`pkg/scion` as the vocabulary both sides share. The ping application
keeps the pinger and its command; its package doc drops the responder
it no longer holds.

## Test plan

*   **Move fidelity:** the rendezvous, link service, directory, and
    selection suites pass unmodified in `pkg/apps/topology`;
    `pkg/controlplane`'s remaining suites pass; the middleware's tests
    pass at `pkg/peeria`; the three-node integration proof — join by
    rendezvous, enroll, publish, promote, survive a death and a
    generation swap — passes unmodified, which is the behavior-neutral
    claim made testable.
*   **Unit tests:** the seam — measured completion by echo, file
    completion from the first entry, a core persisting its draw at
    once, `--neighbor` beside `--link-set` refused, the first-start
    neighbor requirement satisfied by either; the mounts — link and
    directory mounted behind the peer middleware under the measured
    provider, none under the file provider; the file provider — unknown
    members and malformed files fail cleanly, named entries established
    with pinned addresses and an optional interface ID, absent entries
    retired with the interface ID held back, an unchanged file writing
    nothing, a changed file notifying exactly one generation swap; the
    responder in its new home answering a request on its reversed
    arrival path.
*   **Integration tests:** a static lab the new provider exists for —
    three nodes paired by link-set files only, no rendezvous acceptor,
    no directory, no selection loop: they beacon, forward, and answer
    `cion ping` end to end; removing an entry from a file retires the
    link as a generation swap the traffic survives; identity completes
    from the files with the founding core started first.
*   **Negative tests:** both providers' arguments together refused; a
    link-set naming a silent peer keeps its established entry while
    discovery's freshness and the beaconer treat the link as timed
    out; an empty link-set on a non-core's first start fails the
    neighbor requirement; a file reappearing entry reconciles back to
    established with a fresh interface ID when the old one is still
    held back.

## Implementation history
