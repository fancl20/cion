# Implement the spec-native core

This proposal implements the spec-native half of
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md):
the drafts' own service resolution becomes the one exchange the core
speaks beside its services, the greeting stream that resolution
replaces is deleted — its payloads absorbed by the exchanges that
already carry them — enrollment admission leaves the core for the
provider that already owns every other admission decision, and the
WebPKI bootstrap channel moves out to a shared library. It ends by straightening the
record the split left behind: the superseded ADR citations across the
code and the two attribution errors in the ADRs' own text.

[TOC]

## Summary

`pkg/controlplane` today speaks one protocol the drafts do not define:
the discovery greeting, a CION-invented frame (`greetingVersion = 1`)
that neighbors exchange to learn each other's control addresses, adopt
a joiner's ISD-AS on first contact, and relay the core's control
endpoint hop by hop. Everything the greeting carries has a drafts-native
home: peers are named by service destination on the one-hop path and
resolved through the drafts' service discovery (control plane draft,
Section 5), the core is reached over the reversed up segment beaconing
supplies, and identity adoption and arrival freshness belong to
exchanges the application already runs — the rendezvous request and
reply, and the sweep's own probe. This proposal makes that literal —
the greeting is deleted outright, the `AllowAS` enrollment allowlist
it justified and the WebPKI channel leave `pkg/controlplane`, and what
remains is the
enumerated core of ADR-0009's first point, every protocol of it the
drafts' own.

## Motivation

ADR-0009's enumeration promises a core reviewable against the drafts
alone — "every protocol the core speaks is the drafts'" — and its first
point names the mechanism twice: peer control endpoints resolve through
the drafts' service discovery, a service-resolution request carried on
a one-hop path, and the ISD core is reached over the reversed up
segment beaconing supplies, addressed to the core's control service.
The superseded ADR-0007 admitted the greeting plainly ("CION's own but
owed by every node"); ADR-0009 dropped the admission and kept the
mechanism, so the record now describes a core the tree does not hold.

The greeting is also the last seam where core policy hides. Its
identity adoption and its core-endpoint relay are zero-conf
bootstrapping — the measured provider's business, carried by core
loops — and the enrollment allowlist it motivated, the trust service's
`AllowAS` fed from `--allow-ia`, is deployment policy inside the drafts'
trust service. By the ADR's own first test, removing the allowlist
still leaves a forwarding, beaconing, enrolling AS; by its third, the
services that stay — resolution, forwarding, BFD, the trust RPCs — are
what the network depends on whatever the node's policy. Admission is
not among them: a node with no established link has no path to any
control endpoint, so the provider that admits links is the single
place admission can live.

The split of proposals 0011 and 0012 left the rest of the boundary
clean, and the machinery this proposal needs is already standing: the
data plane routes service-destined packets to registered local
services (the greeting itself rides the CS service address for
delivery), `PeerClient` dials `svc:` authorities, and the beaconer
already reads neighbor identity from the link store. What remains is
to finish the sentence ADR-0009 wrote.

### Goals

*   The drafts' service resolution in the core: a service-resolution
    request to the peer's control service address, carried on a
    one-hop path, returning the service's underlay address — the
    drafts' own exchange, served beside the endpoint's other services
    and used wherever a stable underlay address is wanted.
*   Control-plane traffic named by service destination: beacon
    origination, propagation, and registration, and the trust and
    lookup RPCs, address peers as `svc:` destinations on one-hop or
    composed paths instead of greeting-learned underlay addresses.
*   The greeting deleted: its frame, its loop, its neighbor table, and
    the core-endpoint relay go outright — identity adoption absorbed by
    the rendezvous exchange, which already names both sides through its
    request and reply, and arrival freshness by the selection sweep's
    own echo outcomes, the probe it already sends every window.
*   The core reached as the drafts reach it: `coreRoute` resolves the
    core neighbor's control service on the one-hop path and, at
    distance, rides the reversed up segment addressed to the core's
    control service; the joiner's enrollment and registration wait on
    the first reversed segment, absorbed by the retry loops that
    already exist.
*   Enrollment admission is the provider's alone: the trust service's
    `AllowAS` and its wiring are removed; `--allow-ia` remains the
    measured provider's acceptor and link-service gate; the
    name-taken check stays as the mechanism it is.
*   The WebPKI bootstrap channel — the ACME certificate management and
    the WebPKI-verified core client — moves verbatim from
    `pkg/controlplane` into a shared library, imported by the core and
    the assembly as any other vocabulary package.
*   The record straightened: ADR-0008 and ADR-0009 marked accepted
    with their implementing proposals landed, the ADRs' two
    attribution errors fixed, and every superseded ADR citation in the
    code — `ADR-0006` and `ADR-0007` where `ADR-0008` and `ADR-0009`
    are meant — swept with per-reference judgment, not blind
    renumbering.

### Non-goals

*   Any change to the enumerated core's other members: the data plane,
    the link store and generation supervisor, BFD and the health
    monitor, the echo responder, the beaconing loops, and the drafts'
    services stay where ADR-0009 froze them; the health monitor is
    BFD's orchestration and the app-mount seam on the endpoint's mux
    is ADR-0009's own sixth point, and neither moves.
*   Behavior changes to the measured provider's policy beyond the
    grace's carrier: constants, windows, floors, and the comparator's
    two routes are untouched. The one change is the sweep's grace —
    arrival freshness read from the probe's own outcomes instead of
    greeting arrivals — and it is this proposal's to own and test.
*   Removing `--allow-ia` or the provider-side allowlists: admission
    policy stays exactly where ADR-0009 put it — carried by the
    acceptor.
*   Cross-ISD behavior, provider mixing, or a pinned-link-beside-
    measured policy — deferred with the cross-ISD questions, as in the
    ADR.
*   Revocation infrastructure, SCMP beyond what proposal 0012 landed,
    or any trust-model change: the WebPKI channel moves, its behavior
    does not.

## Proposal

### The drafts' service resolution

The core gains the exchange ADR-0009's first point names: a
service-resolution request carried to the peer's control service
address on a one-hop path, answered with the service's underlay
address, in the framing the control plane draft's Section 5 prescribes.
It is served by the endpoint beside the drafts' other services — the
endpoint socket is the registered control service the data plane's
service routing already delivers to — and it is the only new protocol
surface the core acquires.

Service-destined addressing carries the rest. `scion.Addr` already
names a peer by ISD-AS and service; the data plane already rewrites a
service destination to the registered local service on arrival (the
greeting's own delivery proves the path); and `PeerClient` already
pools `svc:` authorities. Beacon origination, propagation, and
registration, and the trust and lookup RPCs, address their peers as
service destinations, resolving through the new exchange only where a
consumer genuinely wants an underlay address — a pooled connection's
pin, the one-hop core shortcut's dial — so the greeting's control
address field has no successor to feed.

### The greeting dies

The greeting is deleted, and its two surviving payloads are absorbed
by the exchanges that already carry them. Identity adoption is the
rendezvous exchange's own act: the acceptor names its entry from the
request's ISD-AS and the joiner names its own from the reply, every
establishment path naming both sides before a link serves, and the
adoption fallback for a live-but-unnamed entry — and the predicate
that waits on one — go with the greeting, the transient unnamed
state's flows re-verified to close inside establishment as the
request and reply already do. Arrival freshness becomes the sweep's
own reading: the probe it already sends every window is the signal —
a candidate that answers within the candidate window is alive and
trying, one gone silent retiring when the window does. Push becomes
pull, and the reachability class is unchanged: the same UDP round
trip to the same rendezvous socket.

`Discovery` dissolves entirely. Its neighbor map, its freshness, its
relay, and its send loop are deleted; its CS registration survives as
the assembly's service-routing plumbing it always was; and the
endpoint's `Pieces` loses the `Neighbors` hand-off — the selection
sweep reads its own probe outcomes, the beaconer the store. The
cross-node vocabulary the application speaks shrinks to exchanges
with distinct jobs — rendezvous for first contact and identity, the
link service for in-band establishment, echo for measurement, BFD for
liveness — and a future provider interoperates through the store and
those exchanges alone, owing no greeting to any peer's sweep.

### The beaconer reads the store alone

The beaconer's send targets stop resolving through the greeting's
neighbor map. Origination and propagation address the neighbor's
control service as a `svc:` destination on the one-hop path — the
drafts' own control-traffic pattern — with the neighbor's ISD-AS read
from the store's snapshot, completing ADR-0009's third point
("neighbor identity lands in the store… and the beaconer reads it
there") for the address as well as the identity: today the beaconer
reads the neighbor's ISD-AS from the store but its control address
from greetings, and after this proposal it reads neither from
anywhere else. Registration follows the same service-destined
addressing on the composed route.

### The core route without the relay

`coreRoute` keeps its two branches and loses its teacher. The one-hop
shortcut — the core a direct neighbor with its verdict up — dials the
core neighbor's control service as a service destination, resolved
through the drafts' exchange when the dial wants an underlay address.
The at-distance branch rides the reversed up segment the path provider
already composes, addressed to the core's control service; the
endpoint address the greeting's relay used to supply is resolved, not
remembered.

The joiner's bootstrap becomes receive-first, as the drafts order it:
the TRC still arrives over the WebPKI domain channel, which needs no
SCION path; with the TRC pinned, the core's beacons verify; the first
reversed up segment makes the core's control service reachable; and
enrollment and registration ride it. The enrollment loop's retry
interval absorbs the wait, and no greeting relay short-circuits the
ordering — the one place this proposal could bite, and the integration
episode below exists to prove it cannot.

### Admission is the provider's alone

`TrustService.AllowAS` and its wiring are removed. The trust service
keeps its drafts' RPCs and the name-taken check — a taken ISD-AS under
another key is refused whatever the policy — and loses nothing else:
enrollment is reachable only over paths, paths exist only over
established links, and the loaded provider admits every link. The
measured provider's acceptor and link service keep their `AllowAS`,
fed from `--allow-ia` exactly as today; the file provider needs none,
the operator's vouch being the whole of its admission. One decision,
one place.

### The WebPKI channel leaves the control plane

The ACME certificate management (`tls.go`) and the WebPKI-verified
core client (`remote.go`) move verbatim into `pkg/webpki`, a shared
library beside `pkg/peeria`: ADR-0003's bootstrap channel, CION's own,
serving the core's enrollment lifecycle from outside the drafts'
subset. The enrollment lifecycle keeps driving it — the shared
libraries exist to be imported by core and apps alike, and the
dependency direction stays one-way.

### The record

With this proposal ADR-0008 and ADR-0009 are accepted — their
implementing proposals (0008's selection machinery, 0011's split,
0012's instruments, this one's resolution) all landed — and two
attribution errors are fixed while the ADRs are still proposed:
ADR-0009's second point credits `pkg/links` with the peer-identity
middleware that lives in `pkg/peeria`, and its first point's closing
sentence — "pkg/controlplane holds exactly this enumeration" — is
corrected to name the core's packages as the enumeration's home, which
its own first sub-bullet already concedes by naming `pkg/dataplane`.
The code's citations follow: every `ADR-0006` reference to the link
store, the selection machinery, or the no-description default points
at ADR-0008; every `ADR-0007` reference to the core/apps boundary
points at ADR-0009; and each is re-read before renumbered, for the
references name decisions, not documents.

## Test plan

*   **Unit tests:** the resolution exchange — a request on the
    one-hop path answered with the registered service's underlay
    address, an unregistered service refused cleanly; the beaconer's
    targets — origination and propagation addressed to the neighbor's
    control service from the store's snapshot alone, with the map
    dependency gone; `coreRoute` — the one-hop branch resolving the
    core neighbor, the at-distance branch riding the reversed up
    segment with no relayed endpoint; the trust service — enrollment
    with no allowlist, the name-taken refusal intact; the sweep's
    grace from its own outcomes — a candidate answering the window's
    probe holds, one gone silent retiring with the window; the
    establishment flows — no live entry left unnamed past the
    rendezvous exchange; `pkg/webpki` passing its suites verbatim
    after the move.
*   **Integration tests:** the three-node line, beacons propagating by
    service destination end to end; the joiner's cold start as the
    centerpiece — a first start completing identity by rendezvous,
    TRC by the domain channel, verification of the core's beacons,
    registration and enrollment over the first reversed up segment,
    with no greeting relay anywhere in the sequence and the timing of
    each stage observed; the candidate-grace episode — a candidate
    answering the sweep's probe holds through the window and promotes
    when the floor needs it, one gone silent retiring on the window's
    expiry, the grace read nowhere but the probe's own outcomes; the
    static lab unchanged — three nodes paired
    by link-set files, beaconing, forwarding, and answering echo with
    no greeting stream at all; the degraded-core episode — the
    topology application declined or failed, the node still resolving,
    forwarding, and serving the drafts' RPCs to its neighbors.
*   **Negative tests:** no greeting state anywhere — no frame, no
    neighbor table, no freshness, in core or application; a peer that
    speaks no greeting of its own — a third provider's candidate — is
    measured, admitted, and established through the store, the link
    service, and the probe alone; an ISD-AS absent from `--allow-ia`
    still enrolls through a link the acceptor admitted, and enrolls
    through nothing else; a crafted resolution answer changes no
    persistent state; a core restart mid-join leaves the joiner's
    retry loop converging on the same ordering.

## Implementation history

*   Resolution: `resolution.go` in `pkg/controlplane` — the drafts'
    exchange (control plane draft, Section 5) as the core's one new
    protocol surface. `ResolveService` sends the empty
    ServiceResolutionRequest to a peer's service address — a one-hop path
    for a neighbor, or the path the peer address carries — and returns
    the QUIC transport address of the reply, unknown transports ignored
    and a missing or malformed port an error; `ServeHTTP3` answers the
    exchange beside HTTP/3 on the endpoint's own socket through a
    demuxing conn, QUIC datagrams told by the two header-form bits and
    everything else — an empty request included — answered on the spot
    with the endpoint's own address. The CS registration the assembly
    (`registerControlService`) and the test harness make on every data
    plane generation maps to the endpoint socket, so the greeting's
    delivery path now carries the `svc:`-destined RPC traffic of every
    peer beside the exchange.
*   Greeting: `discovery.go` and its suite deleted outright — frame, loop,
    neighbor table, freshness, and core-endpoint relay. Identity
    adoption became the rendezvous exchange's own act: the acceptor
    names its entry when a named request finds the unnamed entry the
    claim minted, the joiner's `CompleteIdentity` dials twice — the zero
    ISD-AS of the provisional draw, then the completed one — and
    `dialJoins` names its entry from the reply. The sweep's grace reads
    its own outcomes: `candidateAlive` echoes the candidate's rendezvous
    socket — the address its entry records, or the fixed rendezvous port
    on the host of its recorded remote — and holds named candidates
    alone, the unnamed entries the probes themselves mint retiring with
    the window as they always did. `controlplane.Neighbor`, the
    `Neighbors` pieces of the provider seam, and the `Discovery` pacing
    went with the stream.
*   Beaconer: origination, propagation, and registration address their
    peers as `svc:` CS destinations — the neighbor's ISD-AS read from the
    store's snapshot alone, links establishment has not named skipped —
    and `neighborEndpoint` with the `Neighbors` config went with the
    greeting's map.
*   Core route: the assembly's and the test harness's `coreRoute` keep
    their two branches without the teacher — the one-hop shortcut dials
    the TRC-named core neighbor's control service as a service
    destination on the link's own interface, and the at-distance branch
    rides the reversed freshest up segment — or, before any is verified,
    the bootstrap beacon's route, `Beaconer.BootstrapCore` naming its
    origin — addressed to the core's control service the same way. The
    WebPKI client's dial resolves that service destination through the
    drafts' exchange (`ResolveService` wired as the config's resolution
    hook), so the endpoint address is resolved, not remembered, and the
    enrollment loop's retry interval absorbs the wait for the first
    reversed segment. The exchange reads its conn for each reply's wait,
    so it takes a dedicated one beside the client's — a conn the client's
    QUIC transport reads would race it for the socket's packets, each
    reader swallowing the other's, a hazard the race-detected suites'
    second runs caught.
*   Admission: `TrustService.AllowAS` and its wiring removed; the trust
    service keeps the drafts' RPCs and the name-taken check, and
    `--allow-ia` remains the measured provider's acceptor and
    link-service gate alone, the run argument's help text updated.
*   WebPKI: `tls.go` and `remote.go` moved verbatim into `pkg/webpki` —
    `ManageTLSCert` and `CoreClient` under a package doc naming
    ADR-0003's channel, the core client carrying its own ConnectRPC
    client of the three trust services the lifecycle rides. The
    dependency stays one-way — `pkg/webpki` imports the SCION library and
    the trust material, never the control plane — and the enrollment
    suites pass against the moved symbols, the greeting that once fed
    their wait for the core replaced by the drafts' resolution.
*   Record: ADR-0008 and ADR-0009 marked accepted; ADR-0009's second
    point credits `pkg/peeria` with the peer-identity middleware and its
    first point's closing sentence names the core's packages as the
    enumeration's home; every superseded citation in the code re-read and
    renumbered — ADR-0006 to ADR-0008 for the link store, the selection
    machinery, the generational replacement, and the no-description
    defaults; ADR-0007 to ADR-0009 for the core/apps boundary — the
    `proto/node/v1` sources and their generated files edited in step.
*   Tests: the resolution exchange end to end — a request on the one-hop
    path answered with the registered endpoint's address, an unregistered
    service refused cleanly with the peer's store untouched, and the
    reply's parsing (the QUIC transport served, unknown transports
    ignored, ports checked); the beaconer's service-destined targets
    asserted in its fixture; the sweep-grace pair in a bubble — a named
    candidate answering the window's probe holds, the silent and the
    unnamed retire; the rendezvous naming case; the static lab gained the
    enrollment-past-the-allowlist episode, a vouched link enrolling
    against a core whose `--allow-ia` lists a foreign ISD-AS; and the
    join, static-lab, BFD, ping, WireGuard, and enrollment suites pass
    with no greeting anywhere — the joiner's cold start riding the
    rendezvous exchange, the WebPKI domain channel, the bootstrap beacon,
    and the first reversed up segment alone. The service-destined
    control traffic surfaced one latent crash — an SCMP quote of an
    SVC-addressed packet panicking the interface-down parser on
    `Host.IP` — now guarded, the quote naming no host to drop by.
