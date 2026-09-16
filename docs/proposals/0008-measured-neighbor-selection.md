# Implement measured neighbor selection

This proposal implements
[ADR-0006](/docs/adrs/0006-form-topology-with-measured-neighbor-selection.md):
the configuration file retires — identity, forwarding key, and links become
generated local state and run arguments — links are established bilaterally
through an authenticated request over existing paths or an underlay rendezvous
for first contact, a core-served node directory names the candidates, and a
selection loop keeps at least two neighbors by comparing direct underlay
latency against the composed paths the beaconing of
[proposal 0004](/docs/proposals/0004-beaconing-and-trust-lifecycle.md) already
maintains. The data plane never mutates while serving: a topology change
retires the serving data plane and brings up its replacement, per the ADR's
generational decision.

[TOC]

## Summary

`cion run` takes a bootstrap neighbor address and a domain — the core's own
domain when `--core` is set, the network's core domain otherwise — and
everything else comes from the state directory, where the first start
generates and persists the ISD-AS and forwarding key beside the AS keys. A
link store in `pkg/links` holds the neighbor table (addresses, interface IDs,
states) as the one source both the control plane reads and every data plane
generation is built from; interface IDs are allocated monotonically and never
reused while unexpired segments may reference them. Links come into existence
through a `LinkService` request on the control endpoint's authenticated
channel, or — for a joiner with no paths yet — an underlay rendezvous every
node accepts on an advertised address, return-routability-checked and
rate-capped. A `DirectoryService` on the core's control endpoint collects what
nodes publish once enrolled and serves the list to everyone. The selection
loop probes candidates by underlay echo against SCMP echo over the freshest
composed path, promotes links meaningfully faster than the path alternatives,
keeps at least two neighbors regardless, caps the total, and lands every
membership change as a data plane generation swap — build the replacement,
gracefully retire the serving instance, rebind the same link addresses.

## Motivation

ADR-0006 decides the architecture; this proposal implements it. The
implementation landscape has moved since the ADR's neighbors were designed,
and three of its mechanisms land on ground
[proposal 0005](/docs/proposals/0005-path-library-and-scion-ping.md) and
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md) broke:
the path library gives the selection loop its measurements, the gateway
directory gives the node directory its pattern (authenticated publish, core
served, TTL'd entries), and the node assembly already owns the service
registration a per-generation rebuild must replay. The data plane, by
contrast, is exactly as the ADR assumes: immutable after construction — it
refuses modification of a running instance outright — so the generational
decision needs only the graceful shutdown path it names.

### Goals

*   Retire the configuration file: generate ISD-AS (private range),
    forwarding key, and AS keys on first start into the state directory;
    take the bootstrap neighbor address, the domain, bind addresses, and the
    state directory as run arguments with defaults; keep the enrollment
    allowlist and reachability class as arguments too.
*   Persist the neighbor table — neighbor ISD-AS, local and remote link
    addresses, interface IDs, link state — in a `pkg/links` store following
    the path DB pattern, with interface IDs allocated monotonically and
    retired IDs held until segment expiry can no longer reference them.
*   Make every consumer of the link set read it live: discovery's arrival
    validation, the beaconer's neighbor checks and propagation targets, and
    the path library's one-hop egress resolution consult the link store's
    snapshot, and a node may start with zero links.
*   Establish links bilaterally: a `LinkService` on the control endpoint's
    SCION-native channel between nodes paths already reach, and an underlay
    rendezvous acceptor — nonce-checked, rate-capped, admission-policed — for
    a joiner's first contact; unenrolled candidates retire unless they enroll
    within a constant window.
*   Serve the node directory on the core's control endpoint: nodes publish
    their control and rendezvous addresses and reachability class over their
    authenticated channel once enrolled; the core stores and serves; entries
    expire without refresh.
*   Gate self-picked ISD-ASes at enrollment: a chain renewal request for an
    ISD-AS that already holds an unexpired chain under a different subject
    key is rejected and logged.
*   Run the selection loop with code constants only: probe every candidate by
    rendezvous echo against SCMP echo over the freshest path, promote below
    the promotion ratio or unconditionally under the floor of two, demote
    above the demotion ratio once above the floor, cap the neighbor count,
    and damp both directions to sustained evidence.
*   Land membership changes as generation swaps: build the next data plane
    from the link store, gracefully retire the serving one (stop ingest,
    drain, close), rebind each link's stable local address, and re-register
    every service backend on the new provider.

### Non-goals

*   NAT traversal; the reachability class only marks which candidates a
    node behind NAT may dial.
*   Selection metrics beyond underlay-versus-path latency to the candidate;
    no policy engine, no operator tuning — thresholds are constants.
*   Segment revocation when a link retires; expiration retires stale
    segments, as in ADR-0004.
*   First-contact cryptography: the rendezvous exchange carries no
    certificates — the joiner has none — and trusts return-routability, rate
    caps, and the candidate window; everything above rides the existing
    authenticated channels.
*   Merging with the gateway's directory (`proto/gateway/v1`): different
    owner — the control plane, not an application — though the pattern is
    shared.
*   Depending on [proposal
    0007](/docs/proposals/0007-gateway-service-addressing.md)'s service
    addressing: the rendezvous is underlay-level and the directory rides the
    control endpoint's existing port, so both land regardless of its fate.
*   BFD; and the runtime link up/down of ADR-0006's health decision — this
    proposal implements the membership half (its greeting-timestamp probe,
    the up/down flag, and the interface-down signaling follow), so link
    liveness here remains the greeting timeout; `ASTypeAuthoritative`
    and multi-core ISDs, as in ADR-0003.
*   Moving the gateway's host membership into arguments — it is operator
    data, and keeps its own file given by `--gateway-config`.

## Proposal

### Identity and arguments

The `Config` type and `LoadConfig` retire with `configs/`. First start
generates what the file used to carry: `trust.LoadOrCreateForwardingKey`
beside `LoadOrCreateASKey` (the forwarding key MACs only the node's own hop
fields, so it needs no coordination), and an ISD-AS drawn randomly from the
private ranges, persisted in the state directory beside the keys and logged
loudly — it is the node's name for its lifetime. Later starts read it back;
identity survives restarts through the same persistence the trust material
already uses.

`cion run`'s arguments, with defaults so a restart needs none of them:

| Argument | Role | Meaning |
| :--- | :--- | :--- |
| `--core` | all | Marks the founding core: TRC genesis, issuer, self-enrollment. |
| `--domain` | all | The core's domain. The core's own on `--core` (with `--acme-email` optional and the certificate files as the offline fallback); the network's core domain otherwise — the WebPKI identity of the enrollment and TRC fetch. |
| `--neighbor` | joiner | An existing node's rendezvous underlay address; repeatable. Required when the link store is empty and `--core` is not set; on later starts it seeds additional entries, idempotent by remote address. |
| `--state`, `--internal`, `--control` | all | The state directory and bind addresses, defaulting to today's constants. |
| `--allow-ia` | all | The allowlist gating enrollment on the core and link admission everywhere; open when unset. |
| `--behind-nat` | all | Publishes the node's reachability class as private: joinable by no one, candidate for no one's floor. |
| `--gateway-config` | all | The gateway application's own file (host membership, subnets, exits) — unchanged data, moved out of the retiring file. |

Validation is role-aware: `--core` takes no neighbor; a non-core first start
takes at least one; the domain is always required. `cion ping` and `BootApp`
follow — they assemble the node from the state directory and the same
arguments, not from a file.

### The link store

`pkg/links` follows the path DB pattern — a pure interface, a bbolt
implementation under `impl/bbolt`, shared contract tests under `impl/dbtest`.
Each entry holds the neighbor ISD-AS, the local and remote link underlay
addresses, the local interface ID, the remote's (learned from greetings), a
state — `candidate`, `established`, `retired` — and timestamps. The store is
the one source of truth: the control plane reads snapshots of it, and every
data plane generation is built from its non-retired entries.

Interface IDs are allocated monotonically from a persisted counter, skipping
live IDs; a retired ID is held back until a constant exceeding the longest
hop-field lifetime passes, so no unexpired segment elsewhere can name a link
that no longer exists. A link's local underlay address is allocated once at
establishment — bound on the control address's host at an ephemeral port —
and recorded in the entry; every generation rebinds it identically, which is
what makes a swap invisible to the peer's connected socket.

### Generational data planes

The data plane gains the graceful shutdown the ADR names, and nothing else:
on context cancellation the provider stops ingesting, the processors drain
their queues and exit, the links flush and their sockets close, and `Serve`
returns. The supervisor — new code in the node assembly, beside
`setupDataPlane` — loops: build a provider, the internal link, and one
external link per non-retired store entry; register every service backend
the control plane and the gateway own (the CS service's mapping to the
control address, and whatever the gateway registered through its callback);
serve; on the next link-store change, build the replacement, retire the
serving generation, and swap. The rebind races nothing but the operating
system: the old sockets close before the new ones bind the same addresses,
with a bounded retry.

`Run`'s final `dp.Serve` call becomes this loop. The control plane — trust,
beaconing, enrollment, the endpoint's connections — never restarts: their
sockets are their own, and they submit packets to the internal link's
address, which each generation rebinds. A swap is packet loss measured in
milliseconds; the QUIC connections of the control channel retransmit through
it, exactly as they retransmit through any internet loss.

Every consumer of the link set becomes a snapshot reader of the store:
discovery validates greetings against the current table (and no longer
errors at construction without links), the beaconer resolves propagation
targets and neighbor checks the same way, and the path library's `Conn`
resolves one-hop egress through a link-table source in place of the map it
copies today.

### Link establishment

Between nodes that composed paths already reach, establishment is an RPC:
`LinkService.Request` on the control endpoint's SCION-native channel, the
peer's chain identifying it. The request carries the requester's link local
address and interface ID; the acceptor applies its admission policy (the
`--allow-ia` list, the link-count cap, the rate cap), allocates its own
interface ID and link address, records both entries, and replies with them.
Both sides swap a generation; greetings flow over the established sockets
exactly as today; discovery fills the remote interface ID and control
address; the beaconer integrates the link.

For first contact, every node runs the rendezvous acceptor: one unconnected
UDP socket on the advertised rendezvous address — the control address's host
on a fixed port beside the discovery port, published in the directory and
named by `--neighbor`. The exchange is underlay-level and carries no
cryptography, because the joiner has nothing to show yet: the request is a
nonce, the requester's ISD-AS, and its link address; the reply echoes the
nonce and carries the acceptor's link address and interface ID. The echo is
the return-routability check — a spoofed source never receives its reply —
and the acceptor bounds admission by rate, by the link-count cap, and by the
allowlist when one is set. The resulting entries start as candidates: if the
peer produces no verified beacon or enrollment within a constant window, the
entry retires. `--neighbor` seeds the store with an entry aimed at the given
rendezvous address; the reply retargets it to the acceptor's link address
and the first generation serves it.

### The node directory

A `DirectoryService` joins the control endpoint's services — the drafts'
RPCs beside it are the vendored ones; this is CION's own, in a new
`proto/node/v1` package with generated ConnectRPC code, following
`proto/gateway/v1`. On the core only, it stores what nodes publish: ISD-AS
(from the verified chain, never the claim), control and rendezvous underlay
addresses, reachability class, and the publish time. `Publish` rides the
verified channel every other control RPC does — no new socket, no new trust.
Entries expire without refresh; the publish loop retries until enrollment
has produced the node's chain, then re-publishes on a constant cadence, and
a fetch constant refreshes the local copy in between.

### The enrollment gate

`ChainRenewal` gains the collision check self-picked ISD-ASes need: before
issuing, it asks the trust DB for the ISD-AS's chains; an unexpired chain
under a different subject key than the CSR's rejects the request with a
logged warning — the name is taken. Renewals by the same key pass untouched;
the allowlist continues to gate strangers ahead of the check.

### The selection loop

The topology loop joins the enrollment loops' family in the node assembly —
a lifetime background loop, all constants, no configuration. Each evaluation
window, jittered:

1.  **Probes.** For each directory candidate that is not a neighbor —
    skipping private-reachability ones — send a run of rendezvous echoes and
    take the median underlay round trip; resolve the freshest path to the
    candidate and take the median of a run of SCMP echoes over it, the
    responder every node already serves.
2.  **Promotes.** Below the floor of two neighbors, promote any reachable
    candidate outright. Above it, promote a candidate whose direct median is
    under the promotion ratio (0.8) of its path median, sustained across two
    consecutive windows; at the cap (eight), a candidate must beat the worst
    neighbor by the same ratio to displace it.
3.  **Demotes.** A neighbor whose direct median exceeds the demotion ratio
    (1.25) of its path median for three consecutive windows — and only above
    the floor — retires: its store entry goes to `retired`, beaconing on it
    stops with the generation swap, and expiration retires the segments. A
    neighbor whose greetings have timed out counts as infinitely slow.
4.  **Damps.** Nothing else moves. The ratios and windows are constants; an
    established link is never dropped on a single bad window, and a candidate
    is never promoted on a single good one.

Establishing a promoted candidate is the in-band request; the joiner's
`--neighbor` and the acceptor's candidates are the only underlay paths in.

## Test plan

*   **Unit tests:** identity generation and persistence (first start
    creates, second start reads back); link-store contract tests beside the
    existing ones, including interface ID allocation skipping live and
    recently retired IDs; the snapshot readers — discovery validating
    greetings against a changing table, the beaconer resolving targets, the
    path library resolving one-hop egress — with zero-link starts permitted;
    the acceptor's nonce echo, rate cap, and allowlist refusal; the
    directory handlers recording the authenticated ISD-AS and expiring
    stale entries; the enrollment gate rejecting a CSR for an issued ISD-AS
    under a different key and passing a same-key renewal; the selection
    loop's decisions with an injected clock and RTTs — floor promotion,
    ratio promotion over two windows, demotion over three and never below
    the floor, cap displacement, greeting-timeout handling, and no action
    outside the rules.
*   **Integration tests:** extending `internal/testnetwork`'s topology
    harness — a three-node line (core A — B — C) where C joins with
    `--neighbor` B and `--domain`, enrolls, publishes, and fetches the
    directory; C probes A by rendezvous echo against the two-hop path and
    promotes the direct link when the echo wins; killing B leaves C
    connected through A and the loop seeking a third candidate (and logging
    the unmet floor); a bare `cion run` restart serves from the persisted
    link store without rendezvous; a generation swap mid-traffic — an
    enrollment fetch and a gateway mesh session survive a link change with
    the same local addresses rebound.
*   **Negative tests:** a rendezvous request whose nonce echo never returns
    allocates nothing; a request flood hits the rate cap and the link cap;
    an unenrolled candidate retires after the window; a link request from an
    allowlisted-out ISD-AS is refused; a CSR for a taken ISD-AS is rejected
    and logged; a demotion below the floor never happens; a flapping
    candidate — good window, bad window, good — is never promoted.

## Implementation history

*   Link store: `pkg/links` follows the path DB pattern — the `Link` entry,
    a bbolt implementation with a monotonic interface-ID counter persisted
    beside the entries, shared contract tests in `impl/dbtest`, and an
    in-memory implementation (`impl/memory`) for tests and embeddings.
    Interface IDs are held back by `IfIDHoldback` (the longest hop-field
    lifetime plus an hour), and lookups report absence as a nil entry.
    Consumers read the store live: discovery validates greetings against it
    (adopting an unnamed entry's neighbor from its first greeting and
    recording the remote interface ID), the beaconer resolves its targets
    from its snapshot, and the path library's `Conn` resolves one-hop
    egress through a link-table source instead of the map it copied — all
    three permitting a zero-link start.
*   Identity: the ISD-AS is a draw from the private ranges
    (`trust.GenerateIA`) that persists only when final — the core's at
    once, a joiner's once its bootstrap answers, so a failed first start
    leaves nothing half-named behind. The forwarding key
    (`trust.LoadOrCreateForwardingKey`) MACs only the node's own hop
    fields, as the ADR notes, and is never coordinated. One gap the
    proposal left open: a self-picked ISD cannot match the core's by
    chance, so the rendezvous reply carries the acceptor's ISD-AS and the
    joiner's identity completes with the network's ISD — its drawn AS kept
    — before the node assembles. A first start whose bootstrap neighbor
    never answers fails cleanly and retries draw a fresh identity.
*   Rendezvous: the acceptor (`pkg/controlplane/rendezvous.go`) admits by
    return-routability — the nonce echo — bounded by rate caps keyed by the
    claimed ISD-AS or, for unnamed claims, the claimed address (a node's
    dials share one key however many ephemeral sockets they use), by the
    allowlist, and by caps the returning neighbor never meets: named
    entries — the ones that carry beacons — against the link cap, unnamed
    ones against their own. A claim only ever mints or retargets a
    candidate; an established entry answers with its recorded side
    untouched, since the claim names nothing the acceptor can check. A
    bootstrap joiner claims the zero ISD-AS and the acceptor's candidate
    entry adopts the joiner's final name from its first greeting, so the
    identity completion costs no second exchange. The selection loop's
    probes claim the zero ISD-AS too and deduplicate by the control address
    they claim — a probe mints no entry a candidate sweep could mistake for
    a peer.
*   Services: `proto/node/v1` carries the `LinkService` and
    `DirectoryService` (generated with buf, mounted behind a peer-
    authenticating middleware whose `AuthenticatedIA` the WireGuard
    directory now shares). The directory store is in-memory on the core
    with a TTL; the core publishes into and fetches from its own store,
    everyone else rides the verified channel. `ChainRenewal` gained the
    collision check: an unexpired chain under another subject key rejects
    the CSR with `AlreadyExists`, the holder's own renewal passing.
*   Selection: `RunSelection` probes every peer the directory names by
    rendezvous echo against SCMP echo over the freshest resolved path —
    medians of constant-sized runs — and decides on the constants (floor
    two, cap eight, ratios 0.8 and 1.25, two and three windows). Below the
    floor it promotes any reachable candidate outright, at the cap a
    sustained winner displaces the neighbor with the slowest direct sample
    — no sample counts as infinitely slow — and the floor holds at every
    instant: however many neighbors go bad in one window, the window
    retires only down to it. Streaks reset when evidence lands, so a
    demoted peer re-earns promotion from scratch. Establishment is the
    in-band request when a path resolves — both sides record established
    entries — else the rendezvous exchange a joiner uses; the candidate
    sweep settles both, its evidence a chain of the peer the node knows
    (one it issued on the core, or one a verified beacon's signatures
    resolved through), which retires an unproven peer after the window.
    The acceptor-side entries of never-proven joiners under non-core
    neighbors retire by that window; selection re-establishes those links
    in-band once paths form, the self-healing the ADR's convergence trades
    on.
*   Generational data planes: `Serve`'s graceful shutdown stops ingest,
    drains the processors — which now watch their context — closes the
    links' sockets, and returns with the addresses released; the provider's
    stop is idempotent, as both `Serve` and the supervisor may stop it. The
    supervisor (`internal/services/dataplane.go`) retires the serving
    generation before building its replacement, retrying the rebind on a
    bounded schedule while the operating system releases the ports, and
    re-registers every service backend on each new provider. The control
    endpoint's socket releases with the node's cancellation, so an
    in-process restart rebinds the fixed port. The greeting's core
    announcement no longer decays on the core itself — its own endpoint is
    permanent, a core that starts before its neighbors still announces
    itself once they arrive.
*   Arguments: `cion run` and `cion ping` share the node flags — `--core`,
    `--domain` (always required), `--neighbor` (required on a non-core's
    first start, idempotent by remote address later), `--state`,
    `--internal`, `--control`, `--allow-ia`, `--behind-nat`,
    `--acme-email` with `--cert-file`/`--key-file` as the offline
    fallback, and `--wireguard-config` (the proposal's `--gateway-config`,
    under proposal 0009's rename) pointing at the application's own file,
    the retiring section's JSON shape unchanged. `BootApp` and the tests
    assemble from `NodeConfig`; `configs/` retired with the `Config` type.
*   Tests: the store's contract suite with the interface-ID holdback; the
    snapshot readers' zero-link starts and greeting adoption; the
    acceptor's nonce echo, rate cap, allowlist, link cap, and the silent
    dial that allocates nothing; the link service's admission and
    refresh-without-reallocation; the directory handlers' authenticated
    recording and TTL expiry; the enrollment gate's taken-name rejection
    and holder renewal; the selection loop's decisions with injected
    measurements — floor and ratio promotion, displacement, demotion above
    and never below the floor, greeting timeout, the flapping candidate,
    and the quiet window. The integration proof runs the run command's own
    assembly: a three-node line joined by rendezvous, enrolled, published,
    and fetched; C promotes A below the floor and survives both the
    generation swap mid-traffic and B's death through A; a bare restart
    serves from the persisted link store; and a bootstrap without an answer
    fails cleanly and joins on retry.
