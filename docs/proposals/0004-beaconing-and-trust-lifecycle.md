# Implement spec-aligned beaconing and trust lifecycle

This proposal outlines the implementation of the path layer decided in
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md):
path exploration by spec-aligned beaconing, the two segment stores,
registration, lookup, and the in-node path provider. It also closes the two
gaps the proposal 0003 implementation left open — the signer, verifier, and
network-backed provider are still uninstantiated, and enrollment is one-shot
against chains that expire after three days — because beaconing depends on
both: AS entries are signed with the trust signer and verified against
TRC-anchored chains, and an expired chain invalidates signatures made after
expiry.

[TOC]

## Summary

CION's data plane forwards multi-hop SCION paths, but no node knows any:
control traffic rides one-hop paths to direct neighbors only, and the segment
RPCs are mounted but unimplemented. This proposal activates the trust engine
(a `trust.Engine` composing the existing signer, verifier, and network-backed
provider), replaces one-shot enrollment with a lifetime chain lifecycle, and
builds the path layer of ADR-0004 on top: the founding core originates signed
path-segment beacons, every node verifies the accumulated signatures against
the TRC before storing or propagating them, accepted PCBs become registered
segments in a persistent path database next to the in-memory beacon store,
and an in-node path provider composes segments into end-to-end paths — the
seam that generalizes today's one-hop transport, so a node without a direct
link to the core enrolls through the reversed beacons it receives.

## Motivation

ADR-0004 decides the architecture; this proposal implements it. The first
signed control-plane messages — beacons and segment registrations (control
plane draft, Sections 2.3.5 and 4.3; see
[`draft-dekater-scion-controlplane`](/docs/specs/draft-dekater-scion-controlplane.txt))
— are also where ADR-0003's SCION-native verification takes over and neighbor
identity is finally bound to the link. Evaluating the 0003 implementation
against its ADR surfaced two gaps this proposal closes on the way:

*   `trust.Signer` and `trust.Verifier` are used by nothing outside tests, and
    `trust.NetworkProvider` is implemented but not wired into the binary — an
    enrolled node's chain sits unused, and the ADR's "signer and verifier
    become live" is only half true.
*   `runEnrollment` returns after the first success, while AS chains are valid
    for three days (`ASValidity`, `pkg/trust/certs.go`): a node running longer
    holds an expired chain, silently, until restarted.

### Goals

*   Compose and wire the trust engine: a DB-first provider behind the signer
    and verifier, constructed in the `cion` binary.
*   Keep a valid chain on every node — the core included — by re-enrolling
    before expiry, with warnings as expiry approaches.
*   Implement ADR-0004's exploration: cores originate PCBs, reception verifies
    every AS-entry signature against TRC-anchored chains with the existing
    verifier and enforces the configured-neighbor binding, and propagation
    floods outward with the TRC naming the cores that prune upward sends —
    no link-type configuration.
*   Build the two stores of ADR-0004: the in-memory beacon store for candidate
    PCBs and the persistent path database for registered segments, following
    the trust DB pattern.
*   Register segments per the draft: non-cores terminate PCBs into up and down
    segments, down segments registered with the originating core; cores
    terminate core beacons into core segments.
*   Implement the draft's source-AS segment-request handler (Section 4.2.2)
    and the in-node path provider that composes up, core, and down segments
    into end-to-end paths.
*   Generalize the QUIC-over-SCION transport through the provider, carrying
    control RPCs over SCION paths with replies reversing the arrival path, so
    enrollment and trust fetches work for nodes without a direct link to the
    core.
*   Serve control endpoints on every node, with AS certificates as
    control-plane TLS certificates verified against the TRC (PKI draft,
    Section 2.2.2.4).

### Non-goals

*   Multi-core ISDs: CION stays single-ISD with a single founding core
    (ADR-0003), so no core-to-core link exists in practice — but the core-link
    and core-segment mechanisms are implemented per the draft, unused until a
    second core appears.
*   Peering links and peer entries (Section 2.1.1): intra-ISD peering is not
    representable under emergent link roles (ADR-0004), PCBs never traverse
    peering links, and advertising them in AS entries has no use yet.
*   Endhost-facing path exposure: a local path API or UDP proxy is deferred to
    a follow-up consuming the same provider (ADR-0004's scope boundary); the
    data plane needs no change.
*   Serving trust material from non-core nodes: lookup fetches core and down
    segments from the core's control service, so neighbor-to-neighbor trust
    exchange stays deferred, as in proposal 0003.
*   TRC updates, voting ceremonies, and renewal workflows beyond re-running
    enrollment.
*   PCB selection policies beyond ADR-0004's fixed bounded set: no policy
    engine, no per-policy configuration.
*   Metrics, and chain garbage collection in the trust DB (old chains are
    kept; verification may still need them, and growth is bounded by the
    enrollment rate).

## Proposal

### The trust engine

Add `trust.Engine` to `pkg/trust` — the one composition the ported types were
missing, not a new abstraction. It holds the node's IA, its AS key, and a
`Provider`; it exposes:

*   `Signer(ctx)`: queries the provider for the node's own chains valid now,
    picks one with `LastExpiring`, and builds a `Signer` — algorithm selected
    by `signed.SelectSignatureAlgorithm` (ECDSAWithSHA256 for the P-256 keys
    `pkg/trust/keys.go` generates), TRCID from the ISD's base TRC, validity
    and subject taken from the chain.
*   `Sign(ctx, msg, associatedData...)`: signs a control-plane message with
    the current signer, per the AS-entry signature input of control plane
    draft Section 2.2.2.6 (associated data carried through to
    `signed.Sign`).
*   `Verify(ctx, signedMsg, associatedData...)`: the `Verifier` bound to the
    engine's provider, with its certificate cache.

The provider behind the engine is `NetworkProvider` (`pkg/trust/network.go`),
wired per node type: non-core nodes use the `CoreClient` as the remote; the
core uses none — its DB holds every chain it issued, so the provider is
local-only and a nil remote must resolve to "not found", never a panic.

Until beacons exist as real traffic, a periodic engine self-check makes the
engine observable: sign a nonce, verify it through the provider round trip,
log the result. From this proposal on, the self-check is redundant with the
beacon traffic itself and can be retired.

### The chain lifecycle

`runEnrollment` in `cmd/cion/main.go` becomes a loop for the node's lifetime
instead of returning after the first success. Each pass:

1.  Reads the newest chain for the node's IA from the DB and its remaining
    validity.
2.  Re-enrolls when the remaining validity drops below a renewal threshold
    (a constant of roughly one day, against the three-day `ASValidity`) — or
    immediately when no valid chain exists. While unenrolled the loop keeps
    its fast retry cadence; with a valid chain it settles to a calm
    inspection interval.
3.  Logs a warning when the threshold is crossed and enrollment keeps
    failing, an error when the last chain expires, and it watches the pinned
    TRC's validity the same way (log only — a new base TRC means redeploying,
    per ADR-0003).

The core runs the same loop with a local action instead of an RPC: it
self-issues through its `Issuer` whenever the threshold demands it, keeping
today's synchronous startup self-enrollment as the first pass. Old chains stay
in the DB; verification by validity window keeps using them while they
overlap.

### Control endpoints everywhere, SCION-native TLS

Every node — not just the core — serves its ConnectRPC services over HTTP/3 on
`EndpointPort`, since beacons terminate on each node's
`SegmentCreationService`. ADR-0004 reuses the one-hop control channel but
leaves the neighbor channel's certificate model open: today's channel is the
WebPKI-anchored one, which only the core can serve. This proposal decides the
model the drafts prescribe — AS certificates as control-plane TLS
certificates (PKI draft, Section 2.7.4), which `cppki.CAPolicy.CreateChain`
already issues with id-kp-serverAuth and id-kp-clientAuth:

*   The bootstrap channel, unchanged: the core presents its WebPKI/ACME (or
    file) certificate when the client offers the core's domain as the TLS
    server name. Enrollment and TRC fetch keep riding it.
*   The SCION-native channel: peers present their AS certificate chains,
    mutually authenticated by verifying the chain against the pinned TRC's
    root pool (`cppki.VerifyChain`) instead of WebPKI roots, with the peer's
    IA extracted from the certificate subject. Beacon, registration, and
    lookup RPCs ride this mode.

Beacons themselves carry the authoritative signature: the mTLS layer
authenticates the transport, the reception checks below authenticate the
path.

### Beaconing with emergent link roles

No link type is configured (ADR-0004): roles emerge from beacon flow. The
interface a beacon arrives on is the node's parent side; interfaces beacons
are propagated to are child sides; a link whose neighbor the TRC names as a
core is a core link. Parent-child direction on a link between two non-core
ASes is decided by which side can reach a core and deliver beacons.

The founding core originates a fresh PCB on each of its links every
propagation interval (draft Sections 2.3.4 and 2.3.5.1; CION's interval
constant sits at the draft's intra-ISD floor of five seconds): a
`PathSegment` with new `SegmentInformation` — a cryptographically random
16-bit segment ID and the creation timestamp (Section 2.2.1) — and the core's
own signed AS entry, hop field MACed with the data-plane forwarding key, the
same MAC algorithm the processor verifies. Every other node, on each interval:

1.  Selects from the beacon store a fixed bounded set of candidate PCBs to
    forward — no policy engine; the store's per-key freshness ordering is the
    only selection rule.
2.  Appends its own AS entry — ingress the receiving interface, egress the
    propagation interface, `next_isd_as` the neighbor — and MACs the hop
    field.
3.  Signs the extended PCB (Section 2.2.2.6) with the engine's signer and
    propagates it by calling `SegmentCreationService.Beacon` on the
    neighbor's endpoint over the one-hop path of that link (Section 2.3.5).

Propagation follows ADR-0004's rule, not a configured direction: every
external interface except the one the beacon arrived on, and except
interfaces whose neighbor the TRC names as a core — beacons never travel
toward a core. A node that has not pinned the TRC yet cannot know the cores
and floods upward too; that is harmless, because in a single-core ISD every
beacon already contains the core, and the core drops any beacon containing
itself. On core links — none exist while the ISD has one core — core beacons
flow in both directions (Section 2.3.5), carried by the same mechanism.

Reception applies the checks of Section 2.3.1 before anything is stored:

1.  Every AS entry's signature is verified against the TRC-anchored chain the
    entry references — the engine's verifier, fetching missing chains through
    the provider from the core. The PCB's timestamp must not be in the future
    beyond the clock-skew allowance, and no hop may be expired
    (Section 2.2.4).
2.  A PCB whose segment already contains the local ISD-AS is discarded (loop
    prevention; the general case of the draft's core check).
3.  The last AS entry's ISD-AS must equal the configured neighbor IA of the
    interface the PCB arrived on — the identity-to-link binding ADR-0003
    deferred to the first signed control-plane message. Under emergent roles
    the arrival interface is by definition the parent side, so no link-type
    check exists to apply.
4.  Consecutive AS entries must chain (Section 2.3.1, check 4).

Transit consent is propagation itself (ADR-0004): an operator consents to
transit by forwarding beacons; refusing to propagate leaves the node's links
usable for its own traffic but keeps it out of other ASes' paths. Sovereignty
rests on the signatures — no AS entry exists that the node did not sign.

One bootstrapping subtlety: a fresh node receives beacons before it has the
TRC, so it cannot verify them. It may use an unverified beacon's reversed
path as the route for its enrollment fetch — the WebPKI-authenticated channel
protects that exchange — but unverified PCBs are never stored, propagated, or
registered. Verification starts once the TRC is pinned.

### Two segment stores

ADR-0004's two stores with different lifetimes:

*   The beacon store holds candidate PCBs and is in-memory: write-heavy,
  valid for one beaconing period at a time, keyed by ingress interface and
  segment ID, keeping the latest origination per key and expiring entries
  with their hops (Section 2.3.2). A restarted node is rebuilt by the next
  period's beacons.
*   The path database holds registered up, down, and core segments and is
  persistent, following the trust DB pattern — a pure interface, a bbolt
  implementation, and shared contract tests — in a dedicated package beside
  `pkg/trust`. Segments are stored in CION-owned domain types wrapping the
  vendored `proto/control_plane` messages; the reference implementation's
  `pathdb` and beacon-server packages stay unvendored. A newly registered
  segment replaces the stored segment with the same identity (originating
  core, segment ID, creation timestamp); segments are evicted when their
  timestamp-relative expiration passes, on access and by a periodic sweep.
  There is no revocation mechanism; expiration bounds staleness.

### Registration

Each registration period (a constant on the order of a minute), non-core
nodes terminate selected PCBs per Section 3.1.1 — a final AS entry with unset
next AS and egress interface, signed — producing:

*   Up segments, kept in the local path database (Section 3.1.2). They are
    the node's paths to the core: the provider's route for enrollment, trust
    fetches, and registration itself.
*   Down segments, registered with the control service of the core that
    originated the PCB (Sections 3.1.3 and 3.3), riding the reversed up
    segment.

The receiving core verifies each registered segment as on beacon reception
and rejects segments whose first AS entry is not its own IA (Section 3.1.3).
Cores likewise terminate core beacons into core segments in their own path
database (Section 3.2) — no core beacons exist while the ISD has a single
core, but the path is exercised by the same termination code.

### Lookup and the in-node path provider

The node implements the draft's source-AS segment-request handler
(Section 4.2.2): up segments from the local path database; core and down
segments fetched from the core's control service with expiry-aware caching;
source wildcards expanded into the separate requests the section specifies —
per reachable core AS of the source ISD for core segments, per core AS of the
destination ISD for down segments. This fills the mounted but unimplemented
`SegmentLookupService` (`pkg/controlplane/trustservice.go`); it has no
consumers inside this milestone beyond the provider itself.

One in-node provider composes up, core, and down segments into end-to-end
SCION paths — reversal, expiry filtering, segment combination written once —
and is the only consumer seam (ADR-0004): the control transport and, later,
endhost exposure consume identical paths through it. Concretely:

*   `SCIONConn` (`pkg/controlplane/transport.go`) today synthesizes one-hop
    paths on write and parses only one-hop paths on read. It generalizes: the
    peer address carries either a neighbor (one-hop path, as now) or a SCION
    path supplied by the provider — the hop-field MACs come from the segment,
    computed by each on-path AS at beacon time, not by the sender. On
    receive, any SCION path type is parsed and the arrival path is reversed
    for the reply, generalizing what the one-hop case does today. The data
    plane already forwards SCION path types (`pkg/dataplane/processor.go`);
    only the control plane's transport changes.
*   `CoreClient` consults the provider: the one-hop path when the core is a
    neighbor, else the reversed freshest up segment — which exists from
    beaconing alone, so reaching the core has no bootstrap cycle and
    ADR-0003's deferred enrollment of nodes not directly linked to the core
    completes.

### Node wiring

Startup order in `cmd/cion/main.go` extends proposal 0003's: trust DB and
keys, TRC genesis and self-enrollment (core) or the enrollment loop
(non-core), the control endpoint on every node, the trust engine, the beacon
store and path database, then the beaconing originator (core) or
receiver/propagator/registrant (non-core), and discovery as today. No new
configuration: link roles emerge from beacon flow, and intervals and
thresholds are constants in `pkg/trust` and `pkg/controlplane`, following the
existing style.

## Test plan

*   **Unit tests:** the engine builds a signer from DB chains (algorithm,
    TRCID, `LastExpiring` selection) and a sign/verify round trip with
    associated data succeeds, while tampered messages, wrong-IA signatures
    (bound verifier), and chains unanchored in the TRC fail; the lifecycle
    loop re-enrolls only below the threshold and logs on approach and expiry;
    the core loop self-issues on the same rule; AS-entry creation and
    signature verify; each Section 2.3.1 reception check discards its
    respective malformed beacon (wrong neighbor IA, expired hop, future
    timestamp, broken continuity, bad signature, own IA already on the
    segment); propagation skips the ingress interface and TRC-named-core
    neighbors, and the core drops beacons containing itself; termination
    zeroes egress and `next_isd_as`; the path database persists across
    restart, replaces by identity, and evicts expired segments on access and
    sweep; the lookup handler expands wildcards per Section 4.2.2 and serves
    from cache until expiry; the provider composes up/core/down segments and
    reverses up segments; the multi-hop transport sends over a supplied path
    and reverses arrival paths; mTLS verification accepts a TRC-anchored
    chain and rejects a foreign one, and the core dispatches by TLS server
    name.
*   **Integration tests:** a three-node line topology (core A — B — C, no
    A–C link) where beacons propagate A→B→C with signatures verified at each
    hop, C enrolls through the reversed beacon over B, C registers a down
    segment at A through B, and the provider resolves an end-to-end path from
    C to A; a two-node topology runs past the chain validity (short validity
    or an injected clock) and re-enrolls without restart, keeping the
    engine's signer valid throughout; a restarted node serves up segments
    from the persistent path database before the next beaconing period.
*   **Negative tests:** a beacon whose signature does not match the
    configured neighbor of its ingress interface is dropped; an endpoint
    presenting a chain that does not verify against the pinned TRC fails the
    mTLS handshake; a fresh node without a TRC propagates and registers
    nothing; a node whose enrollment fails near expiry keeps serving and
    logs.

## Implementation history

*   Trust engine: `trust.Engine` (`pkg/trust/engine.go`) composes the signer,
    verifier, and DB-first provider; `NewestChain` and `RenewChain` support
    the chain lifecycle, and `NetworkProvider` resolves a nil remote — the
    founding core's local-only provider — to "not found" instead of a
    panic. The engine's chain lookup for the SCION-native TLS channel reads
    local state only, so no handshake ever spawns a trust fetch.
*   Chain lifecycle: `controlplane.RunEnrollment` and
    `controlplane.RunCoreEnrollment` (`pkg/controlplane/lifecycle.go`) run
    the lifetime loops — re-enrollment below `trust.ChainRenewalThreshold`,
    warnings approaching expiry, errors past it, and the log-only TRC watch.
    Every enrollment attempt is bounded by a timeout, so a wedged connection
    cannot stall the loop.
*   Control endpoints everywhere: `controlplane.EndpointTLS`
    (`pkg/controlplane/mtls.go`) serves the unchanged bootstrap channel for
    clients offering the core's domain as the TLS server name and the
    SCION-native channel — AS chains verified against the pinned TRC's root
    pool — for everything else. Nodes without a pinned TRC accept peers
    unauthenticated for the window in which they receive the beacons that
    route their enrollment; beacon sends ride client-authenticated
    connections whose server certificate is not verified, the PCB
    signatures authenticating the path authoritatively.
*   Beaconing: the `controlplane.Beaconer`
    (`pkg/controlplane/beacon.go`) originates, verifies (Section 2.3.1
    checks against `pkg/segment`'s parsed beacons), stores
    (`controlplane.BeaconStore`), propagates with the TRC pruning core
    interfaces, terminates (Section 3.1.1), and registers up, down, and
    core segments. `pkg/segment` wraps the vendored protobuf messages in
    CION-owned domain types: parsing, AS-entry creation and signature
    inputs (Section 2.2.2.6), hop-field MAC chaining, and data-plane path
    construction.
*   The two stores: the in-memory beacon store
    (`pkg/controlplane/beaconstore.go`) and the persistent path database
    (`pkg/pathdb` with the bbolt implementation in `pkg/pathdb/impl/bbolt`
    and contract tests in `pkg/pathdb/impl/dbtest`), replacing by segment
    identity and evicting expired segments on access and by sweep.
*   Lookup and the provider: `controlplane.LookupService`
    (`pkg/controlplane/lookup.go`) implements the source-AS handler of
    Section 4.2.2 (and the core handler of Section 4.2.3) with
    expiry-aware caching and wildcard expansion per Table 4;
    `controlplane.PathProvider` (`pkg/controlplane/provider.go`) composes
    up, core, and down segments into end-to-end paths — the only consumer
    seam.
*   Transport: `controlplane.SCIONConn` sends over provider-supplied SCION
    paths and reverses full-path arrivals for replies; the discovery
    greeting relays the core's endpoint address, so nodes without a direct
    core link learn where enrollment and registrations are aimed. The
    bootstrap route — an unverified beacon reversed and extended with the
    node's own unsigned hop — carries the enrollment fetch and the trust
    fetches around it until the first verified up segment exists.
*   Data plane: one crash fix the new traffic surfaced — the slow path's
    SCMP responses no longer panic on the absent DRKey provider.
*   Tests: unit coverage per package — engine signer selection and
    round trips, segment MAC chaining and path math, each reception check,
    propagation pruning, termination, path-database persistence and
    eviction, wildcard expansion and caching, provider composition,
    lifecycle decisions with an injected clock, and the TLS channels — plus
    the integration tests of a three-node line topology in
    `pkg/controlplane/network_test.go`: beacons propagate A→B→C verified,
    C enrolls through the reversed beacon over B, C registers a down
    segment at A through B, and the provider resolves the end-to-end path;
    a restarted node serves up segments from the persistent database.
