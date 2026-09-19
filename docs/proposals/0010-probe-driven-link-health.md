# Implement probe-driven link health

This proposal implements the health half of
[ADR-0006](/docs/adrs/0006-form-topology-with-measured-neighbor-selection.md)'s
measured-selection decision: the greeting stream becomes the probe that
measures every established link, a hysteresed verdict turns sustained silence
into a reversible up/down flag inside the serving data plane generation, and
sources that send into a down link receive the SCMP interface-down signal the
drafts prescribe — machinery the data plane already carries behind its
hardcoded up check. It lands beside
[proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md)'s
membership half and shares its seams with it, but depends on neither its fate
nor its timing: everything here stands on today's configured links and
discovery.

[TOC]

## Summary

The greeting gains two time fields — the sender's send time and an echo of
the peer's last-received send time, the TCP timestamp pattern — so each
arrival is a liveness sample and each echo a round-trip sample measured
entirely in the receiver's clock, immune to skew between the nodes. A link
health monitor in the control plane reduces the arrival stream per interface
to one hysteresed verdict: down after sustained silence (today's
three-interval greeting timeout, promoted from discovery's lazy filter to an
explicit state), up again after sustained answers. The verdict reaches the
data plane as a flag on the link — the `IsUp` check that returns `true //
BFD is not supported yet.` today — and nothing else: no queue changes, no
interface ID, no generation swap. The egress validation behind that check
then does what it was built to do: packets routed into a down link are
answered toward their source with SCMP External Interface Down, capped in
rate, and dropped. The greeting stream itself moves beneath the forwarding
plane — sent on the link's own underlay socket, not through the processor —
because a probe gated by its own verdict could never overturn it. On the
sending side of a broken path, the path library recognizes the interface-down
signal it receives and sets aside paths crossing the signaled interface for a
short window, the drafts' negative-cache practice; its own probes stay
authoritative, the received signal only deprioritizes.

## Motivation

ADR-0006's health decision names the gap precisely: every failure signal in
the codebase is passive expiry or an application retry, and nothing converts
a dead greeting stream into forwarding state. Concretely, discovery already
omits neighbors whose last greeting is older than three intervals
(`Neighbors` in `pkg/controlplane/discovery.go`) and the beaconer already
skips those interfaces — but the data plane's `IsUp` is a stub, so
forwarding continues into a dead link until its segments age out six hours
later, and the SCMP External Interface Down branch in the egress validation
(`pkg/dataplane/processor.go`'s `validateEgressUp`) is unreachable code.

The drafts specify the missing tiers: BFD between routers for detection, and
SCMP interface-down as the signal to sources — with the explicit caveat that
sending it is OPTIONAL, it must be rate-limited, and endpoints SHOULD detect
failures by their own means (`draft-dekater-scion-dataplane` sections 6.1 and
6.2, `draft-dekater-scion-controlplane` section 6.5.2). ADR-0006 answered the
detection question by declining the second protocol: the greeting stream
already crosses every link every interval, so it is the probe. This proposal
is the rest of that answer — the verdict, the signal, and the sender's
reaction — which is also the draft-aligned signaling the architecture
already paid for in the data plane's slow path.

### Goals

*   Extend the greeting with send-time and echoed-time fields; record
    arrival and round trip per interface, with old greetings decoding
    leniently to liveness-only samples.
*   A link health monitor holding one hysteresed up/down verdict per
    external interface, all constants: down after sustained silence, up
    after sustained answers. It becomes the one source of neighbor
    liveness — `Neighbors`' freshness filter and the beaconer's interface
    pauses read it instead of re-deriving it.
*   Wire the verdict into the data plane as the flag behind the existing
    `IsUp` check and nothing more; the built-but-unreachable egress-down
    branch then emits SCMP External Interface Down toward sources, under a
    per-interface rate cap.
*   Move the greeting's send path onto the link's underlay socket, beneath
    the forwarding plane, so a down verdict cannot starve the probe stream
    that would overturn it; ingress is unaffected — the peer's greetings
    keep arriving and are the recovery evidence.
*   Sender-side reaction in the path library: SCMP interface-down received
    on a socket (the demux in `pkg/dataplane/dataplain.go` already delivers
    SCMP errors to the offending socket) records the signaled interface in a
    short-lived cache; path composition and the gateway bind's cached paths
    skip crossing paths until it lapses, falling back to them when nothing
    else exists.
*   Expose the per-interface round-trip median so proposal 0008's selection
    loop measures established neighbors by the same stream, beside its
    rendezvous echo for candidates.

### Non-goals

*   BFD (RFC 5880): ADR-0006 declined the second protocol; the greeting
    stream is the detector.
*   Membership changes: promotion, demotion, establishment, retirement, and
    generation swaps are proposal 0008's; up/down never adds or retires a
    link, and a sustained down verdict feeds 0008's loop only as evidence.
*   SCMP Internal Connectivity Down (type 6): one node per AS, no intra-AS
    forwarding to signal; only the external variant (type 5) is emitted.
*   Revocation infrastructure: ADR-0004's stance stands — the sender cache is
    a local, expiring hint, never network state.
*   Authenticating SCMP: the drafts' error messages are unauthenticated and
    this proposal keeps them so; the ADR's trust rule — own probes
    authoritative, received signals advisory — is the entire defense.
*   Persisted health state: the verdict is volatile; a node restarts with
    every link up and re-derives within one silence window.
*   Traceroute, Packet Too Big, and the remaining SCMP menagerie.

## Proposal

### The greeting as probe

`Greeting` gains two fields beside its identity and endpoint payload: the
sender's send time and the send time of the peer's last-received greeting,
echoed back — the pattern TCP timestamps use for round-trip estimation
without synchronized clocks. The receiver's round-trip sample is its own
receive time minus the echoed value, both read from its own clock, so skew
between the nodes cancels and the sample is honest at any clock offset. The
granularity is the greeting interval — a sample reflects the peer's answer
delayed by at most one period — which the median over a small ring of recent
samples smooths; ADR-0006 already prices this granularity in its negative
consequences. A greeting without the fields (a pre-change peer, or a state
directory replayed old wire bytes) decodes leniently: it counts for liveness
and contributes no round-trip sample, the same leniency the gateway store
gives proposal 0006's entry shapes.

Discovery's `record` keeps its interface-keyed table and adds the two
samples; nothing about the greeting's routing, its core-endpoint relay, or
its arrival validation changes.

### The health monitor

A monitor owns the per-interface verdict, reducing the arrival stream with
two constants: `DownAfter` — sustained silence past it marks the link down —
inherits discovery's three-interval timeout so the one silence constant
rules everywhere it is consulted; `UpEvidence` — a count of consecutive
answered arrivals — marks it up again. Both edges are hysteresed by
construction, so a lossy link settles into whichever state its evidence
sustains rather than flapping.

The monitor becomes the one source of neighbor liveness. Discovery's
`Neighbors` stops keeping its own timeout arithmetic and reports the
monitor's up set; the beaconer's interface pauses are then the same verdict
under the behavior it already has; proposal 0008's redundancy floor, when it
lands, counts up links only and treats a down neighbor as the infinitely
slow one its selection loop already names. The monitor also exposes the
round-trip median per interface, the direct-side measurement for
established neighbors that 0008's loop reads beside its rendezvous echo for
candidates.

### The verdict in the data plane, and the probe beneath it

The node assembly hands each external link a health handle at construction —
an atomic the monitor sets and the link's `IsUp` returns, in place of the
unconditional `true // BFD is not supported yet.` That is the whole
mechanical change to the data plane: a flag it already consults, fed. No
generation is built, no interface ID allocated, no queue touched; the
forwarding substrate's configuration stays as immutable while serving as
ADR-0006 requires, the flag being state the egress check reads rather than a
reconfiguration of it.

The consequence is the branch `validateEgressUp` already holds: a packet
whose egress link is down takes the slow path, and its source receives SCMP
External Interface Down carrying the originator's ISD-AS and the down
interface ID, quoted packet and all — the exact message the control-plane
draft's section 6.5.2 specifies, emitted by code that has never run. A
per-interface cap bounds identical notifications per second, the rate
limiting the data-plane draft's section 6.2 asks for; the packet itself is
dropped, as a packet with no viable egress must be.

The greeting's send path moves beneath this verdict. Today discovery writes
greetings to the router's internal address and the forwarding plane carries
them over the link; a down verdict would then discard the only traffic that
could overturn it, and the link would never recover. Instead the greeting
rides the link's own underlay socket — the same bytes, a SCION packet the
peer ingests and delivers exactly as before, but transmitted by the link
rather than routed through the processor, so the probe is causally
independent of the verdict it feeds. Ingress needs no exemption — a down
link gates egress only, and the peer's arriving greetings are the recovery
evidence the monitor waits on.

### The sender's interface cache

`pkg/scion` learns to recognize what it is being told. SCMP errors already
reach the offending socket — the data plane's demultiplexer extracts the
quoted packet's source port — and the library's receive path today drops
them silently. Interface-down (type 5) instead enters a small cache keyed by
the signaled ISD-AS and interface ID, expiring after `IfDownCacheTTL`, ten
seconds, the retention the drafts describe as current practice. Path
composition and the gateway bind's cached path skip a path whose hop fields
traverse a cached interface until it lapses — unless it is the only path,
which stays a last resort, as lowering preference is all the drafts ask of a
source.

The cache only deprioritizes. It removes no state, triggers no fetch, and
overrides nothing the node measures itself: SCMP is unauthenticated, so any
speaker on a path could forge the signal, and the ADR's trust rule — own
probes authoritative, the received signal a prompt — is enforced by making
the received signal worth exactly one skipped path and ten seconds. The
gateway bind's existing behavior completes the loop: a send that fails
despite the cache re-resolves, and its own traffic is the probe.

### Node wiring

The monitor sits in the node assembly beside discovery, consuming its
arrivals and setting the handles of the assembled links; startup order is
unchanged — links are built with handles before `Serve`, every link begins
up, and the first silence window re-derives the truth. `BootApp` and
`cion ping` assemble it identically. Nothing here touches proposal 0007's
service destinations: the greeting keeps its port, its one-hop path, and its
`SvcCS` destination; only its send socket and its fields change.

## Test plan

*   **Unit tests:** the greeting's time fields round-trip, and a
    skewed-clock peer still yields honest round trips — the sample uses only
    the receiver's clock; a fieldless greeting decodes to liveness-only; the
    monitor's hysteresis both ways with an injected clock — down at
    `DownAfter`, up at `UpEvidence`, and a lossy stream settling instead of
    flapping; `IsUp` returning the handle; the slow path emitting type 5
    with the right ISD-AS, interface ID, and quoted packet from a down
    egress, and the cap holding a burst to its rate; the interface cache —
    a crossing path skipped, a lone path kept, an entry lapsing, and a
    forged signal doing no more than that.
*   **Integration tests:** the topology harness with a three-node line —
    blackhole the A–B link's sockets in the harness and watch A mark it down
    within the window while its greetings keep leaving on the underlay
    socket; a ping from A toward B's far side receives type 5 and its next
    resolution avoids the signaled interface; lift the blackhole and the
    link returns up with no generation swap — the serving instance's
    counters continuous across the episode; beaconing pauses on the down
    interface and resumes with it.
*   **Negative tests:** an alternating arrive-and-silence stream never
    crosses either edge twice in a window; a type-5 storm from a crafted
    peer changes no persistent state and ages out entirely; a peer speaking
    the old greeting keeps its link's liveness maintained and its round
    trips merely absent; a restart serves every link up regardless of how it
    shut down.

## Implementation history

*   Never landed. Superseded before implementation by
    [ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md),
    which re-decided the probe carrier: the verdict, up/down flag, and
    SCMP signaling machinery stand as designed here; the carrier is BFD
    per the drafts instead of the greeting stream's timestamps. The
    in-flight work was reverted with the re-decision.

