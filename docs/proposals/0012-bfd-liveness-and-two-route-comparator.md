# Implement BFD liveness and the two-route comparator

This proposal implements the instrument half of
[ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md):
BFD per the drafts as every serving link's liveness, the hysteresed verdict
the sessions reduce to as the one mutable edge inside a serving generation,
the rate-limited SCMP interface-down signal the data plane already knows how
to send, the sender's short negative cache, and the comparator's direct side
moved onto SCMP echo over the one-hop path — the rendezvous echo remaining
the candidate's probe alone. The formation policy around them — measured
selection with a redundancy floor, two-argument joining, the core-served
directory, generational replacement — already stands from
[proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md) and
[proposal 0011](/docs/proposals/0011-minimal-node-core-and-topology-providers.md),
and nothing here changes it. To
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)'s
boundary the instruments return: the sessions and the monitor are core —
liveness owed by every node however its topology is decided, the file
provider's links included — while the prober stays in the topology
application beside the loop it feeds.

[TOC]

## Summary

A BFD session per serving link, in the node core: the drafts' async-mode
subset of RFC 5880, answered and initiated, its control packets SCION-framed
(NextHdr 203) on the link's one-hop path and sent on the link's own underlay
socket — beneath the forwarding plane, so a down verdict cannot starve the
only stream that could overturn it. The data plane's existing dispatch
(`processBFD` delivering to `Link.BFDSession()`) hands every arrival to the
session; the session's own timers — a one-second transmission interval and a
detect multiplier of three, the arithmetic of today's greeting timeout — are
the link's liveness constants. A health monitor beside the sessions reduces
them to one verdict per interface — up until sustained silence, up again on
the next answered arrival, both edges dampened by the session's timers — and
the verdict reaches the data plane as the flag behind the stubbed `IsUp`
check, so the built-but-unreachable egress-down branch finally runs: traffic
routed into a down link is dropped and answered toward its source with SCMP
External Interface Down under a per-interface rate cap. The beaconer's
interface pauses, the core route's one-hop gating, and the selection loop's
infinitely-slow treatment read the same verdict, replacing the greeting
freshness they re-derive today; the greeting stream keeps what is uniquely
its business — neighbor adoption, the control address, the core-endpoint
relay. The selection loop's probe splits by role: an established neighbor's
direct side is measured by SCMP echo over the one-hop path to the peer — the
same destination the baseline echoes, one instrument over two routes — while
a candidate keeps the rendezvous echo, and the redundancy floor counts up
links only. On the sending side, `pkg/scion` learns to recognize the
interface-down signal a socket receives: the signaled ISD-AS and interface
enter a ten-second cache, path composition skips crossing paths while it
lapses (a lone path stays a last resort), and the WireGuard bind drops the
cached path of the destination the signal's quote names.

## Motivation

ADR-0008 chose the instruments; the codebase holds half of each. The data
plane, inherited from the router lineage, carries complete BFD scaffolding —
`processBFD` decodes a NextHdr-203 control header and delivers it to the
link's `BFDSession()`, `NewExternalLink` takes the session as an argument —
but the assembly passes `nil`, nothing anywhere sends a BFD packet, and
`IsUp` returns `true // BFD is not supported yet.` The egress validation
behind that stub (`validateEgressUp` taking the slow path to SCMP External
Interface Down, quote and reversed path and all) has never executed; it has
no rate cap, which the data plane draft's Section 6.2 asks of the
notifications it permits. Every failure signal in the node is passive
expiry: discovery omits neighbors whose last greeting is older than three
intervals, the beaconer's sends quietly fail through the same filter, and
the selection loop treats a stale-greeting neighbor as infinitely slow —
while the data plane forwards into the dead link until its segments age out
hours later.

The measurement side has the mirror-image gap. The selection loop measures
every peer — neighbor and candidate alike — by the rendezvous echo, a plain
underlay round trip to the peer's advertised rendezvous address. ADR-0008
keeps that exchange for the candidate, where no path and no interface exist
and the proxy is the honest measurement of the hypothetical link; for an
established neighbor it is a proxy the ADR prices in its own negative
consequences, and the direct side moves to SCMP echo over the one-hop path —
the same instrument the baseline already reads over the freshest resolved
path, carried by the ping machinery the responder in the node's core answers.

[Proposal 0010](/docs/proposals/0010-probe-driven-link-health.md) designed
the verdict, the flag, the signal, and the sender's cache around a different
carrier — TCP-style timestamps on the greeting stream — and ADR-0008
superseded it on that one choice: the probe carrier is BFD per the drafts.
This proposal resurrects what stands of 0010's design with the carrier
swapped, and adds what 0010 deferred: the protocol itself, the two-route
comparator, and the placement ADR-0009 later fixed — sessions and monitor in
the core, prober in the application.

### Goals

*   A BFD session on every serving link, in the node core, under either
    provider: the drafts' framing (a BFD control header after the SCION
    header, NextHdr 203, one-hop path), both roles — the node answers its
    peers' sessions and initiates its own — and no authentication, demand
    mode, or echo function: CION implements the async control subset the
    data plane draft's Section 6.1 names and nothing more.
*   The session's send path on the link's own underlay socket, beneath the
    forwarding queues and the egress validation: the session must keep
    transmitting while the link is down, which is how recovery is seen
    (ADR-0008), and a probe gated by its own verdict could never overturn
    it.
*   A health monitor reducing the sessions to one verdict per interface —
    down when the detect multiplier expires without an arrival, up on the
    next answered one — that becomes the one source of neighbor liveness:
    the data plane's `IsUp`, the beaconer's interface pauses, the core
    route's one-hop gating, and the selection loop's floor and demotions
    read it instead of re-deriving greeting freshness. The verdict is
    volatile: a node restarts with every link up and re-derives within one
    silence window.
*   The SCMP External Interface Down branch fed and capped: a per-interface
    rate limit on the notifications the slow path emits, the rate limiting
    the drafts' Section 6.2 prescribes.
*   The comparator's direct side over the one-hop path for established
    neighbors, the rendezvous echo kept for candidates, both at the
    selection loop's own cadence — and the floor counting up links, so a
    node whose every neighbor went down promotes from the directory rather
    than resting on verdicts.
*   The sender's interface cache in `pkg/scion`: SCMP interface-down
    recognized on a socket's receive path, the signaled ISD-AS and interface
    held for ten seconds, path composition skipping crossing paths while the
    entry lives, the WireGuard bind dropping the quoted destination's cached
    path so its next send re-resolves through the filtered composition.

### Non-goals

*   Membership changes from the verdict: up/down never establishes or
    retires a link, never builds a generation; sustained down state reaches
    the selection loop as evidence and nothing more. Promotion, demotion,
    and the swaps they cause remain the loop's, on its windows.
*   BFD authentication or the rest of RFC 5880's optional machinery (demand
    mode, the echo function, authentication types); control packets carry
    the no-authentication type the drafts' framing carries.
*   SCMP Internal Connectivity Down (type 6): one node per AS, no intra-AS
    forwarding to signal — only the external variant is emitted.
*   Authenticating SCMP: the drafts' error messages are unauthenticated and
    stay so; the sender's cache only deprioritizes, and the ADR's trust
    rule — own probes authoritative, a received signal one skipped path for
    ten seconds — is the entire defense.
*   Revocation infrastructure: ADR-0004's stance stands, and the cache is
    local, expiring state, never network state.
*   Changes to the greeting stream: no timestamp fields (the superseded
    0010's carrier), no move beneath the forwarding plane. Liveness is
    BFD's alone; greetings carry identity and the core relay, and a down
    link carrying no greetings costs nothing the verdict does not already
    say.
*   Persisted health state, traceroute, Packet Too Big, and the rest of the
    SCMP menagerie.

## Proposal

### The BFD session

`pkg/controlplane` gains the session, in the drafts' own terms: a BFD
control header (RFC 5880 Section 4.1 — version, diagnostic, state, detect
multiplier, discriminator, timers) serialized after a SCION header with
NextHdr 203 over a one-hop path, exactly the frame `processBFD` already
parses on arrival. Each session owns its discriminator, its transmission
interval, and its detection timer; the state machine is the async subset —
Down, Init, Up — advanced by the peer's arriving state and our own, with no
authentication section ever serialized. Two constants, shared by every
session: a one-second transmission interval and a detect multiplier of
three, the same detection latency the greeting timeout derives today, now
the link's liveness constants by the ADR's fifth point.

The session transmits on the link's own underlay socket. `NewExternalLink`
already takes the session; the link hands it a raw writer for prebuilt
packets — a send beneath the egress queue and the validation above it, so
the session's stream survives its own down verdict by construction. Ingress
is the mirror: the peer's control packets arrive on the connected socket,
the processor's BFD branch decodes them, and `ReceiveMessage` hands each to
the session the link already holds. A session cannot ride the internal link
through the processor — a locally originated BFD packet is an ingress BFD
packet to it, and it would be consumed — which is one more reason the send
path belongs to the link.

Sessions live in the monitor, keyed by interface ID, and survive generation
swaps: a swap rebinds the link's stable local address and re-attaches the
writer, the session's state and timers untouched, so a peer sees the
session continue across the milliseconds a swap costs. A link that leaves
the serving set — retired, or demoted — has its session stopped; one that
joins starts a session that begins transmitting at once, up by default
until its first silence window says otherwise.

### The monitor and its verdicts

The monitor is the ADR's ninth point made code: the sessions and their
reduction, one verdict per interface, owned by the core and running for
every serving link whatever the loaded provider is doing — a neighbor's
detection of the node depends on the node answering its BFD, which makes
answering a service of the node itself. The verdict is the detection
timer's own arithmetic, hysteresed by construction: up until three
transmission intervals pass without an arrival, down the moment they do, up
again on the next answered arrival — a lossy link settles into whichever
state its evidence sustains rather than flapping.

The verdict's consumers each replace a re-derivation of greeting freshness:

*   the data plane's `IsUp` — the check behind `validateEgressUp` — reads
    the session the link already carries, so the flag needs no new channel
    to cross the seam;
*   the beaconer's interface pauses: a down interface originates and
    propagates nothing, resuming with the verdict's up edge;
*   the core route's one-hop shortcut, which today falls through to the
    composed route when a core neighbor's greeting goes stale, falls through
    on the verdict instead;
*   the selection loop, whose demotion path treats a down neighbor as
    infinitely slow and whose redundancy floor counts up links only —
    established-but-down entries satisfy no floor.

Discovery's greeting stream keeps its own business entire: adopting a
joiner's ISD-AS on first contact, learning the neighbors' control
addresses, and relaying the core endpoint. Its `Neighbors` map stops
filtering by freshness — the entries stand with their `LastSeen`, identity
for whoever asks — and the one consumer that genuinely wants arrival
recency, the selection sweep's grace for a candidate still proving itself
(a candidate has no serving link, no session, and a peer that keeps
greeting is alive and trying), reads `LastSeen` directly. Greetings
addressed to a down link are dropped at egress like any traffic, and the
rate-capped notification a dropped greeting earns is delivered to a socket
that drops it — the cap bounds even that.

### The verdict in the data plane

The mechanical change to `pkg/dataplane` is small because the lineage built
the hard parts: `IsUp` consults the session instead of returning true, and
the egress-down branch it guards — already taking the slow path, quoting the
packet, reversing the path, filling `SCMPExternalInterfaceDown` with the
local ISD-AS and the egress interface — acquires the per-interface rate cap
the drafts' Section 6.2 prescribes: a code constant bounding identical
notifications per interface per second, exceeded ones dropped with the
packet. Nothing else changes: no queue is touched, no interface ID
allocated, no generation built — the verdict is state the egress check
reads, the one mutable edge inside an otherwise immutable configuration, by
the ADR's eighth point. Both edges notify the node's own consumers — a
verdict flip wakes the beaconer's and selection loop's next pass through
the verdict queries they already make — while the peer learns recovery the
same way it learned failure: its own session's arrivals.

### The comparator's two routes

The selection loop's probe splits by the directory's own distinction.
An established neighbor's direct side is measured by SCMP echo over the
one-hop path to the peer: the probe conn writes to the neighbor's IA and
its control address's host on the endhost port, the conn resolving the
egress interface from the link table as every one-hop write does, the
responder in the peer's core answering on the reversed arrival path — the
same destination, the same instrument, the same median-of-runs discipline
the baseline already reads over the freshest resolved path. A candidate
keeps the rendezvous echo, the underlay round trip to the advertised
rendezvous address that reaches where no path and no interface exist; a
demoted neighbor is a candidate again and is probed as one. The two sides
of the comparator differ in carrier exactly where the ADR's negative
consequences say they do — admission on a proxy the established link's own
measurement confirms or corrects — and measurement cadence stays the
selector's alone, free of the liveness timers.

The floor and the demotions read the monitor alongside the samples: an
established neighbor whose verdict is down counts as infinitely slow for
the window whatever its last sample said, the floor holds at every instant
counting up links only, and a candidate sweep's grace still reads greeting
arrivals. No ratio, window, or constant of the loop changes.

### The sender's interface cache

`pkg/scion` learns to recognize what it is being told. The data plane
already demultiplexes SCMP errors to the offending socket — the quoted
packet's source port — and the library's receive paths drop them silently.
The conn's receive path instead parses an interface-down (type 5) error:
the signaled ISD-AS and interface ID enter a cache shared by the node's
conns, expiring after ten seconds, the retention the drafts describe as
current practice; the quoted packet's destination names whose cached path
just failed. Path composition consults the cache at the moment it holds
full knowledge — each segment's entries carry their ISD-AS and interface
IDs — skipping a composed path that crosses a signaled interface until the
entry lapses, keeping a crossing path only when nothing else exists, as
lowering preference is all the drafts ask of a source. The WireGuard bind's
cached path cannot recover an ISD-AS from a decoded path and does not try:
the signal drops the quoted destination's cache entry, and the next send
re-resolves through the filtered composition — the bind's existing
failure-and-refresh behavior, prompted by the signal instead of a lost
datagram.

The cache only deprioritizes. It removes no state, triggers no fetch, and
overrides nothing the node measures itself: SCMP is unauthenticated, any
speaker on a path could forge the signal, and a forged one is worth one
skipped path for ten seconds.

### Node wiring

The assembly builds the monitor over the link store before the first
generation: `startGeneration` asks it for each serving link's session and
passes both — session to `NewExternalLink`, verdict through it — so every
generation carries the same per-interface sessions, re-attaching writers as
links rebind. The monitor's own loop — starting sessions for serving
entries, stopping them for departed ones, transmitting on each session's
interval — runs under the node's background supervision beside discovery,
and `BootApp` and `cion ping` assemble it identically. The file provider's
nodes get the same sessions by construction: the monitor reads the store,
not the provider. The topology application receives the verdict through the
`Pieces` it already gets — the neighbor map's role narrowing to identity,
the verdicts joining it — and imports the core, never the reverse.

## Test plan

*   **Unit tests:** the session's frame — a serialized control packet
    decodes through the data plane's own `processBFD` and carries the
    one-hop path; the state machine — down at three intervals of silence
    with an injected clock, up on the next arrival, transmitting throughout,
    including while down; the verdict read through `IsUp`; the slow path —
    a down egress emits type 5 with the local ISD-AS, the egress interface,
    and the quoted packet, and a burst exceeds no per-interface cap; the
    monitor — sessions started for serving entries and stopped for retired
    ones, a generation swap re-attaching the writer without disturbing the
    verdict; the probe — a neighbor's direct side measured over the
    one-hop path (the reply's arrival interface the link's), a candidate's
    by rendezvous echo; the floor counting up links, a down neighbor
    demotion-eligible however recent its last sample; the interface cache —
    a crossing composition skipped, a lone path kept, an entry lapsing, a
    forged signal doing no more than that, and the bind dropping exactly
    the quoted destination's path.
*   **Integration tests:** the topology harness on a three-node line —
    blackhole the A–B link's sockets in the harness and watch A mark it
    down within the window while its BFD keeps leaving on the link's own
    socket; a ping from A toward B's far side receives type 5 and its next
    resolution avoids the signaled interface; lift the blackhole and the
    link returns up with no generation swap — the serving instance's
    counters continuous across the episode; beaconing pauses on the down
    interface and resumes with it; the selection loop, its neighbor now
    verdict-down, promotes a reachable candidate to hold the floor. The
    static lab — three nodes paired by link-set files — runs the same
    episode: the monitor is the core's, and the file provider's links carry
    BFD like any other's.
*   **Negative tests:** an alternating arrive-and-silence stream settles
    without crossing either edge twice in a window; a type-5 storm from a
    crafted peer changes no persistent state and ages out entirely; a
    restart serves every link up regardless of how it shut down; a peer
    whose BFD never arrives but whose greetings do keeps its link
    established with the floor counting it, its candidacy grace intact —
    the streams answer different questions and each reading is honored for
    its own.

## Implementation history

*   Core: `pkg/controlplane/bfd.go` holds the session — the async subset
    of RFC 5880 through gopacket's BFD layer, SCION-framed (NextHdr 203)
    over a fresh one-hop path per transmission — and `monitor.go` the
    health monitor: sessions keyed by interface ID, `Session` asked by
    each generation so a swap re-attaches the writer through the same
    session, `Up`/`Verdicts` the consumers read, and one loop that
    reconciles against the store and ticks every session's interval.
    The `dataplane.Session` interface gained `IsUp` and `SetRawWriter`;
    `NewExternalLink` attaches the link's raw writer (a plain write on
    the connected socket), and `connectedLink.IsUp` reads the session
    the link carries.
*   The egress-down branch runs: `validateEgressUp` consults the
    per-interface cap (`notifyCapPerSecond`, a lock-free one-second
    window per interface) before taking the slow path, so a burst of
    packets into a down link earns at most the cap's type-5
    notifications per second; over-cap ones drop with the packet.
    `pkg/scion/ifdown.go` holds the signal type, the ten-second cache
    with its subscriber hook, and the recognition parse; the conn's two
    receive paths record what they recognize, and `PathProvider`
    (gaining the cache) prefers composed paths that cross no signaled
    interface — up and down segments checked where their entries carry
    the ISD-ASes and interface IDs — keeping a crossing path as the
    last resort. The WireGuard bind drops the quoted destination's
    cached path through the cache's subscriber.
*   Consumers: `Discovery.Neighbors` returns the full map with
    `LastSeen` (the greeting timeout stays on the core-endpoint relay
    alone); the beaconer's `Verdicts` field pauses origination and
    propagation on down interfaces; the core route's one-hop shortcut
    requires the verdict; the selection loop's `Verdicts` field feeds
    the demotions and the promotion floor (up links only), the sweep's
    grace reads `LastSeen` against the candidate window, and the probe
    split landed as `echoRTT` — the neighbor's direct side one-hop, the
    candidate's by rendezvous echo, the baseline over the resolved
    path. `establishLink` now falls through to the rendezvous
    establishment when the in-band request fails, so a promotion is not
    hostage to a path that resolves but carries nothing. The monitor
    and the shared cache are assembled beside discovery (`BootApp` and
    `cion ping` identically), passed to every conn and the provider,
    and exposed on `App` for the tests.
*   Tests: the session's frame, state machine, verdict hysteresis, and
    stop; the monitor's reconcile, retarget, and swap survival; the
    slow path's type 5 and its cap (`pkg/dataplane/bfddown_test.go`);
    the cache's retention, recognition, and composition avoidance; the
    bind's drop; the selection's verdict-down demotion, the two floors,
    and the sweep grace; the beaconer's pause; and the two integration
    episodes — the assembly harness's three-node line with promotion
    and recovery, the static lab's file-paired variant
    (`internal/testnetwork/bfd_test.go`). One pre-existing race in
    `TestJoinByRendezvous` surfaced under the new traffic: it killed B
    before C's direct up segments from A's beacons had landed, and the
    test now polls for that precondition — the race itself, in the
    beaconer's serialized sends, predates this proposal and stands.
