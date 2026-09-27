# Compose paths at the common ancestor

This proposal acts on the deferral
[proposal 0005](/docs/proposals/0005-path-library-and-scion-ping.md)'s
history recorded — revisiting compositions left as "a path-selection
concern for a later milestone" — and closes it inside
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)'s
provider seam. The data plane draft's path-construction rules (Section
1.4) name three ways one up and one down segment combine: at their
shared core (Case 2, what the provider builds today), at a common
ancestor below the core (Case 4), and on-path where one segment already
contains the far endpoint (Case 5). The provider builds only the first.
This proposal makes the three one rule: compose at the deepest AS the
two segments share, truncating each segment's core-ward remainder. The
middle node of a line becomes reachable from below — today its own
router rejects the revisiting composition — neighbors stop detouring
through the core, and the data plane, the wire format, and the
control plane change not at all.

[TOC]

## Summary

[`PathProvider.Path`](/pkg/scion/provider.go) composes an up and a down
segment only when the up segment originates at the core the down
segment starts from, and joins them there — the draft's Case 2. On the
line A(core)—B—C that rule composes C→B as `[C,B,A]+[A,B]`: the packet
arrives at B mid-path with a local destination, and the inbound check
`IsLastHop() != dstIsLocal` rejects it with an invalid-destination
error ([processor.go](/pkg/dataplane/processor.go)). B→C composes but
travels B→A→B→C — three crossings for a one-link adjacency. The change:

*   The meeting rule. For each fetched down segment, every stored up
    segment names a candidate meeting — the deepest AS entry common to
    both, the destination and the local node included. The joined path
    is the reversed up segment truncated at the meeting composed before
    the forward down segment truncated from it; either part may be
    empty when the meeting is an endpoint of one segment (Case 5, and
    the existing core-source case as meeting == the local node).
*   Bounded path builders in
    [pkg/segment](/pkg/segment/segment.go), the piece truncation needs:
    a forward path starting mid-segment chains the segment ID through
    the skipped entries; a reversed path truncated short keeps the
    terminator's own chaining. Both follow the one invariant the MAC
    design carries.
*   `LocalPath` resolves a destination an up segment already contains
    with no fetch, keeping its dial-safe contract, and
    `cion ping` between middle and sibling nodes works.

Every path composed today composes identically after the change — the
meeting at the core is the rule's shallowest case — and shorter joins
are preferred over it.

## Motivation

ADR-0004's own motivating topology is a line — core, middle, leaf — and
on that line the provider cannot reach the middle node from below at
all, while the middle node's traffic to below leaves for the core and
returns. Three facts sharpen this:

*   The rejection is the data plane working as specified: a router must
    not deliver a packet whose destination ISD-AS is local before the
    path's last hop. The defect is the composition, which revisits the
    destination mid-path; the draft's Cases 4 and 5 exist precisely to
    cut such compositions short.
*   Siblings under a common non-core parent — B serving C and D —
    transit the core to reach each other, concentrating traffic the
    topology places one hop apart. Each extraneous core-ward hop is
    signed, forwarded, and paid for, twice per round trip.
*   The gap is invisible to the suites: the static lab pings B→A, C→A,
    and A→C
    ([static_test.go](/internal/testnetwork/static_test.go)); the fork
    pings leaf→leaf through the core and core→leaf
    ([ping_test.go](/internal/testnetwork/ping_test.go)). No test sends
    to a middle node or between siblings.

The pieces the rule needs are already in the tree: `Compose`
concatenates up to three parts, the path database queries segments by
either endpoint, and every hop field carries the MAC the routers
verify. What is missing is the meeting computation and the truncating
builders — both local to the path library.

### Goals

*   One composition rule — the deepest common AS entry of an up and a
    down segment, subsuming the draft's Cases 2, 4, and 5 — replacing
    the same-origin-core requirement in `Path`.
*   Truncating path builders beside `ForwardPath` and `ReversePath` in
    `pkg/segment`, with the segment-ID chaining mid-segment entry
    requires.
*   `LocalPath` resolving an on-path destination from up segments
    alone, before the bootstrap fallback, with no fetch.
*   The interface-down filter judging only the hops a joined path
    traverses — a signaled interface on a dropped core-ward stretch no
    longer disqualifies the shortcut.
*   Integration coverage: the line's middle node pinged from below and
    pinging below; a sibling pair meeting at their parent.

### Non-goals

*   Peering shortcuts (Case 3). Intra-ISD peering stays unrepresentable
    — no signal distinguishes a shortcut link from a parent-child link
    (ADR-0004, decision 4) — and no peer entry is created, decoded, or
    matched.
*   Core segments (Cases 1a–1d). The provider still fetches only down
    segments; composing across cores is the multi-core milestone's own
    work, and it stands behind the trust changes ADR-0003 deferred.
*   The bootstrap beacon keeps serving only its originating core: its
    unsigned last hop is the enrollment route, not a general path, and
    truncating it would serve destinations the node has not verified a
    segment for.
*   No selection policy beyond the rule — no multipath, no metrics, no
    configuration. Fewest hops and freshest stay the tiebreakers.
*   No data-plane, wire-format, or control-plane change of any kind;
    the consumers of the path library (ping, the wireguard directory,
    the topology probes) are untouched and gain the paths silently.

## Proposal

### The meeting rule

`Path` keeps its shape: resolve locally, fetch down segments, compose,
keep a crossing path as last resort. The composition loop changes its
question. Where it today asks for an up segment originating at
`down.FirstIA()` and joins at that core, it asks instead for the
deepest AS entry the down segment shares with any stored up segment —
construction-direction depth, the destination and the local node both
eligible — and joins there:

*   Meeting at the shared core is today's Case 2. An up segment crosses
    exactly one core — beacons propagate away from cores and never
    toward them — so a core meeting implies the same origin core the
    current code requires, and the composed hops are identical.
*   Meeting at a non-core AS is Case 4: the reversed up segment
    truncated at the meeting, the forward down segment truncated from
    it, composed. The two segments need not share an origin core — the
    draft's own note on Case 4 — which the rule honors by not asking.
*   Meeting at the destination is Case 5 on the up side: the truncated
    reversed up segment alone. Meeting at the local node is Case 5 on
    the down side: the truncated forward down segment alone, the
    existing core-source branch as its special case.

Every candidate up segment enters the computation — not the freshest
per origin — because a staler up segment through a deeper parent can
meet a down segment the freshest one cannot. The store's bounded
registration and the database's expiry sweep keep the candidate set
small, and the meeting computation over entry lists is linear in both.

Selection stays deterministic and config-free: among the (up, down)
pairs that meet, fewest joined hops wins; ties go to the freshest
segments by creation timestamp, then to the fewest entries — the
existing `freshest` tiebreak carried to pairs. A joined path whose
traversed hops cross a signaled interface stays behind every clean one,
exactly as today; the filter checks only the entries of each segment
the joined path actually uses, so a down stretch beyond the meeting or
a core-ward stretch above it no longer counts against the shortcut.

### Truncating a segment's path

The MAC design carries one invariant the builders rest on: a hop
field's MAC is verified against the segment-ID state at its own
position — the seed chained through the MACs of every entry the segment
crosses before it in construction direction — and that state depends on
the hops before it, never on the hops after it. Removing trailing hops
changes no state any kept router reads.

The two builders, beside `ForwardPath` and `ReversePath`:

*   A forward path from entry *i* — travel beginning mid-segment —
    carries the seed chained through entries 0 to *i−1*, exactly the
    arithmetic `ReversePath` already performs for the terminator, and
    the hop fields of entries *i* onward, construction direction.
*   A reversed path to entry *m* — travel ending mid-segment — keeps
    `ReversePath`'s info field whole, because reversed travel starts at
    the terminator whatever the ending: its chained state covers
    entries 0 to *n−2* independent of *m*. The hop fields run from the
    terminator down to *m*.

Each traversed part carries at least two hop fields — the data plane
rejects singleton segments without the peering flag — because a
non-empty part always joins two distinct ASes: the meeting and, beyond
it, either the local node or the destination, and the local node equals
the destination only in the error `Path` returns before composing.

### What authorization the join carries

Nothing the change traverses is unsignable today and nothing new is
signed. Every hop on the joined path was signed by its AS inside a
segment the local node verified against the TRC-anchored chain; at the
meeting, the AS signed both entries whose ingress and egress the join
crosses, one in each segment, so the turn it makes is a turn it
authorized twice. The routers' per-hop MAC checks are unchanged — the
invariant above is the same one they already maintain — and valley
freedom holds as ADR-0004 argued it: travel still runs child to parent
up to the meeting and parent to child from it. The change removes
hops; it adds none.

### The local variant

`LocalPath` gains one step before the bootstrap fallback: the freshest
up segment whose entries contain the destination yields its truncated
reversed path. Up segments live in the local database, so the variant
keeps its contract — resolving a route inside a dial spawns no RPCs —
and the control routes, which target cores, resolve exactly as before.
The bootstrap beacon's branch is untouched and still serves only its
originating core.

## Test plan

*   **Unit, builders:** for crafted multi-entry segments, the
    mid-segment forward path's info field equals the seed chained
    through the skipped entries; the truncated reversed path shares its
    info field with the untruncated one; each kept hop field's MAC
    input — the state the routers recompute — is identical to the
    untruncated path's at the same position; every emitted part carries
    at least two hop fields.
*   **Unit, provider:** crafted up and down segments covering the four
    meeting shapes — shared core, shared non-core ancestor, destination
    on the up segment, local node on the down segment — resolve to the
    expected hop sequences; the preference order holds (fewest hops
    over freshest, crossing paths last, and only traversed hops counted
    by the filter); `LocalPath` resolves an on-path destination with no
    fetch and still errors on the local ISD-AS; an expired meeting
    segment never serves, and the consumer re-resolves.
*   **Integration, the line:** C pings B — the today-unreachable
    middle — and the reported hops are exactly C and B; B pings C and
    the reported hops are B and C, the core absent from the road;
    replies ride the reversed arrival paths; the existing C→A and A→C
    episodes pass unchanged.
*   **Integration, siblings:** a fork with a parent — A(core)—B,
    B—C, B—D — where C and D ping each other and the reported hops
    meet at B without the core.
*   **Negative:** a destination with no intersecting segment and no
    core-rooted down segment errors as unreachable; the destination
    equal to the local ISD-AS still errors rather than composing.

## Implementation history

*   The builders, beside `ForwardPath` and `ReversePath` in
    [pkg/segment](/pkg/segment/segment.go): `ForwardPathFrom` — the seed
    chained through the skipped entries, hop fields of the entries onward —
    and `ReversePathTo` — `ReversePath`'s info field whole, hop fields from
    the terminator down to the meeting. Each errors on a result below two
    hop fields, making the singleton the data plane rejects unrepresentable
    rather than merely avoided; the emptiness decisions (a meeting at the
    local node carries no up part, at the destination no down part) live in
    the provider's guards, where the proposal's Cases 2, 4, and 5 name
    them. `ContainsIA` became a predicate over a new `IndexOfIA`, the index
    the meeting computation and the local variant both read.
*   The meeting rule in
    [pkg/scion/provider.go](/pkg/scion/provider.go): `Path` fetches the
    down segments once, loads every stored up segment, and considers one
    candidate per (up, down) pair — the deepest common AS entry, by the sum
    of the two construction-direction indices — beside the local node's own
    entry on each down segment, the meeting no up segment names and the
    core-source branch's general form. Selection is `joinRank`: fewest
    joined hops, then the staler piece's creation timestamp — a join is
    only as fresh as the piece that expires first — then total entries.
    `freshestUp` dissolved into `upSegments` (every stored segment a
    candidate, the staler-deeper motivation's own shape) and `containingUp`
    (the freshest containing the destination, clean preferred).
*   `LocalPath` resolves an on-path destination before the bootstrap
    fallback exactly as planned; `Path` gained the explicit
    equal-destination error ahead of composition. The plan's letter made it
    structural for a reason the old code's shape only implied: a down
    segment terminating at the local node — which a core's database always
    holds for that node — composed into a route to self that revisited the
    destination as its own last hop. One existing filter test had built
    exactly that fixture and moved to a real destination.
*   The interface-down filter judges the traversed stretch alone:
    `crossesFrom` takes the meeting's index, so a signal on a core-ward
    entry above the meeting or a down stretch beyond it no longer
    disqualifies the shortcut; the crossing fallback keeps the first
    crossing join, as it kept the first crossing composition before.
*   Tests: the builders' in [pkg/segment](/pkg/segment/segment_test.go) —
    the mid-segment forward path's walk states equal the untruncated walk's
    at the same positions, the truncated reversed path's equal the
    untruncated prefix, every kept hop's MAC verifying against them, and
    the singleton guard erroring; the provider's in
    [pkg/scion](/pkg/scion/provider_test.go) — the four meeting shapes
    (shared core, shared ancestor, destination on the up segment, local
    node on the down segment) resolving to the expected hop sequences, the
    preference order (fewest hops over fresher, the fresher pair on ties),
    the filter's three positions (traversed, dropped above the meeting,
    dropped beyond it), and the negatives (the local ISD-AS and the
    unreachable destination); the integration proofs in
    [internal/testnetwork](/internal/testnetwork/ping_test.go) —
    `TestPingLineMiddleNode` (C→B and B→C at two hops, the line's existing
    episodes unchanged) and `TestPingSiblingNodes` (C↔D meeting at B,
    four hops in two segments) — each episode polling for its side of the
    join pipeline before pinging, a resolution a ping run does not retry.
    The composed-path and expiry unit tests moved their destination off
    the up segments — a middle the local variant now resolves without the
    fetch they meant to exercise.
