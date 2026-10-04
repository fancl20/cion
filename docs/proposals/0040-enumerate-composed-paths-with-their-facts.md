# Enumerate composed paths with their facts

This proposal lands the path seam
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
stands on. The selection loop's route counts need the hop-by-hop link
identity of every composed path, its excluded baselines need resolution
under a link the composed paths must avoid, and its baseline carrier is
the freshest path — three facts the provider computes and discards on
its way to returning one path ranked by fewest hops. Beside them rides
the declared latency of every hop: the StaticInfoExtension the drafts
name for segment latency, each AS attesting its own links' measured
round trips in the entries it signs. The change adds one enumeration
seam beside `Path` that emits every composed candidate with its facts —
link set, freshness, and declared latency among them — makes `Path` a
behavior-preserving wrapper over the seam, speaks the extension at both
ends, and composes the comparator's queries from the seam inside the
topology application, where ADR-0017's owner split puts them. The
composition rule of
[proposal 0025](/docs/proposals/0025-compose-paths-at-the-common-ancestor.md)
is the rule enumerated, and the wire gains no new message or exchange —
one optional, signed extension the drafts already define.

[TOC]

## Summary

`PathProvider.Path` composes candidates inside one loop and keeps only
the winner: every (up, down) meeting at the deepest shared AS entry,
ranked by `joinRank` — fewest joined hops, then the staler piece's
creation timestamp, then total entries — the first clean path returned, a
path crossing a signaled interface held as last resort
([provider.go](/pkg/scion/provider.go)). Before the loop runs,
`LocalPath` short-circuits: a destination a stored up segment contains
resolves as that segment's truncated reversal, and the composition loop
never sees it. The one hop-identity walk the node carries — `crossesFrom`,
the interface-down skip — is unexported and segment-scoped, and the
selection loop's baseline rides the single return
([selection.go](/pkg/modules/topology/impl/measured/selection.go)). The
change:

*   A `Candidate`: the composed path beside the facts composition already
    holds — `Links`, the `(ISD-AS, interface ID)` pairs of the traversed
    stretch, both interface IDs of each entry, the identity the
    interface-down cache keys on; `Hops`; `Fresh`, the staler piece's
    timestamp; `Entries`, the rank's third tiebreak; `Crossing`, the
    signaled flag; and `Latency`, the traversed hops' declared one-way
    delays summed, absent when any hop declares none.
*   An `Enumerate` seam beside `Path`: the composition loop refactored
    from tracking the best to emitting every candidate — the joins, the
    local node's own entry on each fetched down segment, and every
    containing up segment's truncated reversal, the branch `LocalPath`
    short-circuits today, one candidate per containing segment. Exclusions
    are a parameter that hard-filters before composition; signaled
    interfaces keep their demote-to-last-resort semantics.
*   The StaticInfoExtension spoken at both ends: `AppendEntry` writes the
    egress link's measured one-way delay — the node's echo round trip
    halved — into the entry it signs, and the parsed entry surfaces it.
    The message, the field, and the per-interface latency map already
    exist in the wire library the segment format comes from, and
    propagation already forwards upstream entries verbatim — what
    neighbors declare already reaches the path database, protected by
    the signature that covers the whole signed body; today CION writes
    none of it and reads none of it.
*   `Path` unchanged in behavior: the `LocalPath` short-circuit first,
    then the seam without exclusions ordered by the carried rank — first
    clean, crossing last resort. The control transport, the ping
    machinery, and the applications resolve exactly as today.
*   The comparator's queries in the topology application, one helper
    each: the freshest candidate carries the baseline echo, route counts
    come from link sets, the excluded baseline enumerates minus the
    link — replacing the single-path baseline
    [proposal 0012](/docs/proposals/0012-bfd-liveness-and-two-route-comparator.md)
    landed — and the promotion estimate ranks candidates by their
    declared sums.

## Motivation

ADR-0017's decision outcome names three path-layer facts its loop reads,
and the provider holds all three only in passing.

Route counts (decision 4) need each composed path's link set — the
`(ISD-AS, interface ID)` pairs — and a decoded path carries no per-hop
AS identity, so the set can be stated only where the segments are
composed. The walk exists: `crossesFrom` is the same walk the
interface-down skip makes over the traversed entries. What is missing is
emission — the walk's result leaves with the winner and the loser's sets
are never formed.

The excluded baseline (decision 6) asks what the composed paths that
avoid a link serve, measured each window on the excluded baseline.
Resolving it through the interface-down cache would import the wrong
semantics: the skip keeps a crossing path as last resort, but a survivor
crossing the excluded link would make a cut-critical link look useful
through the very path that needs it. Exclusion must hard-filter, and an
empty answer must stand — it is the no-route-into-the-tier fact the
retirement guard reads. An exclusion parameter on composition, not a
cache write.

The baseline carrier (decision 14) is the freshest resolved path,
while `joinRank` is fewest-hops-first — a drift that reaches into the
code's own comments, which call the baseline's source the freshest path.
Freshness carried as a fact lets the comparator pick the freshest
itself, the ADR's letter made explicit in the application that owns the
question, while every other consumer keeps today's order. The
comparator's *measured* round trips stay the selection loop's own
echoes (decisions 14 and 16); what the facts add is the declared sum
beside them.

The promotion estimate (decision 2) leans on the measured tier baseline
alone: promotion prices a candidate against what the freshest path into
the tier measured, and nothing prices the routes the loop did not probe.
The extension the drafts name for exactly this closes it as measurement
distributed rather than description: each node signs its own links'
measured one-way delays, the beacons the network already sends carry
them, and every composed candidate gains a cost without a probe. The
ground is already laid — the drafts delegate the extension's definitions
to [PCBExtensions], whose concrete instance is the vendored wire library
the segment format itself comes from, and propagation forwards upstream
entries verbatim with the signature covering the whole signed body, so
the declaration needs no protection it does not already have. What is
missing is CION speaking it: the entry builder sets no extension, and
the entry parser drops the field.

One coverage gap closes with the same seam. `Path` short-circuits into
`LocalPath` whenever a containing up segment exists, and the peers the
comparator measures most — the node's own tier — sit on its up segments:
their baselines ride the containing branch and never reach the
composition loop. Enumeration that covered joins alone would answer the
baseline and the route counts from different candidate spaces;
containing-up candidates join the enumerated set, exclusion-filtered
like any other.

### Goals

*   The `Candidate` type and its facts, stated where composition holds
    full knowledge — the traversed stretch's link pairs, hops, the staler
    piece's timestamp, the entries tiebreak, the crossing flag.
*   The `Enumerate` seam: every composed candidate emitted with its
    facts, containing-up candidates included, exclusions hard-filtered
    before composition, signaled-down demotion unchanged, the local
    ISD-AS the one error and no path the empty answer.
*   The extension written and read: the entry the node signs declares
    its egress link's latest measured one-way delay, the parsed entry
    surfaces it, and the candidate carries the traversed sum — absent
    when any traversed hop declares none.
*   `Path` as a wrapper over the seam, byte-for-byte behavior-preserving
    for every existing consumer, proven by golden tests against the
    previous output.
*   The comparator's queries as helpers in the topology application: the
    freshest candidate as the baseline echo's carrier, route counts from
    link sets with pairwise edge-disjointness saturating at two, the
    excluded baseline as enumeration minus the link, and the promotion
    estimate over the declared sums.

### Non-goals

*   No policy in the path layer: no multipath serving, no configuration.
    Consumers that care order candidates themselves — a helper each in
    the application, not an engine in the library.
*   No latency measurement in the path layer: the layer never probes and
    stores nothing it measured itself — it sums what the entries'
    signatures already cover. Measured baselines and retirement stay the
    selector's echoes (decisions 14 and 16); the declared sum informs
    the promotion estimate and the probe ranking alone.
*   No operator-declared values and no intra-AS latency: the extension
    carries what the node's own window measured, for description would
    trade the ADR's posture for another run argument, and a single-node
    AS has no internal hops to declare or read — the intra crossing at
    a meeting contributes nothing.
*   No up×core×down composition: core segments keep serving the drafts'
    lookup answers only, as
    [proposal 0039](/docs/proposals/0039-make-the-path-layer-multi-core.md)
    recorded. A destination whose registered-origin cores share no AS
    with any stored up segment stays uncomposable — the undercount
    ADR-0017 decision 4 accepts as erring toward over-protection.
*   No `LocalPath` change: the dial-safe contract and the bootstrap
    fallback stay; enumeration serves the post-enrollment questions the
    topology loop asks.
*   No new message, exchange, or data-plane change: the one wire change
    is the optional, signed extension the drafts define, riding the
    beacons the network already sends at the cadence it already keeps.

## Proposal

### The candidate and its facts

`Candidate` is the decoded path beside the facts composition already
computes on its way to ranking:

*   `Links` — the `(ISD-AS, interface ID)` pairs of the traversed
    stretch, both interface IDs of each entry (`ConsIngress` and
    `ConsEgress`, the pair `crossesFrom` checks), the identity the
    interface-down cache keys on and ADR-0017 names the link's own.
    Entries dropped by truncation — above the meeting on the up side,
    beyond it on the down side — contribute nothing.
*   `Hops` and `Fresh` — the joined hop count and the staler piece's
    creation timestamp, the two halves of `joinRank`'s ordering: a join
    is only as fresh as the piece that expires first.
*   `Entries` — the rank's third tiebreak, total segment entries, so a
    consumer sorting candidates reproduces today's order exactly, the
    corner case of two candidates tied on hops and timestamp included.
*   `Crossing` — whether the traversed stretch crosses a signaled
    interface, the flag the wrapper honors as last resort.
*   `Latency` — the sum of the traversed inter-AS edges' declared
    one-way delays, the path's one-way estimate, absent when any
    traversed edge is declared by neither end: an undeclared edge is
    unknown, not free.

### The enumerate seam

`Enumerate(ctx, dst, exclude ...LinkID) []Candidate` refactors the
composition loop from tracking the best to emitting every candidate, in
the loop's own order — the down-only meeting per fetched down segment,
then each (up, down) meeting — with the containing branch beside it: one
candidate per containing up segment, truncated at its meeting index, not
the freshest alone. Emission order matters to exactly one consumer, the
wrapper's last resort below; the facts carry everything else.

Exclusions hard-filter before composition: a candidate whose traversed
stretch names an excluded link never composes, either of a hop's two
interface IDs sufficing. This is the seam's one semantic difference from
the interface-down skip, and it is why exclusion is a parameter rather
than a cache write — the skip's last resort would let a crossing survivor
answer the excluded baseline's question falsely. An empty result is an
answer: no composed path avoids the exclusion, the no-route fact the
retirement guard reads.

Signaled interfaces keep today's semantics unchanged: a crossing
candidate is emitted, flagged, and stands behind every clean one for
whatever consumer sorts. The local ISD-AS is the one error — a caller
mistake, failed fast at entry — and an unreachable destination is the
empty answer the wrapper translates into today's no-path error. The
bootstrap route stays out of the seam, as
[proposal 0025](/docs/proposals/0025-compose-paths-at-the-common-ancestor.md)
kept it out of composition: the enrollment route is not a general path,
and the topology loop asks its questions post-enrollment.

### The latency a beacon declares

The drafts' signed extensions carry path segment metadata, the
StaticInfoExtension among them, "used to carry path segment metadata,
such as segment latency" (Section 2.2.2.2) — definitions delegated to
[PCBExtensions], whose concrete instance is the vendored wire library
the segment format itself comes from; the message, the field, and the
per-interface latency map already exist there. The reference's current
text describes a richer per-hop metadata shape than the vendored
message; CION speaks the vendored instance — the shape the wire library
it already builds on defines. The delegated definition
makes latency a per-hop propagation delay: one-way, direction
independent with the more conservative value winning where two views of
one link meet, queuing and processing excluded. CION speaks it at both
ends:

*   Writing. The entry builder populates the entry's extension with the
    egress link's latency — the echo round trip the node's own
    evaluation window measured for that link, halved: half a measured
    round trip is the node's estimate of the one-way delay the
    extension defines, endpoint processing riding along as a bias every
    CION link's declaration shares, for the same instrument prices them
    all. The value lands on the link entry the beaconer already reads
    beside. Each AS attests its own links alone, and the entry's
    signature covers the declaration as it covers the rest of the
    signed body. A link without a sample declares nothing, and a link
    that regains one declares again at the next entry the beacons
    carry. The raw value keeps the unit the extension's definitions
    give; the parse seam converts once.
*   Reading. The entry parser surfaces the declarations as a per-link
    map — every `Inter` value keyed by its attesting ISD-AS and the
    local interface, the same identity the `Links` fact carries — and
    the candidate prices each traversed inter-AS edge by lookup on the
    edge, never on the hop field: consecutive entries *i* and *i+1* of
    a part cross the link between AS *i*'s egress interface and AS
    *i+1*'s ingress interface, whichever direction travel runs. A down
    part exits each AS through its egress and the declaration sits on
    the entry at hand; an up part, traversed against construction,
    exits each AS through its ingress, and the same link's declaration
    sits on the adjacent upstream entry — a per-hop-field reading keys
    the wrong entry's map there. Where both ends of an edge declare,
    the higher value wins — the reference's own conflict rule; where
    neither declares, the fact is absent: an undeclared edge is
    unknown, not free.
*   Trust. Each AS's declaration is its own: verified with the entry's
    signature, wrong by at most what the attesting AS chooses to say,
    and never the authority for a question the node can measure itself.
    The declared sum prices what the loop has not probed; the echoes
    correct it wherever the loop has.

### Path stays the default wrapper

`Path` keeps its shape and gains none of its own: `LocalPath` first —
the freshest clean containing reversal, then the bootstrap fallback —
then the seam without exclusions, sorted by the carried rank, first
clean returned. The last resort keeps today's rule exactly: the first
crossing candidate in emission order, not the best-ranked crossing one.
No policy of its own; the golden tests hold the wrapper to the previous
output across the meeting shapes.

### The comparator's queries

The helpers in the topology application, beside the selection loop
that ADR-0017's owner split already houses:

*   The baseline carrier: enumerate to the peer, echo the freshest
    candidate. Freshness picks the route, the echo measures it, and the
    tier baseline is the fastest measured round trip among the members —
    never a freshness value itself. This replaces the single-path
    baseline in `probe`; the direct side over the one-hop path is
    untouched.
*   The route count into a tier: the tier's up links from the store,
    plus the candidates into its members traversing none of them; a
    second route counts only when edge-disjoint from the first — checked
    over all pairs, for a greedy first pick can miss the pair a
    different first would yield — and the count saturates at two. Pairs
    are few and the miss direction is safe either way: undercount errs
    toward over-protection, the blind spot ADR-0017 accepts.
*   The promotion estimate: the declared sums price every composed route
    into the tier — the tier-relative estimate decision 2 names gains
    its breadth, the freshest probed path no longer the only price the
    candidate is judged against, and the loop ranks what to probe
    without probing it. The comparison is round against round: the
    declared one-way sum doubles before it meets a round trip, so each
    side prices the same quantity. The measured tier baseline stays the
    authority wherever an echo exists.
*   The excluded baseline: enumerate to the peer with the link excluded,
    echo the freshest survivor. Empty means the exclusion leaves no
    route into the tier — the link is cut-critical and never retires,
    whatever its latency.

## Test plan

*   **Unit, the facts:** link sets against hand-computed sets — both
    interface IDs per entry, the traversed stretch alone, truncation
    dropping an entry that crosses nothing the candidate travels;
    `Fresh` is the staler piece's timestamp; the rank fields equal
    `joinRank`'s.
*   **Unit, the declared latency:** an appended entry carries its
    egress link's measured one-way delay — the window's echo round trip
    halved — keyed by the interface, and the entry's signature verifies
    over it; a link without a sample declares nothing; an upstream entry
    propagated with an extension arrives byte-for-byte, its signature
    intact; the candidate's one-way sum is hand-computed over the
    traversed inter-AS edges, an up part's edges priced from the
    upstream entries' declarations — the per-hop-field reading keys the
    wrong entry's map there — and one undeclared edge makes the fact
    absent.
*   **Unit, coverage:** a destination both branches serve yields
    containing-up candidates beside the joins, one per containing
    segment; exclusions filter both kinds identically; the emission
    order follows the loop's.
*   **Unit, exclusion semantics:** exclusion never yields a candidate
    crossing the excluded link — no last resort — while a signaled
    interface still yields a flagged one; excluding either of a hop's
    two interface IDs drops the candidate; the local ISD-AS errors, the
    unreachable destination enumerates empty.
*   **Unit, wrapper equivalence:** across the meeting shapes of
    [proposal 0025](/docs/proposals/0025-compose-paths-at-the-common-ancestor.md)
    — shared core, shared ancestor, destination on the up segment, local
    node on the down segment — `Path`'s output equals golden paths
    captured before the change, the entries tiebreak and the
    first-crossing last resort included; `LocalPath` still resolves with
    no fetch.
*   **App, the queries:** the freshest candidate carries the baseline
    echo; the route count finds the disjoint pair a greedy first pick
    misses and saturates at two; the excluded baseline empties exactly
    when every candidate crosses the excluded link, and the cut-critical
    reading follows.
