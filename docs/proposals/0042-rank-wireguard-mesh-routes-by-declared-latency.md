# Rank WireGuard mesh routes by declared latency

This proposal makes the WireGuard application the first consumer that
orders enumerated candidates itself — the place
[proposal 0040](/docs/proposals/0040-enumerate-composed-paths-with-their-facts.md)
named for exactly this: its non-goals keep every policy out of the path
layer and put "a helper each in the application" instead. The mesh
transport's warm loop resolves each peer's route through
`PathProvider.Path` today — the fewest-hops rank — while every
enumerated candidate beside it carries a declared one-way sum the
beacons already attest. What lands here is the application-side pick
that ranks by those sums, and the hysteresis that keeps two near-equal
routes from trading the transport between them every refresh window —
the sustained-evidence posture
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
holds for link changes and
[proposal 0041](/docs/proposals/0041-select-neighbors-by-marginal-utility.md)
implements for neighbor choice, applied to route choice. The send path,
the path layer, and the wire gain nothing.

[TOC]

## Summary

The warm loop resolves a route per mesh peer every refresh interval and
lands it in the shared socket's send cache
([directory.go](/pkg/apps/wireguard/directory.go),
[bind.go](/pkg/apps/wireguard/bind.go)): `Provider.Path` picks, the
cache overwrites, and the rank is fewest joined hops, then freshness,
then entries. The change:

*   The warm loop enumerates and picks itself: `Enumerate` per peer,
    one pure decision function over the window's candidates, the pick
    landed in the cache. The rank is the declared one-way sum,
    ascending — an undeclared sum ranks behind a declared one, unknown
    is not free — with the path layer's own rank breaking ties.
*   The pick switches reluctantly: a challenger must beat the
    incumbent's declared sum by `SwitchRatio`, and lead for
    `SwitchWindows` consecutive windows naming the same challenger —
    the selection loop's `PromotionRatio` and `PromoteWindows` shape,
    as code constants.
*   The socket holds the choice's state beside the send cache: the
    incumbent route's link identity and the challenger streak, written
    in the same critical section that lands the pick, and cleared by
    every eviction — a send-time seed, a failed send, an interface-down
    signal — so a failure-driven replacement picks best at once, as
    today.
*   A route's identity is its link set, not its wire encoding: the
    `(ISD-AS, interface ID)` pairs the candidates carry, stable across
    the recompositions of the same stretch where timestamps and hop
    MACs are not.
*   A `route_switches` counter beside the existing ones, the warm
    loop's replacements made visible; `path_refreshes` keeps its
    expiry-and-failure meaning.
*   Everything a send does stays byte-for-byte: the cache read, the
    arrival-path seed, the `LocalPath` fallback, the one retry. A
    network where nothing declares latency keeps today's behavior —
    the default rank, immediate.

## Motivation

Hop count is the transport's only rank today, and it is a poor proxy
for delay: a two-hop route over a satellite link serves a tunnel worse
than a three-hop terrestrial one, and the transport cannot tell. The
declared sums are already there to tell it — proposal 0040 wrote the
extension at both ends, each AS attesting its own links' measured
one-way delays in the entries it signs, and the candidates carry the
traversed sum. The warm loop is the one place a fetch belongs, so the
pick costs nothing the loop does not already spend: `Path` resolves
through the same enumeration internally.

Reluctance is the other half. The declared sums move — each AS
re-declares at its own measurement cadence, a link that loses its
sample declares nothing, and two near-equal routes can trade the lead
back and forth as they do. An undamped pick would trade the transport
between them every window, and every trade costs in-flight datagrams
their place in line. The codebase's own answer to a move like this is
sustained evidence: the selection loop promotes on a ratio held two
consecutive windows and demotes on one held three, BFD's verdict edges
are hysteresed by construction, and ADR-0017's decision 1 trades
stability against optimality deliberately. Route choice is a smaller
stage than link choice — a switch moves datagrams, not segments — but
the same shape fits, scaled down: one ratio, one streak, both code
constants.

One coverage gap closes beside the change: the warm loop's resolution
has no test today. The pick lands as a pure function — candidates, the
incumbent's identity, the streak in; the pick, the next streak, and
whether a switch landed out — table-tested without a socket.

### Goals

*   The warm loop's pick ranked by declared one-way sums, the choice
    living in the application beside the enumeration's facts.
*   Hysteresis on every latency-driven switch: a ratio the challenger
    must beat and a streak of consecutive windows naming the same
    challenger, both code constants.
*   Behavior preserved wherever latency says nothing: a network
    without declarations keeps the default rank and today's
    immediacy, the send path keeps its whole resolution ladder, and
    every eviction keeps its failure-driven immediacy.
*   The choice's state beside the send cache under the socket's one
    lock, decided and landed in a single critical section.
*   The pick as a pure function with table tests, and the socket and
    loop behaviors covered where they were not.

### Non-goals

*   No path-layer policy or seam: the provider gains nothing, exactly
    as proposal 0040's non-goals hold. The application orders
    candidates; the library composes them.
*   No measurement in the application: the pick reads declared sums
    and probes nothing — measured baselines stay the selection loop's
    echoes.
*   No send-path change: sends never fetch, never rank, never see the
    streak. A send's fallbacks and their immediacy are the contract.
*   No configuration: the ratio, the streak, and the cadence are code
    constants, per ADR-0017's decision 17.
*   No multipath, no per-flow choice, no bandwidth or MTU reading: one
    route per peer, ranked by delay alone.

## Proposal

### The pick and its rank

One window's candidates divide into a clean pool and a crossing pool —
the flagged last resort `Path` honors — and the pick considers the
clean pool, falling back to the crossing one only when nothing clean
composes, the wrapper's own semantics. Within the pool, a declared sum
outranks an undeclared one and a smaller declared sum outranks a
larger; ties and undeclared pairs fall to the path layer's rank —
fewest hops, then freshness, then entries — so the order a
non-declaring network sees is the order it sees today.

The incumbent route loses its route at once when the window can no
longer compose it clean: gone from the pool entirely — the segments
expired, the fetch came back empty, the network reshaped — or demoted
to the crossing pool while clean candidates exist. Both are failure
semantics, and the replacement is the best clean candidate immediately,
what `Path` would answer in the same window.

### The incumbent and its streak

The incumbent is matched among the window's candidates by link set:
the same stretch recomposed carries the same links and new timestamps,
so the identity is stable where the wire encoding is not, and the
matched candidate carries the route's current declaration — the socket
never stores a latency, only the identity and the streak.

A challenger displaces the incumbent when it beats the incumbent's
declared sum by `SwitchRatio` — `0.8`, a challenger a fifth faster —
for `SwitchWindows` — `2` — consecutive windows, the streak naming the
same challenger by its links: a window where a different candidate
leads, where the leader falls back inside the ratio, or where either
side's declaration lapses resets the count. The streak damps both
directions, the selection loop's posture scaled to route choice: a
challenger that alternates the lead with another never reaches two,
and an incumbent that keeps its route resets whatever was building
against it.

The declarations' gaps have their own rules, each shaped so coverage
churn cannot flip the transport:

*   An incumbent with a declared sum never yields to a challenger
    without one — knowledge is not traded for ignorance, and a link
    whose sample lapsed does not demote its route.
*   An incumbent without a declared sum — seeded by a send, or picked
    before the network declared — yields to a declared challenger
    through the streak alone: sustained evidence, no ratio to apply.
*   Neither side declared is today's case exactly: the default rank
    picks, immediately, the hops-first order a non-declaring network
    has always had.

### The socket's route state

The socket holds one route entry per peer beside the send cache — the
incumbent's links and the streak — under the lock the cache already
carries. The warm loop's landing is one critical section: read the
incumbent, decide, write the pick's path, hop expiry, and route state.
A pick that keeps the route still refreshes the cache — a
recomposition of the same stretch carries fresher hop expiry — and a
pick that switches counts `route_switches`.

Every eviction clears the route entry with the cache entry: the
send-time seed (no route facts survive a path the warm loop did not
choose), the failed send's invalidation, and the interface-down
signal's drop. The next warm window after any of them finds no
incumbent and picks best at once — the immediacy a failure deserves,
never hysteresis standing between a dead route and its replacement.

Two windows the hysteresis does not damp remain, both degradations to
today's behavior and never worse: a path lapsing inside the refresh
margin mid-window makes the send seed through `LocalPath` — freshest,
possibly another route — clearing the route state, so the next window
re-picks immediately; and a down-segment fetch that comes back empty
while containing-up routes stand switches to the containing route at
once and back when the fetch returns, the same move `Path`'s
short-circuit makes today. The lookup's expiry-aware caching makes the
second rare.

### What the warm loop does

Per mesh peer, per refresh: enumerate the candidates, and hand them to
the socket's landing. An empty answer or an error keeps the cache and
warns — the empty slice is `Enumerate`'s unreachable, where `Path`
answered an error — and a switch lands an info line. Before a node
enrolls, the enumeration composes nothing and the loop warns per peer
per window; the sends it would serve keep working through the
`LocalPath` bootstrap fallback untouched, and the noise is the cost of
the loop's honesty, accepted.

## Test plan

*   **Unit, the pick:** table tests over the pure function — the rank
    (declared ascending, undeclared behind, the default rank under
    ties), the pool (crossing never picked while clean stands, the
    last-resort pool ranked the same way), the incumbent (absent,
    unmatched, best), the ratio (pass, fail, the exact boundary), the
    streak (advance, reset on a broken window, restart on a new
    challenger, alternation never reaching the threshold), and the
    declaration gaps (known never yields to unknown, unknown yields
    through the streak alone, neither declared picks by the default
    rank at once).
*   **Unit, the socket:** segments declaring their egress links'
    one-way delays enumerate and land through the socket — the
    incumbent held while the streak builds, displaced on the second
    window, the counter counting; every eviction (seed, failed send,
    interface-down signal) clears the route entry and the next window
    picks best at once.
*   **Unit, the loop:** a peer with an empty enumeration keeps the
    cache and warns; a peer with declared candidates gets the pick in
    its cache.
