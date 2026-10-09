# Harden neighbor selection and link liveness

This proposal brings the path layer, the measured provider, and the link
monitor to the decisions of
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
as amended, and lands the episodes its acceptance waits on; the last commit
of the series flips it to `accepted`. It reworks the selection loop of
[proposal 0041](/docs/proposals/0041-select-neighbors-by-marginal-utility.md)
over the enumeration of
[proposal 0040](/docs/proposals/0040-enumerate-composed-paths-with-their-facts.md),
which stops serving the node's retired interfaces; moves the BFD verdict of
[proposal 0012](/docs/proposals/0012-bfd-liveness-and-two-route-comparator.md)
onto the session's state; and fixes the route pick of
[proposal 0042](/docs/proposals/0042-rank-wireguard-mesh-routes-by-declared-latency.md).
No run argument, wire message, or constant changes.

[TOC]

## Summary

The path layer composes over every unexpired segment
([provider.go](/pkg/scion/provider.go)), including segments that leave
through an interface the node has retired. Such a segment stays until it
expires, up to six hours later. Nothing marks the interface down: its BFD
session left with its entry, and the selection loop reads a missing verdict
as up. The loop counts the path as a route and as a survivor, and the
WireGuard application can land it. The data plane answers a packet sent
over it with a parameter problem for an unknown egress interface, not the
interface-down signal a source sets a path aside on.

The selection loop
([selection.go](/pkg/modules/topology/impl/measured/selection.go),
[tiers.go](/pkg/modules/topology/impl/measured/tiers.go),
[queries.go](/pkg/modules/topology/impl/measured/queries.go)):

*   **Pricing.** `tierPrice` returns the baseline echo whenever one
    answered, so a declared route cheaper than the probed one never sets
    the price. When none answered, it prices by every candidate, including
    those that cross a signaled interface or a local down link and those
    whose echoes went unanswered.
*   **Stranding.** A tier is stranded only when no route counts, so a stale
    segment that composes clean keeps a cut tier from its rescue.
*   **Retirement.** The useless test reads latency alone. A link bought as
    its tier's second route can test useless, since its exclusion leaves
    the first route's latency, and promotion then buys it again. One
    streak counts down windows and useless windows alike. The guards read
    facts taken once per window, so two links that are each other's only
    survivor retire in the same pass, and a survivor whose echo went
    unanswered still passes for a route.
*   **The cap.** `admit` counts established entries only, so candidates in
    flight and revived entries take the node past `MaxNeighbors`.
*   **Revival.** The stranded flag rises at any up-link count. A revival
    checks nothing against the table
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)): it
    can revive a second entry for a neighbor the node holds live, which the
    candidate sweep then establishes past the cap. An entry the acceptor
    minted records no rendezvous address and is never re-dialed.

The BFD session and its monitor ([bfd.go](/pkg/controlplane/bfd.go),
[monitor.go](/pkg/controlplane/monitor.go)):

*   **Verdict.** Any decodable arrival raises the verdict, and the peer's
    Down does not lower it while packets arrive. After a loss in one
    direction, the end that still hears its peer keeps forwarding and
    beaconing into a link the other end has marked down.
*   **State machine.** `advance` departs from RFC 5880 in two transitions:
    a Down session moves to Up on the peer's Up, and an Init session falls
    to Down on the peer's Down.
*   **Transmission.** The monitor sends two control packets per interval:
    `reconcile` ticks every serving session, and `tickAll` ticks it again.

The WireGuard pick ([route.go](/pkg/apps/wireguard/route.go)):

*   `pickRoute` matches the incumbent to the first candidate with its link
    set and lands that instance whenever the incumbent stays, though a
    fresher composition of the same route may stand beside it.
*   A lapse of the incumbent's declared sum does not restart the
    challenger's streak, against the function's own documentation.
*   The branch for an undeclared challenger against a declared incumbent
    is unreachable: the rank puts every declared candidate first.

## Motivation

ADR-0017 cannot be accepted while its code contradicts it, and two of its
promises have no episode: the stranded clause with the floor met, and the
equilibrium of regional meshes joined by bridges. Most of the defects come
from facts that read different evidence: the routes the loop counts are
not the routes it probes or the data plane serves, one counter carries two
rules, and the verdict moves on arrivals the session's state does not
accept. Each fix makes a fact read the same evidence as the facts it is
compared with.

### Goals

*   No composed path through an interface the node has retired is
    enumerated, counted, priced, or landed.
*   Each composed route prices itself, by its echo where the window probed
    it and by its declared delays where it did not; an unanswered echo
    prices nothing.
*   A tier with no up link and no answered composed route is stranded,
    whatever stale segments compose into it.
*   A link retires as useless only when its exclusion changes neither its
    tier's route count nor its tier's price beyond the demotion ratio, on
    evidence measured in the window that retires it. The two retirement
    rules count their own windows, and one up link leaves per window.
*   The cap bounds the named live entries at every instant, revivals
    included, and a revival never doubles a live neighbor.
*   The BFD verdict follows the session's state: up only through the
    three-way handshake, down on silence or on the peer's Down, with one
    transmission per interval.
*   The WireGuard pick lands the freshest instance of its route, and a
    lapse of the incumbent's declaration restarts the challenger's streak.
*   The stranded clause and the equilibrium each have an episode, and
    ADR-0017 is `accepted`.

### Non-goals

*   No change to what a start takes. Decision 9 now states what the
    configuration's validation already requires; refusing a joining core
    restarted without its neighbor is the sixth open question of
    [proposal 0043](/docs/proposals/0043-supervise-the-nodes-loops-and-resolve-its-role-once.md).
*   No revocation. A segment through a link retired elsewhere counts as a
    route until it expires, the blind spot decision 4 accepts.
*   No new constant, run argument, or wire message. The ratios, windows,
    floor, cap, and BFD timers keep their values.

## Proposal

### The path layer serves live interfaces only

`PathProvider` gains `Links`, the snapshot of the link table that the
beaconer and the connections already read: the live entries' interface IDs
and their neighbors (`links.Links`). `Enumerate` takes the snapshot once
per call. `compose` drops a candidate whose link set names a local
interface the snapshot lacks, either of an entry's two interface IDs
sufficing, as `crossesFrom` reads them. `containingUp` skips an up segment
whose last entry, the node's own, arrived on an interface the snapshot
lacks, so `LocalPath` and `Path` serve no such segment either. A nil field
or a nil snapshot filters nothing.

A dropped candidate is not a last resort: the data plane forwards nothing
through an interface its generation does not serve. The interface-down
cache keeps its own meaning, a signaled interface demoting a candidate to
the last resort.

The node assembly passes the cached snapshot it builds for the beaconer
([controlplane.go](/internal/services/controlplane.go)), and the harness's
`StartNode` passes its own ([network.go](/internal/testnetwork/network.go)).

### Each route prices itself

The probe keeps the candidate its baseline echo rode: `sample` gains
`carrier`, pointing into its candidates. A new helper, `cheapest`, replaces
`tierPrice`. Each route prices itself by its echo when the window echoed
it, and otherwise by its declared one-way sum doubled, when every edge
declares. An unanswered echo prices nothing, and so does an unknown sum.
The price is the cheapest route, zero when nothing prices.

A tier's price is `cheapest` over the clean candidates into its members,
each member's carrier priced by its baseline echo. A candidate that crosses
a signaled interface or a local down link prices nothing, as it counts as
no route. The tier's baseline stays the fastest answered baseline echo, and
the stranded test is now its only reader.

The excluded measurement stops enumerating. An up link's survivors are the
tier's clean candidates that do not traverse it: the hard filter of
proposal 0040, applied to the window's candidates. The freshest survivor is
echoed, as before. `excludedSample` keeps `echo` and replaces `survived`
with two fields:

*   `price`, `cheapest` over the survivors, the echoed survivor priced by
    its new echo and the surviving carriers by their baseline echoes;
*   `routes`, the route count over the tier's other up links and the
    survivors.

A down link takes no excluded measurement, since no rule reads one.
`Enumerate`'s exclusion loses its last caller and goes, with its map in
`compose`.

### A tier is stranded on its echoes

A tier is stranded when it holds no up link and no member's baseline echo
answered. The window's answered composed routes are the ones its echoes
rode, so a stale segment no longer hides a cut, and a route that answers
keeps the tier unstranded.

### Each retirement rule counts its own windows

`peerStreak` replaces `demote` with two counts, `down` and `useless`. A new
step of the pass, after the tiers and before promotion, advances them for
every established link:

*   `down` grows in a window whose verdict is down and resets in one whose
    verdict is up.
*   `useless` grows in a window decided useless, resets in a window
    decided useful, and holds in an undecided one. A window decides when
    the link is up, its tier is priced, and its freshest survivor answered
    the echo. It decides useless when the excluded route count equals the
    tier's and the excluded price is no worse than the demotion ratio above
    the tier's.

`prune` retires every link whose `down` count has reached `DemoteWindows`,
with no guard: a down link carries no route. It then retires at most one up
link, and none in a window whose eviction took an up link. The up links it
considers have a `useless` count that has reached `DemoteWindows` and a
window decided useless; it retires the one whose exclusion moves its tier's
price least, and only while up links exceed the floor.

The cut-critical guard needs no check of its own: a link whose exclusion
leaves no answered survivor decides nothing, and an answered survivor is a
route. `soleUp` and the tier's `up` set go.

`evict` qualifies a down link whose `down` count has reached
`DemoteWindows`, at no harm, and an up link whose window decided useless
while up links exceed the floor, the reading proposal 0041 gave it. The
harm is the distance from the excluded price to the tier's price, and ties
still go to the slower direct sample. `admit` counts the named live entries
against the cap, as the acceptor's cap counts them, so candidates in flight
hold their places.

### A revival respects the table

The stranded flag rises only below the floor: fewer up links than
`NeighborFloor` and no reachable directory candidate. `dialJoins` revives a
retired entry only while its neighbor has no live entry and the named live
entries number fewer than `MaxNeighbors`, and it drops an answer that names
a neighbor with a live entry. Each check reads the table as the pass's
earlier revivals left it.

The dial's target comes from a new helper, `rendezvousTarget`, which
`candidateAlive` shares: the entry's rendezvous address, or else the fixed
rendezvous port on its remote host. The entries the acceptor minted are
re-dialed too.

### The BFD verdict follows the session

`advance` follows RFC 5880's reception rules (Section 6.8.6):

*   A Down session moves to Init on the peer's Down and to Up on its Init;
    the peer's Up leaves it Down.
*   An Init session moves to Up on the peer's Init or Up; the peer's Down
    leaves it Init.
*   An Up session moves to Down on the peer's Down, with diagnostic 3.
*   An Init or Up session moves to Down on the peer's AdminDown, with
    diagnostic 3.

A detection time without an arrival moves an Init or Up session to Down,
with diagnostic 1 (Section 6.8.4). The verdict is up while the session is
Up. A session that has never reached Up holds its verdict up for one
detection time from its start, and down after it. An arrival no longer
raises the verdict by itself, and the verdict is re-read on every arrival
and every tick. `HealthMonitor.Up` still answers up for an interface it
holds no session for.

`reconcile` no longer ticks. `Run` reconciles and then ticks every session,
at start and at every interval, so a session transmits once per interval.

### The WireGuard pick lands the freshest instance

`pickRoute` keeps one candidate per link set before it ranks: the one
`Before` puts first, the freshest composition of the route. A kept route
lands its freshest instance, and a challenger is the freshest instance of
its own. `routeChoice` gains `declared`, whether the incumbent declared its
sum in the window that last counted the streak; a window in which the
incumbent's declaration has changed restarts the streak at one. The branch
for an undeclared challenger against a declared incumbent goes.

### The lab and the record

The integration lab shapes the loopback with `tc`, through a new helper of
`internal/testnetwork`: a `prio` root qdisc whose added bands carry netem
one-way delays of 1, 5, and 20 ms and a total loss, and u32 filters that
steer each direction of a host pair into its band, grouped by priority so
that one command lifts a group. Shaping needs `CAP_NET_ADMIN`, so the lab
re-executes its test binary in a new user and network namespace, where it
owns the loopback and leaves the host's untouched. It fails, rather than
skips, where `tc` or unprivileged user namespaces are missing.

The architecture overview's account of selection follows the amended ADR
([architecture.md](/docs/design/architecture.md)): a link is kept for what
it adds into the region beyond its peer.

## Test plan

*   **Unit, the path layer:** under a link-table snapshot, a candidate
    whose up part arrives on an interface the snapshot lacks does not
    compose, nor does a down-only meeting whose local entry names one; a
    candidate over live interfaces composes as before. `LocalPath` and
    `Path` pass over the freshest up segment through a retired interface
    for a staler live one. A nil snapshot filters nothing. The exclusion's
    episodes go with the exclusion.
*   **Unit, pricing:** a declared route cheaper than the echoed carrier
    sets the tier's price; a carrier whose echo went unanswered prices
    nothing, declared or not; a candidate that crosses a signaled interface
    or a local down link prices nothing; a tier nothing prices has no
    price. The excluded price reads the survivors alone, the echoed
    survivor by its new echo, and the excluded route count reads the
    tier's other up links and the survivors.
*   **Unit, stranding:** a tier that holds no up link and whose members'
    echoes all went unanswered is stranded, however many clean candidates
    compose into it; one answered echo or one up link keeps it unstranded.
*   **Unit, retirement:** a link bought as its tier's second route never
    decides useless while it is one of two routes; the two counts advance
    and reset apart, a down window holding the useless count and an up
    window resetting the down count alone; a count at `DemoteWindows`
    retires only in a window decided useless; three useless up links in
    one tier retire one per window, down to the floor; an eviction of an up
    link blocks that window's useless retirement; a down link retires at
    its count with no guard, even as its tier's only link.
*   **Unit, the cap:** the eviction takes the qualified link whose
    exclusion moves its tier's price least, a down link at its count
    first; a bridge whose exclusion leaves no answered survivor is never
    evicted, and with nothing else qualifying the promotion waits; `admit`
    counts a named candidate in flight against the cap.
*   **Unit, the equilibrium:** a node at a cap of three holds two regional
    links and a bridge into a far tier, and a composed route through the
    bridge gives the region a third route. A faster regional candidate,
    sustained, evicts one of the regional links and never the bridge,
    whose exclusion leaves its tier no answered route. Then the bridge
    goes down while a far candidate appears: the far tier strands, and its
    rescue waits, the floor holding the two regional up links, until the
    bridge's `down` count reaches `DemoteWindows` and the eviction takes
    it at no harm.
*   **Unit, revival:** the flag rises only below the floor with no
    reachable candidate, and not at the floor with an empty directory; a
    revival skips a retired entry whose neighbor holds a live one, stops at
    the cap, re-dials an entry the acceptor minted at its remote host's
    rendezvous port, and drops an answer naming a neighbor the table holds
    live.
*   **Unit, BFD:** two sessions wired back to back through writers that
    can drop: the handshake raises both verdicts only once it completes,
    and a lone arrival on a Down session raises nothing; dropping one
    direction downs both ends; the peer's Down downs an Up session; a new
    session's verdict stays up for one detection time and falls after it
    without a handshake; restoring the dropped direction brings both ends
    up by the handshake. The state machine matches RFC 5880's table
    transition by transition. In a synctest bubble, the monitor transmits
    once per session per interval.
*   **Unit, the WireGuard pick:** a lapse of the incumbent's declaration
    mid-streak restarts the streak; given two instances of the incumbent's
    route, the pick lands the fresher, whether the incumbent keeps the
    lead or holds against a building challenger.
*   **Integration, the stranded clause:** six nodes in two sides, the
    founding core A with F and G, and C, D, and E, every one joined to A.
    One-way delays are 1 ms within a side, 5 ms between A and C, D, or E,
    and 20 ms between F or G and C, D, or E, the last blackholed while the
    sides form. Once each side stands, every node holding two up links and
    none crossing, the lab cuts A from C, D, and E and lifts the
    blackhole. Every node keeps its floor, and every route into the other
    side crosses the cut. A link between F or G and C, D, or E forms,
    established at both ends, while A's links to F and G and F's link to G
    stay established and every node holds two up links. Only the stranded
    clause can form it: no node falls below the floor, and whatever prices
    the other side, a stale route's declarations near 14 ms or nothing at
    all, a 40 ms round trip neither beats nor seconds it.
*   **Existing episodes:** the line lab, `TestLineCutHeals`, keeps the
    below-floor heal; the BFD labs, `TestBFDLivenessEpisode` and
    `TestBFDStaticLabEpisode`, recover by the handshake; and
    `TestNodeConfigValidate` and `TestJoinDeniedByEnrollAuth` stand for
    decisions 9 and 10.

## Implementation history

*   Landed in six commits: bab745f, the path layer
    ([provider.go](/pkg/scion/provider.go)); c2941ed, the stranded flag,
    the revivals, and the cap; 63f57c0, the BFD verdict
    ([bfd.go](/pkg/controlplane/bfd.go),
    [monitor.go](/pkg/controlplane/monitor.go)); dbba33b, the WireGuard
    pick ([route.go](/pkg/apps/wireguard/route.go)), which keeps each
    route's freshest instance in `freshestPerRoute`; 943c79d, pricing and
    retirement together, for the useless test reads the excluded price;
    and the commit that flips ADR-0017, the lab and this record. The
    selection loop's changes live in
    [selection.go](/pkg/modules/topology/impl/measured/selection.go),
    [tiers.go](/pkg/modules/topology/impl/measured/tiers.go),
    [queries.go](/pkg/modules/topology/impl/measured/queries.go), and
    [provider.go](/pkg/modules/topology/impl/measured/provider.go).
*   A revival re-dials an entry the acceptor minted only once the entry
    names its peer. An unnamed retired entry is re-dialed only when it
    records the rendezvous address it was seeded with (`revivable`): the
    entries a probe mints on the acceptor name no peer, so no live entry
    can be checked against them.
*   A useless retirement's ties at equal harm go to the slower direct
    sample, as the eviction's do.
*   The lab, `TestStrandedTierHeals`
    ([stranded_test.go](/internal/testnetwork/stranded_test.go)), departs
    from the plan's topology. The one-way delays are 1, 15, and 40 ms.
    Each side is a full mesh by its joins, G joining A and F, D joining A
    and C, and E joining C and D, so C's and D's links to A are the only
    bridges. While the sides form, E is blackholed from A, beside F and G
    from the far side. The blackholes lift before the cut, and the lab
    waits for every probe across the sides to land with no link crossing,
    so the link that forms after the cut answers the cut. The shaping
    helpers are test code
    ([netem_test.go](/internal/testnetwork/netem_test.go)): `ownNetns`,
    `shapeLoopback`, `steer`, and `lift`.
*   The planned topology linked the sides before the cut. Its detour
    through a sibling, 12 ms, sat half a millisecond inside the demotion
    ratio over the 10 ms between A and a far node, and with every far node
    joined to A, each bridge was useless beside the other two. Under the
    loopback's noise the bridges retired and returned, and the stale
    segments the churn left read the far tier as stranded at F and G,
    whose rescue crossed early, a consequence the ADR accepts. The landed
    delays keep every comparison clear of its ratio, the two bridges hold
    each other by the route count, and E's blackhole keeps a node whose
    joins are not yet proven from linking A for its floor, which would add
    a third bridge.
*   The unit episodes live beside their code: the path layer's in
    [provider_test.go](/pkg/scion/provider_test.go), where what
    `TestEnumerateExclusion` held beyond the exclusion became
    `TestEnumerateLastResortAndBounds`; pricing, stranding, retirement,
    the cap, and the equilibrium in
    [queries_test.go](/pkg/modules/topology/impl/measured/queries_test.go),
    [tiers_test.go](/pkg/modules/topology/impl/measured/tiers_test.go),
    and
    [selection_test.go](/pkg/modules/topology/impl/measured/selection_test.go);
    revival in `TestSelectionStrandedFlag` and
    [provider_test.go](/pkg/modules/topology/impl/measured/provider_test.go);
    BFD in [bfd_test.go](/pkg/controlplane/bfd_test.go) and
    [monitor_test.go](/pkg/controlplane/monitor_test.go); and the pick in
    [route_test.go](/pkg/apps/wireguard/route_test.go).
