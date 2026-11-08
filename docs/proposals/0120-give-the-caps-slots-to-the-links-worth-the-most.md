# Give the cap's slots to the links worth the most

This proposal implements principle 6 of
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)
as amended here: at the cap, a candidate that earns a link displaces the
link worth least among those it outweighs, a link that would not earn its
place today or one that saves less than the candidate gains by the line to
buy.

[TOC]

## Summary

Today:

*   **At the cap, only a link that would not earn its place yields**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)): the
    eviction takes an up link only when no price it holds down drops by
    `PromotionRatio` and `MarginFloor` without it, and the bounds confirm
    that it gains no one the band
    ([proposal 0118](/docs/proposals/0118-let-paths-react-and-links-settle.md)).
    A link that saves its neighbor a transit gains the band, so at the cap
    nearly every link holds its slot, and a node keeps the links it bought
    first, however much a candidate would gain. In a ring of twelve nodes,
    eight and ten held the cap once settled, and a pair across the ring
    brought to a tenth of its delay announced its promotion at once and
    never linked.
*   **A retry evicts again.** The cap counts the candidate's own entry
    while its far end has not answered, so each window that runs the
    establishment again needs another victim. Victims rarely qualify, so it
    seldom shows; a rule that frees slots more readily would strip a node
    toward the floor while a far end at the cap refuses it.

## Motivation

### Goals

*   At the cap, a candidate displaces a link that saves less than the
    candidate gains by the line to buy, the history confirming both
    (ADR-0039, principle 6).
*   A link that would not earn its place today still yields to any
    candidate that earns a link.
*   An establishment that runs again evicts nothing more.
*   A ring lab in which the cap binds and no cluster forms.

### Non-goals

*   The acceptor's cap: a node at the cap refuses a new peer's request, so
    a pair whose ends both hold the cap links once both have made room.
*   The cap itself, the floor, and the victim's ranking by least harm.
*   A link's worth summed over the peers it serves: each saving stands
    alone, as each price does for promotion.

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| A candidate's gain | its own price less its direct round trip, the tier's price when no route prices it, as promotion reads them; sure, on the lower of the price's reading and its lower bound | what its link would save the paths to it (principle 2); noise raises a price's reading long before its lower bound, which stays up a while after noise that lasted, and a direct round trip only to shrink the gain |
| What a link saves | for its tier and each member, the price without it less the price with it, its own neighbor's at its direct round trip | what the paths would lose without it (principle 2) |
| Outweighed | every saving below `PromotionRatio` of the gain, and `MarginFloor` under it | buying costs more than keeping (principle 4): the gain clears the savings as a direct round trip clears its price |
| Confirmed | each saving at the bounds, the survivors' upper bound less the link's lower bound, outweighed by the sure gain | a displacement is a retirement, and waits for its confidence, on both sides (principle 6) |
| Would not earn its place | short of the line to buy on the readings, and confirmed within the band, as before | a candidate that earns a link outweighs such a link whatever it gains: a second route or a stranded tier's member gains no round trip |

### The eviction

At the cap, the admission computes the candidate's gain, and the eviction
draws its victim from:

*   a down link whose down count reached `DemoteWindows`, as before;
*   while up links exceed the floor, an up link that would not earn its
    place today, as before, or one whose savings the candidate's gain
    outweighs on the readings, and its sure gain at the bounds;
*   a link the clustering does not allow, by the clustering's useless test,
    as before.

The victim is the one whose exclusion moves its tier's price least, ties to
the slower direct sample, as before. A candidate whose own entry is live,
its establishment unanswered, holds the slot an earlier window freed, so
its admission evicts nothing more.

### The labs

*   **Ring.** Twelve nodes on a ring, each 4ms one way from its two
    neighbors, a pair's delay the steps between them the shorter way round:
    each node's eleven peers exceed the cap of eight, and no group stands
    apart. Node 0 founds the network, and each other node joins through the
    one before. Its benchmarks settle it, counting the nodes at the cap;
    draw bursts and a jitter sweep on it; and bring the unlinked pair the
    formed links join at the highest delay to a tenth of it, timed from the
    fall until the pair links, then restored. The lab runs as benchmarks
    alone: the behavior suite, run twice, has no room left in its twenty
    minutes for twelve more nodes to settle.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The gain, the savings test, the eviction by either test, and the retry that evicts nothing more |
| `internal/testnetwork/behavior` | The ring lab |

## Compatibility

The eviction is the node's own: nodes on either rule link and serve as
before.

## Test plan

*   **The savings test.** A link whose every saving the gain outweighs, on
    the readings and the bounds, yields. One that saves its tier, a member,
    or its own neighbor within the ratio or the margin floor keeps its slot,
    as does one whose bounds hold a saving near the sure gain or give none,
    one whose exclusion cuts a member off or loses a route, and any against
    no gain, or a gain the bounds do not confirm. A member no survivor
    prices, or a survivor that did not answer, decides nothing.
*   **The gain.** The member's own price less its round trip, the tier's
    price when no route prices the member, and sure on the lower of the
    price and its lower bound; nothing for a member whose routes none read,
    an unpriced tier, or a round trip that saves nothing, and nothing sure
    without a bound.
*   **The selection.** At the cap, a candidate whose gain outweighs every
    link's savings displaces the least harm, ties to the slower direct
    sample, though every link would earn its place today; one whose gain
    falls short, or whose price's lower bound does not confirm it, waits; a
    link that would not earn its place yields though the candidate's gain
    does not outweigh its savings; a retried establishment evicts nothing
    more; the cap's other tests hold.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before, the ring lab included.

## Implementation history

*   **Either test.** Weighed against the candidate's gain alone, a link that
    would not earn its place today keeps its slot whenever it saves near
    what the candidate gains, and a candidate that gains nothing on its
    price, a second route or a stranded tier's member, displaces nothing.
    The eviction takes a link either test yields.
*   **A retry.** A displacement whose far end refuses leaves the candidate's
    entry live, holding the slot the displacement freed, for as long as the
    far end answers binding requests: a far end at the cap answers no claim
    it holds no entry for. The cap counted that entry, so each window that
    ran the establishment again needed, and with the savings test found,
    another victim. The candidate's own entry now holds its slot. The
    retries run each window, as they do below the cap: in the ring lab, a
    run with a pair brought near refused 176 to 332 exchanges, against 118
    and 120, each logging a warning.
*   **The sure gain.** A first realization weighed each saving at its bounds
    against the gain on the price's reading. In the ring lab's bursts, a
    burst that tripled one link's delay for 76 seconds moved the five-minute
    readings of the routes across it, and the gain a candidate then showed
    on such a route displaced a link, the candidate's far end at the cap
    refusing it: one change, where the commit before made none. Weighed
    against the gain on the price's lower bound, which a burst moves only
    once it lasts, the same bursts changed no link, but the jitter sweep
    changed three on its way down, at 1ms, where the commit before changed
    none: a lower bound stays up a while after jitter that lasted, while the
    readings have recovered. The bounds now weigh each saving against the
    gain on the lower of the price's reading and its lower bound, and the
    same bursts and sweep change no link.
*   **What a pair brought near sets off.** In the ring lab, the ends of the
    unlinked pair across the ring that held the cap displaced a link each,
    and over three runs the pair linked 270 to 280 seconds after its delay
    fell, the readings' five minutes bounding the wait. Each victim, a slot
    free, bought a link in turn, and the far ends of those links made room
    in turn, every step a gain by the line to buy: the links changed six or
    seven times, the last 13 to 17 minutes after the fall. The worst pair
    then stood at 1.54 times the reference with the transit penalty, where
    the commit before never linked the pair and held it at 10 times.
    Restored, two runs changed no link and the third two within four
    minutes. Before the sure gain, two runs changed links 8 and 9 times.
*   **Test adaptations.** The cap's fixture comments give each link's
    savings against the candidate's gain.
*   **Left as it is.**
    *   A displacement whose far end never makes room leaves the displacing
        node a link short while the far end lives.
    *   Each refused retry logs a warning.
*   Mutations: 19 of 19 killed, after a row of the savings test that
    reads a saving the history does not show.
*   The pipeline passed, the race detector's run with the ring lab in the
    behavior suite. Run twice, that suite outlasted its twenty minutes, so
    the ring lab runs as benchmarks alone, and the suite then passed within
    17 minutes.
*   Benchmarks against the commit before, one to three runs each:
    *   The ring settled on 44 to 46 links after 21 or 22 changes within
        6.7 to 7 minutes, 6 to 10 of its 12 nodes at the cap, its worst pair
        at 1.31 to 1.62 times the reference with the transit penalty,
        against 47 and 46 links after 23 changes within 7.2 and 7.7
        minutes, 10 and 8 nodes at the cap, at 1.31 and 1.42. No link was
        displaced while it settled; the joins set the spread.
    *   In the ring's bursts and its jitter sweep, no link changed, as at
        the commit before.
    *   The other labs ran before the sure gain, which moves only what the
        cap displaces, and the cap binds in none of them but the metros lab,
        where each version displaced one link while settling. The metros
        and regions labs settled on 26 and 25, and 30 links, after 15 to 20
        changes within 7.2 to 9.2 minutes, their worst pairs at 1.06 and
        1.07, and at 1.007, as before. After their cuts, the metros,
        regions, and stranded links settled within 10, 30, and 10 seconds,
        and after the restores within 130, 200, and 300 seconds, against 30
        to 120, 50 to 200, and 0 to 20. The site lab, the regions bursts,
        and the pair across the metros, linked after 340 seconds, stood as
        before.
    *   One NAT run settled on 21 links with six retirements of links
        outside its cluster announced at five minutes and never made before
        the lab ended, where the commit before's two runs made theirs within
        two minutes. The NAT lab never reaches the cap; the coordination's
        waits are the follow-up's to read.
