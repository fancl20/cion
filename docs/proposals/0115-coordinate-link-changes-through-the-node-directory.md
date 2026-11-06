# Coordinate link changes through the node directory

This proposal implements
[ADR-0037](/docs/adrs/0037-coordinate-link-changes-through-the-node-directory.md):
each node reports, in its directory entries, the round trips it measured,
its links, and the changes it announced; every node reads the reports each
window, predicts which promotions come first, and holds its own promotion
or retirement back while another node's would serve or undo it.

[TOC]

## Summary

Today:

*   **An entry carries a node's addresses alone**
    ([directory.proto](/proto/node/v1/directory.proto)), so no node learns
    another's round trips, links, or intentions.
*   **Each node changes its links alone**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)). It
    promotes a candidate whose round trip beats its price once the pair's
    drawn wait of two to twelve windows has passed
    ([0111](/docs/proposals/0111-stagger-the-priced-promotions.md)), and
    retires a link it dialed in the third window that judges it useless.
    Nodes that one link would serve each promote, and links that rest on
    each other each retire.

## Motivation

### Goals

*   An entry reports every peer its node measured in that directory, with
    the round trip, the node's link while it is established and its verdict
    up, and the changes the node announced (ADR-0037, decisions 1, 5, and
    7).
*   Every node predicts the order of promotions from the reports, and a
    promotion waits for a lighter one that serves it, or for the node's
    routes to see the links that serve it (decisions 2 to 4).
*   A change is announced from the first window its test holds and made
    once the test held for its windows, and a retirement waits for the
    retirement it rests on (decisions 5 and 6).
*   The stagger goes where a round trip beats its price (decision 8).
*   ADR-0037 is accepted.

### Non-goals

*   A shared plan computed from the reports.
*   Coordinating the second-route, floor, and stranded promotions, and the
    cap's eviction.

## Proposal

### The entry

*   **Each peer measured.** `node.v1.Entry` gains `peers`: each peer's
    ISD-AS, its round trip in microseconds, the node's interface of its
    established link to the peer whose verdict is up, zero for none, and
    whether the node announced promoting or retiring there, a retirement
    naming the links it relies on. The bus's `DirectoryEntry` carries them
    as `PeerReport`s; an entry that names an interface no hop field could
    carry is refused.
*   **Links named at the signing.** The directory asks for the node's
    reports in each directory at each signing, as it asks for its
    addresses; it also wakes at each publication of the link state. The
    provider names each reported peer's link from the link state as it
    stands: the established link whose verdict is up, the lowest interface
    where several reach the peer. `bus.LinkState` gains `Established`.
*   **Signed at once for links and announcements.** The directory signs
    again when a reported peer's link or announcements change, a peer the
    report drops naming none, so a link's gain or loss leaves both ends'
    entries within seconds. A changed round trip, or a peer that names
    neither, starts no signing: it travels with the entry's next one, at the
    latest its refresh.
*   **From the selection.** The selection hands the provider each window's
    reports, by directory: every peer it measured there — under the
    directory a neighbor's link joins, else the one whose entry named the
    address it probed — at the round trip it last reported unless the
    measurement moved by more than a tenth and half a millisecond, with the
    changes it announced.

### The view

*   **Pairs and links.** Each window the selection reads every directory's
    reports: a pair weighs the larger of its ends' round trips; it is linked
    when an end names a link and no end that reports the pair names none,
    each naming end's interface recorded; announcements read as reported.
*   **Paths.** The path between every two nodes over the linked pairs costs
    their weights plus twice `TransitPenalty` per transit, as member prices
    charge it. An unlinked pair violates when its weight beats that path by
    `PromotionRatio` and `MarginFloor`, or no path joins its ends.
*   **What carries over.** The window count; when each violating pair and
    each announced promotion was first seen; when each linked pair was first
    seen linked; and the announced retirements whose links left the linked
    pairs, kept for `StaleAfter`.

### Promotions

*   **Announced, then made.** Where a candidate's round trip beats its
    price, the fastest such candidate that waits on no other node is
    announced, and promoted in a later window once its streak reaches
    `PromoteWindows`. The second-route case keeps the drawn wait; the floor
    and stranded cases promote as today.
*   **Waits.** A promotion waits while a lighter pair of another node,
    announced or violating, first seen so no more than two windows ago,
    would leave its pair violating no more were it linked; and, while the
    published links already serve its pair, as long as a link on a cheapest
    path, first seen linked within `StaleAfter`, crosses none of its routes
    to the peer.

### Retirements

*   **Announced from the first useless window.** While the node's dialed
    up links exceed the floor, each dialed link whose useless count runs is
    announced with the links the routes its last decided window judged it
    by cross: the freshest survivor's and each member's cheapest survivor's.
    The useless retirement picks as today among the links announced since
    an earlier window.
*   **Waits.** It waits while those links cross another node's announced
    retirement, unless that node relies on this link too and this link is
    the heavier, and while they cross a link whose announced retirement left
    the links within `StaleAfter`.

### Packages touched

| Package | Change |
| :-- | :-- |
| `proto/node/v1` | `Entry.peers`, `Peer`, `LinkRef` |
| `pkg/libs/bus` | `DirectoryEntry.Peers`, `PeerReport`, `LinkState.Established` |
| `pkg/modules/topology/impl/measured` | The directory's reports and link state wake; the provider's links; the view, the waits, and the announcements in the selection |

## Compatibility

The entry changes on the wire. A node of an earlier release keeps the new
field as unknown bytes the signature covers and forwards it unread, but
reports nothing and coordinates with no one; networks upgrade together, as
for proposals 0097 and 0098.

## Test plan

*   **The view.** Weights, links, and announcements read from reports; path
    costs charge each transit; the violation test's ratio, margin, and
    unjoined pairs; the cost were a pair linked.
*   **The waits.** A promotion waits on a lighter pair of another node that
    serves it, predicted or announced, for two windows after each first
    shows; on none that serves it not, is heavier, or is its own; on a link
    its routes do not cross yet, until one does or `StaleAfter` passes. A
    retirement waits on an announced retirement it relies on, unless mutual
    and its link the heavier, or its own; and on a departed link its routes
    cross.
*   **The selection.** A candidate is announced, then promoted at
    `PromoteWindows`, and a withdrawn one is no longer announced; a
    promotion waits on a lighter announced one in the directory; a useless
    link is announced from its first useless window with its reliance, and
    retires at `DemoteWindows`; at the floor nothing is announced, and a
    link whose count ran there retires a window after its announcement; a
    retirement waits on another's announced one; the reports carry each
    measured peer at the reported round trip.
*   **The directory and the provider.** Reports round-trip through a signed
    entry, and a wide interface is refused. A changed link signs again at a
    link state publication; a changed round trip or a peer that names no
    link signs nothing then, and travels with the refresh. A changed link or
    announcement compares unequal, a changed round trip or an unlinked peer
    equal. The provider names the lowest established up link alone.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before.

## Implementation history

*   **Policy variants.** A temporary switch ran the benchmark suite under
    each policy from one test binary per round, against proposal 0114's
    runs: the regions lab settled twice and cut three or four times, the
    stranded cut three times, the site lab two or three times, and the NAT
    lab twice. Medians, with ranges where the cuts' tails spread:

    | Policy | Regions, settled | Regions, cut settled | Stranded, cut settled | Site, both joins | NAT |
    | :-- | :-- | :-- | :-- | :-- | :-- |
    | The stagger (0114) | 18.5 changes, 7.3 min | 120 s | 300 s (10–1800) | 12 changes, 7.3 min | 12.5 changes, 5.3 min |
    | Announced | 15.5, 4.9 min | 50 s (50–150) | 210 s | 9, 7.8 min | 10, 3.8 min |
    | Predicted, first round | 15, 5.1 min | 130 s (50–370) | 160 s | 8, 5.0 min | 8.5, 4.3 min |
    | The same, no retirement order | 15.5, 4.0 min | 60 s | 60 s | 6.5, 4.8 min | 9.5, 3.8 min |
    | Predicted | 14, 4.1 min | 250 s (60–300) | 70 s | 7, 4.3 min | 9, 4.3 min |
    | The same, no retirement order | 14.5, 4.0 min | 50 s (10–70) | 10 s (10–200) | 8, 5.3 min | 10.5, 4.3 min |
    | Predicted, second routes too | 17.5, 8.8 min | 95 s (10–300) | 10 s | 6, 4.2 min | 9.5, 3.8 min |

    *   Announced alone, the first node to announce goes first: over three
        regions cuts, 11 links retired as useless, against 8 under
        prediction, and one cut's reach held only after 160 seconds.
    *   The first round announced a retirement at its third useless window
        and made it a window later, so each retirement took a window more.
        The second announces from the first useless window.
    *   Retirement order changes nothing the labs tell apart: once
        promotions wait on each other, retirements that rest on each other
        are rare there. It stays for that case, at no added wait.
    *   The regions cuts' tails come from second-route promotions, whose
        draws remain: in the second round's slowest cut, three nodes bought
        second routes within six seconds, one retired as useless, and reach
        held only after five minutes. Ordered by the round-trip test as
        beaten prices are, second routes left one of four cuts' reach at 310
        seconds, and 14 links retired as useless over the four runs, against
        7 over three; they keep their draws.
*   **Changes from the first prototype.**
    *   The beaten-price loop first tested `qualifies`, which counts a second
        route too, so second-route candidates skipped their draws;
        `tier.beats` holds the beaten price alone.
    *   An announced promotion held the other nodes as long as it stood, so
        a node at its cap with no victim to evict, or whose establishment
        fails, would hold them without end; two windows now bound an
        announcement as they bound a prediction.
    *   The selection first named its links itself, as of its window: a new
        link showed at the accepting end a window late, and a retired link
        stayed named, because `LinkState.Up` reads an interface no entry
        holds as up. The provider now names each link from the link state
        at the signing.
    *   A departure is recorded only for a pair the window before showed
        linked, so an announcement that outlives its link keeps the
        interfaces the departure recorded.
    *   Every change of the reports first signed at once, so a node's entry
        would sign whenever any of its peers' round trips moved past the
        step: a rate growing with the network, each signing flooding an
        entry that grows with it too. Round trips now travel with the next
        signing.
*   **Directory traffic.** The payload of the directory's pushes and syncs,
    per node, instrumented in the regions lab, two runs: 37 and 38 bytes
    per second once the links settled, against 27 at the commit before, and
    144 and 194 while they converged, against 42, a node signing five to six
    times per five minutes then, against one to two. A signed entry is 180
    bytes plus 15 per peer; each signing crossed 32 of the lab's 20 links'
    40 directions, as 2E − N + 1 predicts, and each end of a link sends a
    59-byte summary per entry every five minutes. Before round trips waited
    for the refresh, one run sent 188 bytes per second converging: the lab's
    fixed delays move no round trip, so the labs cannot show the churn the
    change removes.
*   The tests landed as planned, with `TestSelectionReports` and
    `TestObserveRestartsPredictions` beside them. Mutations 61 of 61
    killed.
*   Benchmarks against the commit before, two or three runs each:
    *   The regions lab settled after 14 and 17 link changes within 4.5 and
        10.5 minutes, against 18 and 19 within 6.2 and 8.3, its worst pair at
        1.11 times the reference, as before. The slow run's tail was two
        second routes bought 33 seconds apart, one retired as useless three
        minutes later.
    *   After the regions cut, reach held from 10 seconds in all three runs,
        against 20, and the links settled within 10 to 120 seconds, a median
        of 50, against 100 to 140; the worst pair stood at 1.16 to 1.23 times
        the reference, against 1.23.
    *   After the stranded cut, the links settled within 10 to 310 seconds, a
        median of 60, against 10 seconds to never within the budget; after
        the restore, within 120 to 280, against 0 to 260.
    *   The site lab joined both ways settled after 6 or 7 changes within 4.3
        to 5.5 minutes, against 11 to 14 within 6.8 to 8, and one run of
        three left one pair unreached, as found below; joined inside or
        outside, after 5 changes within 2.5 and 1.8 minutes, against 7 and 8
        within 4.5 and 6.
    *   The NAT lab settled after 9 and 10 changes within 4.3 and 4.8
        minutes, against 11 and 14 within 4.8 and 5.8; its founder-down
        nodes survived in 1.6 and 16.1 seconds and returned in 216 and 219,
        against 14.1 and 15.5, and 219 and 231.
    *   Useless retirements: 6 over the site lab's three runs, against 10; 10
        over the regions cut runs, against 7, one link each promoted for a
        beaten price, the others bought for the floor, a stranded tier, or a
        second route, or accepted.
*   Found, not fixed: in some runs of the site lab joined both ways, one
    pair stays unreached through the assessment, in 2 of 5 runs before
    proposal 0114. The founder's lease to a site node holds a down segment
    over a link that node retired, though a direct link joins the two.
