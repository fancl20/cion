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
