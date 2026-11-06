# Coordinate Link Changes Through the Node Directory

*   Status: accepted
*   Date: 2026-11-06

[TOC]

## Context and problem statement

Each node chooses its links alone
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)).
Every window, about 30 seconds, it measures every peer and promotes a link
whose direct round trip beats the peer's price by the promotion ratio and
margin, sustained for the pair's windows
([ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md)); it
retires a link it dialed once routes avoiding it serve its tier no worse.
A change that raises several nodes' prices at once — a cut, a raised delay,
a join — makes each of them promote, though one link would serve them all.
Once the first new link carries segments, the others serve nothing and
retire as useless minutes later, and reach dips around the retirements. Two
retirements can also rest on each other: each node judges its link useless
over routes through the other's, and both go.

*   **The regions lab:** in a run of
    [ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md)'s
    beacon rule, three nodes promoted links to the same node within 44
    seconds of a cut; two retired as useless about two minutes later, and
    reach held only after 230 seconds. Before ADR-0036, the slowest
    recovery, 570 seconds, followed the same pattern.
*   **The site lab:** site nodes promoted links to the same public node,
    then retired them relying on each other's.

Proposal 0111 delays each pair's promotion by a draw of one to six minutes,
a stagger that stands in for coordination
([0111](/docs/proposals/0111-stagger-the-priced-promotions.md)); pairs that
draw short waits still promote together. A node cannot tell that another
will close its gap: the directory carries each node's addresses alone, and
segments declare the delays of only the links they cross.

The directory now lives on every node
([ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)).
Each node signs its own entry, which floods along links within seconds,
each signer forwarded at most once per five seconds; entries refresh every
five minutes and lapse after fifteen. ADR-0026 rejected a topology computed
from shared delays partly because the directory lived on the founding core.
An offline study of the labs found that publishing each node's links and
its violators — peers whose measured round trip beats the path over the
links by the bound, or would once any one link on that path is lost — gives
every node what a fault-tolerant spanner needs.

How should nodes agree on which of them changes a link, when one change
would serve or undo another?

## Decision drivers

*   **One change per gap:** nodes that one link would serve wait for it,
    and a retirement waits for the retirement it rests on.
*   **Agreement during a change:** the nodes agree on the next promoter from
    data published before the change, ahead of any new measurement.
*   **No coordinator:** every node decides from the replicated directory,
    with no leader and no vote.
*   **The node's own test stays:** each node's measured tests still decide
    its links, and a node without the shared data acts as today.
*   **Bounded cost:** entries stay within CION's scale, and a node signs at
    once only for the changes the other nodes act on.

## Considered options

*   **The stagger,** as today.
*   **Announced changes:** a node announces the change it is about to make,
    and a node whose change another announced change serves or undoes
    waits.
*   **Announced and predicted changes:** each node also publishes the round
    trips it measured, so that every node predicts who promotes next, during
    a change, from data published before it.
*   **A shared plan:** every node computes the whole topology from the
    published round trips and keeps the links the plan gives it.

## Decision outcome

Chosen option: **announced and predicted changes**, realized as follows:

1.  **An entry reports every peer its node measured.** Beside its
    addresses, a node's entry in each directory lists each peer it measured
    there: the round trip, the interface of its link to the peer, and the
    changes it announced there. A pair weighs the larger of its ends' round
    trips, so no node looks closer than its peer measures it. Every node
    already measures every peer every window (ADR-0017), so the entry costs
    one field per peer and no measurement, and no subset can leave out the
    pair a change makes matter, such as a node close to every other.
2.  **Every node predicts the order of promotions.** Each node prices paths
    over the published links as the selection prices routes, the transit
    penalty included. An unlinked pair whose weight beats that path by the
    promotion ratio and margin violates; the lightest violating pair
    promotes first, ties to the lower pair of ISD-ASes — the greedy
    spanner's order.
3.  **A promotion waits for a lighter one that serves it.** A node's
    promotion of a peer whose round trip beats its price waits while a
    lighter pair of another node, announced or violating, would leave its
    own pair violating no more were it linked. Such a pair holds it for two
    windows after its violation, or its announcement, first shows: one
    window for that node's own test or change, and one for the result to
    reach the others. Past them the next lightest goes, so no node waits on
    a change that does not come, such as one from a node at its cap.
4.  **A promotion waits for its node's routes to see the links that serve
    it.** While the published links already serve the pair, its promotion
    waits as long as a link on the cheapest published path, which the node
    first saw within the last five minutes, crosses none of the node's
    routes to the peer, which name each link's interfaces. A herd forms
    from prices that predate another node's new link, and a node can tell
    when its own routes include that link. Five minutes is `StaleAfter`,
    the horizon in which a link change plays out in every node's segments:
    a route that has not crossed the link by then will not.
5.  **A change is announced before it is made.** A node announces a
    promotion from the first window the candidate's round trip beats its
    price, and a retirement from the first window that judges its link
    useless, with the links the routes it judged that link by cross. It
    makes the change once its test has held for its windows — two for a
    promotion, three for a retirement — and the announcement for at least
    one. The announcement thus runs alongside the damping. A node whose
    change yields to an announced one waits, whether or not it predicted
    it.
6.  **A retirement waits for the retirement it rests on.** A node's useless
    retirement waits while the routes it judged the link by cross a link
    another node announced to retire, unless that node's routes cross this
    link too and this link is the heavier, which then goes first. It also
    waits while those routes cross an announced link that left within the
    last five minutes, which the measurements may not yet have caught dead.
7.  **Links and announcements travel at once, round trips with the
    refresh.** An entry names a link only while the link is established and
    its verdict up, as the node's link state stands at the signing, and the
    node signs again whenever a link it names or one of its announcements
    changes. A pair is linked while an end names the link and no end that
    reports the pair names none. Every signing carries the whole report, so
    a changed round trip, or a newly measured peer, starts no signing: it
    travels with the entry's next one, at the latest its refresh five
    minutes on. A round trip is reported anew only once it moves by more
    than a tenth and half a millisecond, so jitter moves no weight.
8.  **The stagger goes where a round trip beats its price.** The order
    replaces proposal 0111's draws there; the second-route case keeps them.
    A node whose directory lacks a peer's entry counts that peer as
    reporting nothing.

This narrows ADR-0017's decision 1: a node still decides its own links, and
waits for the nodes ahead of it. It keeps ADR-0026's prices.

### Positive consequences

*   Where views agree, one node promotes per gap: no redundant link, no
    useless retirement after it, and no dip in reach around one.
*   The node first in the order promotes after two windows, against one to
    six minutes under the stagger.
*   During a cut, the nodes agree on the next promoter from entries
    published before it.
*   Retirements that rest on each other go one at a time.
*   No coordinator: a partition leaves each side coordinating on its own
    entries, and a node without them acts as today.
*   The entries hold what a shared plan would need, should one follow.

### Negative consequences

*   The entry gains a report per peer: a wire change, so nodes upgrade
    together, as for proposals 0097 and 0098.
*   The directory's traffic grows with the square of the network, where it
    grew linearly. An entry framed for a push is 183 bytes plus 15 per
    peer; each signing crosses about N·(d − 1) links for N nodes of d links
    each, and each end of each link sends a 59-byte summary of every entry
    each refresh interval. A node thus sends, and receives, about
    N·[(d − 1)·S + 59·d] bytes per refresh interval for entries of S bytes,
    before the transport's framing. In the regions lab, 9 nodes of about
    4.4 links, a node sent 37 to 38 bytes per second once its links
    settled, against 27, and 144 to 194 while they converged, against 42.
    At 4 links per node, 100 nodes would carry about 1.7 KB/s per node once
    settled, against 0.26, and 300 nodes 14 KB/s, against 0.8.
*   While links change, each announcement and each link gain or loss signs
    and floods a whole entry: a node signs up to once per window, ten times
    its refresh rate, and five to six times per five minutes while the
    regions lab's links converged.
*   Views can disagree for a window: two nodes may each see themselves first
    and both promote, and retirement cleans up as today.
*   A reported round trip is a claim. A node can claim a short one to go
    first; a pair both ends report weighs the larger, and a false claim
    costs the others one wait.
*   The prediction prices paths by published round trips, up to a refresh
    interval old, and the transit penalty, not by measured routes, so it can
    miss; the node's own test decides once the runner-up window or the
    horizon passes.
*   A change whose test held before the node could announce it — a
    promotion that waited on another node's, a retirement whose count ran
    at the redundancy floor — waits a window for its announcement, and a
    retirement two nodes rest on waits for the heavier one's effect.
*   Retirements that rest on each other in a cycle of three links or more
    all wait: the links stay until a node's judgment changes or the cap's
    eviction takes one.
*   Second-route promotions keep their draws and can still herd: in one of
    three regions cuts, three nodes bought second routes within six
    seconds, one retired as useless, and reach held only after five
    minutes. Which link adds an independent route is beyond a prediction
    by round trips; it needs the published links' single failures.
*   A node keeps a graph of the published links and prices every path over
    it each window.

## Pros and cons of the options

### The stagger

*   Good, because it needs nothing from other nodes.
*   Bad, because pairs that draw short waits still herd, every other
    promotion waits up to six minutes, and retirements resting on each other
    still both go. In the labs, the regions network settled after 18.5 link
    changes within 7.3 minutes, the medians of two runs, against 14 within
    4.1 under announced and predicted changes; the site lab joined both
    ways after 12 within 7.3 minutes, against 7 within 4.3.

### Announced changes

*   Good, because it needs one field per change and a rule.
*   Bad, because a node learns of another's change only once announced, and
    the first node to announce goes first, not the lightest. Over three
    regions cuts it retired 11 links as useless, against 8 with predictions
    in the same round of runs, and one cut's reach held only after 160
    seconds.

### Announced and predicted changes

*   Good, because every node can tell whose link would serve it, during a
    change, from data published before it, and still decides its own links.
*   Good, because announced from the first window its test holds, a change
    waits no longer than its damping. Announced only once the damping
    ended, each retirement took a window more, and the stranded lab's cut
    settled after 160 seconds, against 60 without retirement order and 70
    announced from the first window.
*   Bad, because the directory's traffic grows with the square of the
    network, and a prediction can disagree with the measured prices.

### A shared plan

*   Good, because it bounds every pair's stretch, even after any single
    failure, and its order-independent computation cannot cycle.
*   Bad, because noise anywhere rewires links elsewhere unless hysteresis
    holds it, and it replaces ADR-0017's loop rather than refining it.
