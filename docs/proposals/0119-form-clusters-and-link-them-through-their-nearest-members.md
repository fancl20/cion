# Form clusters and link them through their nearest members

This proposal implements the clusters of
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)
as far as they choose links and carry routes: every node computes the same
clusters from the round trips and bounds the directory publishes, joins its
cluster once the bounds confirm the gap, keeps it while the clustering holds
the budget, links outside its cluster only through the member pairs the
round trips choose, and forwards the routes over each link into its cluster
to the other members.

[TOC]

## Summary

Today:

*   **Every peer is every node's candidate**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)): each
    window the selection measures every peer its directories name and may
    promote a link to any. Under
    [proposal 0118](/docs/proposals/0118-let-paths-react-and-links-settle.md)'s
    rules a link that saves a transit earns its place, so the links grow
    toward the cap.
*   **An entry reports each peer's reading alone**
    ([directory.proto](/proto/node/v1/directory.proto)): the round trip, the
    link, and the announced changes, never the round trip's bounds or the
    group its signer belongs to.
*   **A link's routes travel one hop on**
    ([beaconselect.go](/pkg/core/controlplane/beaconselect.go)): a node's
    set covers each of its own links
    ([ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md),
    decision 4), so of the nodes on either side of a link, only its two ends
    hold segments over it. In the metros lab with clusters, a cut between
    two metros left the other members of both metros routing through the
    founder's metro, at 1.7 times the path the links allowed 16 minutes on.

## Motivation

### Goals

*   Every node computes the same natural clusters from the published round
    trips and bounds, at the gap the budget sets (ADR-0039, principles 7
    and 8).
*   An entry reports each peer's bounds beside its reading, and the cluster
    its signer joined.
*   A node joins the cluster the bounds confirm, keeps it while its pairs
    stay within the budget, and leaves once the bounds confirm the budget
    broken (principle 8).
*   Members are each other's candidates. Outside its cluster, a node
    promotes only to the far end of a chosen member pair it holds, and a
    link outside that structure retires once the structure links the two
    units and no member needs it (principle 9).
*   Beacons carry the routes over each link into a cluster on to all its
    members, so a path between two clusters crosses the links between them
    from any member (principle 9).
*   A metros lab shows clusters where the cap binds a flat network, and the
    labs report the clusters.

### Non-goals

*   Clusters as scopes: every node still measures every peer, holds every
    entry, and enumerates every route (principle 10).
*   The path policy and its prices.
*   Clusters of clusters.

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| The budget | a pair's round trip through the clusters within the line to buy on the readings of its direct round trip: at most `PromotionRatio` below, or `MarginFloor` above | no pair loses what a reading alone would buy a link for (principle 7) |
| The gap | separation at least `ClusterGap` times the diameter, `ClusterGap` = 2 ÷ (1 ÷ `PromotionRatio` − 1), 8 | through the closest members a pair travels at most the two diameters beyond its round trip, so at 8 the share stays within the budget's quarter |
| Forming | the gap on the bounds: the diameter at its pairs' upper bounds, the separation at its pairs' lower bounds | the confidence of principle 5, 95% one-sided over `scion.BoundSpan`, as proposal 0118 reads it |
| Leaving | the readings' prediction breaks the budget, and the prediction at lower bounds breaks it at the direct round trip's upper bound | the history confirms the break (principle 8); the readings alone lag nothing |
| The level | the most separated of nested clusters | noise moves it least (principle 8) |
| Links between two units | the lightest member pair, and the lightest on two other members | no member's failure separates them (principle 9) |
| Keeping a pair between two units | a linked pair stays chosen in its place until the lightest pair's reading beats it by the line to buy, both at its reading and at its lower bound | buying costs more than keeping (principle 4); the new pair is bought on its reading, and the linked one let go only once its history confirms it has not been that fast (principle 5) |
| Routes into a cluster | each link into the cluster carries its cheapest route on to every member | a path between two clusters meets at whichever member it needs (principle 9) |

### The entry

*   **Bounds.** `node.v1.Peer` gains `rtt_low_us` and `rtt_high_us`: the
    bounds of the signer's round trips to the peer over `scion.BoundSpan`,
    zero where its probes give none. `bus.PeerReport` carries them as `Low`
    and `High`. Each is reported again only once it moves past the
    reading's step, a tenth and `rttFloor`, and travels with the refresh,
    as round trips do.
*   **Cluster.** `node.v1.Entry` gains `cluster`: the ISD-AS naming the
    cluster its signer joined, zero for none. `bus.DirectoryEntry` carries
    it as `Cluster`. A changed cluster signs at once, as a changed link
    does.

### The clusters

*   **Weights.** The coordination's view weighs each pair by the larger of
    its two ends' readings, and now also by the larger of their lower and
    of their upper bounds. It reads each signer's cluster.
*   **Natural clusters.** The single-linkage dendrogram joins the pairs an
    upper bound weighs, lightest first, ties to the lesser pair. A dendrogram
    cluster of two nodes or more, short of all, is natural when every pair
    inside has an upper bound, and its separation — the least lower bound to
    a node outside — is at least `ClusterGap` times its diameter, the
    greatest upper bound inside. Natural clusters are kept most separated
    first, never overlapping.
*   **Units.** The nodes that name one cluster form one unit; every other
    node is a unit of one.
*   **Chosen pairs.** Between two units, the lightest member pair by
    reading, ties to the lesser pair, and the lightest pair on two other
    members, the side of a unit of one keeping its node. In either place,
    the lightest linked pair stays chosen instead until the lightest pair's
    reading beats it by the line to buy, both at its reading and at its
    lower bound.
*   **Prediction.** A pair in two units travels through their closest
    members, the lightest pair between the units by reading, whatever pair
    the links keep: the readings from each end to its unit's closest member,
    and of the closest pair, a hop from a node to itself weighing nothing. A
    pair some reading misses predicts nothing.

### Membership

Each window the node names:

1.  The natural cluster that holds it, if any, named as an existing member
    names it where every node naming that cluster lies inside, else by its
    least ISD-AS.
2.  Otherwise the cluster it named, while another node names it and the
    break is unconfirmed for every pair across its edge: a break needs the
    readings' prediction beyond the budget of the direct reading, and the
    prediction at lower bounds beyond the budget of the direct upper bound.
3.  Otherwise none.

### The selection

*   **Candidates.** A candidate outside the node's unit is promoted only
    when the node holds a chosen pair to it, whatever the priced case. The
    floor and a stranded tier take the fastest such candidate, else any
    reachable one.
*   **Links outside the structure.** A link to a peer outside the node's
    unit that no chosen pair names is judged useless, whatever its prices,
    once its exclusion keeps the tier's route count, cuts no member off,
    and a chosen pair links the two units in the coordination's view; the
    retirement goes through the counts, the announcement, and the waits as
    any useless link does, and the cap's eviction takes it as weak.
*   **The coordination** predicts promotions only of pairs the clustering
    allows.
*   **The report** carries the node's cluster and each peer's bounds.

### The beacons

*   **Routes into the cluster.** After the node's links, a set covers each
    link into the node's cluster at another member: for a route that
    entered the cluster before it reached the node, the link out of its last
    entry outside the cluster. Each such link that carries a qualifying
    route and has none in the set adds its cheapest route over it. The
    node's own set, which it registers, and the set of each neighbor in its
    cluster take these routes; a neighbor outside the cluster takes the
    routes into its own cluster from its own members.
*   **The cluster** the beaconer reads is the one the selection publishes
    on the node's bus each window, beside the links' delays: the members of
    the node's unit, none while it names no cluster. The beaconer reads no
    directory. A node in no cluster adds no route, so a flat network
    beacons as before.

### The labs

*   **Metros.** Twelve nodes in three metros, 3 to 4ms across and 40 to
    88ms apart: each node's eleven peers exceed the cap of eight. Its
    benchmarks settle it, cut its most crossed link, triple a used link's
    delay, and bring an unlinked pair across two metros near: the pair's
    delay falls to a tenth, timed from the fall until the pair links, any
    node leaves its cluster, and the links settle, then restored.
*   The grading and the settled benchmarks report the clusters.

### Packages touched

| Package | Change |
| :-- | :-- |
| `proto/node/v1` | `Peer.rtt_low_us`, `Peer.rtt_high_us`, `Entry.cluster` |
| `pkg/libs/bus` | `PeerReport.Low`, `PeerReport.High`, `DirectoryEntry.Cluster`, and the cluster topic |
| `pkg/modules/topology/impl/measured` | Publication, the clusters, membership, the candidates, the retirement of links outside the structure, and the cluster published on the bus |
| `pkg/core/controlplane` | The routes into the node's cluster in each set |
| `internal/services` | The beaconer reads the cluster topic |
| `internal/testnetwork/behavior` | The metros lab and the units in the grading |

## Compatibility

The fields are new and optional. A node that predates them names no
cluster, so the others treat it as a unit of one, and reports no bounds, so
no natural cluster forms across the pairs only it measured. Its beacons
carry no routes into a cluster, so it beacons as before.

## Test plan

*   **The entry.** The bounds and the cluster sign and read back; a changed
    cluster signs at once, changed bounds wait for the refresh, and a bound
    within the step reports the last one.
*   **The clusters.** The view bounds each pair by the larger of its ends'
    bounds and reads each signer's latest cluster. A cluster at the gap on
    its bounds is natural and one a bound short is not; a missing bound
    inside, or to a node outside a reading weighs, forms none; nested
    clusters keep the most separated; units follow the names; the chosen
    pairs between two clusters, a cluster and a unit of one, and two units
    of one; a linked pair kept within the line to buy, kept beyond it at its
    reading alone, at its lower bound alone, or with no lower bound, and
    replaced beyond it at both, in either place; the prediction through the
    closest members beside a kept pair, and a pair a reading misses.
*   **Membership.** A node joins the confirmed natural cluster, by the name
    its members use; keeps a cluster whose gap fell short while the budget
    holds; keeps it on a break the bounds do not confirm, and on one the
    readings no longer show; leaves on a confirmed break, and when no other
    node names the cluster.
*   **The selection.** A candidate outside the unit with no chosen pair
    neither promotes nor buys a second route, and one with a chosen pair
    promotes; the floor takes a chosen pair first, else any reachable
    candidate, and a stranded tier any reachable member ahead of a faster
    candidate; a link outside the structure retires once covered, and stays
    while a member needs it or before a chosen pair links the units; the
    eviction takes it first; the coordination predicts no pair the
    clustering does not allow; the report carries the cluster and the
    bounds; the cluster topic carries the node's unit, and nothing once it
    names no cluster.
*   **The beacons.** A set covers each link into the cluster at another
    member, a dearer second route over one such link stays out, and a node
    in no cluster adds none; the node's own set and a member neighbor's take
    the routes into the cluster, a neighbor outside does not.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before, the metros lab included.
