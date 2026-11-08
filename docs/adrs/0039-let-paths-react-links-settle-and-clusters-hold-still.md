# Let Paths React, Links Settle, and Clusters Hold Still

*   Status: proposed
*   Date: 2026-11-07

[TOC]

## Context and problem statement

Two policies decide the route a packet takes, one above the other:

*   **The path policy**
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)) chooses,
    for each destination, among the routes the stored segments compose. A
    lease moves within seconds when its path stops delivering, and when
    another healthy route costs less by the band across two evaluations. A
    move costs each connection on the lease a handshake.
*   **The link policy**, the topology selection
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)),
    chooses the links, and with them the routes the path policy chooses
    among. A link change reshapes segments in every node over five minutes,
    and a link costs upkeep while it lasts: beacons to each neighbor, a
    liveness session, and probes.

The link policy's rules predate the path policy and act as if the link
policy alone served traffic. A link that falls behind the routes around it
retires within minutes. Promotion and retirement read one price through one
ratio pair
([ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md), decision
3), so every pair stands on one side of the line, to promote or to retire,
with only the margin floor between them.

Read at the 80th percentile over five minutes
([ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md)),
the readings hold steady, yet the regions lab's jitter sweep still changed
its links 126 and 139 times
([proposal 0117](/docs/proposals/0117-read-round-trips-at-their-80th-percentile-over-five-minutes.md)).
An instrumented sweep logged each priced decision:

*   **At the line:** 25 of 40 promotions stood within a few percent above
    it, and most of 38 useless retirements took links that still helped,
    by 6 to 23 percent.
*   **On no reading:** more than half of the promotions, and of the
    retirements, rested on a price that declared delays set or that fewer
    than five probes read.

The path policy already moves traffic off a link that falls behind, within
seconds and at the cost of a handshake. The link policy retires the same
link, often on thinner evidence, at the cost of a reshape, and of a second
one when the noise turns and the pair promotes again.

Beneath both policies, every node treats every other alike, so the costs
grow with the square of the network. Every node measures every peer every
window (ADR-0017, decision 1) and holds every node's entry with every round
trip its signer measured
([ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md),
[ADR-0037](/docs/adrs/0037-coordinate-link-changes-through-the-node-directory.md)),
and only the cap bounds a node's links. Yet small networks are rarely flat:
a few operators run nodes in a few datacenters, metros, or homes, a few
milliseconds apart and steady inside each, tens of milliseconds between.
CION already treats one such group as a unit, by accident of addressing: a
site behind a translator keeps a directory of its own, its nodes without a
link outside publish no entry outside and are no candidates there, and paths
reach them through the site's nodes that link outside (ADR-0032, decision
5).

How should the policies divide the work, so that each acts on what it can
judge at its own pace, noise moves none of them, and the costs follow the
network's groups rather than its size?

## Decision drivers

*   **Each policy judges what it can see:** the path policy chooses among
    the routes there are, within seconds; the link policy changes the
    routes, over the horizon in which a change plays out.
*   **Noise moves nothing:** no decision turns on a difference its evidence
    cannot tell from noise.
*   **Real changes play out:** a route that beats the others by what a link
    costs gets its link, and a link no chosen route needs goes.
*   **Every threshold has a reason:** each line states a cost or a worth
    that the system defines, never a number fitted to a lab.
*   **Links stay bounded:** the cap bounds beaconing (ADR-0017, decision
    1), and its slots go to the links worth the most.
*   **Cost by locality:** a node's links, probes, and directory grow with
    its own group and the number of groups, not with the network.
*   **Paths stay near the best:** what grouping costs a pair is bounded,
    and known before a group forms.
*   **Measurement over description:** groups come from measured round
    trips; no operator names them (ADR-0017).
*   **One notion of group:** a site and a cluster of nearby nodes behave
    alike.
*   **Topology, not trust:** no new keys, roles, or TRCs.

## Considered options

To divide the work between the path and link policies:

*   **Each policy on its own, as today:** the link policy reads one line
    both ways, on the readings it has.
*   **A retirement line below promotion's:** a fixed gap between the lines,
    or one that widens while a pair's readings vary.
*   **One line, retirement on longer history:** promotion and retirement
    share the line, and retirement reads further back.
*   **Layered policies:** the path policy reacts and the link policy
    settles; lines price costs, and confidence answers noise.

To follow the network's groups:

*   **Flat, as today:** the cap bounds each node's links.
*   **Regions the operator declares.**
*   **SCION's own hierarchy:** each group an ISD, or one multi-node AS.
*   **Groups by a fixed rule:** each node's first tier, the components of
    mutual first tiers, or a bound on round trips.
*   **k-means or k-medoids** over the round trips.
*   **Natural clusters:** groups far closer inside than to anything
    outside, by a gap that a budget on round trips sets.

## Decision outcome

Chosen options: **layered policies**, and beneath the links, **natural
clusters**, on these principles:

1.  **Paths react; links settle; clusters hold still.** The path policy
    answers what changes within its horizon: a path that stops delivering,
    a route that grows dearer than another. The link policy acts only where
    choosing among the routes there are cannot help: a better route that no
    link offers yet, a peer or an independent route that no other link
    provides, a link that no route the path policy would choose crosses. It
    acts on conditions that outlast the path policy's answer, never in its
    place. A link that falls behind needs no prompt retirement: the path
    policy stops choosing its routes first. Clusters act beneath the links,
    on what neither policy can change: the costs that grow with the
    network. A change of membership reshapes links, which reshape paths, so
    it waits for the most confidence of all.
2.  **A link is worth the routes it gives the path policy.** A link's worth
    is what the paths would lose without it: a peer it alone reaches, a
    route it alone keeps independent, a route cheaper than every route that
    avoids it. However small the lead, the path policy may pick the link's
    route, and losing the link moves every lease on it, which the band
    exists to spare. A link whose routes the path policy would not choose
    is worth nothing, however fast its own round trip.
3.  **The link policy buys no finer than the path policy moves.** A lease
    moves to a cheaper route only when it leads by the band, so a link
    whose lead the band absorbs would not move the leases it was bought
    for. A candidate earns a link only for a gain the path policy would move
    a lease for.
4.  **Buying costs more than keeping.** Buying a link reshapes every node's
    segments and takes a slot; keeping it costs its upkeep alone. The line
    to buy lies above the line to keep, at every price, and a pair between
    them keeps what it has, linked or not. A promotion's evidence carries
    room for its error, so that retirement never undoes a promotion that
    noise made: a link bought on evidence that erred stays rather than
    cycling.
5.  **Lines price; history decides.** Each line the link policy draws
    states a cost or a worth: the path policy's band, which a purchase must
    clear, and what a link costs to buy and to keep. No line widens to
    absorb noise. Noise meets evidence instead: the readings ADR-0038
    defines, and the confidence each decision demands of them, which grows
    with the history kept. Each decision is as confident as being wrong
    costs:
    *   **A retirement waits for confidence:** the reading shows the link's
        worth below the line to keep, and the history confirms, with high
        confidence, that it has stayed there. History alone lags a change,
        so a link that has just improved keeps its place on its reading.
        Meanwhile the path policy serves around the link, and a wrong
        retirement costs two reshapes and the wait for the promotion that
        undoes it.
    *   **A promotion acts on the reading at its horizon, or on
        confidence.** The path policy cannot take a route that no link
        offers, so each window of delay costs the paths. A gain the reading
        alone shows must clear what the path policy moves for with room for
        the reading's error. A gain the history confirms, with the
        confidence a retirement demands, needs no room beyond it: the
        confidence holds the error. Either way, the stable state keeps a
        link that the evidence bought in error.
    *   **Declarations decide nothing:** declared delays, and readings too
        thin to tolerate a high sample, rank the routes to measure.
6.  **Scarcity is priced at the cap.** Below the cap, a link that serves
    stays. At the cap, a candidate that earns a link displaces the link
    worth least among those that would not earn their place today, and
    waits when every link would. A displacement is a retirement, so it
    waits for the same confidence: a link whose worth noise holds near the
    line to buy keeps its slot.
7.  **A cluster is natural, and its cost is known before it forms.** Its
    members lie closer to one another than to any node outside, by a gap:
    its separation is a multiple of its diameter. Joined directly through
    their clusters' closest members, two nodes in different clusters travel
    at most the two diameters beyond their round trip, so the gap bounds the
    share of its round trip that clustering adds to any pair. The budget
    for that share is the link policy's line to buy on the readings:
    clustering never lengthens a pair's round trip by what a reading alone
    would buy a link for. The transits it adds are its price, charged as
    every transit is. The bound covers that route alone, so every node also
    predicts each pair's round trip exactly, from the round trips the
    directory publishes, before a clustering takes effect, and a cluster
    whose pairs the prediction puts beyond the budget splits. A node in no
    cluster stands alone, so a network without groups stays flat.
8.  **Forming costs more than keeping.** Every node computes the clusters
    from the round trips the directory publishes, by one rule that reads no
    clock and no order of arrival, so nodes that hold the same entries
    agree. A cluster forms once its gap holds with the confidence of
    principle 5, stays while the prediction keeps its pairs within the
    budget, and dissolves only once the history confirms the budget broken.
    Between the gap and the budget lies the stable state, as between the
    lines to buy and to keep. Of nested clusters, the one that stands out
    most stands, for noise moves it least.
9.  **Inside a cluster, the flat design holds; between clusters, the link
    policy runs over clusters.** Members are each other's candidates,
    measure each other, and link by worth as principles 2 to 6 have it.
    Between two clusters, a link is worth what it changes in the routes
    between them, a cluster with one route to the rest buys a second, and a
    stranded cluster links at once. Each such link runs between the members
    the round trips choose for that pair of clusters, beside a second
    between other members, so that no member's failure separates them: a
    cluster meets each other cluster through the members nearest it, and its
    links to different clusters may sit on different members. Outside its
    cluster, a node links only as one of those members. Beacons carry the
    routes over each link into a cluster on to all its members, so a path
    between two clusters can start at any member. The path policy prices as
    it does, charging every member a path crosses, so forming links and
    serving traffic still price a route the same way (ADR-0035).
10. **A cluster is a scope chosen by distance, one level deep.** Its
    members share a directory of their own, as a site's do. Outside, the
    cluster shows only the members that hold its links to other clusters,
    and through them its round trips and its membership; its other members
    publish no entry outside, are no candidates for nodes outside, and are
    reached over paths through those members. A site is a cluster and meets
    the network the same way. Clusters group into no larger clusters; a
    later decision nests them if they grow too many to treat flat.

The lines, the confidence, the history each decision reads, and the rule
that computes clusters are the proposals' to set, each from the principle it
serves. This amends ADR-0017's decision 2, under which one test served both
directions: promotion and retirement keep one comparator, the link's worth,
but read it against two lines with different confidence. It amends
ADR-0017's decisions 5 and 7 as well: the cap's victim no longer needs to
qualify for retirement, only to fall short of the line to buy. It replaces
ADR-0026's ratio pair (decision 3). ADR-0038's readings remain the evidence,
and the records keep the longer history that confidence reads. The clusters
narrow ADR-0017's decision 1, so that a node's candidates are its cluster's
members and the far ends of the links between clusters it holds; ADR-0032's
decision 5, under which scopes follow addresses alone; ADR-0036's decision
4, so that a node's beacons also cover each link into its cluster; and
ADR-0037's decision 1, so that an entry reports the round trips of its own
scope.

### Positive consequences

*   Noise near a line moves no link: a pair between the lines keeps its
    state, a retirement needs lasting evidence, and the path policy serves
    while the evidence gathers.
*   Each threshold traces to a cost or a worth the system defines, so a
    change to the path policy's band, or to what a link costs, carries
    through to the lines.
*   A link that nothing chooses still goes, and a route that beats the
    others by what a link costs still gets its link.
*   A gain the history confirms buys its link once the path policy would
    move for it, however small beside the price: a long path whose gain
    falls short of a reading's room for error still gets the link.
*   A node's probes and directory grow with its cluster and the number of
    clusters, and its links follow the structure: dense inside a cluster,
    few between. The cap binds less.
*   What a cluster costs any pair is bounded before it forms, and every
    node predicts it exactly.
*   A network without groups loses nothing: no cluster forms, and it stays
    flat.

### Negative consequences

*   A link that fell behind keeps its slot and its upkeep until the history
    convinces, though its traffic has moved.
*   More links: a link that would not be bought today stays while it
    serves, and confirmed gains buy links that a reading alone would not,
    so a node's links grow toward the cap.
*   Decisions read further back than the readings do, so each peer and
    route keeps more history.
*   Paths between clusters cross the members that hold the links between
    them, and their round trips grow by up to the budget.
*   A node no longer measures other clusters' members, so a pair across
    clusters closer than their clusters' links can go unnoticed until the
    clusters' round trips show it.
*   Clusters are a shared computation over the directory: nodes whose views
    differ disagree on membership until the entries meet, and the
    confidence slows every change of membership.
*   A node's place moves between scopes as it joins and leaves a cluster:
    its entry outside appears and withdraws, and its links change scope.
*   A member forwards to its fellow members, and registers, a route over
    each link into its cluster, so beaconing grows with the links between
    clusters.
*   One more layer to reason about: clusters, links, paths.
*   The labs weigh little of this: their delays hold steadier than the
    Internet's, their caps never bind, and they hold three to nine nodes.
    The principles rest on reasoning; the labs show how a realization's
    rules interact.

## Pros and cons of the options

### Each policy on its own, as today

*   Good, because one line serves both directions, and a link that falls
    behind leaves within minutes.
*   Bad, because no pair is stable: noise across the line promotes and
    retires.
*   Bad, because the link policy repeats the path policy's answer, at the
    cost of a reshape.

### A retirement line below promotion's

*   Good, because it opens a stable state.
*   Bad, because a link that helps by less than the gap retires though the
    path policy picks its routes, and the gap marks no cost the system
    defines.
*   Bad, because a gap that widens with noise mixes the evidence's error
    into the line: a noisy link that helps retires, where more history
    would show its worth.

### One line, retirement on longer history

*   Good, because history absorbs the noise without a second line.
*   Bad, because a pair whose worth sits just below the line promotes on a
    lucky reading and retires once the longer history shows it, so its link
    cycles, slower but still.
*   Bad, because the one line prices buying a link, never keeping one.

### Layered policies

*   Good, because each policy acts on what it can judge, each line has a
    reason, and noise meets confidence rather than a wider line.
*   Bad, because retirement slows, links grow toward the cap, and history
    grows.

### Flat, as today

*   Good, because every pair is judged on its own, and paths run nearest to
    the best.
*   Bad, because probes and the directory grow with the square of the
    network, and links fill every node's cap.

### Regions the operator declares

*   Good, because the operator knows the facilities.
*   Bad, because ADR-0017 derives the topology from measurements, and a
    declared region goes stale as the network moves.

### SCION's own hierarchy

*   Good, because SCION routes ISDs and ASes as units already.
*   Bad, because an ISD is a trust domain with its own TRC, and a multi-node
    AS breaks one node per AS: both reach into trust and identity to solve a
    topology problem.

### Groups by a fixed rule

*   Good, because each node holds its first tier already, and a bound is
    one number everywhere.
*   Bad, because tiers are local labels that two nodes may draw differently,
    the components of mutual first tiers chain across an even spread, and no
    bound fits every scale.

### k-means or k-medoids

*   Good, because they are standard, and k-medoids reads distances alone.
*   Bad, because k-means needs coordinates that round trips do not give,
    both need k and return k clusters even where the network has none, and
    the distance to a center bounds nothing that a pair across a boundary
    pays.

### Natural clusters

*   Good, because the gap needs no scale and no k, bounds what a cluster
    costs before it forms, and finds no cluster where no group stands
    apart.
*   Bad, because it reads the round trips of the whole directory, and a
    cluster near its gap holds still only by the confidence it waits for.
