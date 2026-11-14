# Grow Capacity Between Nodes Under Load

*   Status: proposed
*   Date: 2026-11-13

[TOC]

## Context and problem statement

What runs out first at a CION node is its uplink: a home connection's upload,
or a VPS's share of its host's. The node knows neither rate, and both vary
over the day.

Nothing in CION measures bandwidth or reacts to load:

*   **The queue that fills is outside the node.** A node sends as fast as its
    sockets accept, and the backlog an uplink cannot carry builds beyond it,
    in the router or the provider's buffer. That buffer drops CION's packets
    rather than marking them: they carry no ECN.
*   **The hosts cannot see a node's marks.** Their transports slow on the
    drops at that buffer, but a mark in the SCION header never reaches them:
    the nodes' mesh runs WireGuard over SCION, and wireguard-go carries no ECN
    across its encryption. Not every host negotiates ECN, and some traffic
    reacts to nothing.
*   **Load reads as poor quality.** A loaded link's queue raises the round
    trips its probes meet, and with them the readings
    [ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md)
    defines: the link's price, the delay its beacons declare, and the price of
    every route across it. The path policy moving leases off a dear route
    relieves it, but the link policy and the beacon policy read the same
    prices, so they can retire the link the demand needs, or stop announcing
    its routes: the capacity between two nodes shrinks where their traffic
    needs more.

The measured topology also crowds onto the node least able to carry it: one
with short round trips and a thin uplink. Its round trips beat many prices,
so peers promote links to it, its routes rank cheapest in beacons and leases,
and as its cluster's nearest member it holds the links toward other clusters
([ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md),
principle 9). The cap of eight links
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
decision 1) bounds how many links reach such a node, not the transit they
carry.

The data-plane draft carries ECN in the traffic class of the SCION header
(Section 2.1) and leaves congestion to the endpoints, which switch to another
path (Sections 7.3 and 7.4). It defines no congestion signal between ASes;
the nearest precedent, ICMP's source quench, was deprecated as ineffective
(RFC 6633).

How should the network let the capacity between two nodes grow with the load
between them, when no node knows its uplink's rate?

## Decision drivers

*   **Capacity follows lasting load:** under load that lasts between two
    nodes, the capacity between them grows, first over the paths there are,
    then by new links; load alone never removes a path or a link.
*   **The uplink's rate is unknown and moving:** nothing is configured, and
    no estimate holds for long.
*   **Nodes cooperate:** every node reacts to the signal and slows what it
    sends. A node that does not is a fault, rare and most likely a bug, for a
    breaker to cut off rather than flow control to police.
*   **Measured, not declared:** no node publishes its load; others learn it
    from what their own packets meet (ADR-0017; ADR-0039, principle 5).
*   **Sources choose paths:** a transit can only mark, delay, or drop packets,
    and choose what it beacons and which links it admits; the senders move
    (data-plane draft, Section 7.4).
*   **Each reaction at its own pace:** a slower reaction acts only on what the
    faster ones could not settle, so they do not fight, and the senders
    crossing a hot node leave it over time, not at once.
*   **Standard, with few moving parts:** ECN where the data-plane draft
    carries it, and end-to-end rate control as DCTCP runs it; no rate to
    configure.

## Considered options

For the whole:

*   **Latency alone, as today.**
*   **A configured bandwidth** for each node, which the data plane shapes to.
*   **Published load:** each node declares its headroom in its directory
    entry or its beacons, and others weigh it, as Tor weighs relays.
*   **Hop-by-hop flow control:** a node pauses, or grants credit to, the
    neighbors sending to it, as Ethernet's priority flow control and
    InfiniBand's credits do.
*   **Reservations,** as SCION's COLIBRI proposes.
*   **The hosts react:** each node marks its queue, and the WireGuard gateway
    carries the marks into the hosts' packets (RFC 6040), so their transports
    slow.
*   **Detect, signal, and react:** each node detects the load on its own
    links, signals it to the senders whose traffic crosses them, and the
    network reacts in stages: the senders slow, their leases move, and the
    topology grows.

To detect the load at a link:

*   **A shaper at each uplink:** each node shapes its egress to a rate it
    learns from the round trips to its neighbors, puts its own traffic first,
    and marks its own queue.
*   **A brake at each link, read from stamps:** every node a path probe
    crosses writes into the reply when it passed the probe, the node before
    it reads the one-way delay of the link between them, and a link brakes
    while its forward delay stands over a target.
*   **A brake at each link, read from echoes to the next hop:** each node
    echoes the neighbor across each link as the link's traffic flows, and a
    link brakes while its round trips stand over their least or go
    unanswered.

To signal the load to the senders:

*   **The destination echoes the marks:** the receiving end of each link
    marks the packets that crossed a queue, and the destination returns the
    marks to their source on the packets it sends back: TCP's ECN loop, with
    the nodes as its ends.
*   **The node that holds the excess marks what returns:** a node marks the
    packets that come back over a link whose queue in the node holds data, as
    Frame Relay's backward notification and ATM's ABR service did.

## Decision outcome

Chosen options: **detect, signal, and react**, detecting with **a brake at
each link, read from echoes to the next hop**, and signaling as **the node
that holds the excess marks what returns**, realized as follows:

1.  **The capacity between two nodes grows under lasting load.** While a
    load is new, the network keeps the links it crosses under their limits
    and spreads it over the paths there are; where it lasts, the network adds
    paths and links. A path or link that reads poorly only because it is
    loaded is one the demand needs, so load alone never removes one. Three
    stages serve this goal: detection finds the load at each link it
    crosses, the signal carries it to the senders whose traffic crosses
    there, and the reactions spread the load and grow the capacity, each at
    its own pace.
2.  **Detect: each node finds its links' limits and keeps under them.**
    *   **The brake** finds each link's limit and keeps the link under it. It
        echoes the neighbor across the link as the link's traffic flows, reads
        the queue beyond the node from the round trips against the least the
        link has shown and from the echoes lost, and while that queue stands or
        loses, holds the link's data to what the line beyond carries. The excess
        waits or drops in the node, where the node can measure it, mark it, and
        drop data before control. The brake's goal is the limit, not a short
        delay: delay is what it reads. A brake stands only while its link needs
        it, and each link brakes on its own reading, so a queue past one
        neighbor slows only the link toward it.
    *   **The probes** measure each path a source's traffic rides, end to
        end, as
        [ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md),
        decision 6, has them, and carry ECN as data does.
3.  **Signal: every sender whose traffic crosses a held queue learns of it, as
    fast as its traffic returns.** While a link's queue in the node holds data,
    the node sets CE in the SCION header of the packets that come back over that
    link, as large a share of them as the queue is full. A packet that comes
    back over a link most often answers traffic that left by it, and a reply
    always does, so the marks reach each source at the pace of its own returning
    traffic, and the probes' replies carry them where no traffic returns. One
    hot node marks every path through it, so the paths crossing it read hot
    before their round trips rise. Every packet the nodes' sockets send carries
    ECT(0), the codepoint of RFC 3168; only nodes read these bits, as no host
    sees a SCION header. No node publishes its load.
4.  **React: in three stages, each slower than the one before.**

    | Stage  | Who                    | Pace             | Goal                                             |
    | :----- | :--------------------- | :--------------- | :----------------------------------------------- |
    | Fast   | The brake, each source | Seconds          | Keep each line under its limit, still delivering |
    | Medium | Each source's leases   | Tens of seconds  | Spread the load over the paths there are         |
    | Slow   | The link policy        | Minutes and more | Add links where load lasts, and cut none for it  |

    *   **Fast.** The brake holds the excess at once. Each source slows its
        traffic to a destination as marks reach it, and speeds up again once
        they stop; a stray mark slows it little, so the brake takes a load's
        first strain. The excess drops at its source, whatever transport sent
        it.
    *   **Medium.** A lease on a hot path moves to the best healthy path that
        is not hot, after a hold drawn at random, so the leases crossing one
        hot node leave it over time; a hot path takes no new lease while
        another serves. Leases still move as round trips rise, as ADR-0035
        has them, and return only by its margin, once the path cools.
    *   **Slow.** A node whose traffic to a destination stays hot on every
        path to it, longer than the path policy takes to answer, buys a link
        that opens a route around the hot hops, announced and staggered as
        [ADR-0037](/docs/adrs/0037-coordinate-link-changes-through-the-node-directory.md)
        has every promotion. A link that carried traffic leaves only after a
        drain: its leases move off it, and it retires once the paths that
        took them stay cool through the load it served, or stays if one
        turns hot. A hot node keeps its links and its routes.

    The stages hand the load on. The marks report the brake's queue, and are the
    only load signal between nodes. Each stage reads them over its own horizon:
    a source each mark, a lease a path that stays hot, the link policy heat that
    outlasts the path policy's answer. Each stage that settles the load removes
    what the slower ones would read: the sources' cuts empty the brake's queue
    and the marks stop, the leases that leave a hot node cool it, and a new link
    spreads the load.
5.  **Prices stay unloaded.** The readings the link policy and the beacon
    policy decide by take only the samples taken while cool: a sample whose
    reply came back marked, or taken across a link while its brake held data
    back, counts for nothing, and a reading with no cool sample keeps its
    last value. Load then moves leases, which is the path policy's work, and
    never retires a link or withdraws a route.

This narrows
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 6,
so that the probes carry ECN, and its decision 5, so that a hot path repels
the leases on it. It narrows
[ADR-0038](/docs/adrs/0038-read-round-trips-at-their-80th-percentile-over-five-minutes.md)'s
decision 3, so that readings take cool samples alone. It extends ADR-0039's
principle 2, so that a link is also worth the capacity it adds, and its
principle 5, so that a link that carried traffic retires on a drain. The cap
on a node's links stays as ADR-0017 and ADR-0039 set it.

### Positive consequences

*   The capacity between two nodes grows under lasting load, and load alone
    never shrinks it.
*   Each line stays under its limit with no rate configured, and the excess
    waits or drops in the node, data before control.
*   The marks ride the traffic: the busier a source's traffic, the sooner it
    learns, and one hot node flags every path through it.
*   Every flow is held, whatever its transport: the node reacts for its
    hosts, so a host that ignores ECN, or loss, slows too.
*   No bandwidth is configured and no load published.
*   The stages do not fight: transit leaves a hot node over time, returns as
    it cools, and only load that lasts reshapes the links.
*   A link leaves only once its traffic has fit elsewhere, at the load it
    served, so a busy hour neither prices links nor retires one bought for
    it.

### Negative consequences

*   A brake finds its link's limit only by passing it: each time its rate
    climbs past the limit, the line beyond drops a little before the brake
    cuts.
*   A round trip mixes a link's two directions: a queue on the way back
    brakes the link's traffic forward too, until the far end's brake holds
    its own queue.
*   Echoes cost: a busy link is echoed several times a second, and its
    neighbor answers each.
*   Marks on returning traffic are exact only where that traffic rides the
    reverse of the path it answers; other traffic hears through the probes'
    replies alone.
*   The control class skips the brake's wait, counted against its rate: a
    burst of control traffic still queues at the line.
*   A route that stays hot gives the link policy no fresh reading until it
    cools.
*   Capacity is bought on marks, not on a measured headroom: the route a new
    link opens may prove hot too, and leaves by its own drain.
*   A drain that fails moves its leases twice, and a link that served is held
    through its drain, its upkeep paid meanwhile.
*   A node that does not slow goes unchecked until a breaker stands.

## Pros and cons of the options

### Latency alone, as today

*   Good, because it needs nothing new.
*   Bad, because load reads as poor quality, so the link policy can retire,
    and the beacon policy drop, the links and routes the demand needs. The
    buffer that fills marks nothing, and the hosts learn of it only as it
    drops.

### A configured bandwidth

*   Good, because shaping to a known rate is simple and exact.
*   Bad, because the rate moves, and a configured one is wrong most of the
    time and asks the operator for what the node can measure.

### Published load

*   Good, because others can avoid a loaded node before they meet it.
*   Bad, because a declaration lags, invites every sender to the node
    declared freest, and decides on what no one measured (ADR-0039,
    principle 5).

### Hop-by-hop flow control

*   Good, because a neighbor stops sending before the queue overflows, and
    bursts lose nothing.
*   Bad, because over a wide-area round trip a pause needs a bandwidth-delay
    product of headroom per link, stalls flows that could have moved,
    deadlocks where dependencies form a cycle, and hands a neighbor a lever
    to stall the node. Datacenters keep pauses rare by end-to-end rate
    control, the role the sources' rates and path choice play here.

### Reservations

*   Good, because a reserved flow is guaranteed its rate.
*   Bad, because admission, keys, and policing at every node exceed what
    CION's scale needs, and no draft specifies them.

### The hosts react

*   Good, because the hosts already run congestion control, and ECN spares
    them the drops.
*   Bad, because the mesh's WireGuard carries no ECN across its encryption,
    not every host negotiates ECN, and some traffic reacts to nothing.

### Detect, signal, and react

*   Good, because each stage does what its horizon allows: the node that
    sees a queue holds it at once, the senders slow and move within the path
    policy's horizon, and only load that lasts reshapes the links, which no
    single reaction could do alone.
*   Bad, because three reactions must be kept apart by their pace, and a
    line meets a few seconds of overload while the fast stage finds its
    limit.

### A shaper at each uplink

*   Good, because the node holds its queue, so it can put its own traffic
    first and drop what does not slow before the uplink.
*   Bad, because its rate estimates a moving uplink, and the hub lab found
    that hard. Learning from the round trips to its neighbors, the shaper
    read its own queue as the uplink's and sat at its floor rate through the
    load: the hub's own traffic lost nearly three quarters of its packets.

### A brake at each link, read from stamps

*   Good, because each link is read one way, so a queue counts only against
    the traffic that crosses it.
*   Bad, because it takes SCMP types no specification assigns, every node a
    probe crosses must keep records and stamp truly, and the readings drift
    with the two ends' clocks until each link's least is relearned.

### A brake at each link, read from echoes to the next hop

*   Good, because it needs nothing new on the wire or of any other node: a
    standard echo, answered by the neighbor's responder and timed by the
    node alone. The echoes skip the node's own queue, so unlike the shaper
    the brake never reads its own wait as the line's, and they follow the
    link's traffic, so the busier the link, the more often it is read.
*   Bad, because a round trip mixes the link's two directions, and the echoes
    cost a share of the link.

### The destination echoes the marks

*   Good, because it is TCP's ECN loop with the nodes as its ends: standard,
    holding every flow whatever its transport, and returning every congested
    hop in one echo.
*   Bad, because it orders nothing, an echo waits for a packet going back,
    and a link reads its queue only as often as BFD beats. Built and run in
    the hub lab, it left the uplink's wait about where latency alone left
    it, and its sources' repeated cuts sank the hub's own traffic to two
    thirds of what it carried without them.

### The node that holds the excess marks what returns

*   Good, because the node that holds the queue tells the senders itself,
    from a fill it knows exactly, at the pace their own traffic returns, with
    nothing to wait for at the destination.
*   Bad, because a mark is exact only where the returning traffic rides the
    reverse of the path it answers, and a sender whose traffic sees no return
    hears only through its probes' replies.
