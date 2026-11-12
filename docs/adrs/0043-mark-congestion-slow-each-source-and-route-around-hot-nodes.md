# Mark Congestion, Slow Each Source, and Route Around Hot Nodes

*   Status: proposed
*   Date: 2026-11-13

[TOC]

## Context and problem statement

What runs out first at a CION node is its uplink: a home connection's upload,
or a VPS's share of its host's. The node knows neither rate, and both vary
over the day.

Nothing in CION measures bandwidth or reacts to load:

*   **The queue that fills is outside the node.** A node sends as fast as its
    sockets accept. Each link's egress is a first-in, first-out queue of 64
    packets behind the control class
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md),
    decision 8), and the backlog an uplink cannot carry builds beyond it, in
    the router or the provider's buffer. That buffer drops CION's packets
    rather than marking them: they carry no ECN.
*   **The hosts cannot see a node's marks.** Their transports slow on the
    drops at that buffer, but a mark in the SCION header never reaches
    them: the nodes' mesh runs WireGuard over SCION, and wireguard-go
    carries no ECN across its encryption. Not every host negotiates ECN,
    and some traffic reacts to nothing.
*   **Paths weigh no load.** ADR-0035 judges paths by round trip and loss,
    and left load to a later decision, after a lab with links of unequal
    capacity.

The measured topology crowds onto the node least able to carry it: one with
short round trips and a thin uplink. Its round trips beat many prices, so
peers promote links to it; its routes rank cheapest in beacons and leases;
and as its cluster's nearest member, it holds the links toward other
clusters
([ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md),
principle 9). The cap of eight links
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
decision 1) bounds how many links reach such a node, not the transit they
carry, and raising the cap waits for a protection that bounds load itself.

The data-plane draft carries ECN in the traffic class of the SCION header
(Section 2.1) and leaves congestion to the endpoints, which switch to another
path (Sections 7.3 and 7.4). It defines no congestion signal between ASes;
the nearest precedent, ICMP's source quench, was deprecated as ineffective
(RFC 6633).

How should a node keep its uplink from overloading without knowing its rate,
and how should the senders whose paths cross it learn of it and react?

## Decision drivers

*   **The uplink's rate is unknown and moving:** nothing is configured, and
    no estimate holds for long.
*   **Nodes cooperate:** every node reacts to the signal and slows what it
    sends. A node that does not is a fault, rare and most likely a bug, for
    a breaker to cut off rather than flow control to police.
*   **Measured, not declared:** no node publishes its load; others learn it
    from what their own packets meet (ADR-0017; ADR-0039, principle 5).
*   **Sources choose paths:** a transit can only mark, delay, or drop
    packets, and choose what it beacons and which links it admits; the
    senders move (data-plane draft, Section 7.4).
*   **No stampede:** the senders crossing a hot node leave it over time, not
    at once, and do not all return when it cools.
*   **Links follow lasting demand:** the links carry the demand that lasts;
    a link is bought for what the network offers or for demand that outlasts
    the path policy's answer, and goes once its traffic fits elsewhere
    (ADR-0039, principle 1).
*   **Standard, with few moving parts:** ECN where the data-plane draft
    carries it, and congestion control end to end as DCTCP runs it; no rate
    to configure, and no packet sent for the signal beyond the path probes.
*   **Judged where bandwidth is scarce:** a lab with links of unequal and
    varying capacity.

## Considered options

*   **Latency alone, as today.**
*   **A configured bandwidth** for each node, which the data plane shapes to.
*   **Published load:** each node declares its headroom in its directory
    entry or its beacons, and others weigh it, as Tor weighs relays.
*   **Hop-by-hop flow control:** a node pauses, or grants credit to, the
    neighbors sending to it, as Ethernet's priority flow control and
    InfiniBand's credits do.
*   **Reservations,** as SCION's COLIBRI proposes.
*   **A shaper at each uplink:** each node shapes its egress to a rate it
    learns from the round trips to its neighbors, puts its own traffic
    first, and marks its own queue.
*   **A brake at each link:** a node limits a link's egress while that link
    reads congested, and lets go once it reads clean.
*   **The hosts react:** each node marks its queue, and the WireGuard
    gateway carries the marks into the hosts' packets (RFC 6040), so their
    transports slow.
*   **The probes measure each hop, the sources slow:** every node a path
    probe crosses keeps when it passed, writes its times into the reply on
    the way back, and reads from the times of the node after it the one-way
    delay of the link between them; a node marks the replies that cross a
    congested link, as Frame Relay's backward notification and ATM's ABR
    service did, and each source slows on the marks in its own probes'
    replies.
*   **The destination echoes, the sources slow:** the receiving end of each
    link marks the packets that crossed a queue, the destination returns
    the marks to their source on the packets it sends back, and each source
    slows its own traffic: TCP's ECN loop, with the nodes as its ends.

## Decision outcome

Chosen option: **the probes measure each hop, the sources slow**, with **a
brake at each link**, realized as follows:

1.  **Probes measure each hop.** The ping application
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md),
    decision 6) probes the path each destination's traffic rides with an
    SCMP informational message of CION's own, answered by another, beside
    the echoes it keeps for health. Every node the probe crosses keeps a
    record of when it passed the probe on. As the reply passes back, each
    node writes into it when it passed the probe and when it passes the
    reply. From those times and its own, the node before it reads the
    one-way delay of the link between them, each way, and keeps how far each
    stands over the least it has seen, in which the two ends' clocks cancel.
    A probe that does not return counts for nothing: its loss is the path's
    health, not its load.
2.  **A node marks the replies whose link's queue stands.** While a link's
    egress queue in the node holds packets, the node sets CE in the SCION
    header of the replies passing back over that link, as large a share of
    them as the queue is full. The marks keep the queue from filling, not
    its wait short: the fuller it gets, the more the sources slow, before it
    drops. The queue fills only while the link's brake holds it (decision
    10), and the node knows its size, so no clock, jitter, or buffer beyond
    the node enters a mark. Every packet a node sends into the network
    carries ECT(0), the codepoint of RFC 3168; only nodes read these bits,
    as no host sees a SCION header. The marks come back once per probe
    rather than once per packet, so ECT(1) and the scalable response RFC
    9331 asks of its senders do not fit. Copying in the marks the underlay's
    routers set in the outer IP header (RFC 6040), and choosing what
    codepoint to show them, is a later step.
3.  **Each source slows on the marks in its own probes' replies.** A node
    keeps a rate for each destination node, unset until a reply to one of
    its probes comes back marked. As DCTCP does, it averages the share of
    its replies that come back marked, cuts the rate by half that share at
    most once per probe sent after the last cut, and raises it slowly while
    the replies come back clean. The average starts at none and moves with
    every reply, so a stray mark cuts little: the brake, not the sources,
    takes a load's first strain. The excess waits briefly or drops at the
    node, whatever transport sent it. The control class is not paced. A
    source probes the path its traffic rides in proportion to that traffic,
    so the loop runs at the traffic's pace, and the node's own traffic
    answers only its own probes, as every source's does.
4.  **Probes carry ECN.** The probes are ECN-capable as data is, so a reply
    returns marked if any link its probe crossed is congested. Beside the
    paths in use, the ping application probes a random sample of each
    destination's other paths, as Prequal samples servers by probe rather
    than by their reports. A path whose replies return marked, or whose
    queueing delay passes a line, is hot. Health stays as ADR-0035 judges
    it.
5.  **Leases leave hot paths gradually and return by the margin.** A lease
    on a hot path moves to the fastest healthy path that is not hot, after a
    hold drawn at random, so the leases crossing one hot node leave it over
    time; a hot path takes no new lease while another serves. A lease
    returns to a path only by the margin ADR-0035 sets (decision 5), and
    only once the path has cooled. A destination with no other path leaves
    the slowing to its source.
6.  **A node that stays hot sheds transit, and takes it back slowly.** Its
    link policy admits no new link, and its beacon policy
    ([ADR-0042](/docs/adrs/0042-file-the-beacon-policy-as-a-module.md))
    cuts the transit routes it carries while the node stays hot, and
    restores them one at a time, far apart, while it stays cool; a route
    restored that heats the node again goes at once. It never sheds its own
    routes nor a receiver's last. Both read the node's readings of its own
    links, which no other node is told.
7.  **Prices stay unloaded; lasting shortage buys capacity.** The link
    policy reads only the probes that return cool, so the readings ADR-0038
    defines carry no more queueing than a cool path holds, and no busy hour
    moves a price; a route that stays hot gives it no reading until it
    cools, and the decisions that need one wait. Capacity is a worth of its
    own, beside the peers and the independent routes a link gives (ADR-0039,
    principle 2): a node whose probes to a destination keep returning
    marked while every path to it is hot, for longer than the path policy
    takes to answer, buys a link that opens a route around the hot hops,
    announced and staggered as ADR-0037 has every promotion. Until the link
    stands, the flow has nowhere else to go, and its source slows on the
    marks.
8.  **A link that carries traffic leaves only after a drain.** Before
    retiring a link that a lease rode since its last drain, the node drains
    it: the link stays up, its leases move to other paths, and it takes no
    new ones. A drain lasts a day, the cycle most load repeats on, so it
    meets the busy hour whenever it starts. The link retires once the paths
    that took its traffic stay cool through the drain; if any turns hot, the
    drain ends, the link stays, and the next drain waits twice as long. A
    link no lease rode since its last drain is judged by its unloaded prices
    alone.
9.  **Load stays local.** No directory entry, tag, or beacon declares it;
    each node learns of another's load from the marks and delays its own
    probes meet.
10. **Each link brakes on its delay, and its queue marks.** A node limits a
    link's egress while the link's forward delay stands over a target. Its
    data plane holds the link's queue, a fixed number of packets, and one
    module rules both what leaves the queue and what its fill tells the
    sources (decision 2). The module drains the queue at a rate taken from
    what the link sent in the last second, cuts it each second the reading
    stays over, in proportion to how far over it stands, as Swift cuts its
    window, and releases it once the link has read clean for a second. The
    control class skips the queue but counts against the rate, and probes
    skip it too, so a link's reading never counts the brake's own wait. The
    reading takes the least of the link's last few delays, as LEDBAT filters
    its own, so jitter that leaves some probes fast reads as no queue; a
    step in the link's base delay, from a route's change or the clocks'
    drift, reads as queue until the least it is read against ages out.
    Under a steady load the marks hold the sources and the brake stands only
    until they do. Each link brakes on its own reading, so a queue past one
    neighbor slows only the link toward it. The brake and the marks are
    built together. Pause or credit between neighbors stays rejected, and a
    breaker for a node that does not slow waits for the lab.
11. **A lab with bandwidth judges it.** The fabric gains links with a
    bandwidth limit and a finite queue, their rate varying, and the labs'
    flows answer their senders as transports do. The labs show the queue at
    a thin, well-placed node's uplink staying short while its sources slow
    and transit moves off it. Before the brake is built, they gain the
    cases it changes: a queue past one neighbor, traffic moving between
    links, a node with one link, a path that crosses two queues, and jitter
    on a loaded link.

This is the later decision ADR-0035 left load to. It narrows that record's
decision 6, so that probes measure each hop and carry ECN, go in proportion
to the traffic a path carries rather than only where traffic leaves a gap,
and the link policy reads those that return cool; and its decision 5, so
that a hot path repels the leases on it. It extends ADR-0039's principle 2,
so that a link is also worth the capacity it adds, and its principle 5, so
that a link that carries traffic retires on a drain. The cap on a node's
links stays as ADR-0017 and ADR-0039 set it; raising it, with a cost for
keeping a link and beaconing that scales with links, is a decision of its
own, once this one stands in the lab.

### Positive consequences

*   The queue at a congested uplink stays short for all who cross it, with
    no rate to configure: the brake holds the excess in the node at once,
    and the sources slow as the marks come back.
*   Jitter that leaves some probes fast reads as no queue, and a step in a
    link's base delay reads as one only until its least ages out; the marks
    come only from the queue the brake fills.
*   Every flow is held, whatever its transport: the node reacts for its
    hosts, so a host that ignores ECN, or loss, slows too.
*   Congestion anywhere on a path reaches its source: every hop marks the
    same reply.
*   Each link is read one way: a queue on the way back slows only the
    traffic it holds, not the traffic crossing the link the other way.
*   Probes follow traffic, so the busier a link, the more often it is read
    and the faster its loop runs.
*   No bandwidth is configured and no load published: the marks ride the
    probes' replies.
*   A link's brake holds its queue in the node only until the marks catch
    up, slows only that link, and lets go once the link reads clean.
*   Transit leaves a hot node over time and returns as it cools.
*   Demand that outlasts the path policy's answer gets capacity: a link
    opens a route around a hot node, and stays while its traffic would not
    fit elsewhere.
*   A link leaves only once its traffic has fit elsewhere, at the load it
    served, so a busy hour neither prices links nor retires one bought for
    it.
*   A thin node stops being a hazard that only the cap contains.

### Negative consequences

*   Nothing is ordered while no brake stands: the node's own traffic and
    other nodes' control calls share the uplink's queue with transit,
    first-come, until the link's reading crosses the target.
*   Probes grow with traffic, each answered, and each costs work at every
    node it crosses.
*   Every node a probe crosses writes into its reply, and is trusted to
    write truly.
*   A link carrying little traffic is read only every few seconds: bursts
    outrun the brake and the marks.
*   A delay the brake cannot move, such as jitter that slows every probe,
    brakes the link to its floor until the reading clears.
*   The brake's queue is bounded in packets, not in wait, as the marks keep
    it from overflowing rather than short: 64 packets are half a second at
    1 Mbit/s.
*   The readings drift with the two ends' clocks until each link's least is
    relearned.
*   A path that crosses two queues is marked at both, and slows more than
    either would ask alone.
*   A node that does not slow goes unchecked until a breaker stands.
*   The probe and its reply take SCMP types no specification assigns, which
    scionproto sets aside for experiments; a wider deployment needs types
    assigned.
*   Probes spend more of the prober's budget, sampling paths no lease rides.
*   A route that stays hot leaves the link policy without a reading of it
    until it cools.
*   Capacity is bought on marks, not on a measured headroom: the route a new
    link opens may prove hot too, and leaves by its own drain.
*   A drain that fails moves its leases twice, a handshake for each of their
    connections each way.
*   A link that served is held through a day's drain before it retires, its
    upkeep paid meanwhile.

## Pros and cons of the options

### Latency alone, as today

*   Good, because it needs nothing new.
*   Bad, because the buffer that fills marks nothing: paths learn of it only
    as their round trips rise and hosts only as it drops, and a node whose
    processor is the bottleneck never shows.

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

### A shaper at each uplink

*   Good, because the node holds its queue, so it can put its own traffic
    first and drop what does not slow before the uplink.
*   Bad, because its rate estimates a moving uplink, and the hub lab found
    that hard. Learning from the round trips to its neighbors, the shaper
    read its own queue as the uplink's and sat at its floor rate through the
    load: the hub's own traffic lost nearly three quarters of its packets.
    Timed beneath its queue, it halved the median delay of the hub's own
    traffic, but its rate overshot between rises and the buffer still
    filled.

### A brake at each link

*   Good, because the node holds a link's queue only while the marks have
    not caught up, so the control class skips it when it matters most, a
    queue past one neighbor slows only the link toward it, and a limit
    never outlives its load. Its reading comes from probes that skip the
    queue, so unlike the shaper it never reads its own wait as the uplink's,
    and its queue gives the marks a measure the node knows exactly.
*   Bad, because each link brakes on its own reading: while brakes stand,
    the uplink splits by link rather than by flow, and a path that crosses
    two queues brakes at both. One rate for all a node's links would split
    by flow, but it needs the uplink's wait told apart from a neighbor's,
    which probes as sparse as these read at different moments.

### The hosts react

*   Good, because the hosts already run congestion control, and ECN spares
    them the drops.
*   Bad, because the mesh's WireGuard carries no ECN across its encryption,
    not every host negotiates ECN, and some traffic reacts to nothing.

### The probes measure each hop, the sources slow

*   Good, because the node that sees the congestion tells the sources
    itself, nothing waits for a packet going back, each link is read one
    way so a queue counts only against the traffic that crosses it, and
    the loop runs as fast as the traffic it holds.
*   Bad, because the loop runs at the probes' pace, each probe costs work at
    every node it crosses, and every node must be trusted to stamp truly.
    Marked from the delays themselves, without the brake, it misjudged both
    labs. On the hub's 1 Mbit/s uplink, whose queue stood over the target
    while the load fit, the sources cut flows the line carried: the hub's
    own flow kept a third to two thirds of its traffic under load. With the
    cuts in proportion to the marks, the hub's transit stayed whole, but in
    the flow lab a full buffer lost the probes, and in four runs of ten the
    cuts had not caught up after a minute.

### The destination echoes, the sources slow

*   Good, because it is TCP's ECN loop with the nodes as its ends: standard,
    holding every flow whatever its transport, and returning every
    congested hop in one echo.
*   Bad, because it orders nothing, an echo waits for a packet going back,
    and a link reads its queue only as often as BFD beats. Built and run in
    the hub lab, it left the uplink's wait about where latency alone left
    it, and its sources' repeated cuts sank the hub's own traffic to two
    thirds of what it carried without them.
