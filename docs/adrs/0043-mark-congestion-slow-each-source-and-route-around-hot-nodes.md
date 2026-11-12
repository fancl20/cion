# Mark Congestion, Slow Each Source, and Route Around Hot Nodes

*   Status: proposed
*   Date: 2026-11-12

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
    carries it, and congestion control end to end as TCP and QUIC run it;
    no rate to estimate, and no packet sent for the signal alone.
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
*   **The hosts react:** each node marks its queue, and the WireGuard
    gateway carries the marks into the hosts' packets (RFC 6040), so their
    transports slow.
*   **The marker echoes:** the node at a link's receiving end writes its
    marks into the replies of the path probes that cross the link, as Frame
    Relay's backward notification and ATM's ABR service did.
*   **The destination echoes, the sources slow:** the receiving end of each
    link marks the packets that crossed a queue, the destination returns
    the marks to their source on the packets it sends back, and each source
    slows its own traffic: TCP's ECN loop, with the nodes as its ends.

## Decision outcome

Chosen option: **the destination echoes, the sources slow**, realized as
follows:

1.  **Each node sends ECN-capable and slows on the marks echoed to it.** A
    node sets ECT(1), the codepoint RFC 9331 gives senders whose response
    scales with the marks, in the SCION header of every packet it sends into
    the network, its sockets' and its hosts' alike; only nodes read these
    bits, as no host sees a SCION header. It keeps a rate for each
    destination node, unset until an echo shows marks: it cuts the rate in
    proportion to the share of its bytes echoed as marked, raises it while
    the echoes come back clean, and holds it while none come back. The
    excess waits or drops at the node, whatever transport sent it. The
    control class is not paced.
2.  **The receiving end of a link marks.** BFD sends a control packet every
    second on the link's own socket, beneath the sender's queues, so how
    late each arrives against that beat measures the queue it crossed. While
    that queue stays over a target, the receiving end marks the
    ECN-capable packets arriving over the link congested, with a
    probability that rises the longer it stays. Copying in the marks the
    underlay's own routers set in the outer IP header (RFC 6040) is a later
    step.
3.  **The destination echoes the marks.** For each source node, it counts
    the bytes it delivered and those that arrived marked, and returns both
    running totals in an end-to-end option on every packet it sends that
    source with room for it. The path library's probe replies are such
    packets, so a source hears at least once per heartbeat on a path in
    use. No packet carries the echo alone, and a lost one costs nothing:
    the next carries the totals.
4.  **Probes carry ECN.** The path library's probes are ECN-capable as data
    is, and each reply reports whether its probe arrived marked, beside its
    round trip. Beside the paths in use, the library probes a random sample
    of each destination's other paths, as Prequal samples servers by probe
    rather than by their reports. A path whose probes return marked, or
    whose queueing delay passes a line, is hot. Health stays as ADR-0035
    judges it.
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
    routes nor a receiver's last. Both read the marks echoed on the node's
    own traffic, which no other node is told.
7.  **Prices stay unloaded; lasting shortage buys capacity.** The link
    policy reads only the probes that return cool, so the readings ADR-0038
    defines carry no more queueing than a cool path holds, and no busy hour
    moves a price; a route that stays hot gives it no reading until it
    cools, and the decisions that need one wait. Capacity is a worth of its
    own, beside the peers and the independent routes a link gives (ADR-0039,
    principle 2): a node whose traffic to a destination stays marked while
    every path to it is hot, for longer than the path policy takes to
    answer, buys a link that opens a route around the hot hops, announced
    and staggered as ADR-0037 has every promotion. Until the link stands,
    the flow has nowhere else to go, and its source slows on the marks.
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
    packets meet.
10. **Node-held queues and hop-by-hop control wait for the lab.** A shaper
    that holds the node's queue and puts its own traffic first, pause or
    credit between neighbors, and active probing are weighed against this
    loop once it stands there, by what each adds to it: an order for the
    node's own traffic, a shorter tail, a faster loop. So is a breaker for
    a node that does not slow.
11. **A lab with bandwidth judges it.** The fabric gains links with a
    bandwidth limit and a finite queue, their rate varying, and the labs'
    flows answer their senders as transports do. The labs show the queue at
    a thin, well-placed node's uplink staying short while its sources slow
    and transit moves off it.

This is the later decision ADR-0035 left load to. It narrows that record's
decision 6, so that probes carry ECN and the link policy reads those that
return cool, and its decision 5, so that a hot path repels the leases on it.
It extends ADR-0039's principle 2, so that a link is also worth the capacity
it adds, and its principle 5, so that a link that carries traffic retires on
a drain. The cap on a node's links stays as ADR-0017 and ADR-0039 set it;
raising it, with a cost for keeping a link and beaconing that scales with
links, is a decision of its own, once this one stands in the lab.

### Positive consequences

*   The queue at a congested uplink stays short for all who cross it, with
    no rate to estimate: the sources slow as the marks come back.
*   Every flow is held, whatever its transport: the node reacts for its
    hosts, so a host that ignores ECN, or loss, slows too.
*   Congestion anywhere on a path reaches its source: the marks of every
    hop collect on the packet, and one echo returns them.
*   No bandwidth is configured, no load published, and no packet sent for
    the signal: marks and echoes ride packets already flowing.
*   Transit leaves a hot node over time and returns as it cools.
*   Demand that outlasts the path policy's answer gets capacity: a link
    opens a route around a hot node, and stays while its traffic would not
    fit elsewhere.
*   A link leaves only once its traffic has fit elsewhere, at the load it
    served, so a busy hour neither prices links nor retires one bought for
    it.
*   A thin node stops being a hazard that only the cap contains.

### Negative consequences

*   Nothing is ordered: the node's own traffic and other nodes' control
    calls share the queue with transit, which is short but first-come.
*   A link reads its queue once a second, from BFD: bursts outrun the marks,
    and the reading drifts with the two ends' clocks.
*   An echo waits for a packet going back: one-way traffic hears only from
    its source's probe replies, once per heartbeat.
*   A node that does not slow goes unchecked until a breaker stands.
*   Each packet back to a source grows by the echo, which the data plane
    inserts; a full-size packet on a long path has no room and goes
    without.
*   The echo rides an option type the SCION specification reserves for
    experiments; a wider deployment needs one assigned.
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

### The hosts react

*   Good, because the hosts already run congestion control, and ECN spares
    them the drops.
*   Bad, because the mesh's WireGuard carries no ECN across its encryption,
    not every host negotiates ECN, and some traffic reacts to nothing.

### The marker echoes

*   Good, because the node that sees the congestion tells the sources
    itself, with nothing for the destination to count.
*   Bad, because only the probes are sure to pass back through it, the
    destination's traffic riding its own lease, so the loop runs at the
    probes' pace.

### The destination echoes, the sources slow

*   Good, because it is TCP's ECN loop with the nodes as its ends: standard,
    holding every flow whatever its transport, and returning every
    congested hop in one echo.
*   Bad, because it orders nothing, an echo waits for a packet going back,
    and a link reads its queue only as often as BFD beats.
