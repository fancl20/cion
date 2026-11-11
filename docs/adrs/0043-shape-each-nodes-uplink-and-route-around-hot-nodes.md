# Shape Each Node's Uplink and Route Around Hot Nodes

*   Status: proposed
*   Date: 2026-11-11

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
    decision 8), unmarked and unfair between sources, and the backlog an
    uplink cannot carry builds beyond it, in the router or the provider's
    buffer, where CION neither sees nor orders it.
*   **The paths' probes skip the data queues.** They travel in the control
    class (ADR-0035, decision 6), so a path's price misses the queueing its
    traffic meets. ADR-0035 left load to a later decision, after a lab with
    links of unequal capacity.
*   **The labs have no bandwidth:** they model delay, jitter, and loss.

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
*   **A node protects itself:** its own traffic survives whatever transit
    arrives, and a neighbor that ignores a signal gains nothing by it.
*   **Measured, not declared:** no node publishes its load; others learn it
    from what their own packets meet (ADR-0017; ADR-0039, principle 5).
*   **Sources choose paths:** a transit can only mark, delay, or drop
    packets, and choose what it beacons and which links it admits; the
    senders move (data-plane draft, Section 7.4).
*   **No stampede:** the senders crossing a hot node leave it over time, not
    at once, and do not all return when it cools.
*   **Spec-native:** the signals the drafts define, and no new message.
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
*   **Local control, endpoints react:** each node shapes its uplink to a rate
    it measures, orders and marks its own queue, and the senders whose
    probes meet the marks move.

## Decision outcome

Chosen option: **local control, endpoints react**, realized as follows:

1.  **A node holds its bottleneck in its own queue.** A shaper keeps the
    node's egress, across all its links, just under its uplink, at a rate
    the node measures rather than knows: it backs off when the round trips
    to its neighbors rise together, the mark of its own uplink filling, and
    climbs while it holds a backlog and they do not, as cake-autorate does
    for links of varying rate. The backlog builds in the node, where the
    node can order and mark it.
2.  **The node's own traffic goes before transit.** Behind the control
    class, which stays first and capped (ADR-0035, decision 8), what the
    node's sockets and hosts send takes strict priority over transit, and
    transit shares what is left fairly by the link it arrived on, which no
    sender can forge.
3.  **Queues mark before they drop.** An active queue manager holds each
    queue's delay near a target: it marks congestion on packets that carry
    ECN and drops those that do not. The node's SCION sockets send ECN, and
    the WireGuard gateway carries marks between the SCION header and the
    hosts' packets (RFC 6040), so the hosts' transports slow down.
4.  **Probes meet what data meets.** The path library's probes queue as data
    and carry ECN, and each reply reports whether its probe arrived marked,
    beside its round trip. Beside the paths in use, the library probes a
    random sample of each destination's other paths, as Prequal samples
    servers by probe rather than by their reports. A path whose probes
    return marked, or whose queueing delay passes a line, is hot. Health
    stays as ADR-0035 judges it.
5.  **Leases leave hot paths gradually and return by the margin.** A lease
    on a hot path moves to the fastest healthy path that is not hot, after a
    hold drawn at random, so the leases crossing one hot node leave it over
    time; a hot path takes no new lease while another serves. A lease
    returns to a path only by the margin ADR-0035 sets (decision 5), and
    only once the path has cooled. A destination with no other path leaves
    the slowing to its transports.
6.  **A node that stays hot sheds load slowly.** Its link policy admits no
    new link, and its beacon policy
    ([ADR-0042](/docs/adrs/0042-file-the-beacon-policy-as-a-module.md))
    carries fewer transit routes through it, never its own routes nor a
    receiver's last. Both read the node's own load, which no other node is
    told.
7.  **Load stays local.** No directory entry, tag, or beacon declares it;
    each node learns of another's load from the marks and delays its own
    packets meet.
8.  **Hop-by-hop flow control waits for the lab.** Pause or credit between
    neighbors is weighed once the shaper, the order, the marks, and the
    leases stand there.
9.  **A lab with bandwidth judges it.** The fabric gains links with a
    bandwidth limit and a finite queue, their rate varying, and the labs
    show a thin, well-placed node keeping its own traffic while transit
    moves off it.

This is the later decision ADR-0035 left load to. It narrows that record's
decision 6, so that probes queue as data, and its decision 5, so that a hot
path repels the leases on it. The cap on a node's links stays as ADR-0017
and ADR-0039 set it; raising it, with a cost for keeping a link and
beaconing that scales with links, is a decision of its own, once this one
stands in the lab.

### Positive consequences

*   A node's own traffic and its links' liveness hold, whatever transit
    arrives.
*   Congestion shows where CION can act: in the node's own queue, as marks
    and delay that its senders' probes meet.
*   No bandwidth is configured and no load published: the signals ride
    packets already flowing.
*   Transit leaves a hot node over time and returns as it cools, and a
    neighbor that ignores the marks gains only its fair share.
*   A thin node stops being a hazard that only the cap contains.

### Negative consequences

*   Strict priority can starve transit while the node's own traffic fills
    its uplink, other nodes' control calls among it, since they cross a
    transit as data; their senders move away, but a path with no
    alternative stalls.
*   The shaper costs throughput: it holds the rate under the uplink, and
    finds a link that has grown faster only by climbing.
*   Round trips that rise together can mislead: a full downlink, or
    neighbors all behind one congested segment, looks like the node's
    uplink and slows its egress for nothing.
*   Each packet costs more work in the data plane: shaping, ordering, and
    marking.
*   Probes spend more of the prober's budget, sampling paths no lease rides.
*   Marks reach only the hosts' transports that negotiate ECN; the others
    meet drops.

## Pros and cons of the options

### Latency alone, as today

*   Good, because it needs nothing new.
*   Bad, because the queue that fills sits outside the node, the probes miss
    it, and a node whose processor is the bottleneck never shows.

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
    control, the role path choice plays here.

### Reservations

*   Good, because a reserved flow is guaranteed its rate.
*   Bad, because admission, keys, and policing at every node exceed what
    CION's scale needs, and no draft specifies them.

### Local control, endpoints react

*   Good, because each lever is local and bounded, the node protects itself
    whatever others do, and the senders act on what they measure.
*   Bad, because the shaper estimates a moving rate, priority can starve
    transit, and the senders react only as fast as their probes see.
