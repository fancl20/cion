# Give the labs' uplinks a bandwidth

This proposal implements decision 11 of
[ADR-0043](/docs/adrs/0043-mark-congestion-slow-each-source-and-route-around-hot-nodes.md):
the fabric gains uplinks, each a rate and a finite queue that the lab may
vary while it runs; a lab sends data between nodes over SCION; and a hub lab,
where a thin and well-placed node draws its peers' transit, benchmarks what
the network does today, the baseline the record's later proposals are judged
against. No production code, wire message, stored field, or run argument
changes.

[TOC]

## Summary

Today ([taps.go](/internal/testnetwork/fabric/taps.go),
[fabric.go](/internal/testnetwork/fabric/fabric.go)):

*   **Taps shape pairs.** A tap holds a host pair's packets for a delay or a
    jittered one, or drops a share of them; nothing bounds how fast a host
    sends.
*   **The labs carry no data.** Their traffic is pings, probes, control
    calls, and BFD.

This proposal adds:

*   **Uplinks.** An uplink carries one or more hosts at a rate and with a
    queue bounded in time. Every packet those hosts send to any other host
    leaves through it after the packet before it, taking its size at the
    rate, and a packet that would wait past the bound is dropped. The lab
    changes the rate at will and reads what the uplink sent, dropped, and
    held.
*   **Flows.** A flow sends datagrams of a size from one node to another at
    a rate, over the path the sender's path library leases, as data; the
    receiver counts them and reads each one's one-way delay.
*   **The hub lab.** Seven nodes, one of them five milliseconds from every
    other and on a thin uplink, the rest twenty milliseconds apart: the
    measured topology links every node to the hub and carries their transit
    through it. Two benchmarks load it: steady flows past the hub's uplink,
    and flows that fit until the uplink's rate falls.

## Motivation

ADR-0043 decided that the receiving end of each link marks the packets that
crossed a queue, that each source slows on the marks its destinations echo,
and that the senders whose probes meet the marks move. Each of those
decisions is a proposal of its own, and each is judged in a lab where
an uplink runs out (decision 11). The fabric models delay, jitter, and loss,
and no link runs out; no lab sends the data that would fill one.

### Goals

*   A lab gives any host an uplink of a rate and a queue, hosts behind one
    NAT one uplink between them, changes the rate while it runs, and reads
    per window what the uplink sent, dropped, and how long its packets
    waited.
*   A lab runs flows between nodes over SCION and reads per window each
    flow's delivered share, and the median and 95th percentile of its
    one-way delay.
*   The hub lab and its two benchmarks report the hub's own flow, the
    transit flows, the hub's uplink, the leases that moved, and the links
    that changed, before, under, and after the load.
*   The history records the baseline: what today's network does under load.

### Non-goals

*   No change to the node: the marks, the echo, the sources' rates, and the
    leases' reaction are the record's later proposals.
*   No answers: the flows run one way; the echo's proposal makes them answer
    their senders as transports do.
*   No downlink: the record's context holds the uplink to run out first.
*   No hub lab in CI: its benchmarks run on demand, as every benchmark does
    ([proposal 0071](/docs/proposals/0071-benchmark-the-networks-by-the-paths-they-serve.md)).

## Proposal

### Uplinks

`Fabric.Uplink(rate, queue, hosts...)` draws an uplink carrying the hosts,
at `rate` bits per second, its queue bounded at `queue`: the wait at the
current rate past which a packet is dropped, as a modem's buffer holds a
time's worth of its line. A host rides one uplink at most.

*   **What crosses it.** A packet whose source host the uplink carries and
    whose destination host it does not: the fabric shapes before any NAT
    translates, so the source is the sender's own host. A node's packets to
    its own host, between its applications and its router, and a site's
    packets between its members cross nothing.
*   **Departure.** The uplink keeps when its line falls free. A packet
    starts at that time or now, whichever is later; it is dropped if that
    start lies more than the bound away, and otherwise holds the line for
    its size at the rate. The packet's hold is its wait and its
    serialization, and the taps' delay and jitter follow the departure; a
    jittered direction keeps its packets in order from it. Packets leave in
    the order they were sent, and no packet takes a goroutine of its own
    beyond the timer that already carries a delayed one.
*   **Varying.** `SetRate` changes the rate for the packets sent after it;
    those queued keep their departures.
*   **Reading.** `Window` returns what the uplink sent, in packets and
    bytes, the packets it dropped, and the mean and longest wait of those
    it sent, since the window before, and starts the next.

### Flows

`testnetwork.StartFlow(t, from, to, port, rate, size)` starts a flow and
stops it with the test:

*   **The sender** opens a conn on its node's internal link, which marks no
    control class, so its packets cross every transit as data; awaits its
    lease's first path to the receiver's ISD-AS, asking again each second;
    then offers datagrams at random times, a mean of `size` bytes at the
    rate apart — a Poisson process's arrivals, so that flows lock in step
    neither with each other nor with a queue — reads the lease's path for
    each, and sends it stamped with its sequence and its send time. A
    datagram without a path counts as offered and unsent.
*   **The receiver** reads on the given port of its node and records each
    datagram's one-way delay, the bubble's one clock serving both ends.
*   **Reading.** `Window` returns the datagrams offered and received, and
    the delays' median and 95th percentile, since the window before.

### The hub lab

Node 0 is the founding core and node 1 the hub. The hub sits 5ms one way from
every node, and every other pair 20ms: a route through the hub costs 10ms
and a transit, against 20ms direct. Every node joins through the founder. The
hub's uplink carries 1 Mbit/s and queues 250ms; the other nodes' uplinks are
unbounded.

*   **Steady load (`TestBenchHubLoaded`).** Once the link set settles, three
    flows run between node pairs whose chosen path crosses the hub, 400
    kbit/s each, and one from the hub, 200 kbit/s: 1.4 Mbit/s into a 1
    Mbit/s uplink. The load runs ten minutes; the flows then stop, and the
    benchmark reads ten minutes more.
*   **A rate that falls (`TestBenchHubRateFalls`).** Once the link set
    settles, the same flows run at 150 kbit/s each and 100 kbit/s from the
    hub, which the uplink carries; after five minutes its rate falls to 400
    kbit/s for ten, then returns to 1 Mbit/s for ten.

For each phase, both benchmarks report the hub's own flow and the transit
flows apart, each as its delivered share and its delay's median and 95th
percentile; the hub's uplink, as the share it dropped and its mean and
longest wait; the leases that moved; and the link changes. Each phase ends
with whether every pair reaches over its chosen path. The bubble's virtual
time costs a benchmark minutes of wall time.

### Packages touched

| Package                         | Change                                       |
| :------------------------------ | :------------------------------------------- |
| `internal/testnetwork/fabric`   | Uplinks: drawing, departure, rate, windows   |
| `internal/testnetwork`          | Flows, and a lab of one flow over an uplink  |
| `internal/testnetwork/behavior` | The hub lab and its two benchmarks           |

The behavior package's doc names the benchmarks.

## Compatibility

No production code changes. A lab that draws no uplink runs as before: an
unbounded uplink holds no packet.

## Test plan

*   **The fabric's tests:** an uplink paces its packets at its rate, drops
    those that would wait past the bound, holds packets in their order,
    lets a node's packets to its own host and a site's between its members
    pass, applies a rate change to the packets after it, keeps a jittered
    direction in order from the departure, and reports its windows.
*   **The flow lab (CI):** two nodes 10ms apart, the sender on a 500 kbit/s
    uplink queuing 100ms. A flow of a third of the line arrives nearly
    whole, each datagram within its one-way delay and the bound's wait; a 1
    Mbit/s flow beside it delivers a share of what both offer, each
    datagram after the standing queue, while the uplink drops the rest.
*   **The hub lab's benchmarks** run on demand; the history records them.
