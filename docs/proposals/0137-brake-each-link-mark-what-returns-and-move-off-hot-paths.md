# Brake each link, mark what returns, and move off hot paths

This proposal implements decisions 2 and 3 of
[ADR-0043](/docs/adrs/0043-grow-capacity-between-nodes-under-load.md), and
the fast and medium stages of its decision 4. Each node brakes each of its
links: it echoes the neighbor across the link as the link's traffic flows,
reads the queue beyond the node from the round trips and losses, and paces
the link's data to what the line carries. The fill of the link's queue in
the node marks the packets that come back over it; each source slows its
traffic to a destination on the marks, and its leases leave the paths that
run hot. The brake sends its echoes itself, on echo mechanics that move into
the ping library, which the ping application rides too. No wire message,
stored field, or run argument is added.

[TOC]

## Summary

Today:

*   **Nothing reacts to a full buffer but the hosts.** Each link's egress
    queue of 64 packets ([udpip.go](/pkg/core/dataplane/udpip.go)) drains as
    fast as the socket takes them, and the backlog builds in the router's
    buffer beyond the node, which drops. In the hub lab
    ([proposal 0136](/docs/proposals/0136-give-the-labs-uplinks-a-bandwidth.md)),
    at the rates this proposal gives it, the hub's own flow waits 254ms at the
    95th percentile under load, and 241ms once its uplink's rate falls.
*   **No packet is ECN-capable,** and no node marks.
*   **The ping application probes whole paths**
    ([prober.go](/pkg/apps/ping/prober.go)) within a budget of 20 probes a
    second, and a node may leave it out.
*   **A link's liveness is its BFD messages alone**
    ([bfd.go](/pkg/core/liveness/bfd.go)): a full queue on the line drops
    them with the rest, and the link goes down while the peer's traffic still
    arrives. In the hub lab, ten minutes of load past the hub's uplink take
    down between 1 and 14 links.

This proposal adds:

*   **A congestion module** with one method, the brake: each link's echoes,
    reading, rate, and marks.
*   **Paced links.** The data plane drains each link's data at the rate the
    module sets, holds at most 100ms of it at that rate, and tells the module
    what each link wrote.
*   **Marks on what returns.** A packet that comes back over a link gets CE
    in proportion to how full the link's queue is.
*   **A ping library** holding the echo mechanics the brake and the ping
    application share: resolving a responder, sending an echo, and timing its
    reply.
*   **ECN in the SCION library.** Every packet is ECN-capable; the library
    reads the marks on echo replies and arrivals, paces each destination's
    traffic on them, and ranks the paths that run hot after the ones that do
    not.
*   **Liveness on any arrival.** Every packet from the peer counts as a sign
    of life for the link's BFD session.
*   **Labs for the brake,** which check that it brakes and lets go, and
    **benchmarks** that grade what the line beyond drops and carries.

## Motivation

ADR-0043 has the capacity between two nodes grow under load, through three
stages: detection, at each link; the signal, from the node that holds the
excess to the senders; and reactions at three paces. This proposal lands the
first two stages and the fast and medium reactions, which hold every line
under its limit and spread the load over the paths there are. The slow
reaction, which adds links, and the prices that leave load out are a later
proposal's.

### Goals

*   Under a load past a line's capacity, the link toward it brakes within
    seconds; once its rate settles, the line drops at most 15% of what it is
    offered and carries at least 80% of its rate.
*   A queue past one neighbor brakes only the link toward it; a link whose
    traffic leaves lets go within seconds; jitter and a step in a link's
    round trip brake a link seldom.
*   The sources whose traffic crosses a braked link slow, whatever transport
    sent it.
*   The leases on a hot path leave it over time; a hot path takes no new
    lease while another serves.
*   In the hub lab, load takes down no link both its ends hold.
*   Nodes without this proposal keep working beside those with it.

### Non-goals

*   No link bought on marks, no drain, and no price that leaves load out:
    ADR-0043's slow stage and decision 5.
*   The destination rates read the marks on the replies to the ping
    application's probes alone: a node that leaves the application out keeps
    no rate, and the labs' flows answer nothing. The rates' reading of the
    traffic that returns comes with flows that answer, in the later proposal.
*   No marks from the underlay's routers (RFC 6040).
*   No breaker for a node that does not slow.
*   No configured rate, and no run argument.
*   Links under 256 kbit/s: the brake's reading needs sixteen echoes within
    four seconds, which slower links do not send.

## Proposal

### The congestion module

A new module, congestion (`pkg/modules/congestion`), rules each link's
egress queue. The composition root binds it, as it binds the beacon policy,
and it outlives the data plane's generations, so a link keeps its state
across them. Its `Policy` is called by the data plane's processors and
senders and by the method's own echoes, so no method blocks:

*   `Wrote(ifID, packets, bytes, held)`: what a link wrote, and whether its
    rate held data back as it did.
*   `Rate(ifID)`: the rate the link's data drains at, zero for none.
*   `Mark(ifID, fill)`: whether to mark a packet that came back over the
    link, given its queue's fill.
*   `Sampled(ifID, sample)`: the outcome of an echo across the link.

`congestiontest` holds the contract every method keeps.

### The brake

The module's one method, `brake`, keeps each link under its limit:

*   **Echoes.** Each link is granted the packets it writes in 100ms at the
    packet rate its last step measured, between 4 and 128. A write that uses
    a grant up calls for one echo across the link. A free link whose last
    step wrote under 128 kbit/s, which no cut brakes, calls for one every ten
    seconds at most, which keeps its least fresh.
*   **The reading.** The link keeps the least round trip of each 10s span
    for a minute, and reads the echoes sent since its last cut within four
    seconds. They read over on loss when answered under half the time, at
    80% one-sided confidence. They read over on a queue when the tenth
    percentile of their round trips, the losses counted, stands the 15ms
    target or more over the least: its lower bound at 80% confidence needs
    sixteen echoes, so nine in ten must stand over, and jitter that leaves
    some fast reads as no queue. They read under when its upper bound
    stands within the target, and nothing otherwise. Four seconds hold
    sixteen echoes at 256 kbit/s in 1500-byte packets.
*   **The step,** once a second at most, as a method's call reaches the
    link:
    *   A link whose last echo went five seconds ago loses its rate: its
        traffic left it.
    *   With no echo come since the last step, the rate holds.
    *   A reading over cuts the rate from what the link wrote since its last
        step, or from its rate where that is lower: to 0.7 of it on loss, as
        CUBIC and BBR cut; on a queue, to what the queue delivered of it,
        the written rate over 1 plus how fast the round trips grew, less
        what drains the queue's excess over the target within a second,
        keeping half at least. No rate falls under 128 kbit/s; a link that
        wrote nothing is not cut; a free link brakes only to a rate under
        what it wrote.
    *   A rate that held no data back since the last step is released.
    *   Otherwise a reading under climbs the rate by an eighth, and by a
        sixty-fourth just under the rate its last cut came at; a reading of
        nothing climbs it by a sixty-fourth.
*   **The marks.** Each packet that comes back over a link adds the link's
    fill to what the link owes in marks; a packet that finds a whole mark
    owed is marked, so the share marked follows the fill. An empty queue
    clears what the link owes. What a link owes is a count of its own, moved
    atomically, so a mark waits on no lock the steps take.
*   **Logs.** Each brake set, and each released, logs once.

### Paced links

`RunConfig.Congestion` hands the data plane the policy; nil paces and marks
nothing. Each external link's sender:

*   **Paces its data.** Data goes a packet's time at the rate apart, a
    millisecond ahead at most; control goes first, ahead of the data, and
    counts against the rate.
*   **Bounds the wait.** The paced queue holds what the rate sends in 100ms,
    about an uplink's buffer, and the queue's room at most; the oldest data
    past it drops.
*   **Reports each write** to the policy with whether the rate held data
    back: the queue held more than half its bound, or dropped some.

Each link's data egress queue holds 1024 packets, up from 64: 12ms at 1
Gbit/s, where 64 held under a millisecond; its control queue holds 64. The
packet pool makes a buffer for every packet the queues and batches can hold,
64 at a time as they are first needed rather than all at the start, so a
queue that never fills costs no memory. A full egress queue, paced or not,
drops its oldest packet to take the newest. A link's fill is the larger of
its queue's share of its capacity and of its bound.

### Marks

A packet that came in over an external link, once its path has validated,
gets CE in its traffic class when it is ECN-capable, the link's fill is
above zero, and the policy marks it.

### Liveness

A BFD session counts every packet from its peer as a sign of life: the
detection time runs from the later of the last control message and the last
other arrival. Only control messages move the session's state, so a link
still comes up by the handshake alone. RFC 5880's asynchronous mode, the one
the sessions run, downs a session after a detection time without a control
message; the rule departs from it, against the failure
[scionproto/scion#4019](https://github.com/scionproto/scion/issues/4019)
reports upstream, where the control messages a loaded link loses take its
session down. Demand mode, which RFC 5880 provides for this, is a later
proposal's.

### The echoes

The brake sends the echoes its policy calls for itself, from a loop of its
own, on two conns the composition root binds: one its echoes ride, and one
its resolutions read.

*   **Calls.** The policy's calls come in on a channel of 64, a call past
    them dropped, as the link calls again with its next grant.
*   **Echoes.** Each call sends an echo to the neighbor's responder over the
    one-hop path out of the link, and an echo unanswered within a second
    counts as lost. A link no usable entry holds is skipped. The echoes draw
    on no budget, as the traffic bounds them.
*   **The neighbor's host.** The neighbor's responder is resolved over a
    one-hop path; eight echoes lost in a row resolve it again, and the echoes
    keep the host they had meanwhile.

The echo mechanics move into the ping library (`pkg/libs/ping`), which the
ping application's prober rides too:

*   a conn that sends echo requests and delivers the replies to its own;
*   the requests awaiting their replies, each settled by its reply with its
    round trip and mark, or as lost after its wait, in the order sent;
*   the responder hosts, each resolved off the caller's loop over its paths
    in turn, a failed resolution retried after a spacing.

The prober keeps its pacing, its budget, and its bursts. A probe's sample
records whether its reply came back marked, and the reply to a probe of a
path in use goes to the destination's rate. The `cion ping` client moves
into the library too, and the responder moves from the node's assembly into
the core's own package, `pkg/core/responder`.

### The SCION library

*   **ECN-capable sends.** Every packet a socket writes carries ECT(0) in its
    traffic class, beneath the control DSCP on control sockets.
*   **Marks read.** An echo carries whether it arrived with CE. A socket
    other than a control one counts what each source sends it, and how much
    of it comes marked, in spans of ten seconds over the last thirty.
*   **Destination rates.** The node's ECN state, shared by every socket,
    keeps for each destination node a base, the most sent there in any second
    of the last ten, and a rate, unset until an answer to a probe of a path in
    use comes back marked. Each answer moves an average of the share marked
    by a sixteenth, from zero, as DCTCP's gain moves its average. A marked
    answer to a probe sent after the last cut cuts the rate to 1 minus half
    the average of the lesser of the rate and the base, never under 64
    kbit/s; a destination whose base lies under that gets no rate. After a
    clean answer, the rate climbs by 1/256 every 100ms, to twice the base;
    a rate unmoved for 30 seconds unsets. While a rate is set, a write whose
    turn lies more than 100ms ahead is dropped; control sockets are not
    paced.
*   **Hot paths.** A path is hot when its probes' answers of the last thirty
    seconds came back marked more than half the time, at 80% confidence,
    which three marked in a row make; so is a lease's path when the
    destination's arrivals did. Within a tier of health, a path that is not
    hot ranks before a hot one.
*   **Leases.** A lease on a hot path leaves for the fastest healthy path
    that is not hot after a hold drawn at random within ten seconds; a hot
    path takes no lease while a path that is not hot serves.

### The labs

*   **Lines.** The fabric's uplinks become lines, a rate and a queue bounded
    in time on what a host sends or, as a downlink, receives. A line's window
    reports the packets it sent and dropped, their bytes, and their waits.
*   **The hub lab** runs at four times proposal 0136's rates, its uplink at
    4 Mbit/s falling to 1.6 Mbit/s, so each flow's share of the uplink stays
    above 256 kbit/s and a brake can read every link the flows load. Each
    phase also counts the links lost, whose liveness fails while both ends
    hold them, and the links retired.
*   **The brake labs** check what a brake does, in CI:
    *   **A thin uplink (`TestFlowCrossesAThinUplink`):** a flow that fits
        keeps proposal 0136's bounds; beside a flow twice the line, the
        joiner's link brakes, and its control traffic still reaches the core.
    *   **A queue past one neighbor:** only the link toward the thin
        downlink brakes.
    *   **Traffic moving between links:** once the flow leaves a braked
        link, the link lets go within 15 seconds, and the link it moves to,
        which carries it within its capacity, does not brake.
    *   **A path across two queues:** both links brake.
*   **The brake benchmarks** grade how well, skipped unless `CION_BENCH` is
    set, each printing what it measured for benchstat:
    *   for the thin uplink, the queue past one neighbor, and the two queues,
        what the line drops and carries once its link's rate settles, its
        waits, and what the flows deliver;
    *   for traffic moving between links, how long the brake takes to let go,
        and what the flow delivers on the link it moves to;
    *   for jitter on a loaded link, and from a minute and a half after a step
        in its round trip, the seconds the link holds a rate, and what the
        flow delivers.

### Packages touched

| Package                       | Change                                                            |
| :---------------------------- | :---------------------------------------------------------------- |
| `pkg/modules/congestion`      | New: the policy, the brake and its echoes, and the contract suite |
| `pkg/core/dataplane`          | Paced senders, bounded waits, oldest-first drops, fill, marks     |
| `pkg/core/liveness`           | Every arrival keeps a session alive                               |
| `pkg/core/responder`          | New: the echo responder, moved from the assembly                  |
| `pkg/apps/ping`               | The prober rides the ping library and reads marks                 |
| `pkg/libs/ping`               | New: the echo mechanics, and the `cion ping` client, moved        |
| `pkg/libs/scion`              | ECT(0); marks read; destination rates and pacing; hot paths       |
| `pkg/libs/evidence`           | A sample records whether its answer came back marked              |
| `internal/services`           | The brake, the responder, and the shared ECN state, assembled     |
| `internal/testnetwork`        | Lines; the hub lab's rates; the brake labs and their benchmarks   |

`docs/design/architecture.md` names the responder, the ping library, the
congestion module, and the marks.

## Compatibility

*   **Older nodes** forward marked packets unread, send nothing ECN-capable,
    and never brake or mark. Their responders answer link echoes, which are
    standard SCMP echoes, so a node brakes its links to them as to any.
*   **No wire message is new,** and no stored field changes.

## Test plan

*   **The brake,** on virtual time: grants follow the last step's packet
    rate and bound; a free link under 128 kbit/s echoes once in ten seconds;
    loss and queue readings, their confidence and window, and their cuts;
    the floor; no cut without writes; no brake for a free link above what it
    wrote; climbs, release, and silence; marks follow the fill, exactly from
    many processors at once, while the mutex is held; each brake logs once,
    outside the mutex.
*   **The data plane:** a paced link writes its data at its rate and its
    control at once, counted against the rate; the paced queue drops its
    oldest past 100ms or past its room; a step holds data back past half the
    bound; a full egress queue drops its oldest; the packet pool covers every
    queue, making its buffers a block at a time as they are first needed,
    and a Get waits only once the pool made them all; a packet that comes
    back over a link is marked only when ECN-capable and its link's fill
    calls for it.
*   **Liveness:** a session hearing only other arrivals stays up past its
    detection time, and one hearing nothing goes down.
*   **The brake's echoes:** each goes over the one-hop path to the resolved
    host, which they keep while it resolves again; every call the queue
    holds sends; a down link is skipped; a lost echo goes to the policy; the
    policy's calls reach the echoes, and their outcomes the policy.
*   **The ping library:** a request settles by its reply with its round trip
    and mark, or as lost after its wait, in the order sent; a host resolves
    once at a time, over its paths in turn, a failed resolution retried after
    its spacing and the host held kept meanwhile; a conn delivers the replies
    to its own requests alone.
*   **The prober:** probe samples record marks, and the replies to the probes
    of a path in use go to the destination's rate.
*   **The SCION library:** ECT(0) on every write; marks read on echoes and
    arrivals; the destination rates' cuts, climb, unset, and pacing; hot
    paths and their rank; a lease leaves a hot path after its hold, and
    takes no hot path while another serves.
*   **The brake labs** in CI.
*   **The brake benchmarks** against the goals, and **the hub benchmarks**
    for the links load takes down, beside today's delivery and lease moves;
    the history records both.

## Implementation history

*   **Grants follow the link's packet rate.** Grants of at least sixteen packets
    left the hub lab's links one or two echoes a second, too few for a delay
    reading; grants of four read a link that writes 128 kbit/s.
*   **The paced queue holds 100ms.** With grants of four, brakes engaged on slow
    links and cut them toward the floor, and the 64-packet egress queue held
    seconds at the braked rate: the hub's own flow waited 2.3 seconds at the
    95th percentile. Dropping the oldest data past 100ms at the rate, and
    cutting to 0.7 on loss, ended it.
*   **A brake stands while its rate holds data back.** Releasing a link whose
    writes fell under three quarters of its rate released and braked the hub's
    links every second, as their queues of a packet or two ran dry; counting any
    waiting packet as held kept jitter's false brakes for 10 to 16 seconds. Held
    is data trimmed or more than half the bound queued.
*   **No cut without writes, and a floor.** The far side of a congested link
    lost its echoes' replies on the way back and braked to the floor every few
    seconds; a link now cuts from what it wrote, never under 128 kbit/s, and a
    free link only to a rate under what it wrote. A free link that writes under
    the floor echoes once in ten seconds, which keeps its least fresh.
*   **The bound stops at the queue's room.** At 64 packets, the bound passed the
    channel above about 7.7 Mbit/s; above about 15 Mbit/s the queue dropped at
    its entry, the rate never held data back, and the brake let go every second.
    The data queue holds 1024 packets and its bound stops there; the control
    queue holds 64.
*   **The packet pool makes its buffers as they are first needed.** With
    1024-packet queues made at the start, the Metros lab's process grew from
    1.14 GB to 2.37 GB and the Regions lab's from 1.05 GB to 2.47 GB; made on
    demand, they took 0.54 GB and 0.53 GB.
*   **A Get waits only once the pool made every buffer.** The pool first let a
    Get that found it empty wait whenever another Get had just made a block, and
    the block could drain before the first took a packet; a receiver on a node
    with no other traffic then waited for good, and its link went dead. In one
    hub run at proposal 0136's rates, a joining node's only link never came up,
    and under the race detector's load tests over real sockets timed out and a
    stopped data plane never returned. A Get now takes its packet under the
    pool's mutex.
*   **Marks take no lock.** Under the brake's mutex, marking from 24 goroutines
    on one link took 143.6ns a packet, and 162.3ns beside the link's writes;
    with each link's debt an atomic count, 75.3ns and 83.1ns.
*   **The echoes keep the neighbor's host while it resolves again.** An echoer
    that dropped the host after eight lost echoes paused a congested link's
    echoes while it resolved across that link, and the brake read the silence as
    the traffic gone and let go.
*   **The brake on a single path.** Switched off and on in the prototype's labs,
    the brake cut the bottleneck's wait from 97ms to between 23 and 58ms and its
    drops from 28–63% to 3–10%, and the flow lab's control traffic crossed the
    line in all five runs instead of none, for one or two points of the flows'
    delivery.
*   **Rejected:** a reading over the last sixteen echoes, which braked on jitter
    in three runs of five; no fast probe above the last cut, which left the
    round-trip step braked in every run; holding while blind, and braking only
    where the rate would hold, which changed nothing measured.
*   **The lab of traffic moving between links times the lease.** It first timed
    the flow's move from the pick, one to three seconds before the lease moved,
    and the packets sent to the braked link meanwhile were trimmed.
*   **The labs split.** The brake labs check what a brake does, in CI; the
    benchmarks grade how well. Under the race detector, two counts of
    `internal/testnetwork` take 580 to 650 seconds, past the default ten
    minutes, so the race pass takes a 20-minute timeout.
*   **The hub lab runs at four times proposal 0136's rates.** At its rates, once
    the uplink's rate fell, each loaded link of the hub carried 100 to 150
    kbit/s of payload, its share of the uplink under the floor: its brakes set
    and let go within seconds, and no lease left a path for running hot. At four
    times, the brake reads every link.
*   **The hub goal counts the links load takes down.** Today's network delivers
    more in the hub lab because load takes its links down: the hub's BFD
    messages drop in its full uplink, its links go down, the paths through it
    stop composing, and the flows leave for direct paths. ADR-0043 rules out
    shrinking the capacity under load, and this proposal adds none, so the goal
    counts the links lost, and the benchmarks record delivery beside them.
*   **Where the excess drops.** In one instrumented run under steady load, the
    sources' rates dropped 70% of what was lost, the brakes of the transit
    sources' links toward the hub 14%, and the hub's own brakes 16%; after the
    fall, 22%, 41%, and 37%. The transit sources brake because their echoes'
    replies wait in the hub's uplink. A lease leaving a hot path often took
    another path through the hub, as a path not in use reads hot only once its
    probes return marked.
*   **Liveness on any arrival departs from RFC 5880,** whose asynchronous mode,
    the one the sessions run, downs a session after a detection time without a
    control message. A later proposal moves the sessions to demand mode, kept up
    by SCMP echoes across each link.
*   Mutations: the brake's policy, 84 of 85 killed, the survivor equivalent; the
    marks' lock, 2 of 2.
*   The pipeline passed. `TestPathsFollowMeasuredHealth`'s `within_the_band`
    fails as often without this change, when a path's recovering burst restarts
    its samples and the burst's later losses price it past the band; a follow-up
    fixes it.
*   **The brake benchmarks,** five runs each. Toward a thin downlink, the line
    dropped 3.6–8.5% of what it was offered and carried 88–98% of its rate,
    waiting 30–62ms on average, and the link toward the other neighbor never
    braked; past two queues, 2.9–9.5% and 87–97%; past a thin uplink, 6.4–12.9%
    and 96–99%. A link let go a second after its traffic moved, and the link the
    traffic moved to carried it whole and never braked. Jitter held a link for 4
    seconds in one run of five, and a step in the round trip braked no link.
*   **The hub benchmarks,** five runs each against today's network, at the lab's
    new rates. Ten minutes of steady load took down 1 to 14 of today's links and
    none of this network's; after the fall, 0 to 11 and none. The uplink dropped
    0.7% of its packets under steady load against 3.9%, and 1.7% after the fall
    against 3.5%. The flows delivered less: today's network, losing the hub's
    links, sends them around the hub, while this one keeps them on it and drops
    the excess in the nodes. Under steady load, the hub's own flow delivered
    95.7% against 97.8% and transit 92.5% against 98.5%; after the fall, 95.4%
    against 98.4% and 94.6% against 98.5%. Leases moved 13 times against 22
    under steady load, and 9 against 12 after the fall, which lies within the
    runs' spread. In two runs the link policy retired a link or two under load,
    on the prices the load raised.
*   **The data plane benchmarks** against today's, six runs each: the forwarding
    pipeline moved no case past its noise, and 1.4% more packets a second over
    all; processing a packet took 2.6% longer for a crossover's transit and 5.5%
    less time for a delivery, the rest within noise. Marks add 13ns to a packet
    that comes back over a link whose queue is empty, and 55ns where a full
    queue marks every packet.
