# Measure each hop, brake each link, and slow each source

This proposal implements decisions 2 and 3, and the fast stage of decision
4, of [ADR-0043](/docs/adrs/0043-grow-capacity-between-nodes-under-load.md),
with lab cases for the brake. The ping
application probes the paths a node's traffic rides with an SCMP message of
CION's own. Every node the probe crosses keeps when it passed it, and as the
reply passes back, reads its next link's one-way delay from the times the
node after it wrote, and writes its own. A link whose delay stands over a
target brakes: the node paces the link's egress, and the excess waits in the
link's queue in the node. The queue's fill marks the replies passing back
over the link, and the SCION library paces the node's traffic to each
destination at a rate the marks in its own probes' replies cut, as DCTCP
cuts its window. The probe and its reply, of SCMP types no specification
assigns, are the new wire elements; no stored field or run argument changes.

[TOC]

## Summary

Today:

*   **Nothing reacts to a full buffer but the hosts.** A node sends as fast
    as its sockets accept: each link's egress queue of 64 packets
    ([udpip.go](/pkg/core/dataplane/udpip.go)) drains as fast as the socket
    takes them, and the backlog builds in the router's buffer, which drops.
    In the hub lab
    ([proposal 0136](/docs/proposals/0136-give-the-labs-uplinks-a-bandwidth.md)),
    every packet through the hub waits out that buffer: the hub's own flow
    waits 158ms at the 95th percentile under load, and 254ms once its
    uplink's rate falls.
*   **No packet is ECN-capable,** and no node marks.
*   **Probes measure whole paths.** The ping application
    ([prober.go](/pkg/apps/ping/prober.go)) probes the paths requesters
    publish by SCMP echo, within a budget of 20 probes a second, each hot
    path in use every five seconds where no caller confirmed it, and
    publishes round trips and losses. Transit forwarding
    ([processor.go](/pkg/core/dataplane/processor.go)) never reads past the
    SCION header, and a destination's data plane drops SCMP informational
    messages other than echo and traceroute.

This proposal adds:

*   **A probe and its reply:** SCMP informational types 200 and 201, laid out
    in a new library. The reply carries one stamp: when the node that last
    wrote it passed the probe, and when it passed the reply.
*   **Hop records and stamps.** The data plane keeps, for two seconds, when
    it passed each probe and over which link. As a reply passes back, it
    reads the stamp the node after it wrote, measures the link between them
    each way, hands both delays to the congestion module, and writes its
    own stamp.
*   **A congestion module** that rules each link's egress queue. It reads
    the link's forward queue: the least of its last four delays over the
    least of the last minute. While that stands over 15ms, it brakes the
    link, draining its egress queue at a rate it cuts in proportion to how
    far over the reading stands, and lets go once the link reads clean.
    While the egress queue holds packets, it marks as large a share of the
    replies passing back over the link as the queue is full.
*   **ECN-capable sends.** The library's sockets set ECT(0) on every packet.
*   **Probes that follow traffic.** The library counts the packets the
    node's sockets send to each destination node and publishes the counts,
    with the path the last packet rode, on the node's bus. The ping
    application probes that path on each hundred packets, at most every
    10ms, and every five seconds while traffic flows.
*   **Destination rates.** The library keeps a rate for each destination
    node, unset until a reply to one of the node's traffic probes comes back
    marked. It averages the share of replies marked, cuts the rate by half
    that share on a marked reply to a probe sent after its last cut, and
    climbs while the replies come back clean. While a rate is set, a write
    whose turn lies more than 100ms ahead is dropped.
*   **Lab cases for the brake:** downlinks in the fabric, and labs for a
    queue past one neighbor, traffic moving between links, a node with one
    link, a path that crosses two queues, and jitter on a loaded link.

## Motivation

ADR-0043 found that a node's uplink fills outside the node, that nothing
tells the senders crossing it, and that paths weigh no load. A first build
marked the replies from the probes' delays themselves and halved each
source on its first marks; in the hub lab, the delays of the hub's 1 Mbit/s
uplink stood over the target while the load fit, and the sources cut flows
the line carried. Cut in proportion to the marks, the sources kept the hub's
transit whole, but in the flow lab a full buffer lost the probes, and the
cuts had not caught up after a minute in four runs of ten. The record now
has each link brake on its delay, a reaction local to the node, and marks
the replies from the queue the brake fills, which the node knows exactly
(decisions 2, 3, and 10).

### Goals

*   Under a load past a link's capacity, the link brakes within seconds,
    the buffer beyond the node drains, and the excess waits or drops in the
    node until the sources' rates settle.
*   The sources whose probes cross a braked link slow; a node whose traffic
    crosses none sends as it does today.
*   Jitter that leaves some probes fast brakes no link; a queue on a link's
    way back slows no traffic crossing it the other way.
*   A link that reads clean lets go of its brake, and its sources' rates
    climb, then unset.
*   Nodes without this proposal keep working beside those with it.

### Non-goals

*   No hot paths, lease moves, transit shedding, or bought capacity on
    marks: decisions 4 to 8.
*   No marks from the underlay's routers (RFC 6040): a later step.
*   No breaker for a node that does not slow.
*   No configured rate, and no run argument.

## Proposal

### The probe and its reply

A new library, `pkg/libs/probe`, lays out both messages after the SCMP
header's type, code, and checksum:

| Type | Message | Body                                                     |
| :--- | :------ | :------------------------------------------------------- |
| 200  | Probe   | Identifier (2 bytes), sequence (2 bytes)                 |
| 201  | Reply   | Identifier, sequence, probe stamp (8 bytes), reply stamp (8 bytes) |

The code is 0. The identifier is the probing socket's port, as in an echo,
so the data plane delivers the reply to that socket. A stamp counts
nanoseconds since the Unix epoch, big-endian, and is absent when zero. The
library reads and writes both messages, and updates an SCMP checksum for the
words a node rewrites (RFC 1624).

### Sending and reading

*   **ECN-capable sends.** `scionHeader` sets ECT(0) in the traffic class of
    every packet a socket writes, beneath the control DSCP on control
    sockets. Only nodes read these bits, as no host sees a SCION header.
*   **Probes and replies.** A socket writes a probe with `WriteProbeTo` and a
    reply with `WriteProbeReplyTo`, whose stamps it leaves absent. The echo
    reader returns probes and replies beside echoes: `Echo` gains `Probe`,
    true for types 200 and 201, and `Marked`, true when the packet arrived
    with CE. It records an interface-down signal quoting a probe as it does
    one quoting an echo.

### Hop records and stamps

The data plane reads the probes and replies that pass through it, in
transit, from the node's sockets, or to them, after it has validated the
packet's path:

*   **A probe passing** is recorded under its source address, identifier, and
    sequence, with the processor's batch clock and the link it leaves by:
    none when the probe is delivered to the node. The record holds 1024
    entries, drops the oldest beyond them, and forgets an entry after two
    seconds.
*   **A reply passing** looks up the record under its destination address,
    identifier, and sequence. If it arrived over the link its probe left by,
    the forward delay is the reply's probe stamp less the record's clock,
    and the reverse delay is the batch clock less the reply stamp; an absent
    stamp skips its delay. The data plane hands the delays to the
    congestion module and marks the reply if the module says so (below). If
    the reply leaves over a link, the data plane then writes its own stamp,
    the record's clock and the batch clock, and updates the checksum. A
    reply without a record carries an absent probe stamp.
*   **Delivery.** `getDstPortSCMP` delivers a probe to the responder's port,
    a reply to its identifier, and an SCMP error quoting a probe to the
    quoted identifier, as it does an echo's.

Probes and replies stay in the control class. Since the clocks of a link's
two ends differ by an offset, a delay is read only against the least the
same link has shown; a node never compares two links' delays.

### The congestion module

A new module, congestion (`pkg/modules/congestion`), a policy the
composition root binds as it binds the beacon policy, rules what leaves each
link's egress queue and what the queue's fill tells the sources. It
implements the data plane's `Congestion` interface: the data plane hands it
each measurement and what each link writes, asks it each link's rate, and
asks it whether to mark each reply, given the fill of the egress queue of
the link the reply came back over. It outlives the data plane's
generations, so a link keeps its readings and its rate across them.

*   **Readings.** For each link and direction, the module keeps the least
    delay of the last minute, in buckets of ten seconds, and the last four
    delays. The link's queue is the least of the four over the minute's
    least: jitter that leaves one probe in four near the least reads as no
    queue, and a step in the link's base delay, from a route's change or the
    clocks' drift, reads as queue for a minute at most.
*   **The target** is 15ms, or two of the gaps between the packets the node
    writes where those are longer: a probe sent just behind its traffic's
    packet waits for it on the line, 17.7ms on a 500 kbit/s line. The module
    measures the gap from the links' writes, over a second at least.
*   **The rate.** Once a second, each link whose forward queue stands over
    the target gets `(1 + target/queue)/2` of what it wrote in the last
    second, or of its rate where that is lower: Swift's cut with a β of one
    half, a few percent just over the target and nearly half far over it.
    No rate falls under 64 kbit/s. A link whose readings have stayed under
    the target for a second loses its rate. The module logs each brake set
    and released.
*   **The marks.** For each reply that comes back over a link, the module
    adds the fill of the link's egress queue, the packets it holds as a
    share of the 64 it can, to what the link owes in marks; a reply that
    finds a mark owed is marked, and the link owes one less. The marks keep
    the queue from filling rather than its wait short: the fuller it gets,
    the more replies are marked, and the sources slow before it drops.

The data plane paces each link's sender at its rate: it writes the link's
data from the egress queue only as the rate allows, while the control
queue, which carries the probes and replies, skips the pacing but counts
against the rate. With no rate, a link writes as it does today, and its
egress queue holds nothing to mark. A packet that finds the egress queue
full drops, as it does today. A reply the module marks gets CE in its
traffic class if it is ECN-capable.

### Destination rates

The library's ECN state, one per node and shared by every socket, keeps for
each destination node:

*   **What the node sent there.** Each write that a socket other than a
    control one makes, and the pacing lets through, counts its bytes in a
    tick of 100ms. The rate's base is the most bytes the node sent there in
    any second of the last ten. The destination's count of packets, with the
    path the last of them rode, goes on the node's bus at its first packet,
    at every hundredth, and at the first one five seconds after the last
    update.
*   **The answers.** The ping application hands the state each reply to a
    traffic probe, with whether it came back marked and when its probe was
    sent. The state averages the share of replies marked, as DCTCP averages
    its marked share, with a gain of 1/16 from a start of zero.
*   **The rate.** A marked reply to a probe sent after the last cut cuts the
    rate to `1 - average/2` of the lesser of the rate and the base, or of the
    base where no rate was set, never under 64 kbit/s; a destination whose
    base lies under 64 kbit/s gets no rate. At each tick after a clean
    reply, the rate climbs by 1/256, to at most twice the base. A rate
    unmoved for 30 seconds unsets.
*   **Pacing.** While a rate is set, a write whose turn lies more than 100ms
    ahead is dropped, never queued. Control sockets and SCMP messages are
    not paced, so no probe the rate drops reads as a loss.

The ticks close as the next write or answer arrives, since a library runs no
loop. The state logs each rate set and unset.

### Probes that follow traffic

The ping application subscribes to the counts. When a destination's count
has grown by a hundred since its last traffic probe, at least 10ms ago, or
has grown at all five seconds after it, the application probes the path the
destination's last packet rode with a probe of type 200; a one-hop path is
not probed. These
probes draw on no budget, since the traffic bounds them; they publish no
round trip or loss, so a path's health stays as ADR-0035 judges it; and a
probe unanswered within the probe wait counts for nothing. Each reply goes
to the destination's rate. The application's other probes stay echoes.

### The responder

The responder answers a probe with a reply carrying the probe's identifier
and sequence, beside the echoes it answers today.

### The labs

*   **Downlinks.** The fabric gains a host's downlink, a rate and a finite
    queue on what it receives, as proposal 0136's uplinks are on what it
    sends.
*   **The flow lab judges the loop,** on a 2 Mbit/s uplink, where a packet
    takes 4.5ms on the line. Its first phase, one flow at a third of the
    line, keeps its bounds. In its second, with a second flow at twice the
    line, the uplink's mean wait stays under 40ms against its 100ms bound
    once the sources' rates settle.
*   **A queue past one neighbor:** a node sends to two neighbors, one behind
    a thin downlink; only the link toward it brakes and marks, and the flow
    to the other keeps its rate.
*   **Traffic moving between links:** a flow over a braked link moves to
    another link; the first link's brake lets go within seconds, and the
    second brakes only once it congests.
*   **A node with one link:** its link brakes under its own flow, the flow
    slows on the marks, and its control traffic passes.
*   **A path that crosses two queues:** both links brake and mark, and the
    lab records how far the source slows past what the thinner asks.
*   **Jitter on a loaded link:** a flow that fits crosses a link with
    jitter; the link brakes seldom and the flow arrives nearly whole.
*   **The hub lab** runs its two benchmarks against today's.

### Packages touched

| Package                | Change                                                    |
| :--------------------- | :-------------------------------------------------------- |
| `pkg/libs/probe`       | New: the probe's and reply's layout, stamps, and checksum update |
| `pkg/libs/bus`         | The counts of packets sent to each destination, with their last path |
| `pkg/libs/scion`       | ECT(0); probes and replies written and read; the destination rates, counts, and pacing |
| `pkg/core/dataplane`   | Hop records and stamps; each link's paced sender and write count; marks on replies; delivery of probes and replies |
| `pkg/modules/congestion` | New: the links' readings, rates, and marks              |
| `pkg/apps/ping`        | Probes that follow traffic; replies handed to the rates   |
| `internal/services`    | The congestion module bound in the assembly; the responder's replies; the ECN state handed to every socket |
| `internal/testnetwork` | Downlinks; the lab cases; the flow lab judges the loop    |

`docs/design/architecture.md` names the probes, the stamps, the congestion
module, and the rates.

## Compatibility

*   **The probe and its reply** take SCMP informational types 200 and 201,
    which scionproto sets aside for experiments; the control-plane draft has
    a node drop informational types it does not know.
*   **Older nodes** forward probes and replies in transit unread, so the node
    before one reads the links on either side of it as one. An older
    destination drops a probe, so no reply returns and the traffic to it is
    never paced. Older nodes send nothing ECN-capable, probe by echo alone,
    and never brake.
*   **Health is unchanged:** the probes that measure it stay echoes.
*   No stored field or run argument changes.

## Test plan

*   **The probe library:** both layouts round-trip; absent stamps read as
    absent; the checksum after a rewrite equals the one computed afresh.
*   **The library,** on virtual time: ECT(0) on every write, beneath the
    control DSCP; probes and replies written and read, with `Marked`; unset
    rates write at once; a stray marked answer cuts little, and the cut
    deepens as the average does; an answer to a probe sent before the last
    cut cuts nothing; clean answers climb to twice the base; 30 seconds
    unmoved unsets; a write whose turn lies past 100ms is dropped; control
    sockets and SCMP write at once; the counts go out at the first packet,
    every hundredth, and after five quiet seconds.
*   **The data plane:** a probe in transit, from the node, and to it leaves
    a record; a reply reads the stamp after it, hands both delays, and
    writes its own stamp with a valid checksum; a reply over another link
    than its probe's, or without a record, hands nothing; records expire
    and stay within their bound; a paced link writes its data at its rate,
    its control at once, counted against the rate; a reply the module marks
    gets CE only when ECN-capable; probes, replies, and errors quoting probes
    reach their sockets.
*   **The congestion module,** on virtual time: delays at the least set no
    rate; the least of four over the target sets `(1 + target/queue)/2` of
    what the link wrote, and each further second over cuts again; one fast
    probe in four keeps the link clear; a second clean releases; the least
    ages out after a minute; the target follows the gaps between the node's
    packets where those are longer; the share of replies marked follows the
    egress queue's fill.
*   **The ping application:** a hundred packets probe the last path, at
    most every 10ms, and five quiet seconds probe once; replies reach the
    rates and publish no sample; echoes go on as today.
*   **The labs:** the flow lab and the lab cases in CI; the hub benchmarks
    against today's.
