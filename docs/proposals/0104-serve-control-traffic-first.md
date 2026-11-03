# Serve control traffic first

This proposal implements
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 8:
on every link, on egress and on ingest, the data plane serves BFD, SCMP, and
the control-plane traffic the node itself sends before data, and caps that
class so it cannot starve data. The ADR's other decisions land through
proposals of their own.

[TOC]

## Summary

Today:

*   **Ingest shares one set of queues.** A link's receive loop hands every
    arrival to the processor queue its flow hashes to, and a full queue drops
    it as a busy processor (`receive`,
    [udpip.go](/pkg/core/dataplane/udpip.go)). A peer's BFD packets, SCMP
    echoes and signals, and the node's own control calls wait and drop with
    data.
*   **Egress has one queue per link.** The processors queue each forwarded
    packet on its egress link's queue, 64 deep, dropping it when full, and the
    link's sender writes the queue in batches, in order (`Send`, `send`). BFD
    alone skips it: a session writes its prebuilt packets on the link's own
    socket (`WriteRaw`).
*   **The slow path answers through the same queue.** Interface-down signals
    and the other SCMP errors leave through the ingress link's queue
    (`runSlowPathProcessor`, [dataplane.go](/pkg/core/dataplane/dataplane.go)).
*   **Nothing marks control traffic.** The node's sockets send every packet
    with traffic class zero (`scionHeader`,
    [conn.go](/pkg/libs/scion/conn.go)).

So an overloaded node drops what judges its links and paths: a peer's BFD
packets wait behind data at the receiver until the link's verdict falls, and
echo probes and interface-down signals drop with the data they report on.

## Motivation

### Goals

*   BFD arrivals reach their link's session whatever the data queues hold.
*   SCMP, and the control-plane traffic the node itself sends, queue apart
    from data on ingest and on egress, and go first.
*   While data waits, control takes at most a quarter of a link's sends, and
    a flood of control never takes data's queue room.
*   The forwarding cost per packet stays within noise.

### Non-goals

*   Marking the underlay's own header: the IP DSCP waits for the load
    decision.
*   Classing other nodes' control calls, in transit or arriving here: the ADR
    keeps the class to SCMP in transit.
*   The applications' conns: they stay data, the voting submitter's and the
    WireGuard directory client's calls included.
*   Counters per class: control drops count in the existing counters.
*   Packets the kernel drops before the receive loop reads them.
*   Congestion marks and queue management, which the load decision takes.

## Proposal

*   **Three classes at ingest.** A link's receive reads two fields of the
    SCION common header before it queues an arrival, the next header and the
    traffic class:
    *   *BFD*, next header BFD: the receive loop decodes the message and
        hands it to the link's session itself, as the processor does today,
        and returns the buffer. BFD then skips every queue on ingest, as
        `WriteRaw` has it skip them on egress.
    *   *Control*, next header SCMP from any link, or the control DSCP in the
        traffic class on the internal link alone, whose only senders are the
        node's own sockets: the arrival goes on the control queue, which one
        processor of its own serves beside the data processors, with the
        first slow path processor's queue as its slow path.
    *   *Data*, everything else: the processor queue its flow hashes to, as
        today.

    A full control queue drops the arrival as a busy processor, as a full
    data queue does. A BFD message behind an extension header reaches the
    processor's BFD branch as data, as it does today.
*   **Two queues per link at egress.** A packet keeps its class through
    processing, in the packet's last padding byte, and the processor queues a
    control packet on its egress link's control queue, as deep as the data
    queue. The sender builds each batch from control first, at most a quarter
    of the batch, then data, then more control if data ran dry. The batch's
    first packet, which the sender blocks for, may be of either class.
*   **The slow path answers as control.** Every packet the slow path sends
    back is SCMP, so it queues on the ingress link's control queue.
*   **The node marks its control-plane sockets.** The SCION library's conn
    takes a control flag that sets the control DSCP, CS6, in every packet's
    traffic class. The node sets it on the conns of the control plane, the
    bootstrap client, the echo responder, and the topology source, and leaves
    the applications' conns unmarked. The DSCP lives in the underlay library,
    which the data plane and the sockets share.
*   **The packet pool grows** by one processor queue and one control queue
    per link, so the receive loops never wait on a pool the queues hold.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/core/dataplane` | The classes at ingest, BFD in the receive loop, the control processor and queues, the sender's order, the slow path's class, the pool |
| `pkg/libs/underlay` | The control DSCP |
| `pkg/libs/scion` | The conn's control flag |
| `internal/services` | Which conns are control |

## Compatibility

The node's own control packets carry CS6 in the SCION traffic class. A
receiving node classes arrivals from its neighbors by their next header
alone, so nothing changes in what a node forwards, answers, or admits.

## Test plan

*   **The classes.** A table over the classifier: SCMP from an external link
    and from the internal link is control; BFD over a one-hop and an empty
    path is BFD; UDP carrying CS6 is control from the internal link and data
    from an external one, its ECN bits ignored; unmarked UDP, and a packet
    shorter than the common header, are data.
*   **BFD skips every queue.** With the data processor queues and the control
    queue full, a BFD arrival on an external link reaches its session.
*   **Control skips busy processors.** With the data processor queues full,
    an SCMP arrival on an external link and a CS6 arrival on the internal
    link land on the control queue, and a data arrival drops as busy.
*   **A control flood leaves data's room.** With the control queue full, a
    control arrival drops and a data arrival lands on its processor queue.
*   **The sender takes control first.** With the writer held and both queues
    full, the first full batch carries control ahead of data, at most a
    quarter of the batch plus the packet it blocked for; with data empty,
    control fills a batch, and with control empty, data does.
*   **Control survives a full data queue.** With the data egress queue full,
    a data packet's send fails, a control packet's succeeds, and the control
    packet leaves in the next batch.
*   **The slow path answers as control.** The interface-down answer to a
    packet for a down link queues on the ingress link's control queue.
*   **The conn marks.** A control conn's datagrams and echo requests carry
    CS6, and an unmarked conn's carry zero.
*   **End to end.** The two-node echo test and the interface-down tests pass
    through the control processor unchanged.
*   **Cost.** `BenchmarkForwardPipeline` and `BenchmarkProcessPkt` stay
    within noise of the baseline.

## Implementation history

*   Landed as proposed: the classes and the BFD reader
    ([class.go](/pkg/core/dataplane/class.go)), the links' queues and the
    sender's order ([udpip.go](/pkg/core/dataplane/udpip.go)), the control
    processor, the slow path's class, and the pool
    ([dataplane.go](/pkg/core/dataplane/dataplane.go)), the conn's mark
    ([conn.go](/pkg/libs/scion/conn.go)), and the node's control conns
    (`controlConn`, [controlplane.go](/internal/services/controlplane.go)).
    The class the plan calls BFD is the link class in the code: the link's
    own exchange, which only BFD is today. The classifier reads the next
    header alone, so the paths BFD rides are checked where the receive loop
    decodes it: a one-hop or an empty path's message reaches the session,
    and a SCION path's does not. Interleaved runs of
    `BenchmarkForwardPipeline`, twelve a case, put the change at 0.0% by
    geometric mean, and `BenchmarkProcessPkt`, whose code it leaves alone,
    stayed within noise.
