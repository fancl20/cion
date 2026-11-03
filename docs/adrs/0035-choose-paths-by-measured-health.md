# Choose Paths by Measured Health

*   Status: proposed
*   Date: 2026-11-03

[TOC]

## Context and problem statement

A node chooses paths without state. The path provider, the SCION library's
seam
([ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md),
decision 1), composes the stored segments into candidates on every call and
ranks them: fresh before stale, then by declared delay, then by hop count.
What it knows of failure is per link: the BFD verdict of the node's own
links, and the interface-down signals of remote routers, each setting aside
the paths through its link for ten seconds
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
decision 13). This has four costs:

*   **Dead paths stay first.** A path through a link that died elsewhere
    ranks first until its segments read stale, five minutes after the
    beacons stop refreshing them. A signal holds it off for ten seconds at
    a time, and between signals traffic returns to it. A sender never sees
    a send error: its packets reach the local router whatever lies beyond.
*   **What traffic rides is not what is judged.** Control clients resolve a
    path when they dial and keep the connection for minutes, the WireGuard
    gateway keeps its own path per peer, ping keeps one for a run, and the
    labs grade the provider's pick
    ([ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md)).
*   **Only the topology selection measures routes.** It echoes each peer's
    freshest route and the routes that avoid each of its links, once a
    window, for its own comparator (ADR-0017, decisions 14 and 16). Nothing
    it learns reaches path choice, nothing measures the paths traffic
    rides, and a node whose links come from a file measures nothing.
*   **Overload reads as failure.** BFD packets share the receive queues
    with data, and signals and echo replies wait in the data queues. A
    congested link loses the packets that judge it: its verdict turns down,
    and probes across it go unanswered.

The control-plane draft splits path selection in three: each AS selects the
beacons it propagates, then the segments it registers, and the endpoint
selects among the paths a lookup returns (Section 8.3.4). The last step is
the sender's. Every sender in CION today runs inside a node: hosts are plain
tailnet clients, and ADR-0005 linked the path library into the node's
process with no path service for anything else. The node chooses for its
control clients, for ping and punch, and for the WireGuard tunnels that
carry its hosts' traffic, and these want different things: a control call
wants the fastest healthy path and rarely moves, while bulk egress may want
its flows spread.

How should a sender choose each flow's path from evidence of health, where
does the evidence come from, and what keeps it alive under load?

## Decision drivers

*   **Fail over on evidence:** a path that stops delivering leaves service
    within seconds, and returns when probes answer, not when a timer lapses.
*   **The sender chooses:** per flow, by the sender's own policy, as the
    drafts intend.
*   **One view, one instrument:** every sender in a node reads the same
    health, and one budget of probes serves every requester, the topology
    selection included.
*   **Judge what traffic rides:** the path a flow uses is the path measured
    and graded.
*   **Bounded cost:** probes go only where traffic leaves a gap; an idle
    destination costs nothing.
*   **Signals prompt, never steer:** an unauthenticated signal costs a
    probe, not a switch.
*   **Minimal core:** the core keeps what the network depends on; a node
    without the instrument still serves.

## Considered options

Where path choice lives:

*   **The core:** one path manager per node.
*   **A policy module:** one implementation per node, the operator's choice.
*   **The SCION library, at the sender:** each caller passes its policy with
    its flow.

Where measurement runs:

*   **In the path library:** each instance probes on its own.
*   **In the topology selection:** the library reads its results.
*   **In a resident application:** one prober measures what every requester
    asks for, over the node bus.

How control traffic meets overload:

*   **In the data queues,** as today.
*   **In a control class served first.**

## Decision outcome

Chosen options: **the SCION library, at the sender**, measurement **in a
resident application**, and **a control class served first**, realized as
follows:

1.  **Path choice is the sender's, in the SCION library.** Beside the path
    provider, the library keeps path sets per destination, health per path
    and per link, and leases. It runs no loop and decides no policy: each
    caller passes its own with a lease, and the library evaluates state
    when it is called, as
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)'s
    decision 2 requires of a library. The node's assembly builds one
    instance for every sender the node runs (the control clients, the
    applications, and the topology source), so they share one view. An
    endpoint outside the node would build its own. This narrows ADR-0005's
    decision 1: the library holds state beside the provider.
2.  **A path is its links.** A path's identity is the sequence of (ISD-AS,
    interface) pairs it crosses, which segment refreshes keep, so its
    record outlives them. Evidence on a path lands on its links too: when
    the paths through one link fail together while the paths avoiding it
    answer, the link is suspect, and so is every path through it. A
    standby shares no link with the path it stands by, where the paths
    allow.
3.  **Health decides service; cost orders the healthy.** A path is
    unknown, healthy, suspect, ejected, or half-open. Every path that
    delivers is healthy, a lossy one included. A suspect path keeps its
    leases and takes no new ones until a verification decides. A path is
    ejected only when a whole verification burst goes unanswered, or when
    loss across a window is near total; it is probed again after a backoff
    that doubles with each relapse, and returns when the probes answer.
    Among healthy paths the cost is the measured round trip raised by
    loss, the declared delays standing in until a path is measured. Stale
    segments make a path suspect, not dead.
4.  **Evidence comes from callers, probes, signals, and links.** A caller
    reports what its traffic saw: an exchange completed, a timeout, a
    round trip. A refusal, such as a handshake that refuses a chain or a
    rejected beacon, shows a delivering path, never a loss. An
    interface-down signal (control-plane draft, Section 6.5.2) makes the
    paths through its link suspect and prompts a verification; it moves no
    lease by itself. This realizes ADR-0017's decision 13, under which
    probes are the authority and the signal a prompt, in place of the
    fixed hold. A link down or retired at the node takes its paths out at
    once, as composition does today.
5.  **A flow holds a lease while its path serves.** A lease is per peer:
    every connection to one control peer shares it, so their evidence
    pools and they ride one path. A lease keeps its path while the path
    is not ejected, and moves when it is, or when another healthy path
    costs less by a margin across two evaluations. A caller may ask for
    near-best spreading instead: its leases to one destination choose
    among the healthy paths within the margin of the best, never per
    packet. A datagram caller reads its lease per packet; a connection
    rides the path it was dialed over, and a lease that moves dials anew.
6.  **A resident application measures what is requested.** The ping
    application becomes resident, with one loop and one budget of probes
    per node. Requesters publish what they need measured on the node bus
    ([ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)):
    the library its leased paths, each with when a caller last confirmed
    it, their standbys, its suspects, and when an ejected path is due for
    its half-open probe; the topology selection its baseline and excluded
    routes. The application probes each path once for all of them, by
    SCMP echo end to end to the destination's responder (Section 6.6.1),
    verifies the requested paths through a link a signal names, and
    publishes each path's round trips, losses, and last answer on the bus.
    It skips a leased path a caller confirmed recently, and an idle
    destination gets no probes. This narrows ADR-0017's decisions 14 and
    16: the topology selection keeps what measures a link (the binding
    requests and punch probes to candidates, the one-hop echo to each
    neighbor, and the delays the beacons declare) and requests its route
    measurements.
7.  **Without the application, a node serves on passive evidence.** The
    zero-conf default loads it
    ([ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)).
    A node whose list leaves it out chooses from callers' reports,
    signals, and link state over composition's order, and its topology
    selection prices routes by their declared delays, leaving undecided
    what needs a route measurement.
8.  **Control traffic goes first.** On every link, on egress and on
    ingest, the data plane serves a control class before data: BFD, SCMP,
    and the control-plane traffic the node itself sends. The class is
    capped, so it cannot starve data. Overload then drops data, not the
    packets that judge links and paths.
9.  **The labs judge the leased path.** The chosen path ADR-0025 grades is
    the path a lease holds.

### Positive consequences

*   A path that stops delivering leaves service within a heartbeat and a
    verification burst; a recovered one returns when probes answer.
*   Every sender in a node, the topology selection included, reads one set
    of measurements paid from one budget, so forming links and serving
    traffic price a route the same way.
*   A signal, forged or lapsed, costs a probe; no lease moves on a signal
    alone.
*   The library stays a library: an endpoint outside the node can link it.
*   The labs grade what traffic rides.
*   Overload no longer turns link verdicts down or loses probes.
*   A node whose links come from a file gains measured paths.

### Negative consequences

*   A node probes: each leased path and its standby, every few seconds
    where traffic does not confirm them. Probe traffic grows with the
    destinations in use.
*   Measurement is optional: a node without the application loses fast
    failover and recovery, and its topology selection decides less.
*   The library fails over only to paths that beaconing kept. Today's
    selection of the freshest beacons does not ensure a disjoint standby;
    beacon selection is a separate decision, to be judged by recovery
    after a cut.
*   Probes in the control class measure a path's delay without the data
    queue, so congestion shows only in callers' timeouts and losses. Load
    (congestion marks, congestion control per link, spreading by load) is
    left to a later decision, after a lab with links of unequal capacity.
*   At transit the class holds SCMP alone: other nodes' control calls
    cross as data, and an SCMP flood within the cap crowds out other
    nodes' probes and signals, though never data.
*   A lease that moves costs each of its connections a new handshake.
*   An endpoint outside the node measures for itself: the node offers no
    path service beyond its process, as ADR-0005 decided.
*   The bus grows two topics: requests and measurements.

## Pros and cons of the options

### The core

*   Good, because the control clients reach it without injection.
*   Bad, because path choice is the sender's, not what the network depends
    on whatever the node's policy, which is what the core holds
    (ADR-0009).
*   Bad, because one manager imposes one policy on every sender.

### A policy module

*   Good, because a second policy would have an obvious home.
*   Bad, because a policy module is the operator's, one per node
    ([ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)),
    while the policy differs per flow.
*   Bad, because an endpoint outside the node cannot use it.

### The SCION library, at the sender

*   Good, because it is the drafts' model: the endpoint selects.
*   Good, because the policy travels with the flow, and any endpoint can
    link the library.
*   Bad, because only the instance the node builds is shared: an outside
    endpoint keeps its own view.

### In the path library

*   Good, because nothing else needs to run.
*   Bad, because a library with a loop has become an application
    (ADR-0009, decision 2).
*   Bad, because each instance probes on its own, and the library and the
    topology selection would measure the same routes twice.

### In the topology selection

*   Good, because the selection already echoes routes.
*   Bad, because a node whose links come from a file runs no selection,
    and the selection's targets and cadence (each peer's freshest route,
    once a window) miss the paths flows lease.

### In a resident application

*   Good, because one loop and one budget serve every requester, and the
    library keeps no loop.
*   Good, because the core stays minimal: a node without it still serves.
*   Bad, because measurement becomes optional, and requests and results
    cross the bus.

### In the data queues

*   Good, because nothing changes.
*   Bad, because overload loses the packets that judge links and paths.

### In a control class served first

*   Good, because overload drops data, never the packets that judge links
    and paths.
*   Bad, because the class needs a cap, and SCMP from any sender enters it.
