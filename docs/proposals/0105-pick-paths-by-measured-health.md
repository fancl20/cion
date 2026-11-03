# Pick paths by measured health

This proposal implements
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decisions
2, 3, and 7, decision 4 but for the callers' reports, and decision 6 but for
the topology selection's route requests. The SCION library keeps each path's
health from the measurements of a resident ping application, which probes
what the library's picks ask it to over the node bus, and the picks follow
health. Leases and the callers' reports land through a proposal of their own,
and so do the selection's route requests.

[TOC]

## Summary

Today:

*   **Picks rank without state.** `Choose` ranks every candidate
    `Enumerate` composes by `Outranks`: fresh before stale, then declared
    delay, then hops; `LocalPath` ranks the up segments containing the
    destination the same way ([provider.go](/pkg/libs/scion/provider.go)).
    An interface-down signal marks the candidates crossing its link for ten
    seconds (`InterfaceDownHold`, [ifdown.go](/pkg/libs/scion/ifdown.go)).
    A path through a dead link ranks first until its segments read stale,
    five minutes on: the regions lab recovered from a cut in 279 to 309
    seconds
    ([proposal 0087](/docs/proposals/0087-publish-interface-down-signals-on-the-node-bus.md)'s
    history).
*   **Who picks.** `Choose`, through `Path`, serves ping and punch, and the
    labs grade it. `LocalPath` serves the control plane's dials, the founder
    and issuer routes, and WireGuard's cold cache and directory dials.
    WireGuard's mesh route and the topology selection rank `Enumerate`'s
    candidates themselves.
*   **Only the selection measures routes,** for its own comparator. Ping is
    the one-shot client behind `cion ping`.

## Motivation

### Goals

*   A path a pick depends on that stops delivering leaves the picks within
    one heartbeat and a verification burst, and returns at its next
    half-open probe once it delivers again.
*   The picks follow measured health and measured round trips, and today's
    order where nothing is measured.
*   Probes go only to the destinations the picks asked about in the last ten
    minutes, often only for those asked about in the last minute, within a
    node-wide budget: a node's probes grow with the destinations it uses,
    not with the network.
*   A node without the ping application picks as today.

### Non-goals

*   Leases, stickiness, and the callers' reports: the next proposal, which
    also moves WireGuard's mesh route onto the picks.
*   The topology selection's route requests: until a proposal of their own,
    it echoes its routes itself.
*   Changing `Outranks`, `Crossing`, or the ten-second hold: WireGuard's
    route pick and the selection read them.
*   A control-marked conn for the ping application: its echoes are control
    by protocol, and its service resolution rides as data.
*   Load.

## Proposal

*   **A path's identity.** Composition gives each candidate an ID: the
    (ISD-AS, interface) pairs its packets cross, in order. That is its links
    less the core-ward interface of each part's turning entry, which no
    packet crosses. The bootstrap route has none and is never measured.
*   **Two bus topics** ([bus.go](/pkg/libs/bus/bus.go)):
    *   *Path requests*: each requester's entries, updated by the requester
        alone, as the conns update the interface-down topic. An entry names
        a path's ID and links, its destination, the path to probe it over,
        its role (in use, standby, or half-open with the time its probe is
        due), and the time of the destination's last pick.
    *   *Path measurements*, which the ping application publishes: per path
        ID, its destination and links, its last twenty probes (time, round
        trip or loss), its last answer and last loss, and the bursts lost
        whole since its last answer.
*   **Health,** evaluated at each pick from the topics' last events. A
    candidate's health is the first of:
    1.  *ejected*: a burst lost whole since its last answer, or nine in ten
        of at least ten recent probes lost;
    2.  *suspect*: an interface-down signal held on a link it crosses and
        newer than its last answer;
    3.  *healthy*: an answer within three minutes, three of the slowest
        probes;
    4.  *suspect*: stale segments, or a crossed link whose measured paths
        are all ejected while some measured path avoiding it answers;
    5.  *unknown*.

    A path's cost is its median measured round trip divided by its delivery
    rate, loss counted up to nine in ten; an unmeasured path has none.
*   **The picks.** `Choose` and `LocalPath`'s containing branches take the
    best candidate by health (healthy, unknown, suspect, ejected), then by
    cost where both are measured and differ by more than 20% and 2 ms, then
    by `Outranks`. The band keeps near-equal round trips from flipping the
    picks. `Enumerate` fills each candidate's health and cost and keeps its
    order.
*   **Requests.** Each `Choose` and `LocalPath` updates the library's
    entries for its destination: the pick, in use; the best other candidate
    sharing no link with it, else the best other, standby; and the best
    ejected candidate whose prior order beats the pick, half-open after its
    backoff, ten seconds doubling with each lost burst up to a minute. Every
    entry carries the pick's time. Entries lapse ten minutes after the
    destination's last pick, and the library drops lapsed entries at its
    next update. A provider without the topics updates nothing.
*   **The ping application becomes resident** (entry `ping`), loaded by
    inference on every node. Its loop:
    *   probes each requested path by SCMP echo to the destination's
        responder, whose host it resolves over the path on a conn of its
        own, once per destination and again after a lost burst;
    *   paces each path by its destination's last pick. While the
        destination was picked within the last minute, its in-use path is
        probed every five seconds and its standby once a minute; for the
        nine minutes after, its in-use path is probed once a minute, and its
        standby not at all. A half-open path gets a burst of five probes
        over a second at its due time, and a lost probe of an in-use path,
        and an interface-down signal on a link a requested path crosses,
        call a burst for that path;
    *   keeps a node-wide budget of twenty probes a second, spent on bursts
        first, then half-open probes, heartbeats, and the once-a-minute
        probes;
    *   publishes the measurements as each probe settles, and forgets a path
        ten minutes after its last request.

    The heartbeat bounds how long a silent failure of a path in use goes
    unseen, at six seconds with its burst; a signal from the router before
    the failure calls the burst sooner. Once a minute matches the cadence at
    which registrations and lookups refresh the segments the candidates are
    composed from, so a slower probe would describe a candidate set that has
    since changed, and a faster one buys little for a destination nothing
    is sending to. Ten minutes is the age at which a pooled connection
    redials, so a destination dialed once stays measured until its next
    dial. The one-shot client behind `cion ping` stays.
*   **Assembly.** The provider takes the two topics; the application's
    environment already carries the bus and its conns.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | The path requests and measurements topics |
| `pkg/libs/scion` | The identity, health, the picks' order, the requests |
| `pkg/apps/ping` | The resident prober |
| `pkg/apps` | The `ping` entry |
| `internal/services` | The provider's topics |

## Compatibility

Every node already answers echoes at its responder. The probes add echo
traffic toward the destinations a node picks paths to; nothing on the wire
changes.

## Test plan

*   **Identity.** A meeting's and a containing branch's IDs carry the
    crossed interfaces alone, and two compositions of one route share an ID.
*   **Health.** A table: each state from its records, signals, staleness,
    and links; a signal older than the last answer leaves a path healthy;
    ejection by a lost burst and by near-total loss; the backoff's doubling
    and its cap.
*   **The picks.** `Choose` and `LocalPath` prefer healthy over unknown over
    suspect over ejected; within a tier, a cost beyond the band wins and one
    within it leaves `Outranks` to decide. The provider's existing tests,
    without the topics, pass unchanged.
*   **Requests.** A pick updates its destination's in-use, standby, and
    half-open entries with their lapse; lapsed entries are dropped;
    `LocalPath` requests from its containing branches.
*   **The prober.** With fake echoes, in a synctest bubble: the cadences of
    a destination picked within the last minute, for the nine minutes after,
    and after the lapse; a burst on a lost in-use probe and on a signal;
    half-open at the due time; the budget and its order; the record's
    bookkeeping; the host resolved once and again after a lost burst.
*   **The table.** Inference loads `ping` on every node, a list may leave it
    out, and the walk counts it resident.
*   **End to end.** A lab: cutting the link the best path crosses moves
    `Choose` to the standby within one heartbeat and a burst, and restoring
    it brings the path back at its half-open probe; with `ping` left out,
    `Choose` follows the ten-second hold as today.
*   **The labs.** Every lab passes with the application loaded, and the
    regions cut benchmark reports its recovery against the 279 to 309
    seconds above.
