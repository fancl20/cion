# Probe sparsely the candidates held in reserve

This proposal narrows the window's probes under the clusters of
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md),
which make a node's candidates its cluster's members and the far ends of the
chosen pairs it holds: each window probes those and the node's neighbors as
before, and every other candidate, held in reserve for the floor and a
stranded tier, once per third of the reading span, reading it from its
history between.

[TOC]

## Summary

Today:

*   **Every window probes every peer**
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)):
    each window sends each candidate up to three binding requests, a punch
    for one whose rendezvous address answers nothing, and one more request
    per address to choose among several, one peer after another
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 1).
*   **In a clustered network most of those probes decide nothing at the
    window.** Under
    [proposal 0119](/docs/proposals/0119-form-clusters-and-link-them-through-their-nearest-members.md),
    a node links outside its cluster to the far end of a chosen pair it
    holds, and to any other peer only for the floor or a stranded tier,
    when no chosen candidate answers. Its readings of those other peers
    serve the clustering, which reads them over five and fifteen minutes,
    and the fallback. In the settled metros lab, each node sends the other
    metros' nodes 35 to 36 probe datagrams a minute.

## Motivation

### Goals

*   Each window probes the peers the node may link at any time: its
    neighbors, its cluster's members, the far ends of the chosen pairs it
    holds, and every peer the clustering sets no limit on.
*   Every candidate held in reserve is probed often enough that each
    reading span holds the round trips a reading decides on, and each bound
    span those an upper bound needs.
*   Between its probes, a window reads a candidate in reserve as it reads a
    probed one: its routes, its reading and bounds, its address.

### Non-goals

*   Clusters as scopes: every node still measures every peer, holds every
    entry, and enumerates every route.
*   The routes' probes: the prober probes each priced route every half
    minute, and a route reading needs five probes within its five minutes,
    so they leave little room.
*   The order of the window's probes, one peer after another.

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| The peers probed each window | the node's neighbors; the peers the last window's clustering lets it link — its unit's members, the far ends of the chosen pairs it holds, the peers of a unit no reading joins to its own, the peers its view does not hold; every peer before its first clustering, and while its up links fall short of the floor | a promotion acts on the reading at its horizon (ADR-0039, principle 5), and below the floor any reachable candidate will do |
| How often a candidate in reserve is probed | `SparseProbe`, a third of `scion.ReadingSpan`: 100 seconds | each reading span holds two runs or more, six round trips against the five a reading decides on, and each bound span six runs, eighteen round trips against the fourteen an upper bound needs, while a window lasts under a sixth of the reading span |
| A run unanswered | the next window probes the candidate | the window reads an unanswered candidate at zero, so a candidate waits for its next run only after an answer |

### The probes

*   **The reserve.** The candidates the last window's clustering did not
    let the node link are held in reserve: the node links one only for the
    floor or a stranded tier. While the node's up links meet the floor, a
    candidate in reserve is probed once its last answered run is
    `SparseProbe` old, or once the addresses its entries name no longer
    hold the one that run probed.
*   **Between runs.** The window reads a candidate in reserve from its
    history: the reading and bounds of the round trips its last instrument
    holds within the spans, the address its last run probed, and the routes
    to it, enumerated as every window enumerates them. The tiers, the
    prices, the requests, the floor, a stranded tier, and the report read
    it as they read a probed candidate.

### The labs

*   The metros lab's settled benchmark reports the datagrams the nodes send
    to each other's rendezvous sockets, the candidates' probes, per node and
    minute, inside the metros and across them, from a tally the fabric
    keeps.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The reserve and its sparse probes |
| `internal/testnetwork/fabric` | A tally of the UDP datagrams delivered to a port |
| `internal/testnetwork/behavior` | The metros lab's probes in its settled benchmark |

## Compatibility

Nothing on the wire changes. A node's entry reports a candidate in
reserve's round trip and bounds as before, from fewer probes.

## Test plan

*   **The probes.** A candidate in reserve is probed at the first window,
    read from its history at the next — its reading, bounds, and routes —
    and probed again once its run is `SparseProbe` old, while the neighbors
    and a chosen pair's far end are probed every window. Below the floor,
    after an unanswered run, once the run's address is gone, while the node
    holds a link to the candidate, and once a link the node held since the
    run retired, the candidate is probed at the next window. A read from
    the history keeps the reading's and the bounds' spans, and reads
    unreachable once no round trip lies within the reading's span.
*   **The fabric.** The tally counts the datagrams delivered to its port by
    source and destination, and none delivered before it was drawn, dropped,
    or addressed to another port.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before, the metros lab's probes included.

## Implementation history

*   **Test adaptations.** The selection's fixture answers each enumeration
    with the routes its samples give, so a window that reads a candidate
    from its history prices the routes as a probe would.
*   Mutations: 16 of 16 killed. The first test of an unanswered run let one
    live: a candidate with no earlier round trip loses its run anyway once
    the window forgets its last instrument, so the test now lets a run go
    unanswered after an answered one.
*   The pipeline passed once two readiness labs of the ping application,
    which waited two seconds for each reply and received none under the
    race detector, waited five, as the expiry lab does.
*   Benchmarks against the commit before: five runs each of the metros
    lab's settled benchmark, six and four of the NAT lab's, two and one of
    the metros cut, two each of the pair brought near, and one each of the
    raised delay:
    *   **The probes.** In the settled metros lab, each node sent the other
        metros' nodes 9.2 to 9.6 probe datagrams a minute, against 35.2 to
        36. Its metro mates are all its neighbors, whose links carry their
        probes as before.
    *   **Settling.** The metros lab settled on 25 to 27 links after 13 to
        20 changes within 7.8 to 14.3 minutes, against 26 or 27 after 15 to
        17 within 8.5 to 9.7, its worst pair at 1.06 or 1.07 times the
        reference in both. The last changes of every run, before the change
        and after, retired links outside the structure, among them links to
        the founder that stranded nodes had dialed again. Three runs of five
        after the change went one such round more, and one metros run
        before it never settled within the hour, the founder linked to six
        nodes at its end.
    *   **NAT.** The NAT lab settled on 15 to 17 links after 10 to 16
        changes within 5.5 to 8.7 minutes, against 15 to 17 after 11 to 15
        within 6.7 to 8.7, every pair reached in every run.
    *   **A cut.** After a cut between two metros, the better paths
        surfaced at once and the links settled within 10 seconds after one
        change, the worst pair at 1.52 and 1.62 times the reference with
        the transit penalty, against 1.52; after the restore, within 40 and
        50 seconds after one change, against 140 after three.
    *   **A pair brought near** linked within 410 and 630 seconds, against
        500 and 580, no node leaving its cluster, the worst pair then at
        1.21 or 1.22 times the reference.
    *   **A raised delay** changed no link, as before; its restore settled
        after two changes within 320 seconds, against one within 50.
    *   The regions lab settled on 31 links after 15 changes within 6.8
        minutes, against 30 after 17 and 20 in proposal 0121's runs; the
        site lab joined both ways on 15 links, and the stranded lab on 8,
        as before.