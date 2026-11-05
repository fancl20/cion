# Select Beacons per Origin and per Link

*   Status: accepted
*   Date: 2026-11-05

[TOC]

## Context and problem statement

A node forwards and registers the five freshest beacons it holds:
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md),
decision 1, collapses the draft's selection policies to a fixed bounded set,
and `BestSetSize` ([beacon.go](/pkg/core/controlplane/beacon.go)) fixes it
at five. Neither records why five. The control-plane draft leaves selection
to the AS's policy and suggests a diverse set (Section 2.3.3); it calls a
best set of 20 typical and 50 the most (Section 2.3.4), and scionproto's
control service defaults to 20.

The beacon store keys a candidate by its arrival interface, its origin, and
its segment ID ([beaconstore.go](/pkg/core/controlplane/beaconstore.go)),
and every origination draws a new segment ID. A route its core beacons
every five seconds thus enters the store once per origination, up to 64
candidates per interface. The path database keys segments by route instead
([pathdb.go](/pkg/modules/pathdb/pathdb.go)).

Instrumented best sets, over the second half of a run, counting the rounds
of nodes that store five distinct routes or more:

*   **The regions lab, one core:** such a node stores a median of 49
    distinct routes, yet in 21% of rounds its five beacons carry fewer than
    five, copies of one route taking the other slots.
*   **The site lab, two cores:** such a node stores a median of 23, and in
    24% of rounds its five beacons carry fewer than five. In 11% of rounds,
    a node that holds both cores' routes forwards one core's alone.

This has four costs:

*   **No backup is ensured.** The library fails over only to paths that
    beaconing kept, and a standby shares no link with the path it stands by
    where the paths allow
    ([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md),
    decision 2). ADR-0035 left beacon selection to a decision of its own,
    judged by recovery after a cut.
*   **An origin can go missing.** Freshness favors the cores whose beacons
    arrive soonest. A peer that has not enrolled receives the founder's
    beacons alone
    ([0113](/docs/proposals/0113-send-unenrolled-peers-the-founders-beacons.md)),
    which reach it only where every node upstream forwarded one.
*   **A link's routes can stop at the node.** A path joins an up segment and
    a down segment at a node both cross. A link whose routes the node does
    not forward appears in no segment downstream, and no path meets through
    it.
*   **Slots go to copies.** Five beacons per round carry fewer than five
    routes.

Freshness does one thing well: a route whose beacons stop, through a link
that died, leaves the five freshest within a round or two, while its
candidates stay unexpired for six hours.

Which beacons should a node forward and register each round, and how many?

## Decision drivers

*   **Recovery after a cut:** where the topology offers a route that avoids
    a link, every node keeps one.
*   **Every origin everywhere:** each core's routes reach every node, the
    founder's first.
*   **Every link onward:** the cheapest route over each link travels on, so
    paths can meet at every node.
*   **Dead routes leave:** a route whose beacons stop leaves the set within
    seconds, as today.
*   **Bounded cost:** the set stays bounded, since signing and verification
    grow with it.
*   **No policy engine:** one fixed rule, no configuration (ADR-0004).

## Considered options

*   **The freshest candidates,** as today.
*   **The freshest distinct routes:** one candidate per route.
*   **Every origin and a backup:** each origin's cheapest route, and routes
    that avoid the links every chosen route crosses.
*   **Five routes:** every origin and a backup, filled to five by price or
    by the fewest shared links.
*   **Every origin, a backup, and every link:** the above, then each link's
    cheapest route.
*   **Every origin, a backup, and every link, at least five:** the above,
    filled to five by the fewest shared links.

## Decision outcome

Chosen option: **every origin, a backup, and every link**, realized as
follows:

1.  **A candidate is a route.** The beacon store keeps one candidate per
    route, holding its newest origination. A route is the sequence of
    ISD-AS, ingress, and egress its entries cross, the path database's key.
2.  **A route qualifies while its beacons arrive.** A route qualifies while
    its newest copy arrived within the last three propagation intervals and
    has not expired, so a route whose beacons stop leaves the set fifteen
    seconds later.
3.  **Routes rank by price, as the library ranks paths.** A route's price is
    its declared round trip plus twice `TransitPenalty` for every AS it
    crosses in transit ([provider.go](/pkg/libs/scion/provider.go)). A route
    with an undeclared delay ranks after every priced one; ties go to fewer
    AS hops, then to the newer route.
4.  **The set covers every origin, then a backup, then every link.** Each
    origin's cheapest route enters first, the founder's leading. Then, while
    some link is crossed by every route chosen and a qualifying route avoids
    it, the cheapest such route enters. Then, for each of the node's links
    that carries a qualifying route and has none in the set, the cheapest
    route over it enters.
5.  **Each receiver gets routes it can take.** A neighbor's set is chosen
    among the routes that do not cross it, and the set of a peer that has
    not enrolled among the founder's routes. The node terminates and
    registers its own set, chosen among every qualifying route.
6.  **The size follows the node.** A set holds one route per origin, the
    backups, and at most one more route per link. It keeps its first 64
    picks, the store's bound per interface. The measured topology caps a
    node's links to bound beaconing fan-out
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 1), at eight, so its sets stay far below the bound. In a
    static topology, a node with many links belongs at the core: beacons
    never travel toward a core, so its links to non-cores take no slots,
    and it originates one beacon per link instead.
7.  **The labs judge it:** the cut benchmarks and the settling benchmarks,
    against today's selection. A slow recovery that follows several nodes
    promoting links for the same gap is the topology selection's, which
    beacon selection cannot steer.

This narrows ADR-0004's decision 1: the set is one fixed rule, not a fixed
size. The absence of a policy engine stays.

### Positive consequences

*   Each link's cheapest route travels on, so paths can meet at every node:
    in the site lab, the worst pair's path settled at 1.1 times the
    shortest the delays allow in both runs, against 1.1 and 1.5 today.
*   Every core's routes reach every node, and the founder's, which a peer
    that has not enrolled needs, never drop out.
*   A backup is forwarded and registered where the topology offers one, so
    the library's standby can exist.
*   No slot goes to a copy, and a stable topology forwards the same routes,
    refreshed, round after round: the regions lab settled after 17 and 18
    link changes, within 6.7 and 7.5 minutes, against 18 and 21 within 7.5
    and 17.7 today.
*   The size follows the topology, with no constant to tune.

### Negative consequences

*   A dead route stays in the set for up to three propagation intervals,
    against one or two today, and its withdrawal compounds per hop.
*   Signing follows the links: a node extends about links × (cores + links)
    beacons per round, against five per link today. A static non-core node
    with 64 links would extend about 4,100.
*   Selection costs a pass per receiver each round over the qualifying
    routes.
*   The store records when each route last arrived, beside its
    origination.
*   The path database holds fewer segments: 69 to 85 up segments in the
    regions lab, against 160 to 182 today, so fewer paths compose.
*   Recovery after a cut still depends on the topology selection. In the
    prototype's slowest regions run, three nodes promoted links to the same
    node within 44 seconds, and two of those links retired as useless about
    two minutes later; today's slowest run, 570 seconds, followed the same
    pattern.

## Pros and cons of the options

The prototype ran each option two or three times per benchmark, beside
today's selection.

### The freshest candidates

*   Good, because a dead route leaves soonest.
*   Bad, because copies of one route take slots, and no backup, origin, or
    link's routes are ensured.

### The freshest distinct routes

*   Good, because it ends the copies at no cost.
*   Bad, because the freshest routes share their first links: neither a
    backup nor an origin is ensured.

### Every origin and a backup

*   Good, because it settles fastest: 14 link changes within 6.7 and 7.7
    minutes in the regions lab.
*   Bad, because two or three routes per receiver leave too few paths: the
    regions lab's chosen paths reached 1.21 times the best its links offer,
    against at most 1.02 today, and after a cut 1.58 to 4.73 times the
    shortest the delays allow, against at most 1.19.

### Five routes

*   Good, because filled by the fewest shared links, it recovered from
    every regions cut within 10 seconds, at about today's path quality.
*   Bad, because five has no ground, and filled by price, the regions lab
    once never settled: its links changed 27 times in an hour.

### Every origin, a backup, and every link

*   Good, because the site lab's worst pair settled at 1.1 times the
    shortest in both runs, against 1.1 and 1.5, with the fewest link
    changes, and the size follows the node.
*   Bad, because the path database holds the fewest segments, one regions
    cut took 230 seconds to recover, through a promotion herd, and the
    stranded lab settled 160 to 200 seconds after its cut, against 10 to 220
    today.

### Every origin, a backup, and every link, at least five

*   Good, because it recovered from every regions cut within 10 seconds and
    kept most of the site lab's gain, its worst pair at 1.1 and 1.2.
*   Bad, because five has no ground, and the recoveries it improved on were
    promotion herds, which the topology selection causes.
