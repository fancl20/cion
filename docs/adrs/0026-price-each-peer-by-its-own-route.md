# Price Each Peer by Its Own Route

*   Status: accepted
*   Date: 2026-10-26

[TOC]

## Context and problem statement

[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
defines a link's utility by its tier (decision 2): the price of the cheapest
composed route into the peer's latency class, and the count of independent
routes there. Promotion asks whether a candidate's direct round trip beats
its tier's price by the promotion ratio (decision 5). Retirement asks whether
excluding a link changes neither its tier's price nor its route count
(decision 6). Routes are priced by their round trips alone.

[ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md)'s
benchmarks grade each pair's path against the shortest the lab's delays
allow, with a penalty for each node a path crosses. On those measures the
settled topologies leave one kind of gap:

*   **Regions lab.** The worst pair costs 1.97 to 2.13 times the reference
    under a 5ms penalty, and 1.49 times without one. Each worst pair links
    two members of a tier the node already reaches. Nodes 1 and 7 sit 8.2ms
    apart and cost 16.6ms over the links, penalty included; 4–5 and 4–8 are
    the others.
*   **Stranded lab.** In three runs of eight, nodes 3 and 5, 1ms apart,
    cost 7ms over the links. One more cut costs them 85 to 91 times their
    delay.

The tier price hides these pairs. A link into the tier prices the whole tier
at its cheapest member, so a member served only by a detour never shows: node
1's link to 4 prices its tier at 7.3ms, and a direct link to 7 at 8.2ms never
beats that.

Transits hide a second share of the gap. Nodes 2 and 5 sit 9.0ms apart and
reach each other through 8 in 10.2ms. Raw, the detour looks fine. Under the
penalty the labs charge, it costs 15.2ms.

A fault-tolerant greedy spanner computed offline from every pair's delay
holds the worst pair to 1.51 times the reference with the same 16 links. The
gap is not the link budget; it is which links.

## Decision drivers

*   **Every peer served:** a link's worth is what it does for each peer
    beyond it, not for the tier's best-served member.
*   **Transits cost:** each node a path crosses adds processing and one more
    failure on the way, as ADR-0025 grades paths.
*   **Promotion and retirement agree:** they form a feedback loop (ADR-0017,
    decision 2), and a pair of rules that read different prices cycles.
*   **Margins survive jitter:** a ratio alone flips on milliseconds once a
    link leaves the jitter-free lab fabric.
*   **Decisions stay local:** no node needs data beyond its own measurements
    and the routes its segments compose.
*   **Measured before decided:** each option's outcome is known from the
    labs before it is chosen.

## Considered options

*   **Tier prices, as today.**
*   **Member prices on raw round trips:** each peer priced by the cheapest
    route into it.
*   **Member prices with a transit penalty:** the same, each route charged
    per node it crosses.
*   **A spanner from shared delays:** every node computes one topology from
    a matrix of delays, or from published links and the pairs that violate
    the stretch bound.

## Decision outcome

Chosen option: **member prices with a transit penalty**, amending ADR-0017's
decisions 2, 5, and 6 as follows:

1.  **A peer's price is its own.**
    *   It is the cheapest clean composed route into that peer, priced as
        decision 2 prices routes: by the echo where the window probed it,
        by the declared delays where it did not.
    *   Each route is charged a transit penalty of 5ms for every node it
        crosses between its ends, each way.
    *   A peer no route prices takes its tier's price.
    *   Tiers stay. They class peers for the stranded clause, the
        second-route case, route counts, and eviction's harm.
2.  **Promotion compares a candidate with its own price.**
    *   The priced case admits a candidate whose direct round trip beats
        its own price by the promotion ratio and by at least a margin floor
        of 2ms, on sustained evidence.
    *   The floor case, the stranded clause, the second route for a
        single-route tier, and the cap stand as decision 5 holds them.
3.  **A link is useless only when every member keeps its route.**
    *   Without the link, the tier's two quantities must hold as decision 6
        holds them.
    *   Every member must keep a route within the demotion ratio of its own
        price; the link's own neighbor is judged against its direct round
        trip, the sample promotion compares.
    *   No member may lose its last route.
    *   Promotion and retirement thus read one price through the same ratio
        pair, with the margin floor between them.
4.  **The penalty and the floor are code constants** (ADR-0017,
    decision 17). The penalty takes the labs' default (ADR-0025,
    decision 2).

### Positive consequences

*   Measured on a scratch copy, five runs of each benchmark:
    *   the regions lab's worst pair stands 1.20 to 1.24 times the
        reference under the 5ms penalty, where it stood 1.97 to 2.13, and
        1.08 to 1.12 times without the penalty, where it stood 1.49;
    *   its worst pair after any single cut stands 1.38 to 1.58 times, where
        it stood 2.53 to 4.83;
    *   the stranded lab never leaves a 7-times pair.
*   The labs settle and heal as before, with no cycling: promotion and
    retirement read the same price.
*   Decisions stay local, on the instruments the loop already runs.

### Negative consequences

*   More links:
    *   the regions lab's two near regions mesh, and its link set settles
        on 20 or 21 links where 15 to 17 stood;
    *   it stores 126 to 159 up segment records where it stored 92 to 109.
*   Cuts hit harder:
    *   a cut takes more pairs at once, 46 to 54 of 72 still reaching right
        after it where 56 to 63 did;
    *   the denser set can keep changing after it, so in one run of five
        every pair reached again only after 460 seconds.
*   The penalty is a judgment, now made by the product. The path ranking
    still charges no transits (proposal 0072); the topology carries the
    penalty instead.
*   Each window prices every member's routes: more computation, no more
    probes.

## Pros and cons of the options

### Tier prices, as today

*   Good, because a tier's price is one number, and redundancy per tier is
    what the floor protects.
*   Bad, because a tier's best-served member hides every other: a member
    reached only by a detour never earns a link.

### Member prices on raw round trips

*   Good, because each peer earns the link its own route lacks. In the
    regions lab, the worst pair stands 1.13 to 1.16 times the reference
    without a penalty, matching the offline spanner at the same link count.
*   Good, because it adds no links where tier prices kept 15 to 17.
*   Bad, because a detour through one more node prices as a few
    milliseconds. Under the labs' penalty the worst pair stays 1.68 times
    the reference.

### Member prices with a transit penalty

*   Good, because a route pays for every node it crosses, as the labs grade
    paths. The worst pair falls to 1.20 to 1.24 times under the penalty.
*   Bad, because the penalty buys links: near regions mesh, segments
    multiply, and a cut takes more pairs at once.

### A spanner from shared delays

*   Good, because it bounds every pair's stretch, even after any single
    failure, and its order-independent computation cannot cycle.
*   Bad, because every node must compute from the same published data, and
    repair depends on the directory, which lives on the founding core.
*   Bad, because it replaces ADR-0017's loop rather than refining it.
