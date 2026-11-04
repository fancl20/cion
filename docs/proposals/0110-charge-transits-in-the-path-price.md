# Charge transits in the path price

This proposal refines how
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md) orders the
healthy paths (decision 3) and the margin a lease's challenger must beat
(decision 5). The picks and the leases rank paths by the price the topology
selection already charges, the cost plus a penalty for each transit, as the
record's consequence that forming links and serving traffic price a route
the same way asks. The margin stops growing with the path: it is at most
one transit's price.

[TOC]

## Summary

Today:

*   **The picks and the leases rank by cost alone**
    ([health.go](/pkg/libs/scion/health.go),
    [lease.go](/pkg/libs/scion/lease.go)): the measured round trip raised by
    loss, else twice the declared delays. The topology selection prices the
    same routes with a penalty for each transit, 5 milliseconds each way
    ([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)). A path one
    transit longer at the same round trip ties for the picks and costs the
    selection 10 milliseconds more.
*   **The band grows with the path.** Two costs tie within 20 percent of the
    smaller, and within 2 milliseconds at least, and a lease moves only to a
    path cheaper beyond that. On the far region's 200-millisecond paths the
    band is 40 milliseconds: graded through leases, the regions benchmarks
    showed pairs at up to 1.68 times the best path over the formed links,
    their round trips within the band
    ([proposal 0109](/docs/proposals/0109-judge-the-leased-path.md)).

## Motivation

### Goals

*   The picks, the leases, and the topology selection price a path alike:
    its cost plus a penalty for each transit, for the forwarding it costs
    and one more failure on the way.
*   A lease moves to a path that saves a transit's price, however long the
    path.

### Non-goals

*   The cost itself: the measured round trip raised by loss, else the
    declared delays, and health still decides before price.
*   The topology selection's rules: its member prices stay as they are, and
    its tier price stays the cheapest route's cost.
*   The labs' grading penalty: ADR-0025's reference stays outside the design
    it grades.

## Proposal

*   **One transit penalty.** `TransitPenalty`, 5 milliseconds for each
    transit each way, moves into the SCION library, and the topology
    selection's member prices read it from there.
*   **A path's price** ([provider.go](/pkg/libs/scion/provider.go)) is its
    cost plus the penalty for each AS it crosses between its ends, each way.
    The picks rank healthy paths by price, then by the prior order, and a
    lease moves to a healthy path whose price beats its own beyond the band.
*   **The band's cap.** Two prices tie within 20 percent of the smaller, at
    least 2 milliseconds and at most one transit's price, 10 milliseconds.
    Short paths keep today's band, and on long ones a lease moves for the
    price of a transit.

One lost probe of the 20 a record keeps raises a cost by 5 percent, beyond
the cap on paths of 200 milliseconds or more: a lease can then move between
two otherwise equal long paths. The move back waits for the loss to leave
the other path's record, 20 of its slow probes later.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | `TransitPenalty`; `Candidate.Price`; the picks and the leases rank by price; the band's cap |
| `pkg/modules/topology/impl/measured` | Member prices from `Candidate.Price` |
| `internal/testnetwork` | The paths lab's branches price a transit apart |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **The price.** A path's price charges each transit both ways; a path
    without a cost has none.
*   **The band.** Two prices tie within 20 percent of the smaller, at least
    2 and at most 10 milliseconds.
*   **The picks and the leases.** A path one transit shorter at the same
    round trip ranks first and takes the lease; on long paths, one cheaper
    by more than a transit's price takes the lease within 20 percent.
*   **The paths lab.** Once the cut lifts, the lease returns to the branch
    through B, a transit shorter; with B's branch slower by a transit's
    price, the lease stays.
*   **The benchmarks.** The regions settled, regions cut, and stranded cut
    benchmarks run against the commit before, the leases' cost over the
    best paths reported.

## Implementation history

*   Landed as planned. In runs on one machine against the commit before,
    the regions network's leases cost 1.00 times the best paths over the
    formed links on average and at most 1.06 times, once settled and after
    its cut, against up to 1.68: a transit's price now outweighs the band
    on the far region's paths. The network recovered from its cut in 10
    seconds in 4 runs of 6, against 6 of 6; the slow runs promoted links
    after the cut and retired them as useless minutes later, the tail the
    commits since proposal 0107 showed in 0 to 4 runs of 6. One of three
    settled runs went through 21 link changes in 13 minutes, against at
    most 14 in 8. The stranded network recovered from its cut in 10
    seconds in three runs of three.
