# Judge the leased path

This proposal implements
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 9:
the chosen path the labs grade under
[ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md)
is the path the source's lease of the destination holds, the path its
traffic rides. With it every decision of ADR-0035 has landed but near-best
spreading, and the record is accepted.

[TOC]

## Summary

Today:

*   **The labs grade picks.** The behavior labs read each ordered pair's
    chosen path with `Choose`
    ([assess_test.go](/internal/testnetwork/behavior/assess_test.go)),
    which ranks the candidates at each read and keeps nothing. The NAT
    founder-down benchmark reads its pairs the same way
    ([nat_test.go](/internal/testnetwork/behavior/nat_test.go)).
*   **Traffic rides leases**
    ([proposal 0106](/docs/proposals/0106-lease-each-peers-path.md)). A
    lease keeps its path while the path serves, and moves when it is
    ejected or once a healthy path costs less beyond the band for five
    seconds. A pick and a lease differ after a change: a pick follows the
    rank at once, and a lease only on that evidence.
*   **A lease measures its standby, not its challenger.** Its requests name
    the leased path, the best path sharing no link with it as the standby,
    a suspect, and a half-open path
    ([health.go](/pkg/libs/scion/health.go)). A cheaper path that shares a
    link with the leased one is never measured, so the lease never moves to
    it.

## Motivation

### Goals

*   The labs grade what traffic rides: each pair's leased path, for reach
    and for cost alike.
*   A lab's read uses the lease as a send does, so the lease is measured as
    one in use.

### Non-goals

*   The grading itself: ADR-0025's reference, penalty, and measures stay.
*   The paths lab, which reads both the pick and the lease
    ([paths_test.go](/internal/testnetwork/paths_test.go)).
*   Near-best spreading, which waits for a caller with several flows to
    one destination and for the decision on load that ADR-0035 defers.

## Proposal

*   **Every read is a lease's.** For each ordered pair, a lab reads the
    source's lease of the destination as a send does, waiting on the
    destination's lookup while nothing composes, within the lookup budget as
    today
    ([assess_test.go](/internal/testnetwork/behavior/assess_test.go),
    [nat_test.go](/internal/testnetwork/behavior/nat_test.go)).
*   **A lease names the segments its path joins**
    ([lease.go](/pkg/libs/scion/lease.go)), as `Choose`'s candidate does,
    so the labs count the segments the chosen paths join, which ADR-0025
    asks of the path layer.
*   **A lease measures the path it would move to**
    ([health.go](/pkg/libs/scion/health.go)). When the best path besides
    the one in use ranks above it and is not the disjoint standby, the
    requests name it standby too, so it is measured, and taken once it is
    healthy and cheaper beyond the band. A pick ranks first among its
    candidates, so it names no more than before.
*   **ADR-0035 is accepted.**

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | `Leased.Segments`; a lease's challenger is requested |
| `internal/testnetwork/behavior` | Reads each pair's lease |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **The requests.** A lease whose best challenger shares a link with it
    requests the challenger standby beside the disjoint standby; a pick
    requests no more than before.
*   **The behavior labs** pass, reading leases.
*   **The benchmarks.** The regions settled, regions cut, and stranded cut
    benchmarks run against the commit before; what the leases' evidence
    changes in their numbers is recorded in the implementation history.
