# Count the dialed links against the useless retirement's floor

This proposal grounds on the promise
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
makes that links change only on sustained evidence, and narrows its
decision 6 again after
[proposal 0068](/docs/proposals/0068-retire-a-useless-link-from-its-dialing-end-alone.md):
the useless retirement runs only while the up links the node dialed exceed
the floor, so a link it accepted never frees it to shed one it dialed. No
wire message, stored field, run argument, or constant changes.

[TOC]

## Summary

`prune` ([selection.go](/pkg/modules/topology/impl/measured/selection.go))
retires at most one up link per window as useless, and since proposal 0068
only a link the node dialed. The guard before it still counts every up
link: the useless retirement runs while up links exceed the floor, and the
links the node accepted count. A peer's floor link therefore lifts its
acceptor above the floor and frees it to retire a link it dialed, and
that link's acceptor falls below its floor and dials again. The regions
lab showed the cycle across four nodes:

1.  Node 1, below its floor, dials node 4.
2.  Node 5, below its floor, dials node 1, which now holds three up links,
    one of them accepted.
3.  Node 1 retires its link to node 4 as useless — the link from node 5
    reaches the same tier — and node 4, below its floor, dials node 5.
4.  Node 5, lifted above its floor by the link from node 4, retires its
    link to node 1; node 1, below its floor, dials node 4 again.

Each retirement is the dialer's own and each passes the useless test. The
guard counts the up links whose entries record a rendezvous address — the
links the node dialed, the mark proposal 0068 reads. Promotion's floor,
the down-verdict retirement, and the cap's eviction keep counting every up
link, so a node its peers already link to the floor dials nothing for it.

## Motivation

The cycle is what stands between the regions lab and settling every run.
Under proposal 0068 the lab settled in 14 of 15 runs, taking 6 to 22
minutes of virtual time; the fifteenth retired 55 links as useless and
never held for ten minutes.

Two other remedies were weighed. Picking floor links by what they add
rather than by speed makes a floor link less likely to turn useless later,
but an accepted link still frees its acceptor to retire a link it dialed.
A damped retirement — a longer streak, or a hold after a retirement —
slows the cycle without removing its cause. The guard's cost is a node
that keeps up to the floor's worth of the links it dialed where links its
peers dialed already serve the same tiers, bounded by its cap and its
eviction: the regions lab settles on 16 or 17 links where it settled on 10
to 12.

### Goals

*   A link a node accepted frees none of the links it dialed for useless
    retirement.
*   The regions lab settles in every run and runs unskipped.
*   No wire message, stored field, run argument, or constant changes.

### Non-goals

*   No change to promotion, the stranded clause, the down-verdict
    retirement, or the cap's eviction.

## Proposal

### The guard

`prune` counts the established up links that `dialed` reports and returns
before the useless loop while that count is at or below the floor. The
down-verdict loop before it reads every established entry, as it does
today.

### Packages touched

| Package                              | Change                         |
| :----------------------------------- | :----------------------------- |
| `pkg/modules/topology/impl/measured` | The useless retirement's guard |
| `internal/testnetwork/behavior`      | The regions lab runs unskipped |

## Compatibility

Nothing on the wire or in the store changes. A node running the change
keeps up to the floor's worth of the links it dialed where it would have
shed one; its peers see a link that stands longer. Mixed networks
converge no worse than today.

## Test plan

*   **The guard:** a useless dialed link stands while the node's dialed up
    links sit at the floor, however many links it accepted, and retires
    once a third dialed link lifts them above it.
*   **The behavior labs:** the stranded lab passes, and the regions lab
    settles in every run.

## Implementation history
