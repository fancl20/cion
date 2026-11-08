# Let the heaviest of a retirement cycle go first

This proposal narrows decision 6 of
[ADR-0037](/docs/adrs/0037-coordinate-link-changes-through-the-node-directory.md)
as
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)
amends it: retirements that rest on each other in a cycle let the cycle's
heaviest link go first, as two that rest on each other already do.

[TOC]

## Summary

Today:

*   **A cycle of retirements all wait**
    ([coordination.go](/pkg/modules/topology/impl/measured/coordination.go)):
    a node's useless retirement waits while the routes it judged its link
    by cross a link another node announced to retire, unless that node's
    routes cross this link too and this link is the heavier. Retirements
    that rest on each other through a third or more all wait, and their
    links stay until a judgment changes or the cap's eviction takes one
    (ADR-0037, negative consequences). In the NAT lab, whose cap never
    binds, two runs in six kept six links outside its cluster that way,
    their retirements announced at five minutes and never made, four of
    them resting on each other in a cycle and two on the cycle: 21 links,
    where the other runs settled on 15 or 16.

## Motivation

### Goals

*   Retirements that rest on each other, directly or through other
    announced retirements, let the heaviest link of the cycle go first;
    the others wait as before.
*   A retirement still waits on an announced retirement that rests on
    nothing of its own.

### Non-goals

*   Promotions' waits, and the departed links' five minutes.
*   What a retirement rests on: the routes it judged its link by, as
    before.

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| A cycle | the announced retirements that rest on a node's retirement and on which it rests, each through announced retirements | each waits on the next, so none goes unless one does |
| Which goes first | the heaviest link of the cycle, ties as `lighter` orders pairs | as for two retirements that rest on each other: every node reads the same weights, so one link goes |

### The waits

A node's retirement of its link waits on another node's announced
retirement whose link its routes cross, unless the other retirement is in
its link's cycle and its link is the cycle's heaviest. Each node computes
the cycle from the announced retirements the directory publishes, its own
from the routes it judged its link by. A retirement outside every cycle
that rests on one waits for the cycle to break.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The retirement's cycle and the heaviest-first rule |

## Compatibility

The waits are each node's own. A node on either rule reads the same
announcements; one on the old rule keeps waiting in a cycle of three or
more, where the new rule's heaviest goes.

## Test plan

*   **The waits.** A retirement whose link is the heaviest of a cycle of
    three goes; one in a cycle with a heavier link waits; one that rests on
    a chain that rests on nothing of its own waits, however heavy its link;
    two that rest on each other keep the heavier-first rule; the departed
    links' waits hold.
*   **The labs.** The labs pass, and the NAT lab's settled benchmark runs
    against the commit before, five runs each.
