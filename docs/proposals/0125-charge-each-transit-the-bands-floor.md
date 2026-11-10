# Charge each transit the band's floor

This proposal narrows the transit penalty from 5ms each way to the band's
floor, 2ms, the least difference a price tells from jitter. Every path pays
it for each AS it crosses between its ends: in the picks and the leases
([ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)), in the
selection's member prices
([ADR-0026](/docs/adrs/0026-price-each-peer-by-its-own-route.md)), in the
coordination's paths, and in the beacons' prices
([ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md)).
ADR-0026 names 5ms; the value is a parameter, which this proposal sets.

[TOC]

## Summary

Today:

*   **A transit costs 10ms a round trip**
    ([provider.go](/pkg/libs/scion/provider.go)): `TransitPenalty` is 5ms
    each way, and the band a lease moves past is capped at one transit's
    price ([health.go](/pkg/libs/scion/health.go)). A route through one
    more node takes over only once it is 10ms faster, and on paths over
    50ms a lease moves only for 10ms. Inside a metro of the metros lab,
    whose round trips span 1 to 4ms, one transit outweighs the round trips
    between its nodes several times over.
*   **The bounds answer the noise.** A lease moves to a cheaper path only
    once both prices' bounds part by the band
    ([proposal 0124](/docs/proposals/0124-weigh-the-leases-moves-in-an-evidence-library.md)).
    Before that, the penalty also stood between the leases and the jitter:
    at 2ms, the ring lab's leases rode routes three times the shortest under
    20ms of jitter on every pair, against 1.40 at 5ms. With the bounds, the
    ring held its shortest routes at every level at both values.

## Motivation

### Goals

*   A transit costs each way the band's floor: a route through one more
    node takes over once it is faster by two floors, one each way.
*   The band's cap stays one transit's price, so a path that saves a
    transit takes over however long the path.
*   The labs grade the paths by the penalty the nodes charge.

### Non-goals

*   The band's share and floor, the promotion ratio, and the margin floor.

## Proposal

### The lines and their reasons

| Threshold | Value | Reason |
| :-- | :-- | :-- |
| The transit penalty | `bandFloor`, 2ms each way | the least difference a price tells from jitter: a transit decides between routes whose round trips the measurements barely tell apart, and outweighs no gain much beyond them; the bounds, not the penalty, keep the jitter from moving a lease |
| The band's cap | one transit's price, 4ms | as before: a path that saves a transit takes over however long the path |

### The labs

*   The grading penalty is `scion.TransitPenalty`, so each build is graded
    by what its nodes charge.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scion` | `TransitPenalty` at the band's floor |
| `internal/testnetwork/behavior` | The grading penalty |

## Compatibility

Nothing on the wire carries a price. A node prices routes, chooses leases,
and judges links by its own penalty, so nodes on either value run side by
side.

## Test plan

*   **The prices.** A route's price charges the penalty for each transit,
    each way; the band's cap is one transit's price; the tests that price
    routes hold at 2ms and at 5ms alike.
*   **The labs.** The labs pass, and every lab's settled, cut, delay,
    burst, and jitter benchmarks run at 2ms against 5ms.
