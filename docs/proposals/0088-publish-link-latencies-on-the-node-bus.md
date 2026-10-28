# Publish link latencies on the node bus

This proposal implements
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
with its latency topic. The selection loop publishes each window's per-link
one-way delay estimates on the node bus, and the beaconer reads the topic
instead of the shared sample table.

[TOC]

## Summary

Each selection window measures every neighbor's echo round trip and records
half of it, the one-way estimate, through `topology.LatencyRecorder`
([selection.go](/pkg/modules/topology/impl/measured/selection.go)) into
`controlplane.LinkLatency` ([linklatency.go](/pkg/core/controlplane/linklatency.go)),
a table the node's assembly shares with the beaconer. The beaconer declares
the egress link's sample in each entry it signs
([beacon.go](/pkg/core/controlplane/beacon.go)).

The table is kept one link at a time. A window records the links it counts
as neighbors, so a link that left the neighbors keeps its last sample, and
an interface ID a new link reuses declares the old link's delay until the
next window records it.

## Motivation

### Goals

*   One latency state per window: the estimates of the links the window
    measured, published whole, so a link the window did not measure
    declares nothing.
*   The table, the recorder interface, and the topology environment's
    `Latencies` field go: the selection and the beaconer hold the topic.

### Non-goals

*   What is measured and declared stays: each neighbor's echo round trip
    halved, declared on the egress link of the entries the beaconer signs.
*   No other topic.

## Proposal

### The topic

`(*Bus).Latencies()` carries `bus.LinkLatencies` events:

*   `NewLinkLatencies(m)` returns the estimates of a map from interface ID
    to one-way delay, copied, with the zero delays left out.
*   `Of(ifID)` returns a link's estimate, zero when the event holds none.

The zero event holds no estimate.

### The publisher

The selection publishes once per window, where it records today: each
neighbor's echo round trip halved, a neighbor the window did not measure
left out. A window the context ends publishes nothing, as it records
nothing today.

### The readers

| Reader | Before | After |
| :-- | :-- | :-- |
| `controlplane.BeaconerConfig` | `Latencies`, the table | `Latencies`, the topic, read when an entry is built |
| `measured.SelectionConfig` | `Latencies`, the recorder | `Latencies`, the topic |
| `topology.Environment` | `Latencies`, the recorder | none: the provider takes the topic from `Bus` |

`controlplane.LinkLatency` and `topology.LatencyRecorder` go.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | `(*Bus).Latencies()`, `LinkLatencies` |
| `pkg/core/controlplane` | The beaconer reads the topic; `LinkLatency` removed |
| `pkg/modules/topology` | `LatencyRecorder` and `Environment.Latencies` removed |
| `pkg/modules/topology/impl/measured` | The selection publishes on the topic |
| `internal/services` | The topic wired; the table removed |

The [architecture](/docs/design/architecture.md)'s node bus entry names
the topic.

## Compatibility

There is no wire or storage change.

## Test plan

*   **The topic:** an event copies its map, leaves zero delays out, and
    reports zero for a link it lacks.
*   **The selection:** a window publishes each measured neighbor's halved
    round trip, a later window that measures none publishes no estimate
    for it, and a window the context ends publishes nothing.
*   **The beaconer:** a propagated entry declares the last event's estimate
    for its egress link, and nothing for a link the event lacks.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each. The settled and delay benchmarks,
    whose paths rank on the declared delays, hold.

## Implementation history

*   Landed as proposed: the topic ([bus.go](/pkg/libs/bus/bus.go),
    [latencies.go](/pkg/libs/bus/latencies.go)), the selection's publish
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)), and
    the beaconer's read ([beacon.go](/pkg/core/controlplane/beacon.go)).
    Five runs each against the node before it, the stranded and NAT
    settled benchmarks and both delay-lowered benchmarks held. The regions
    network settled with its worst pair at 1.13 to 1.23 times the
    reference in fifteen runs, mostly 1.16, where the node before it
    measured 1.11 to 1.23, mostly 1.13, in fifteen. The declared estimates
    differ only for a retired entry revived as a candidate, which no run
    revived, and a variant keeping the table's semantics measured 1.11 to
    1.16, mostly 1.13, in ten runs.