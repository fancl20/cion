# Route each core to the cores it links to

This proposal lets a core open a bootstrap slot for every fellow core whose
beacon it verifies, whenever it first hears it. A core's only route to
another core is that slot's reversed beacon, and today a slot opens only for
origins heard before the node pins the TRC. The founder pins at creation, so
it holds no route to any core that joins after it. No message type, stored
field, run argument, or constant changes.

[TOC]

## Summary

A core reaches a core it links to over its bootstrap route: the freshest
beacon that core originated, reversed and extended with the node's own hop
(`BootstrapRoute` in [beacon.go](/pkg/core/controlplane/beacon.go)). Cores
store no up segments, and the provider composes no core segments
([proposal 0039](/docs/proposals/0039-make-the-path-layer-multi-core.md)), so
nothing else routes one core to another.

`HandleBeacon` opens a slot only while the TRC is unpinned; after the pin it
refreshes the slots it holds. The rule fits a non-core: its slots carry its
enrollment until up segments take over. A core, though, pins either at
creation, as the founder does, or before a later core joins. It never opens a
slot for a core that joins after its pin.

Measured on a scratch lab: the regions network, with the founder's first
child joining as an authoritative core over a direct link to the founder.
Once settled, the child reached the founder in six reads of six, and the
founder reached the child in none ("no path to destination"). With the change
below, both directions reached over their link in six reads of six.

## Motivation

### Goals

*   Every core reaches every core it links to, in both directions,
    whichever pinned first.
*   The founder's own traffic, and its hosts', reaches the cores that join
    after it.

### Non-goals

*   No core-segment legs in path composition (proposal 0039).
*   No route between cores that share no link: propagation never sends a
    beacon toward a core, so a core hears only the cores it links to.
*   No change for non-cores: their slots still open only before the pin.

## Proposal

### A core opens a slot for every core it hears

`HandleBeacon` records each verified beacon in its origin's slot on a core,
before or after the pin. A non-core keeps refreshing only the slots it
opened before its pin. The checks before the record already hold a pinned
node's beacons to origins the TRC names as cores.

`BootstrapCore` is unchanged. Once the TRC is pinned, only issuers take
turns, so the slots a core opens for fellow cores that issue nothing never
join its alternation.

### Packages touched

| Package                 | Change                                              |
| :---------------------- | :-------------------------------------------------- |
| `pkg/core/controlplane` | A core opens a slot for every verified beacon       |
| `internal/testnetwork`  | The two-core lab reaches each core from the other  |

## Compatibility

Nothing on the wire changes. A core on the previous release keeps no route
to the cores that joined after its pin.

## Test plan

*   **The beaconer:** a core pinned from its creation opens a slot for a
    fellow core it verifies, and its bootstrap route leaves through the link
    to that core; a non-core still opens none after its pin.
*   **The two-core lab:** the founder and the authoritative core each reach
    the other with an echo over their link.
*   **The behavior labs:** they pass. Their networks hold one core, so the
    benchmarks do not move.

## Implementation history
