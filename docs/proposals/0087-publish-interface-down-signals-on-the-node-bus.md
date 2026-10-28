# Publish interface-down signals on the node bus

This proposal implements
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
with its interface-down topic. The node's conns publish each SCMP External
Interface Down signal they recognize as the interface-down state, the
signals that still hold, and the path provider and the WireGuard application
read the topic instead of the shared cache.

[TOC]

## Summary

The node's conns share one negative cache of interface-down signals,
`scion.InterfaceDownCache` ([ifdown.go](/pkg/libs/scion/ifdown.go)):

*   **Recording:** a conn that receives a type-5 error records the signaled
    ISD-AS and interface for ten seconds (`IfDownCacheTTL`).
*   **Composition:** the path provider
    ([provider.go](/pkg/libs/scion/provider.go)) asks the cache about each
    entry of a candidate's traversed stretch, and demotes a crossing
    candidate to the last resort.
*   **The receiver:** the cache hands every signal to one function,
    registered through `OnSignal`. The WireGuard application registers its
    mesh socket's drop of the quoted destination's cached path
    ([bind.go](/pkg/apps/wireguard/bind.go)), and resets it to nil on
    release.

The receiver slot takes one function: a second reader would replace the
first. The receiver runs on the receiving conn's read path. Composition
reads the cache once per entry, so one composition can see a signal arrive
halfway.

## Motivation

### Goals

*   One interface-down state that the node's conns publish and every reader
    reads: the signaled interfaces until each signal lapses, and the
    destinations whose packets the signals quoted.
*   Any number of readers, each on its own goroutine: the WireGuard
    application subscribes instead of taking the cache's one receiver slot.
*   One snapshot per composition, as composition reads the link state.

### Non-goals

*   What a signal does stays: the ten-second hold, composition's demotion
    of a crossing candidate, and the mesh socket's drop of the quoted
    destination's cached path.
*   A conn's own echo read still fails on the signal that quotes its
    request: the conn parses the signal where it reads it.
*   No other topic.

## Proposal

### The topic

`(*Bus).InterfaceDown()` carries `bus.InterfaceDownState` events: the
signals the node holds. Its methods:

*   `Signaled(link, dst, now, until)` returns the state with one more
    signal: the link, a `segment.LinkID`, held until `until`, and the quoted
    packet's destination unless zero. It leaves out whatever lapsed by
    `now`.
*   `Holds(link, now)` reports whether a held signal names the link.
*   `Seq()` counts the signals the state has taken, and
    `QuotedAfter(seq)` returns the destinations a held signal quoted after
    the `seq`-th.

The zero state holds no signal.

`Topic[T]` gains `Update(f)`, for a topic several components publish on:
it publishes the event `f` makes of the last one, and no other publish
comes between the read and the publish.

### The publishers

`scion.ConnConfig.InterfaceDown` becomes the topic. A conn that recognizes
a signal updates it with `Signaled`, held for `InterfaceDownHold`, the
ten seconds `IfDownCacheTTL` held. `InterfaceDownCache` goes, and with it
the signal's unused `DstHost`.

### The readers

| Reader | Before | After |
| :-- | :-- | :-- |
| `scion.PathProvider` | `InterfaceDown`, the cache, asked per entry | `InterfaceDown`, the topic, read once per call beside the link state |
| `wireguard.Config` | `InterfaceDown`, the cache's receiver slot | `InterfaceDown`, the topic, subscribed |
| `apps.Environment` | `InterfaceDown`, the cache | `Bus` |
| `services.App`, for the labs | `InterfaceDown()`, the cache | `Bus()` |

The mesh socket subscribes from the application's `Run`. On each event, it
drops the cached path of every destination quoted after the last event it
handled, so a signal never drops a path twice.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | `(*Bus).InterfaceDown()`, `InterfaceDownState`, `Topic.Update` |
| `pkg/libs/scion` | The conns publish on the topic, and the provider reads it; `InterfaceDownCache` removed |
| `pkg/apps` | The environment carries the bus |
| `pkg/apps/wireguard` | The mesh socket subscribes |
| `internal/services` | The topic wired; the cache and its accessor removed |

The [architecture](/docs/design/architecture.md)'s node bus entry names
the topic.

## Compatibility

There is no wire or storage change.

## Test plan

*   **The topic:** `Update` publishes on the last event, and updates from
    many goroutines keep every signal. The state holds a signal until it
    lapses, leaves the lapsed ones out of the next state, and reports the
    destinations quoted after a count.
*   **The conns:** a recognized signal reaches the topic; an echo read still
    fails on the signal that quotes its request.
*   **The provider:** a candidate crossing a held signal is demoted, and one
    crossing a lapsed signal is not.
*   **The mesh socket:** each event drops the cached path of a destination
    quoted since the last one, once, and leaves the other paths.
*   **The labs:** the behavior labs pass, and the BFD lab's signal reaches
    the topic.
*   **The benchmarks:** five runs each. The NAT and cut benchmarks hold.

## Implementation history

*   Landed as proposed: the topic ([bus.go](/pkg/libs/bus/bus.go),
    [ifdown.go](/pkg/libs/bus/ifdown.go)), the conns' publish and the
    provider's read ([conn.go](/pkg/libs/scion/conn.go),
    [provider.go](/pkg/libs/scion/provider.go)), and the mesh socket's
    subscription ([bind.go](/pkg/apps/wireguard/bind.go)). Five runs each,
    the benchmarks held: a rebind recovered in 16.5 seconds, and a restarted
    peer in 13.0 to 13.1 in four runs, the fifth failing to boot on a link
    address still held, as runs before the change did. The regions network
    recovered from its cut in 279 to 309 seconds, once in 13, and the
    stranded network in 21 to 285.