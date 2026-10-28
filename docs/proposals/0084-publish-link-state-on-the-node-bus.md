# Publish link state on the node bus

This proposal implements
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
with its first topic, the node's link state. It adds the node bus, publishes
the link state from the node's assembly whenever it changes, and moves every
reader of link state onto the topic.

[TOC]

## Summary

Link state reaches its readers through ten snapshot functions in six
configs:

| Config | Fields |
| :-- | :-- |
| The beaconer's ([beacon.go](/pkg/core/controlplane/beacon.go)) | `Links`, the table; `Verdicts` |
| The path provider ([provider.go](/pkg/libs/scion/provider.go)) | `Links`, the usable links |
| The conns' ([conn.go](/pkg/libs/scion/conn.go)) | `Links`, the usable links |
| The topology environment ([topology.go](/pkg/modules/topology/topology.go)) | `Verdicts`, `Observed` |
| The selection's ([selection.go](/pkg/modules/topology/impl/measured/selection.go)) | `Verdicts`, `Observed` |
| The link service ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)) | `Verdicts`, `Observed` |

The assembly ([dataplane.go](/internal/services/dataplane.go)) caches the
table by the store's write count and derives the usable links from it and
the monitor's verdicts on every read. The measured provider's loops combine
the store, `Verdicts`, and `Observed` on their own.

Each reader combines snapshots taken at different moments, and nothing
tells a reader that link state changed: the follow and re-punch loops poll
it every second.

Measured on the change below, five runs each, the benchmarks hold against
the node before it:

*   **NAT:** a rebound link recovered in 14.5 to 15.6 seconds, against 14.5
    to 14.8; a restarted peer was reached again in 13.0 to 13.1 seconds, as
    before; and a node behind a symmetric NAT joined in 44 to 112 seconds,
    against 44 to 109. In the settled network, every pair's best path over
    the formed links stayed at its reference.
*   **Cuts:** the regions network recovered from its cut in 281 to 307
    seconds, the tail the node before it showed in four runs of five. Over
    fifteen runs each, the stranded network recovered in 10 to 306 seconds,
    against 10 to 305. One run of each never settled: the cut took the
    founder's first link, which left the founder below its floor with no
    candidate it reaches.

## Motivation

### Goals

*   One value for link state: the live entries, each with its verdict and
    observed source, and the table and usable links derived from them once.
*   One field per config for link state: the topic, or the bus where a
    module is wired.
*   A publish on every change: a store write, a verdict's flip, an
    observation's move, and a generation swap. A loop can then react to
    link state instead of polling it.

### Non-goals

*   No reader subscribes yet. The follow and re-punch loops keep polling
    until the next proposal rebuilds them as one reconciler subscribed to
    the topic.
*   The data plane loop keeps the store's write signal: it builds each
    generation from the store's serving entries.
*   The health monitor keeps reading the store.
*   No other topic. The directory, the node's own host and reach, the
    latencies, and the interface-down signals are each adopted where a
    reader changes, and the applications' environment gains the bus with
    the first topic an application reads.

## Proposal

### The bus

`pkg/libs/bus` is the node's event bus, and declares its topics:

*   `bus.New()` returns a bus nothing has been published on. Each topic is
    an accessor naming its event, its publisher, and its readers:
    `(*Bus).Links()` is the first.
*   `Topic[T]` carries events of one type and remembers the last one:
    *   `Publish(e)` makes `e` the last event and delivers it to every
        subscriber, replacing an event the subscriber has not taken yet. It
        never blocks.
    *   `Subscribe(ctx)` returns a channel of events: the last one at once
        when the topic holds one, then each one published after, a slow
        subscriber receiving the latest. The channel closes when `ctx` ends.
    *   `Latest()` returns the last event, for a component that reads the
        state on demand: the zero event before the first publish, and from
        a nil topic, the read of a component wired with no bus.

The bus runs no loop. The next proposal's reconciler is the first
subscriber.

### The link state

`(*Bus).Links()` carries `bus.LinkState` events:

*   `Link` is one live entry: the store's `Entry`, `Down` while the link's
    BFD session holds its verdict down, and `Observed`, the source the link
    last observed its peer at.
*   `LinkState`, built by `NewLinkState(links...)`:
    *   `Table()` maps every live entry's interface to its neighbor. The
        beaconer reads it.
    *   `Usable()` keeps the links whose verdict is up. Every route out of
        the node reads it.
    *   `Up(ifID)` reports a verdict. An interface the state lacks is up,
        as the monitor counts one it runs no session for.
    *   `Observed(ifID)` returns an observation, zero where none is held.

    The zero `LinkState`, the topic's before its first publish, holds no
    table, and its nil usable links filter nothing.

### The producer

The node builds its bus when it is set up. Four sources nudge the link
state through a one-slot channel, and none blocks:

| Source | Change |
| :-- | :-- |
| The store's write signal | Every write |
| The monitor, through the new `HealthMonitorConfig.OnChange` | A session's verdict flips, or departed links' sessions stop |
| The data plane, through `NewUDPProvider`'s new observation hook | An external link's observed source moves |
| The generation swap | The new generation's links observe afresh |

An external link now replaces its observed source only when it moves, so the
hook runs once per move and the receive path no longer allocates per packet.

The link state loop, under `Fatal`, publishes on each nudge: the store's
live entries, each with the monitor's verdict and the serving generation's
observation. The boot publishes once before the node's loops start, so their
first passes read the store's links.

The assembly's table cache (`linkTable`, `usableLinks`, `usable`) and the
store's `links.Links` go.

### The readers

| Reader | Before | After |
| :-- | :-- | :-- |
| `controlplane.BeaconerConfig` | `Links`, `Verdicts` | `Links`, the topic, read once per pass for the table and the verdicts |
| `scion.PathProvider` | `Links` | `Links`, the topic's usable links |
| `scion.ConnConfig` | `Links` | `Links`, the topic's usable links |
| `topology.Environment` | `Verdicts`, `Observed` | `Bus` |
| `measured.SelectionConfig` | `Verdicts`, `Observed` | `Links`, the topic |
| `measured.LinkService` | `Verdicts`, `Observed` | `Links`, the topic |
| The core route's one-hop shortcut | `usableLinks` | The topic's usable links |

The measured provider takes the topic from the environment's bus when it is
wired. A nil topic keeps what the nil field it replaces meant: no links for
the beaconer, no filter for the path provider, no one-hop link for a conn,
and every link up with nothing observed for the selection and the link
service.

### Reads trail changes

A reader sees link state as of the last publish, a goroutine wake after the
change. The observation a link request's agreement rule reads is the
tightest case: the rule wants the source of the request's own arrival. The
request's QUIC handshake crosses the link before the request, and each of
its packets moves the observation it carries, so the publish lands before
the handler reads.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | New: the bus, its topics, and the link state |
| `pkg/core/liveness` | `HealthMonitorConfig.OnChange` |
| `pkg/core/dataplane` | `NewUDPProvider`'s observation hook; the record replaced on a move |
| `pkg/core/controlplane` | The beaconer reads the topic |
| `pkg/libs/scion` | The path provider and the conns read the topic |
| `pkg/modules/links` | `Links` removed |
| `pkg/modules/topology` | The environment carries the bus |
| `pkg/modules/topology/impl/measured` | The provider, the selection, and the link service read the topic |
| `pkg/modules/topology/impl/providertest` | The contract suite wires a bus |
| `internal/services` | The bus, the link state loop, and the nudges; the table cache removed |

The [architecture](/docs/design/architecture.md) names the bus among the
shared libraries and the link state among the components' interactions.

## Compatibility

There is no wire or storage change.

## Test plan

*   **The bus:** a subscriber receives nothing before the first publish,
    the latest event in place of one it has not taken, and the last event
    at once when it subscribes late; its channel closes once its context
    ends. `Latest` reads the zero event before the first publish and from a
    nil topic, and the last event after.
*   **The link state:** the table holds every live entry and the usable
    links leave the down ones out; an interface the state lacks is up; the
    zero state filters nothing, and an empty published one filters
    everything.
*   **The producers:**
    *   The monitor reports a verdict's fall and rise, and a departed
        session's stop, once each, and a new session's startup grace not at
        all.
    *   An external link reports a move of its observation once, and a
        repeated source not at all.
    *   A store write wakes the data plane loop and nudges the link state,
        whose next publish holds the entry. The published state keeps
        retired entries out and marks down only what the monitor holds
        down.
*   **The readers:** their tests run on topics and pass unchanged in what
    they assert.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each. The NAT benchmarks, whose
    observations and verdicts now reach the measured provider through the
    bus, hold.

## Implementation history

*   Landed as proposed: the bus and the link state
    ([bus.go](/pkg/libs/bus/bus.go), [links.go](/pkg/libs/bus/links.go)),
    the producer ([linkstate.go](/internal/services/linkstate.go)) and its
    hooks ([monitor.go](/pkg/core/liveness/monitor.go),
    [udpip.go](/pkg/core/dataplane/udpip.go)), and the readers. The
    Summary's figures are the benchmarks' runs.
