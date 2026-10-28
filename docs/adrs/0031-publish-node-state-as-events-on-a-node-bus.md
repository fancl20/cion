# Publish Node State as Events on a Node Bus

*   Status: accepted
*   Date: 2026-10-27

[TOC]

## Context and problem statement

A node's components react to state other components own:

*   the neighbor table (the links module);
*   each link's verdict (liveness);
*   the source each link observes its peer at (the data plane);
*   the node directory and the node's own host and reach (the topology
    module);
*   the per-link latency estimates (the selection loop);
*   the interface-down signals the conns receive.

The state crosses components in four ways:

*   **Snapshot functions in configs.** Link state alone takes about ten:
    `Verdicts` four times, `Observed` three times, and `Links` three times.
    Each consumer combines them on its own, and "usable" (the table minus
    down links) is computed in `internal/services` for some consumers only.
*   **One coalescing signal:** the store's write signal, which the data
    plane's generation loop wakes on.
*   **Callbacks:** `Learn`, `InterfaceDownCache.OnSignal`, and
    `LatencyRecorder`.
*   **Polling loops:**
    *   the follow loop and the re-punch loop, every second;
    *   the confirm pass and the join dials;
    *   the directory publish, which picks up a new host or reach on its
        next interval.

More reacting consumers are coming. Next is a re-punch triggered by a
link's down edge rather than by polling.

## Decision drivers

*   **Consistent snapshots:** a consumer reads one consistent view of
    another component's state, without sharing that component's locks.
*   **React without polling:** a component wakes when the state it depends
    on changes.
*   **No lost changes:** a subscriber that starts late, restarts, or falls
    behind still reads the current state.
*   **Producers never wait:** publishing never blocks, and no subscriber
    code runs under the producer's lock.
*   **The labs and the layering hold:** the labs run many nodes in one
    process, and the one-way dependency from modules and applications to
    the core and the libraries stays.
*   **Visible dependencies:** what a component reads stays readable from its
    code.

## Considered options

*   **Keep snapshot functions and polling.**
*   **A global event bus:** one process-wide bus.
*   **A link state view:** one bespoke interface for link state.
*   **A node bus of edge events:** one bus per node, each event a change.
*   **A node bus of full-state events:** one bus per node, each event the
    full state it describes.

## Decision outcome

Chosen option: **a node bus of full-state events**.

1.  **One bus per node.** The node's assembly builds it and delivers it in
    the environments it already hands the topology source and the
    applications. It is never a package-level value.
2.  **The bus declares every topic.** Each topic's accessor names its event
    type, its publisher, and its readers, so the bus package is the catalog
    of the state the node's components share. An event's type is defined in
    the bus or in a package a library may import.
3.  **An event carries the full state it describes,** never a change to
    it, and is never mutated once published. A happening is published as
    the state it leaves: an interface-down signal as the set of interfaces
    signaled down.
4.  **A topic remembers its last event.** A new subscriber starts from it,
    and a subscriber slower than its publisher skips to the latest event:
    the events it missed carry nothing the latest does not. Publishing never
    blocks, and no subscriber's code runs under the publisher's lock.
5.  **A reader subscribes or reads the last event.** A component that
    reacts to a change subscribes. A component that reads the state on
    demand reads the topic's last event. The core's and the libraries'
    configs take the topics they read.
6.  **Capabilities and indexed data stay dependencies:** the path provider,
    the trust engine, the peer channel, the factories, and the mounts.
7.  **The first topic is link state:** the neighbor table's live entries,
    each with its verdict and observed source, and the table and the usable
    links derived from them. It replaces the link-state snapshot functions.
    Later topics are each adopted where a consumer changes: the directory,
    the node's own host and reach, latencies, and interface-down.

### Positive consequences

*   A reader takes one immutable event, consistent by construction, and
    takes no other component's lock.
*   Reacting loops wake on change instead of polling. A late, restarted, or
    slow subscriber reads the current state, so no change goes missing.
*   About ten link-state fields across the topology environment, the
    selection, the link service, the beaconer, the path provider, and the
    conns become one topic, with one derivation of the usable links.
*   A module or an application that starts reading another topic needs no
    new field in its environment.
*   The state the node's components share is listed in one package.

### Negative consequences

*   What a component reads moves from functions in its config to the
    topics it holds.
*   The bus package grows with every topic, and an event type a library may
    not import is defined in the bus.
*   Every publish builds a new event. At the node's scale (under ten links,
    tens of directory entries), the cost is negligible.
*   A subscriber sees the latest event, not each one before it. A reader
    that needs every change keeps its own record of them.

## Pros and cons of the options

### Keep snapshot functions and polling

*   Good, because nothing changes.
*   Bad, because each new reacting consumer adds fields along the whole
    path and polls on its own cadence.

### A global event bus

*   Good, because producers and consumers decouple fully.
*   Bad, because one process holds many nodes in the labs.

### A link state view

*   Good, because it covers the dominant shared state with one interface.
*   Bad, because the next shared state needs another bespoke interface.

### A node bus of edge events

*   Good, because each event is small.
*   Bad, because a late subscriber needs a snapshot and a resync anyway, and
    every consumer of state rebuilds it from the events.
*   Bad, because a subscriber that falls behind must queue every event or
    lose a change.

### A node bus of full-state events

*   Good, because the events deliver levels: a reader's state is
    consistent, and no change goes missing however late or slow the reader.
*   Good, because one mechanism serves every piece of shared state, and
    their declarations sit together.
*   Bad, because dependencies become topics rather than functions.
