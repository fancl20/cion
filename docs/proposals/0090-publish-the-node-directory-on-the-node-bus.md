# Publish the node directory on the node bus

This proposal implements
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
with its directory topic. The measured provider publishes each directory
fetch on the node bus, the link upkeep wakes on it, and every other reader
reads the topic's last event in place of the provider's copy.

[TOC]

## Summary

The measured provider's node directory keeps the last fetched copy of the
core's directory, refreshed every thirty seconds
([directory.go](/pkg/modules/topology/impl/measured/directory.go)). Its
readers pull it:

*   **Inside the provider:** the selection reads it each window, the punch's
    reflector and the link service's echo when they run, and the link
    upkeep on each pass, for the peers that report themselves undialable
    ([upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go)).
*   **Outside it:** the node's assembly turns it into each node's
    `apps.Reach`, which the portal tags
    ([portal.go](/pkg/apps/portal.go)), and the labs read it through the
    application.

A fetch that brings a peer's report wakes nothing: the link upkeep re-weighs
its re-punches only at its next link state event or due time, so a punched
link to a peer that reports itself undialable after the link went down waits
for some other change.

## Motivation

### Goals

*   One value for the node directory: the entries the last fetch returned,
    published by the fetch.
*   The link upkeep re-weighs its re-punches when the directory changes.
*   The directory's entry and its reach report are types every reader can
    import, so the portal reads the reports with no translation.

### Non-goals

*   The fetch keeps its cadence, the core's store and service stay, and
    what an entry holds stays.
*   No other topic.

## Proposal

### The topic

`(*Bus).Directory()` carries `bus.Directory` events: the node directory as
the node last fetched it.

*   `bus.DirectoryEntry` and `bus.Reach` move from the measured provider,
    unchanged, as the event's types.
*   `NewDirectory(entries...)` returns the directory of the given entries.
*   `Entries()` returns them, nil before the first fetch, and `Entry(ia)`
    returns one node's.

### The publisher

The node directory publishes each successful fetch: a joiner's from the
core, the core's from its own store. Its local copy and `Entries` go.

### The readers

| Reader | Before | After |
| :-- | :-- | :-- |
| `measured.SelectionConfig` | `Directory`, a function | `Directory`, the topic, read each window |
| The reflector, the link service's echo | The provider's copy | The topic's last event |
| The link upkeep | The provider's copy, per pass | The topic, subscribed |
| `apps.Environment` | `NodeReach`, the assembly's translation | none: `Bus` carries it |
| `services.App`, for the labs | `Directory()`, `NodeReach()` | `Bus()` |

`apps.Reach`, the provider's `Directory`, and the assembly's `directory` and
`nodeReach` go.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | `(*Bus).Directory()`, `Directory`, `DirectoryEntry`, `Reach` |
| `pkg/modules/topology/impl/measured` | The directory publishes; the readers read the topic; the upkeep subscribes |
| `pkg/apps` | The portal reads the topic; `Reach` removed |
| `internal/services` | The translation removed |
| `internal/testnetwork` | The labs read the topic |

The [architecture](/docs/design/architecture.md)'s node bus entry names
the topic.

## Compatibility

There is no wire or storage change.

## Test plan

*   **The topic:** the zero directory holds no entries, and a directory
    returns its entries and each by ISD-AS.
*   **The publisher:** a fetch publishes its entries, and a failed one
    publishes nothing.
*   **The upkeep:** a down punched link is punched again once a fetch
    brings its peer's undialable report, with no link state event.
*   **The portal:** the reports tag the nodes as before.
*   **The labs:** the behavior labs pass, the reports they await read from
    the topic.
*   **The benchmarks:** five runs each. The NAT benchmarks hold or
    improve.

## Implementation history

*   Landed as proposed: the topic ([bus.go](/pkg/libs/bus/bus.go),
    [directory.go](/pkg/libs/bus/directory.go)), the fetch's publication
    ([directory.go](/pkg/modules/topology/impl/measured/directory.go)), the
    provider's readers
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go),
    [selection.go](/pkg/modules/topology/impl/measured/selection.go),
    [upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go)), and the
    portal's ([portal.go](/pkg/apps/portal.go)). The labs and benchmarks ran
    once over this change and proposal 0089's; that proposal's
    [history](/docs/proposals/0089-publish-the-nodes-own-host-and-reach-on-the-node-bus.md)
    records them.
