# Follow and re-punch links as their state changes

This proposal moves the follow loop and the re-punch loop onto the node
bus's link state, as
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
decided for reacting loops. One loop, the link upkeep, subscribes to the
link state and wakes on each change, when an action ends, and at the retry
or grace it waits on, instead of polling every second.

[TOC]

## Summary

The measured provider keeps each link on its peer's mapping with two loops
([provider.go](/pkg/modules/topology/impl/measured/provider.go)), each
passing every `FollowInterval`, one second:

*   **The follow loop** compares each live entry's locator with the source
    its link observes the peer at. An established entry observed elsewhere
    sends a confirm, its retries backing off from `FollowRetry`, and a
    candidate takes the observation once its verdict is up.
*   **The re-punch loop** punches a punched link again once its verdict has
    stayed down for `RepunchGrace`, its retries backing off from
    `RepunchRetry`, `RepunchAttempts` per down period.

Each pass reads the store, the link state, and the directory, whether
anything changed or not. A change waits up to a second for the next pass,
and an action holds its loop: a confirm or a re-punch that goes unanswered
holds it for `EstablishTimeout`, five seconds, and every other entry waits.

## Motivation

### Goals

*   React to link state: an observation's move, a verdict's flip, and a
    store write each start a pass at once.
*   Wake on time only for what waits on it: a retry's backoff or a down
    link's grace.
*   Run each entry's action off the loop, one per entry at a time, so one
    entry's unanswered confirm or re-punch delays no other entry.

### Non-goals

*   The selection, the confirm pass, and the join dials keep their
    cadences.
*   What is followed and re-punched stays, and so do the waits:
    `FollowRetry`, `FollowRetryMax`, `RepunchGrace`, `RepunchRetry`, and
    `RepunchAttempts`.
*   The directory and the node's own reach become no topics: a pass reads
    them when link state or time wakes it.

## Proposal

### The link upkeep

`runUpkeep` ([upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go))
replaces the two loops. It subscribes to `(*Bus).Links()` and runs a pass:

*   on each link state event;
*   when an entry's action ends;
*   at the earliest time the last pass returned: an entry's next confirm, a
    down link's grace, or its next re-punch.

A pass reads the store's entries and acts on each as the two loops did:

*   **Follow:** on the event's observations and verdicts.
*   **Re-punch:** on the event's verdicts and the directory's reach reports,
    while the node's own published rendezvous address goes unanswered.

A pass starts each due confirm and re-punch off the loop and marks its entry
busy until the action ends; a busy entry starts nothing else. A candidate's
adoption, one store write, stays in the pass. `FollowInterval` goes.

### The waits

`loops.Attempts` gains `Next(k)`: when the key may try next, false once its
tries reached `Limit`. The re-punch memory's `due` returns the due links and
the next wake, and the upkeep records each re-punch it starts.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/loops` | `Attempts.Next` |
| `pkg/modules/topology/impl/measured` | The link upkeep replaces the follow and re-punch loops |

## Compatibility

There is no wire or storage change. A change starts its confirm, or its
link's grace, at once rather than at the next pass, and an idle node runs no
pass.

## Test plan

*   **The waits:** `Next` reports a key never tried due at once, a tried
    one within its delay's band, and none past `Limit`. The re-punch memory
    returns each step's due links and its next wake within its band.
*   **The upkeep's following:** a confirm starts at once on the
    observation, a failing one retries once per `FollowRetry`, and a
    candidate takes the observation on its verdict's up event.
*   **The labs:** the behavior labs pass, the recovery lab's re-punch among
    them.
*   **The benchmarks:** five runs each. The NAT benchmarks hold.

## Implementation history

*   Landed as proposed: the link upkeep
    ([upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go)) and
    `Attempts.Next` ([backoff.go](/pkg/libs/loops/backoff.go)). Each action
    works on its own copy of its entry, for the pass that started it reads
    on.
