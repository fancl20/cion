# Follow each link's own flow

This proposal implements
[ADR-0029](/docs/adrs/0029-follow-each-links-own-flow.md). A node's own
answered link request records the source its link observes the peer at; a
link that observes its established peer elsewhere sends one; and a candidate
follows the source its BFD session answers. A recovery lab joins the
translated labs, and a benchmark restarts a public node.

[TOC]

## Summary

The acceptor's link service moves an entry's locator to the source the
request's own link observed
([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)). The
requester records the reply's claimed address instead, both in the
selection's establishment
([selection.go](/pkg/modules/topology/impl/measured/selection.go)) and in the
provider's pass over its entries at start
([provider.go](/pkg/modules/topology/impl/measured/provider.go)). Nothing
else moves an established entry's locator, and a candidate's moves only on
rendezvous claims
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)). The data
plane records each arrival's source per link and answers the link's own
conversation there ([udpip.go](/pkg/core/dataplane/udpip.go)); the provider
reads it as `Observed`.

Measured on the change below, five runs each, in the translated network of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md):

*   **Restart:** when the public node 2 restarted on its state, every pair
    with it answered its ping again by the benchmark's second read, 13
    seconds after. Before the change, at most two of its six peers reached
    it, and it reached two, for ten minutes, in three runs of three.
*   **Rebinding:** once a translator dropped node 3's mappings, every pair
    with it answered again 13.4 seconds after, where none had for ten
    minutes.
*   **Symmetric:** a node behind a symmetric translator enrolled and linked
    within 55 to 109 seconds, where it had never enrolled.
*   **Unchanged:** the settled network still reached all 42 pairs, its worst
    pair 22.5 times the reference; with the founder lost, every survivor
    reached every other within 17 to 114 seconds, and the restarted node
    returned within 215 to 261 seconds.

## Motivation

### Goals

*   A link's transit follows its peer's packets within seconds: after a
    translator's mapping changes, after a node restarts, and for a joiner
    behind a symmetric translator.
*   A lab asserts all three recoveries.

### Non-goals

*   No wire change.
*   No links between two translated nodes: hole punching gets its own
    proposal.

## Proposal

### The answered request

`SelectionConfig` gains `Observed`, the data plane's per-link observation
the provider already reads. When a node's own link request is answered, the
selection's establishment and the provider's pass record the source the
link observes the peer at, falling back to the claim rule while the link has
observed nothing.

### The follow loop

The provider runs one more loop. Every second (`FollowInterval`), it compares
each live, named entry's locator with its link's observation:

*   an established entry observed elsewhere sends its link request, at most
    once every five seconds (`FollowRetry`), and the answer records the
    observation;
*   a candidate observed elsewhere takes the observation once its BFD
    verdict is up.

The external link's account of who moves its locator follows.

### The labs

*   **The recovery lab:** the translated network with node 6 behind a
    symmetric translator. Every pair answers a ping, again once node 3's
    translator drops its mappings, and again once node 2 restarts on its
    state.
*   **The restart benchmark,** on demand like the others: node 2 restarts on
    its state, and the pings between it and every other node are read until
    every one answers or ten minutes pass.

### Packages touched

| Package                              | Change                                          |
| :----------------------------------- | :---------------------------------------------- |
| `pkg/modules/topology/impl/measured` | The answered request's record, the follow loop  |
| `pkg/core/dataplane`                 | The external link's account of its locator      |
| `internal/testnetwork/behavior`      | The recovery lab, the restart benchmark         |

## Compatibility

No wire change. A node of an earlier release keeps its locators as before;
its peers of this release follow its flow and record its observation.

## Test plan

*   **The answered request:** the record is the link's observation, and the
    claim rule's only while the link has observed nothing.
*   **The follow loop:** an established entry observed elsewhere sends one
    request per `FollowRetry` and records the observation its answer leaves;
    a candidate follows only once its session answers; an entry observed at
    its locator sends nothing.
*   **The recovery lab:** it passes in the behavior labs' runs.
*   **The benchmarks:** the restart, rebinding, and symmetric benchmarks
    recover, and the settled and founder-down benchmarks measure as before,
    five runs each.

## Implementation history

*   Landed as proposed: the answered request's record and the follow loop
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go),
    [selection.go](/pkg/modules/topology/impl/measured/selection.go)), the
    external link's account ([udpip.go](/pkg/core/dataplane/udpip.go)), and
    the recovery lab and restart benchmark
    ([translated_test.go](/internal/testnetwork/behavior/translated_test.go)).
    The Summary's figures are the benchmarks' five runs each.
