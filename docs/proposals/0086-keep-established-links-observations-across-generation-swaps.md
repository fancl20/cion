# Keep established links' observations across generation swaps

This proposal keeps the source an established link observes its peer at
across the data plane's generation swaps, as the monitor already keeps the
link's BFD session. An established link that keeps its addresses continues
its predecessor's observation, so a swap no longer leaves it observing
nothing.

[TOC]

## Summary

Each generation builds one external link per serving entry
([dataplane.go](/internal/services/dataplane.go)), and each new link starts
with no observation ([udpip.go](/pkg/core/dataplane/udpip.go)). A swap stops
the serving generation before it builds the next, and while no generation
serves, the link state holds no observation for any link. After the swap, a
link observes nothing until its peer's next arrival, up to one BFD
transmission interval, one second. Meanwhile:

*   **A confirm records the claim.** An answered confirm records the link's
    observation, else the peer's claimed address
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)). Behind
    a NAT, the claim names the peer's private address, so a confirm
    answered in the gap aims transit where nothing answers until the next
    follow moves it back. In the NAT benchmarks' runs since
    [proposal 0085](/docs/proposals/0085-follow-and-re-punch-links-as-their-state-changes.md),
    follows moved a locator back from a peer's private address 14 times.
    One of them held a rebind's recovery to 20.4 seconds, where the other
    runs took 16.5 to 17.0.
*   **The upkeep carries the mismatch over.** The link upkeep keeps an
    entry's mismatch over a cleared observation
    ([upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go)), or each
    swap would restart the entry's grace and reset its backoff.
*   **The link answers at its locator.** A link's own conversation — its
    BFD stream and the node's one-hop sends — answers its observation, else
    its locator, so in the gap it answers an address the peer may have
    left.
*   **The acceptor moves nothing.** A link request answered in the gap finds
    no observation to record, and the locator stays where it was.

## Motivation

### Goals

*   A swap leaves each established link's observation standing while the
    link keeps its local and remote addresses, the gap between the
    generations included.

### Non-goals

*   What moves a locator, and the claim rule, stay as they are.
*   A candidate observes afresh in each generation. The acceptor may hold
    two candidates on one prober's flow, the probe's unnamed entry beside
    the named one. Once the prober settles on one, the other keeps
    answering the flow at its last observation until a swap clears it, and
    a kept record would let the prober's candidate follow it back. With
    candidates' records kept, the NAT and site labs never settled.
*   An established link whose addresses change in the swap observes afresh:
    a re-punch moves it to a new local address, and a takeover aims it at a
    new remote, each a new flow.

## Proposal

### The observation record

`pkg/core/dataplane` gains `Observation`, one interface's record of the
source its peer's packets arrive from. `NewExternalLink` takes the record
the link continues: the link records each arrival's source in it, reports a
move as before, and answers there. A nil record starts one of the link's
own. `UDPProvider.Observed` goes; the record's holder reads it.

### The node's records

Each generation holds one record per serving interface
([dataplane.go](/internal/services/dataplane.go)). A generation's build
hands an established entry the record of the generation it replaces when
that generation served the interface on the same local and remote
addresses, and every other entry a fresh record. The link state reads the
records of the last generation that served, so the swap's gap reads the
replaced generation's.

### The upkeep

The link upkeep stops carrying an entry's mismatch over a cleared
observation. An established link observes nothing again only on a new flow,
and the old flow's mismatch says nothing about it.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/core/dataplane` | `Observation`; `NewExternalLink` takes it; `UDPProvider.Observed` removed |
| `internal/services` | Each generation's records, which its build carries |
| `pkg/modules/topology/impl/measured` | The upkeep's carry-over removed |

The [architecture](/docs/design/architecture.md)'s data plane entry names
the observation among the state an established link keeps across
generations.

## Compatibility

There is no wire or storage change. After a swap, an established link
answers its peer where the peer's packets last came from rather than at its
locator, and the link state publishes no cleared observation for it.

## Test plan

*   **The record:** a link built on a record another link filled answers at
    its observation before its own first arrival, and an arrival from the
    same source reports no move.
*   **The node:** across a swap, the gap included, an established link's
    observation reads the same while the link keeps its addresses; a
    candidate's, and an established link's whose local or remote address
    changed, read none in the next generation.
*   **The upkeep:** its tests pass without the carry-over's case.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each. The NAT benchmarks hold, and no
    follow moves a locator back from a peer's private address.

## Implementation history

*   Landed as proposed: the observation record
    ([udpip.go](/pkg/core/dataplane/udpip.go)), each generation's records
    ([dataplane.go](/internal/services/dataplane.go)), and the upkeep
    without the carry-over
    ([upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go)). Five runs
    each: no follow moved a locator back from a peer's private address; a
    restarted peer's links recovered in 13.0 to 13.2 seconds and a rebind in
    16.5 to 16.9; the settled, symmetric, and founder-down benchmarks
    measure as before.
