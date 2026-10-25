# Serve every pair a live path ranked by declared latency

This proposal fixes what the benchmarks of
[proposal 0071](/docs/proposals/0071-benchmark-the-networks-by-the-paths-they-serve.md)
found in the paths nodes choose, and implements decision 1 of
[ADR-0025](/docs/adrs/0025-judge-network-behavior-by-the-paths-it-serves.md):
every pair reaches over its chosen path, which the CI labs assert with the
last change, flipping the record to accepted. Two changes land before the
assertion, each on its own seam. A received beacon's missing trust material
comes from the beacon's sender, as the control plane draft provides. The path
layer ranks every candidate it composes, a candidate the beacons still
refresh before one they stopped refreshing, then by declared latency: the
rank [proposal 0042](/docs/proposals/0042-rank-wireguard-mesh-routes-by-declared-latency.md)
gave the WireGuard pick. Beacon selection and segment lifetime stay as they
are. No wire message, stored field, or run argument changes.

[TOC]

## Summary

Across ten runs of each network, proposal 0071's benchmarks reported:

*   The stranded network reached only the 12 pairs within its sides. Its far
    side refused every beacon the healed link carried: verifying a near-side
    signer fetched the signer's chain from the core, over routes the cut had
    killed.
*   Right after a cut, 55 to 64 of the regions network's 72 pairs reached over
    their chosen paths while every pair held a live candidate, and the count
    came back within half an hour in six runs. A segment lives six hours,
    nothing retires one whose link is gone, and the choice ranks it by hop
    fields and freshness alone.
*   The worst chosen path of a run stood 2.5 to 26 times the reference: the
    rank counts a 3ms hop field as it counts a 90ms one, and passes over
    faster candidates the segments hold.

Measured on scratch copies, five runs of each network: with the sender's
material and the rank below, every pair of both networks reached over its
chosen path in every run, once settled and once the network settled again
after a cut, and a settled network's chosen paths cost what the best paths
over its formed links cost. Selecting one route per arrival interface by
declared latency and expiring hop fields after 22.5 minutes, on top, halved
the stored segment records; but after a cut the worst settled path stood
11.6 times the reference rather than 4.1, and in one stranded run 4 pairs
held no live candidate right after the cut.

## Motivation

### Goals

*   Every pair reaches over its chosen path once a lab settles, and once the
    stranded lab's heal settles, asserted in CI.
*   A beacon verifies with material its sender holds, whatever routes the
    node holds to the core.
*   A segment through a link gone elsewhere stops being chosen within
    minutes.
*   The chosen path is the live candidate declaring the lowest latency.

### Non-goals

*   No change to topology formation, beacon selection, or segment lifetime:
    fewer registered routes cost backup paths, the trade-off the topology and
    beaconing evaluation weighs.
*   No revocation, and registration stays additive.
*   No transit penalty in the rank: the penalty is the labs' parameter
    (ADR-0025, decision 2), its default calibrated by measurement.
*   No probing of candidate paths, and no hysteresis in `Choose`; the
    WireGuard pick keeps its own.
*   No change to how a core verifies registered segments, or to how a link's
    loss is handled.

## Proposal

### A beacon's trust material comes from its sender

The control plane draft resolves a receiver's missing TRCs and chains at the
sending AS: every entity holds the material that verifies what it sends, so
the receiver of a message can always obtain it by contacting the sender
(Section 1.6, one of the mechanisms that avoid circular dependencies after
systemic failures), and a PCB's missing material can be requested from the
sending AS's control service (Section 2.3.1). The node fetches from the core
instead, over routes a cut can kill.

The beacon handler verifies each AS entry with the sender as the server to
ask: the neighbor at the arrival interface, which reception already matched
to the beacon's last entry, at its control service over the one-hop path.
Every node serves TRCs and chains from its database
([trustservice.go](/pkg/core/controlplane/trustservice.go)), and the sender
verified the same entries before propagating them. Fetched material verifies
against the pinned TRCs before it is stored, as it does from the core: a
sender can withhold material, never forge it.

*   `trust.NetworkProvider` honors the `Server` option its interface already
    carries ([provider.go](/pkg/core/trust/provider.go)). With a server set,
    it asks the fetcher its `Peer` function returns for that server first,
    and `Remote`, the core client, only when the sender yields nothing: a
    node not yet enrolled cannot reach a sender's control service, whose
    channel admits enrolled peers alone, while the core's bootstrap channel
    serves it. Without a server, it asks `Remote`. The TRC and chain calls of
    `Remote` become a `Fetcher` interface that both satisfy, and the
    requests' wire forms move into the trust package, shared with the core
    client.
*   `Engine.VerifyBound` takes the server; registrations and the labs' own
    verifications pass none.
*   `PeerClient` provides the fetcher: the trust material calls over its
    one-hop channel, the mutually verified channel the confirm dials
    ([peerclient.go](/pkg/core/controlplane/peerclient.go)). The node sets the
    provider's `Peer` once the client exists, since the client's credentials
    come from the engine.

### The path layer ranks fresh, then fast

`Candidate` ([provider.go](/pkg/libs/scion/provider.go)) gains `Stale`: its
staler piece was created more than five minutes ago. Registration refreshes
the routes beaconing selects every minute, and a fetched down segment is
cached for at most a minute, so a selected route's pieces stay a few minutes
fresh; a route reads stale once the beacons stopped refreshing it, because
it died or because beaconing selects others now.

The WireGuard pick's rank moves into the path layer as `Candidate.Outranks`,
staleness first: a fresh candidate before a stale one, a declared sum before
an undeclared one, a smaller sum before a larger one, then `Before` — fewest
hops, the fresher, fewer entries.

*   `Choose` ranks every enumerated candidate by it, the containing branches
    among them, where it took a containing branch ahead of the rest: a stale
    containing branch could hold a pair on a dead route while a fresh meeting
    served it. A crossing candidate stays the last resort, and the bootstrap
    route the fallback when nothing composes. A provider without a lookup
    composes from its up segments alone.
*   The containing branch, which `LocalPath` resolves and control RPCs ride,
    takes the containing up segment whose branch ranks first, where it took
    the freshest. ADR-0004 named the freshest up segment for that route
    because one exists from beaconing alone; a fresh one still does.
*   The WireGuard pick ranks with it ([route.go](/pkg/apps/wireguard/route.go)),
    and its switch hysteresis stands, save for an incumbent gone stale while
    a fresh route leads: it is replaced at once, as one the window cannot
    compose is.

### The labs assert reachability

The regions and stranded labs assert, once their networks settle, that every
ordered pair's chosen path crosses only links up at both ends, the
assessment's reachability. Each polls for up to ten virtual minutes, so a
segment that outlived its link reads stale before the check binds. ADR-0025
flips to accepted.

### Packages touched

| Package                         | Change                                                                  |
| :------------------------------ | :---------------------------------------------------------------------- |
| `pkg/core/trust`                | `Fetcher`; `NetworkProvider`'s `Peer`; `VerifyBound`'s server           |
| `pkg/core/webpki`               | The core client builds its requests with the trust package's forms      |
| `pkg/core/controlplane`         | Beacons verified with their sender; `PeerClient`'s fetcher              |
| `pkg/libs/scion`                | `Candidate.Stale` and `Outranks`; `Choose`; the containing branch       |
| `pkg/apps/wireguard`            | The pick ranks with `Outranks`                                          |
| `internal/services`             | The provider's `Peer` set to the peer client's fetcher                  |
| `internal/testnetwork/behavior` | Reachability asserted in the regions and stranded labs                  |

### Migration

Each commit keeps the tree green:

1.  **Trust from the sender.**
2.  **The rank.**
3.  **Reachability asserted**, and ADR-0025 accepted.

Each history entry records, across five runs, the benchmarks its step moves.

## Compatibility

The wire is unchanged: the trust material calls are the drafts', and every
node serves them. A node on the previous release keeps fetching from the
core. Control RPCs ride the up segment that ranks first rather than the
freshest, and `Path` composes every candidate before it falls back to the
bootstrap route.

## Test plan

*   **Trust from the sender:** with a server set, the provider fetches
    through the server's fetcher, stores what verifies against the pinned
    TRCs, refuses what does not, and asks the core client only when the
    server yields nothing; without one, it asks the core client. The beaconer
    verifies a beacon with the neighbor at its arrival interface as the
    server, and refuses it when no one holds the signer's chain. The stranded
    cut benchmark reaches its cross-side pairs.
*   **Rank:** a candidate whose staler piece is older than five minutes reads
    stale; `Choose` takes the fresh candidate declaring the lowest sum, and a
    stale one only when no fresh one composes, a containing branch competing
    with the rest; the containing branch `LocalPath` resolves follows the
    same rank; the WireGuard pick replaces a stale incumbent at once, and its
    other tests hold.
*   **Reachability (ADR-0025, decision 1):** the regions and stranded labs
    assert every pair reaching over its chosen path.
*   **Benchmarks:** after the rank, every pair of both networks reaches in
    every run, once settled and after a cut, and a settled network's chosen
    paths cost what the best paths over its formed links cost.

## Implementation history

*   Trust from the sender landed: the beacon handler names the neighbor at
    the arrival interface ([beacon.go](/pkg/core/controlplane/beacon.go)),
    the provider asks it before the core client
    ([network.go](/pkg/core/trust/network.go)), and the peer client asks over
    its one-hop channel ([peerclient.go](/pkg/core/controlplane/peerclient.go))
    with the request forms it shares with the core client
    ([material.go](/pkg/core/trust/material.go)). Across five runs, the
    stranded network reached 28 to 30 of its 30 pairs once settled, where it
    had reached 12 in every run. Right after its cut, 18 to 20 pairs reached
    over their chosen paths, against 10, and 26 to 28 once the link set had
    held for five minutes, against 12. Every pair held a live candidate right
    after the cut, so the pairs left chose paths over the cut links.
*   The rank landed in the path layer ([provider.go](/pkg/libs/scion/provider.go)),
    and the WireGuard pick ranks with it
    ([route.go](/pkg/apps/wireguard/route.go)). Taking the containing
    branches first, as `Choose` did, held two regions pairs on stale branches
    through gone links while fresh meetings at 13 and 22ms served them. The
    lookup became optional because `Choose` now enumerates before it falls
    back, and the e2e labs' ping providers carry none. Across five runs, the
    regions network reached all 72 pairs once settled, where it had reached
    71 in most runs; its worst chosen path stood 2.0 to 2.1 times the
    reference, against 2.5 to 26, and every chosen path cost what the formed
    links' best path cost. After its cut, all 72 pairs reached again in every
    run, 261 to 320 seconds on, where 62 to 72 had and six runs of ten
    recovered; the worst path once settled stood 2.0 to 4.1 times the
    reference, against 2.5 to 26. The stranded network reached all 30 pairs
    in every run, once settled and after its cut.
