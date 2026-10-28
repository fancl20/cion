# Publish the node's own host and reach on the node bus

This proposal implements
[ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)
with its topic of the node's own state: the host the node's publications
carry and the rendezvous answer its latest link reply reported. The
topology provider publishes them as they change; the node directory and the
WireGuard application publish their entries at once when they do, and the
link upkeep wakes on them.

[TOC]

## Summary

The node's own host and reach are computed where they are read:

*   **The host:** `Provider.PublishedHost` resolves it on each call
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)): the
    founding core's domain, looked up once the last answer's memo lapses
    ([external.go](/pkg/modules/topology/impl/measured/external.go)), else
    the host a rendezvous reply taught, else the control host. The node
    directory, the WireGuard application, and the wildcard-bound conns call
    it, the conns on every packet
    ([wildcardhost.go](/internal/services/wildcardhost.go)).
*   **The rendezvous answer:** a flag the link replies set, read by the
    node directory's publication and by the link upkeep's re-punch.

A change reaches the node's peers at the next publication: the node
directory and the WireGuard application publish on a one-minute cadence
([directory.go](/pkg/modules/topology/impl/measured/directory.go),
[directory.go](/pkg/apps/wireguard/directory.go)). Nothing wakes the link
upkeep when the answer flips: a punched link that went down while the node
still counted as answered waits for its next link state event.

## Motivation

### Goals

*   One value for the node's own state, the published host and the
    rendezvous answer, which the topology provider publishes as either
    changes.
*   The node directory's and the WireGuard application's publications go
    out at once on a change, and keep their cadence.
*   The link upkeep re-weighs its re-punches when the answer flips.
*   No reader resolves the host: the conns' send path reads the topic.

### Non-goals

*   What the host and the answer are stays: the founding core's domain,
    held through a failed lookup; else the learned host, persisted; else
    the control host, the wildcard naming none; and the latest link reply's
    report.
*   Whether a NAT stands between the node and its peers is still read at
    each directory publication, by binding the host.
*   No other topic.

## Proposal

### The topic

`(*Bus).Self()` carries `bus.SelfState` events: `Host`, the host the
node's publications carry, zero publishing nothing; and
`RendezvousUnanswered`, the latest link reply's report that the node's
published rendezvous address went unanswered. The zero state names no host.

### The publishers

The topology provider publishes the state:

*   **At wiring:** the state the node starts with: the learned host the
    state directory holds, else the control host, or the founding core's
    domain when the domain is an address.
*   **On a change:** a rendezvous reply that teaches a new host, and a link
    reply whose answer differs from the last.
*   **The founding core's domain:** a loop looks the domain up as the
    provider starts running, then a minute after an answer and thirty
    seconds after a failure, and publishes each new answer. The first
    answer lands as the provider starts, where a conn's first send looked
    it up before.

The file provider publishes its control host once, at wiring.

### The readers

| Reader | Before | After |
| :-- | :-- | :-- |
| `measured.NodeDirectoryConfig` | `Host`, per publication; `Reach` | `Self`, subscribed; `BehindNAT`, per publication |
| `wireguard.Config` | `PublishedHost` | `Self`, subscribed |
| The wildcard-bound conns | `PublishedHost`, per packet | The topic's host |
| The link upkeep | The provider's flag | The topic, subscribed |
| `apps.Environment` | `PublishedHost` | none: `Bus` carries it |

The node directory and the WireGuard application publish on each event as
well as on their cadence: `loops.SleepOr` pauses for a duration or until a
channel delivers. The link upkeep runs a pass on each event.

`Provider.PublishedHost`, the provider's flag, the domain's memo, and the
assembly's `publishedHost` go.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | `(*Bus).Self()`, `SelfState` |
| `pkg/libs/loops` | `SleepOr` |
| `pkg/modules/topology/impl/measured` | The provider publishes; the directory and the upkeep subscribe |
| `pkg/modules/topology/impl/file` | The provider publishes its control host |
| `pkg/apps`, `pkg/apps/wireguard` | The application subscribes |
| `internal/services` | The wildcard host reads the topic |

The [architecture](/docs/design/architecture.md)'s node bus entry names
the topic.

## Compatibility

There is no wire or storage change. A host learned or an answer reported
reaches the core's directory at once rather than at the next minute's
publication.

## Test plan

*   **The topic and `SleepOr`:** `SleepOr` returns true on its duration and
    on a delivery, and false once its context ends or its channel closes.
*   **The provider:** the state at wiring; a learned host and a changed
    answer each published once, an unchanged one not at all; the founding
    core's domain published on its first answer and held through a failed
    lookup.
*   **The publications:** the node directory and the WireGuard application
    publish at once on an event, and again on their cadence.
*   **The upkeep:** a down punched link is punched again once the answer
    flips, with no link state event.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each. The NAT benchmarks hold or
    improve.

## Implementation history

*   Landed as proposed: the topic ([bus.go](/pkg/libs/bus/bus.go),
    [self.go](/pkg/libs/bus/self.go)), `SleepOr`
    ([loops.go](/pkg/libs/loops/loops.go)), the providers' publications
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go),
    [provider.go](/pkg/modules/topology/impl/file/provider.go)), and the
    readers ([directory.go](/pkg/modules/topology/impl/measured/directory.go),
    [upkeep.go](/pkg/modules/topology/impl/measured/upkeep.go),
    [directory.go](/pkg/apps/wireguard/directory.go),
    [wildcardhost.go](/internal/services/wildcardhost.go)). The labs and
    benchmarks ran once over this change and proposal 0090's, five runs
    each against the node before them.
    *   **NAT network:** it settled in 2m20s to 2m50s in four runs and
        4m30s in one, against 2m50s to 3m30s, on paths as short. Its public
        nodes, finding a node behind a NAT in the directory as soon as it
        learns its host, punched toward it before it dialed out: 9 to 10
        punches a run against 6 to 8. A rebind recovered in 16.5 to 16.7
        seconds, a restarted peer in 13.0 to 13.2, a node behind a
        symmetric NAT joined in 44 to 109, and the founder returned in 186
        to 264.
    *   **Regions and stranded networks:** they settled as before.
    *   **Site network:** joined at the parents' inside addresses, it
        linked 3 to 4 of its 6 pairs at their inside addresses, against 4
        to 5, and the paths its links offer averaged 1.42 to 1.75 times the
        reference, against 1.25 to 1.42; joined outside, it settled as
        before. A site node's inside address, which a site peer's
        rendezvous teaches it, now leaves the directory once a public peer
        teaches it the gateway's, where the minute's cadence had kept it
        listed for the other site nodes to dial. Those links depended on
        when the publication ran; serving the inside addresses is the site
        directory's
        ([ADR-0028](/docs/adrs/0028-serve-each-site-a-directory-of-its-own.md)).
