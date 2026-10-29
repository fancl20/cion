# Drain a link before retiring it

This proposal makes a planned retirement graceful, as
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
decided (decision 15): the node withdraws beaconing from a link it means to
retire, keeps forwarding over it, and retires it once every segment through
it reads stale. A useless link and the cap's eviction victim leave no other
node choosing a path over a link that no longer exists.

[TOC]

## Summary

The selection retires an up link in two cases, both its own decision
([selection.go](/pkg/modules/topology/impl/measured/selection.go)): a link
its tier serves no worse without, and the victim the cap evicts for a
promotion. Either way the store write retires the link at once, and the next
data plane generation drops it. The retiring node drops the link from its own
composition, but the segments through it stay fresh at every other node
until five minutes after their last refresh
([provider.go](/pkg/libs/scion/provider.go)). Until then:

*   **A node that sends** over the link meets the interface-down signal at
    the retiring node
    ([proposal 0073](/docs/proposals/0073-answer-a-retired-links-packets-with-the-interface-down-signal.md)),
    sets the path aside for ten seconds, and sends into it again at each
    lapse.
*   **A node that reads** its paths without sending keeps choosing paths
    through the gone link while their segments are fresh and the cheapest.

Measured with the cut benchmarks on the node at `3c8665d`: in one of five
instrumented regions runs, node 6 promoted two links within 90 seconds of
the cut and retired one as useless 208 seconds after it. Twelve pairs then
chose paths through the retired link until 488 seconds, each holding a fresh
path over the formed links meanwhile; the other four runs recovered at 249
to 308 seconds. Three of ten uninstrumented cut runs recovered at 408 to 481
seconds the same way.

ADR-0017 decided removal this way: "the node withdraws beaconing from the
link and expiration retires the segments." The beaconer never withdrew: it
reads the link table, and a link leaves the table only when it retires.

## Motivation

### Goals

*   A retirement the selection plans leaves no fresh segment through the
    link at any node when the link closes.
*   The link forwards until then, so the paths chosen through it keep
    working while their segments age.
*   The node that decides the retirement drains the link alone; its
    neighbor needs no change.

### Non-goals

*   Unplanned departures. A link whose verdict stayed down retires at once,
    as today: it carries no packet, and its beacons stopped with its
    verdict. Its sources learn of it from the interface-down signal or from
    staleness.
*   The signal's ten-second hold, and the selection's prices, which read
    stale routes as routes: follow-ups of their own.
*   Revocation: ADR-0004 adds none.

## Proposal

### The drain

A node drains a link by recording when it began: `links.Link` gains
`Draining`, a time, zero while the link carries beacons, stored with the
entry. From then on:

*   **No beacon crosses the link.** The beaconer originates and propagates
    none over it, and terminates or propagates none that arrived over it. A
    segment is a terminated beacon, and every beacon over the link passes
    this node's beaconer at one end, so no new segment can name the link.
*   **The link forwards.** The data plane, the BFD session, the verdict, and
    the node's own composition treat the link as before.

A segment's timestamp is its origination at a core, so every segment through
the link dates from before the drain began. Once the drain has lasted
`StaleAfter`, every such segment reads stale at every node, behind every
fresh path the rank holds, and the link retires. The entry keeps its drain
across a restart.

### When the selection drains

*   **The useless retirement drains.** Where the prune retires the useless
    link today, it drains it, and retires it once the drain has lasted
    `StaleAfter`.
*   **A window that decides the link useful ends the drain:** the entry's
    `Draining` returns to zero, and the link carries beacons again.
*   **The cap's eviction drains an up victim** and admits nothing that
    window; a down victim retires at once, as today. The cap counts the
    draining entry until it retires, so the promotion waits for the drain,
    and no second victim drains while one does.
*   **A draining link counts as gone for the floor:** neither toward the
    dialed up links a useless retirement needs above it, nor toward the up
    links below which reachability alone admits. Nor is it among the
    victims an eviction chooses from.
*   **A link whose verdict stays down retires at once,** draining or not.

One up link still leaves per window: a window that starts a drain retires
no other up link and starts no other drain.

### The link state

`bus.LinkState` reports which links carry beacons: the live entries not
draining. The beaconer reads it in each pass, as it reads the table today.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/links` | `Link.Draining`; both stores keep it |
| `pkg/libs/bus` | `LinkState` reports the links that carry beacons |
| `pkg/core/controlplane` | The beaconer carries no beacon over a draining link |
| `pkg/modules/topology/impl/measured` | The useless retirement and the eviction drain first; a useful verdict ends a drain |

## Compatibility

The stored entry gains a field, and an entry stored before it reads as not
draining. Nothing changes on the wire: the neighbor stops hearing beacons
over the link, and the beacons it sends over it go unused.

Retirements the selection plans take `StaleAfter` longer. A network that
trims redundant links while it forms settles that much later: the regions
network retired three to seven links as useless on its way to settling, its
last one fixing the settle time.

## Test plan

*   **The stores:** both keep `Draining` across a write and a reopen.
*   **The link state:** it reports a draining link as live and usable, and
    as carrying no beacons.
*   **The beaconer:** it originates and propagates nothing over a draining
    link, and neither propagates nor terminates a candidate that arrived
    over one.
*   **The selection:** a useless link drains and retires after `StaleAfter`;
    a useful window ends the drain; an eviction drains an up victim and
    admits the candidate once the victim retires; a draining link counts
    toward neither the floor nor the victims; a down link retires at once.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs of each settled and cut benchmark against
    the node before it. Cuts recover by the cut link's staleness horizon,
    with no tail from a retirement after the cut; settled networks reach the
    same paths, later by the drain where they retire useless links.

## Implementation history
