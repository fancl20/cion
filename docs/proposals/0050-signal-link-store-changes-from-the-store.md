# Signal link-store changes from the store

This proposal makes the link store's change signal the store's own, as
decision 5 of
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md) describes
the reload machinery: "The store, the change signal, and the generation
supervisor are the reload machinery: sources write, the node rebuilds — one
mechanism every source feeds and no source owns." The node wraps its link
store in a decorator that signals every write, and the topology providers
stop signaling by hand. This narrows the change notification that
[proposal 0011](/docs/proposals/0011-minimal-node-core-and-topology-providers.md)
put in each provider's configuration. No run argument, wire message, or
store format changes.

[TOC]

## Summary

Each writer of the link store pairs its writes with a signal it places by
hand. The measured provider takes a `Notify` callback
([provider.go](/pkg/modules/topology/impl/measured/provider.go)) and passes
it to its rendezvous acceptor and its link service as `Changed`
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go),
[linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)), and
its selection loop takes another `Changed`
([selection.go](/pkg/modules/topology/impl/measured/selection.go)). The file
provider takes its own `Notify`
([provider.go](/pkg/modules/topology/impl/file/provider.go)). Seventeen
writes in five files meet ten signal calls, behind five callback fields that
are each nil-checked. The selection pass and the file reconciliation thread
a `changed` result through their steps to signal once at the end.

The node receives the signal in `notifyLinkChange`
([dataplane.go](/internal/services/dataplane.go)), which moves the link
table snapshot's version and wakes the data plane loop's generation swap.
Because a write that missed its signal would leave both stale, the snapshot
also expires after a second: `tableTTL` covers "the writes that do not
notify".

Two gaps follow from signals placed by hand:

*   The file provider signals once at the end of a reconciliation, and a
    write the store refuses returns before the signal. The writes that
    landed earlier in the pass, the retirements among them, reach the data
    plane only at the next signal from any writer.
*   A provider must know to signal, though the topology contract never says
    so: `Pieces.Store` is where "the provider's decisions land", and landing
    them is not enough.

## Motivation

The signal belongs to the store's writes, not to the writers: every write
the data plane must apply passes through the store. A decorator makes every
write signal by construction, closes the reconciliation's gap, and lets a
provider land its decisions in the store and do nothing more, the contract
ADR-0013 describes.

### Goals

*   Every successful write to the node's link store signals the node,
    whoever writes it.
*   No topology provider carries a change callback, a nil check for one, or
    a result threaded only to signal.
*   The link table snapshot rebuilds when the signal moved its version, and
    only then.

### Non-goals

*   No change to the `links.DB` methods or rules, to the stores, or to the
    generation swap.
*   No filter on which writes signal: every successful write does, as four
    of the six writers do today. A selection pass or a file reconciliation
    that writes more than once can cost one more swap than it does today;
    the node's one-slot channel coalesces the rest.
*   No change to what the providers write.

## Proposal

### The store signals its writes

`links.Notifying(db, notify)` returns a `links.DB` that forwards every
method to `db` and calls `notify` after each `Insert` or `Update` that
returns no error. A refused write signals nothing, and neither do the reads
or `Close`. The decorator lives in the links contract package, beside
`Check`, `Links`, and `Serving`.

The node wraps its store where it opens it
([controlplane.go](/internal/services/controlplane.go)): `n.linkStore`
holds the wrapped store with `notifyLinkChange` as its signal, so the
provider's `Pieces.Store`, the node's own readers, and `App.Links` all see
it. The raw store's close stays the release the group owns.

### The providers stop signaling

The measured provider's `Config.Notify`, `RendezvousConfig.Changed`,
`LinkService.Changed`, and `SelectionConfig.Changed` go, with the helpers
that nil-check them, and so does the file provider's `Config.Notify`. The
selection pass's `sweep`, `promote`, and `prune` stop returning whether they
changed the table, where that result served only the signal, and the file
reconciliation drops its `changed` flag. `Pieces.Store`'s documentation
states that a write is all it takes to land a decision.

### The snapshot rebuilds on the signal alone

`tableTTL` and the snapshot's timestamp go
([dataplane.go](/internal/services/dataplane.go)): `linkTable` rebuilds when
`notifyLinkChange` has moved the version since the last build, and serves
the cached snapshot otherwise.

The change lands in one commit: a decorator beside the providers' own
signals would signal twice, and providers without signals before the
decorator would signal nothing.

## Test plan

*   **Unit, the decorator:** the links contract suite runs on a memory store
    wrapped by `Notifying` and passes as the bare store does. A counting
    signal fires once for each successful insert and update, and not for a
    refused write or a read.
*   **Unit, the providers:** the tests that counted callbacks count writes
    through a wrapped store instead. The file provider's seed signals once
    per entry, an unchanged file writes nothing, and a changed file signals
    once per write. A selection pass that changes nothing writes nothing.
*   **Unit, the node:** on an assembled founder, a write through the node's
    store wakes the data plane loop, and the entry it writes appears in the
    next read of the link table with no wait.
*   **Integration:** the labs' generation swaps stand as they are: the
    static lab's link removal and the rendezvous labs' joins and promotions
    each land as swaps the traffic survives.
