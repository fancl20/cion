# Keep the last link to a reflector in each directory

This proposal narrows the link retirements of
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
and
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)
by the reflector of
[ADR-0030](/docs/adrs/0030-punch-through-both-nats.md): in each directory a
punch runs in, a node keeps its last up link to a neighbor that can serve it
as a reflector there, and only a down verdict retires that link.

[TOC]

## Summary

Today
([selection.go](/pkg/modules/topology/impl/measured/selection.go),
[provider.go](/pkg/modules/topology/impl/measured/provider.go)):

*   **Every punch needs a reflector at both ends** (ADR-0030, decision 3).
    The node that asks and the node that answers each learn their reflexive
    address from the rendezvous acceptor of an established neighbor that
    reports itself dialable in the punch's directory. A probe's punch needs
    one as much as an establishment's.
*   **The retirements weigh routes and prices alone.** A link the clustering
    does not allow retires once a chosen pair links the two units, its tier
    keeps its route count without it, and it cuts no member off; a useless
    link retires once its tier serves no worse without it; the cap evicts a
    link that yields. None asks whether the link is the node's reflector.
*   **A node can retire its last reflector.** In one run of the NAT lab,
    node 4, behind a NAT in the cluster of nodes 3 to 6, retired its links
    to the public nodes 0 and 2, neither of them a pair the clustering
    chose. Its remaining neighbors, 3 and 6, sit behind NATs and report
    themselves undialable, so 4 held no reflector. The one punch between 4
    and 5 had failed on its handshake while 4 still held one; with none
    left, every later probe between the two failed at 4's end, so they read
    each other as unreachable and never tried again. Whether the pair
    linked turned on whether a punch between them succeeded before the
    retirements.

## Motivation

### Goals

*   In each directory that holds a node no rendezvous exchange reaches, a
    node keeps its last up link to a neighbor that can serve it as a
    reflector there.
*   The useless retirement, the clustering's, and the cap's eviction pass
    over that link; a down verdict still retires it.
*   The reflector a punch picks and the link the selection keeps follow one
    definition.

### Non-goals

*   Regaining a reflector once lost: a node whose last reflector's link
    went down, or whose far end evicted it, holds none until the floor or a
    stranded tier promotes a link to a dialable neighbor.
*   Where a punch reflects once clusters become scopes (ADR-0039, principle
    10): a cluster of nodes behind NATs then holds no dialable member in its
    own directory, so a punch there finds no reflector whatever links its
    members keep, and the proposal that makes clusters scopes settles where
    it reflects.

## Proposal

*   **A reflector link** joins a directory, is established, its verdict up,
    and leads to a node whose entry there reports a rendezvous address
    answering: the link a punch in that directory can reflect over.
    `pickReflector` picks the first of them in the directory's order, as
    today.
*   **A directory a punch runs in** holds an entry that reports no
    rendezvous address answering: the node's own, which its peers punch
    toward, or a peer's, which the node punches toward.
*   **The last reflector link** of such a directory, when the node holds one
    alone, is kept each window: the useless retirement neither announces
    nor retires it, and the cap's eviction passes over it. A retirement the
    node announced before the link became its last is withdrawn, the record
    naming why.
*   **A down verdict** still retires the link after `DemoteWindows`: a dead
    link reflects nothing.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The reflector links in one helper, which `pickReflector` and the selection share; the selection keeps the last one of each directory a punch runs in |

## Compatibility

Nothing on the wire changes. A node behind a NAT may hold one link more
than the clustering chose: its last link to a dialable neighbor in each
directory a punch runs in. A directory every node of which answers its
rendezvous exchange keeps nothing.

## Test plan

*   **The reflector links.** Only links established, up, and joining the
    directory, to nodes whose entries there report an answering address,
    count; `pickReflector` picks the first of them.
*   **The last one.** A directory that holds an undialable entry keeps its
    one reflector link; one holding two keeps neither; one where every
    entry answers keeps none.
*   **The selection.** A node behind a NAT keeps its last link to a
    dialable neighbor though the clustering does not allow it, and retires
    it once a second dialable neighbor's link stands beside it; an
    announced retirement of the link is withdrawn once it is the last; the
    cap's eviction passes over it.
*   **The labs.** The labs pass, and the NAT benchmarks run against the
    commit before.
