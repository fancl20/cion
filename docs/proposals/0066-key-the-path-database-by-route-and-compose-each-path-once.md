# Key the path database by route and compose each path once

This proposal grounds on the promise
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)
makes of the path layer's stores — they "stay small at CION's target
scale" — and narrows the identity ADR-0004 gave the path database:
originating core, segment ID, and creation timestamp become the segment's
type and the route it crosses, the identity the reference implementation
keys its own path database by. Path enumeration stops composing one
candidate per pair where one part of the pair travels nowhere. No run
argument or wire message changes; the store's key format does.

[TOC]

## Summary

Every origination of a beacon draws a fresh segment ID and timestamp
(`NewPCB`, [segment.go](/pkg/libs/segment/segment.go)), and the path
database writes a segment under exactly those three fields
(`marshalKey`, [db.go](/pkg/modules/pathdb/impl/bbolt/db.go)). Each
registration pass terminates the five freshest candidates
(`registerOnce`, [beacon.go](/pkg/core/controlplane/beacon.go)), so every
pass adds up to five rows to a non-core's up segments and five to its
core's down segments, and each row stays until its hops expire six hours
later. A node that has run for six hours holds about 1,800 up segments over
a single route, and its core about 1,800 down segments per registrant.

`Enumerate` ([provider.go](/pkg/libs/scion/provider.go)) composes every
up segment with every down segment at their deepest common AS entry. For
two non-core nodes the candidate count is the product of the two row
counts. Where one node sits behind the other — a joiner enrolled through
a non-core neighbor — every pair meets at an end of one part: at the local
node, the pair's path is the down segment's tail, which the down-only
meeting already emits; at the destination, it is the up segment's
reversal, which the containing branch already emits. Every pair repeats a
path the loop carries once.

The selection loop enumerates each directory peer once per window and
keeps the candidates for the window
([selection.go](/pkg/modules/topology/impl/measured/selection.go)); the
WireGuard application enumerates each mesh peer every refresh
([directory.go](/pkg/apps/wireguard/directory.go)). A candidate retains
about 330 bytes, so a leaf-to-leaf enumeration over saturated stores —
some 3.2 million candidates — holds about a gigabyte.

## Motivation

A node runs out of memory a few hours after a second non-core node joins
the network: before it, the only directory peer is the core, whose
enumeration is linear — the core holds no down segments to itself. On the
userspace fabric, a line of the founding core, a middle node, and a joiner
enrolled through the middle composed 7,695 candidates from the joiner to
the middle ten seconds into the run and 46,075 fifty seconds later, under
the labs' pacing. The process's allocation rate grew from 20 MB/s before
the join to 360 MB/s ninety seconds after it.

The path database survives a restart, so a node the kernel killed reloads
the same rows and the first selection window or WireGuard refresh repeats
the enumeration: the node crash-loops until its segments expire. The core
pays as well: every lookup answer carries each registrant's originations,
and each answer's reader parses them all.

The store's contract is wrong, not its bound. Successive originations over
one route are one route: a node routes over the links they cross, and the
freshest of them carries the longest validity. The reference
implementation keys its path database by a hash of each entry's ISD-AS and
interface IDs and keeps the newest segment per key; CION keyed by the
origination and kept them all.

### Goals

*   One segment per route and type in the path database: the freshest
    origination holds the slot, and a staler or equal one leaves it alone.
*   Each path composed once where a pair's meeting leaves one part no
    travel.

### Non-goals

*   No change to beaconing: origination and registration cadences, the
    best set's size, hop expiration, and the beacon store stay as they
    are.
*   No change to the wire: registrations and lookup answers carry the same
    messages, and a core answers fewer segments.
*   No deduplication of the down segments a lookup fetches: an answer from
    a core that still keys by origination composes linearly once the idle
    meetings compose nothing, and the lookup cache's minute is unchanged.
*   No revocation: expiration still bounds staleness.
*   No migration: a network adopting the route identity starts with empty
    path databases.

## Proposal

### Key the path database by route

`pathdb.Key` becomes the segment's type beside its route: each AS entry's
ISD-AS and ingress and egress interface IDs, in construction order
([pathdb.go](/pkg/modules/pathdb/pathdb.go)). `Insert` stores a segment
unless the stored segment with its key is at least as fresh by creation
timestamp, and reports whether it stored the segment. The bbolt store
encodes each hop's three fields, then the type: the route opens with the
originating core, so a key's first eight bytes remain the prefix a query
by origin seeks. The type keeps one route stored as two types apart.

### Compose each path once

`Enumerate` skips an (up, down) pair whose deepest common entry is the up
segment's terminator — the local node — or the down segment's terminator —
the destination. The down-only meeting and the containing branch emit
those paths with one piece each, so the skipped pair's candidate was never
fresher and never fewer in entries. A meeting where both parts travel
composes as before. The route count, the comparator's freshest carrier,
and WireGuard's ranking read the same distinct paths.

## Test plan

*   **Contract tests** ([dbtest.go](/pkg/modules/pathdb/impl/dbtest/dbtest.go)):
    the originations of one route share one slot holding the freshest; a
    repeated or staler origination stores nothing; another route is
    another slot; one route stored as two types holds two slots; expiry
    and persistence hold as before, the persisted key compared by route.
*   **Composition** ([provider_test.go](/pkg/libs/scion/provider_test.go)):
    from the middle of a line, many up segments beside each down segment
    through the node compose one candidate per down segment; from below
    the middle, many down segments to the destination beside each up
    segment through it compose one candidate per up segment; the coverage
    and retired-interface episodes count the down-only meeting and the
    containing reversal alone.
*   **Integration** ([network_test.go](/internal/testnetwork/network_test.go)):
    the line lab waits for a fresher origination to replace the first
    segment C terminated, then finds one segment per route in every path
    database and one candidate in each enumeration between B and C.

## Implementation history

*   Landed as proposed ([pathdb.go](/pkg/modules/pathdb/pathdb.go),
    [db.go](/pkg/modules/pathdb/impl/bbolt/db.go),
    [provider.go](/pkg/libs/scion/provider.go)).
