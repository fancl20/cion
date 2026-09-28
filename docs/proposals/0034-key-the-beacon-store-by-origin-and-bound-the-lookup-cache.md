# Key the beacon store by origin and bound the lookup cache

This proposal closes the last deferral [proposal
0015](/docs/proposals/0015-trust-verification-and-issuance-hardening.md)
recorded in its non-goals — "no hardening of the path layer's own stores;
the lookup cache and the beacon store's keying are separate findings with
separate proposals" — by keying the beacon store's candidates by the
origin the rest of the system already treats as their identity, and by
giving the lookup service's cache a key that names what it fetched and a
bound that empties it of answers no reader accepts.

[TOC]

## Summary

The beacon store keys a candidate by its ingress interface and segment ID
(`beaconKey`, `pkg/controlplane/beaconstore.go`); the path database writes
the same segment under a three-part identity — originating IA, segment ID,
creation timestamp (`pkg/pathdb/impl/bbolt/db.go`, `marshalKey`). The two
bytes of segment ID are drawn at random at origination (`NewPCB`,
`pkg/segment/segment.go`), and two cores whose beacons share a link into a
node share the ingress field of their keys there, so the ID alone
distinguishes them — a sixteen-bit space where a collision between
unrelated segments is expected, not exceptional, as candidates accumulate.
On a collision, `Insert` reads the newcomer as a re-origination of the
incumbent and the fresher replaces the other
(`pkg/controlplane/beaconstore.go`): an unrelated segment silently evicts a
valid candidate, and everything the store feeds — propagation to children
and both registrations into the path database (`BestSet`'s callers,
`pkg/controlplane/beacon.go`) — never sees the path that left. The
deliberate shape rides the same seam: an enrolled core chooses its own
segment IDs, its beacons pass every check proposal 0015 bound — the origin
a TRC-named core, every signature bound to the identity its entry claims —
and the eviction costs it nothing but the choice of a number.

The lookup service's cache has the same species of key and no bound at
all. It is written under the pair of the core fetched from and the
destination asked about (`fetchCached`, `pkg/controlplane/lookup.go`) and
never deletes: reads skip expired entries, and one map entry per pair ever
asked about stays for the process's lifetime — growth any peer the control
endpoint answers reaches by asking about new destinations, in a store
whose own TTL caps an entry's usefulness at a minute. And the key omits
the segment type it fetched: core-segment and down-segment fetches share
one key space, kept apart today only by the shape of their callers — the
source handler's core branch runs for wildcard and core destinations, its
down branch for concrete non-cores — while `Down`, the seam the path
provider will call, carries no such guard and no production caller yet.

## Motivation

The store's own contract is right; its key is wrong. The beacon store
promises the latest origination per key (`pkg/controlplane/beaconstore.go`),
and the promise is what a receiving node wants: one slot per segment,
replaced when that segment is re-originated fresher. What the key leaves
out is which segment — the origin — so the promise covers segments that
were never the same one. The loss is quiet by construction: the
per-interface cap absorbs it as capacity, no reader reports a path
missing, and the node's children learn one route where two existed.

The deliberate case is the finding's security half. A core beyond a shared
link originates beacons with IDs it picks; every cryptographic check
passes, and the store's key does the rest — the victim's candidates leave
every neighbor downstream of the shared link that the attacker's freshness
outraces. The per-interface cap bounds how much a single collision costs;
nothing bounds how often one is tried. Keying by origin does: another
core's ID is no longer the victim's address in the store.

The cache's growth needs no attacker. A node that serves path questions
about many destinations holds one dead entry per pair past its minute of
usefulness, for as long as the process lives — the same accumulation
proposal 0015 bounded in the Telegram authorizer's decision map, whose
entries drop when their window passes. The type-blind key is quieter: no
caller crosses it today, so nothing fails today; the seam arms it. The
first caller of `Down` that resolves a path to a core destination writes
down segments over the core-segments entry — or reads core segments as the
answer to a down question — and the crossing is a routing answer served
from the wrong question's cache. The disjointness belongs in the key, not
in the callers' shape, for the callers will change and the key is what
stays.

### Goals

*   The origin in the beacon key: candidates are keyed by ingress
    interface, originating ISD-AS, and segment ID; the
    latest-origination-per-key contract, the per-interface cap, and
    `BestSet`'s freshness ordering are unchanged.
*   The type in the cache key: each fetched segment kind is cached under
    its own name, the pair beside the type it answers.
*   The cache's bound: entries whose expiry has passed leave on the
    write that follows, the Telegram decision map's shape — the map holds
    what the TTL still covers, and nothing else.

### Non-goals

*   No change to the path database — its keys already carry the full
    identity, and its expiry sweep stays as it is.
*   No policy in the beacon store — no per-origin caps, no preference
    between origins; the per-interface cap remains the store's only bound
    and freshness its only ordering.
*   No persistence for the beacon store — a restarted node is rebuilt by
    the next period's beacons, as today.
*   No negative caching and no TTL change — an empty answer still enters
    no entry, and a cached answer still lives at most its minute.
*   No change to segment ID generation at the originator and none to
    beacon verification — what proposal 0015 bound stays bound; the
    change is what the store concludes from verified beacons.

## Proposal

### Key the beacon store by origin

`beaconKey` grows the originating ISD-AS, and `Insert` reads it from the
beacon's first entry — `FirstIA`, `pkg/segment/segment.go` — the identity
reception already verified against the TRC's core list and the entry's
signature. The replacement rule keeps its form — same key, fresher
timestamp replaces — and changes its reach: one origin's re-origination
still holds one slot, and two origins sharing an ingress and an ID are two
candidates, each visible to `BestSet`, both counted under the
per-interface cap. `evictStale` walks keys, not names, and needs nothing;
the first entry's presence is reception's verified precondition, not a
guard this adds.

### Key the cache by what it answers

The cache key becomes the pair beside the segment type it fetched. A
core-segment fetch and a down-segment fetch for one destination are
different questions and answer from different entries; the source
handler's branches and `Down` all write and read through the one map, and
the crossing that today lives in the callers' shape becomes the key's
own. No caller grows a guard, for none is needed.

### Let the cache forget

The write in `fetchCached` — under the lock it already holds — deletes the
map's entries whose expiry has passed, the Telegram authorizer's shape for
its asks and its invites. No background sweeper: a goroutine that wakes on
its own keeps the service from sitting whole inside a fake-time bubble,
and the write path already owns the map. The map then holds what the TTL
and the fetched segments' own expirations still cover; a minute of
distinct questions costs a minute of memory, and a peer's spray of
destinations no longer outlives its usefulness.

## Test plan

*   **Unit tests, the store:** episodes beside the beaconer's existing
    store use (`pkg/controlplane/beacon_test.go`) — two candidates of
    distinct origins over one ingress and one segment ID are both stored
    and both returned by `BestSet`; the same origin's fresher
    re-origination still replaces its own entry; the per-interface cap
    bounds the widened keys as one set.
*   **Unit tests, the cache:** episodes extending the cache's
    (`pkg/controlplane/lookup_test.go`) — an entry past its expiry leaves
    on the next write; an entry still within its expiry survives another's
    write; one core-and-destination pair fetched under two types answers
    each kind from its own entry; an empty answer still enters no entry.
*   **Integration tests:** a lab whose two cores' beacons share one
    segment ID through one shared child — both register as up segments
    and both compose paths, where today one does; the lab pins the
    shared ID at origination (`PCBWithID`, `pkg/segment/segment.go`).
*   **Negative tests:** however many writes pass, an entry within its
    expiry is never dropped; a re-originated segment never holds two
    slots; a beacon of another origin never replaces its namesake.

## Implementation history
