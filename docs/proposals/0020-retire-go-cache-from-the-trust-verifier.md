# Retire go-cache from the trust verifier

This proposal removes the repository's one unmaintained dependency —
`patrickmn/go-cache`, frozen at a 2018 pseudo-version — by giving the trust
verifier a typed TTL cache local to `pkg/trust`. It grounds on [proposal
0004](/docs/proposals/0004-beaconing-and-trust-lifecycle.md), whose engine
the cache serves, and on [proposal
0015](/docs/proposals/0015-trust-verification-and-issuance-hardening.md),
which hardened the verification path the cache sits on. No boundary moves
and no record is re-decided: the cache's semantics — lazy expiry,
first-write-wins — are kept exactly and made explicit in a type the node
owns, and the dependency leaves `go.mod` and `vendor/`.

[TOC]

## Summary

The engine's verifier keeps recently used crypto material in
`patrickmn/go-cache` (`pkg/trust/verifier.go`, `pkg/trust/engine.go`):
`NewEngine` constructs `cache.New(defaultCacheExpiration, 0)` — a one
minute default, and a zero cleanup interval, so no janitor goroutine,
chosen deliberately, in the constructor's own words: "a cache without a
background goroutine keeps the engine whole inside a fake-time bubble."
The whole surface the code uses is three calls — the constructor, `Get`
in `cacheGet`, `Add` in `cacheAdd`, the last with its error discarded
beside an inherited note: `XXX(matzf): could use Set, subtle difference`.
Two key families live in the one cache: `notify-<TRCID>` holds
`struct{}{}` for a minute, deduplicating TRC fetch attempts, and
`chain-<IA>-<SKID>` holds chains for a jittered window capped by the
chain's own validity. The values ride through `any`, asserted back to
`[][]*x509.Certificate` at the read.

The replacement is `ttlCache[V]` — a map under one `RWMutex`, entries of
value and expiry, lazy expiry on read, first-write-wins add, and no
sweeper because none is needed: a read that finds an entry expired
deletes it. The engine holds one typed instance per key family, the
exported `Cache` field — marked experimental since proposal 0004 carried
it in — leaves the `Verifier`, and a zero-value `Verifier` keeps today's
tolerance: no cache, every read through the provider.

## Motivation

The dependency argument stands alone. `patrickmn/go-cache` is the only
direct dependency in [go.mod](/go.mod) without a module file of its own —
imported `+incompatible` at a pseudo-version from 2018, upstream archived
since — while everything beside it, certmagic, quic-go, scionproto, bbolt,
is alive. What it provides here is a map with timestamps; what it carries
is a janitor the engine turns off, an `interface{}` API, and options —
item counts, snapshots, flushes — the verifier never touches.

The semantics it does carry are load-bearing and undocumented. The
`Add`-versus-`Set` difference the XXX names decides whether a straggler
fetch resets the window the first fetch established: keep-first means
concurrent verifications of one key install a single window, the first
one's, and the losers' results are dropped. That is the correct answer —
a slow second fetch must neither extend nor shorten the first's
expiration — and today it is an inherited accident. A local type turns
the note into a stated invariant.

Scale finishes the argument. The cache holds tens of entries — one per
peer ISD-AS and subject key ID in view — for windows of about a minute.
Nothing third-party is buying anything at that size, and the no-janitor
property the engine chose at its call site becomes structural: the type
cannot start a goroutine.

### Goals

*   The type: an unexported `ttlCache[V any]` in `pkg/trust` — one
    `RWMutex`, entries of `{value V, expires time.Time}`, a `get` that
    returns the value only while it is unexpired, an `add` that keeps an
    existing unexpired entry. No goroutine exists to start.
*   The pruning read: a `get` that finds an entry expired deletes it, so
    residue is the live set; an entry no read ever touches again lingers
    as one map slot, bounded by the distinct peer keys ever seen.
*   The typed pair: the engine holds one cache for chains and one for TRC
    notifications; the `any` assertion leaves the read path;
    `MaxCacheExpiration` keeps its role capping the jittered window.
*   The field: the exported `Cache` leaves the `Verifier` — nothing
    outside `pkg/trust` sets it today, the engine's two constructions and
    the test suite's, which set none — and a zero-value `Verifier` keeps
    verifying uncached.
*   The dependency: `patrickmn/go-cache` leaves `go.mod` and `vendor/` —
    no other import in the repository, vendored code included, reaches
    it.

### Non-goals

*   No behavior change: the TTLs and their jitter (`cacheExpiration`),
    the key shapes, the hit and miss behavior, the minute notify window —
    identical; the verifier's answers and its fetch counts do not move.
*   No size bound or eviction policy — no LRU, no capacity, no sweep
    loop; the live set is bounded by the peers and cores in view.
*   No ADR — no boundary moves; the change is a type, a field, and a
    dependency.
*   No store work — [proposal
    0018](/docs/proposals/0018-trust-database-expiry-sweep.md) owns the
    trust database's delete and sweep; this touches the verifier's memory
    alone.
*   No shared cache utility — the type stays in `pkg/trust`, unexported;
    a second user earns the extraction.

## Proposal

### The type

`ttlCache[V any]` is a map of `ttlEntry[V]` under one `RWMutex`, made by
`newTTLCache[V]()`. `get(key)` reads under the lock and reports the value
only while `time.Now()` is before the entry's expiry; a present but
expired entry is deleted under the write lock before the miss is
reported, so the map forgets what its readers have already refused. A
miss returns the zero value, whether the key is absent or expired.
`add(key, value, ttl)` computes the expiry from `time.Now().Add(ttl)` and
stores, keeping an existing unexpired entry — first-write-wins, the
XXX's resolution as a sentence: concurrent fetches of one key install
one window, the first fetch's, and the losers' results are dropped
exactly as today. The engine's no-janitor comment, written at its call
site, becomes the type's own doc comment: lazy expiry by construction,
whole inside a fake-time bubble.

### The engine's pair and the verifier's field

The engine holds `chains *ttlCache[[][]*x509.Certificate]` and `notifies
*ttlCache[struct{}]`, constructed beside the engine's other fields.
`Verify` and `VerifyBound` build their `Verifier` with the pair, as they
build it with the provider today, and `getChains` and `notifyTRC` read
and write the typed caches directly — `cacheGet`, `cacheAdd`, and the
`any` assertion leave with the shared helper they served. The
`Verifier` keeps its `MaxCacheExpiration` field, read unchanged by the
jittered window, and gains the caches as unexported fields the engine
sets in the same construction; a `Verifier` built without them, as the
test suite builds its two, holds nil caches and verifies uncached —
every read through the provider, today's nil tolerance.

### The removal

The import leaves `verifier.go` and `engine.go`, the requirement leaves
[go.mod](/go.mod)'s direct block, `vendor/github.com/patrickmn/` is
deleted, and `go mod tidy && go mod vendor` settles the graph — no
package in the repository or its vendored dependencies reaches the
module, so nothing else moves.

## Test plan

*   **Unit tests:** the cache suite under `testing/synctest` — a
    roundtrip inside the window; a read after the bubble advances past
    expiry misses, and the following `add` of the same key stores fresh;
    an `add` over a live entry keeps the first; concurrent `add`/`get`
    episodes for the race detector; a zero-value `Verifier` with nil
    caches verifies through the provider on every call.
*   **Integration tests:** the engine suite — a second `Verify` of the
    same signed message within the window asks the provider for its
    chains once, and the notify window deduplicates a repeated TRC
    report; the testnetwork labs are unchanged, for nothing in them
    observes the cache.
*   **Negative tests:** an expired entry's value is not returned while
    the map still holds it; a bare `Verifier` is today's uncached
    verifier — its provider is asked on every verification.

## Implementation history

*   (To be recorded as the change lands.)
