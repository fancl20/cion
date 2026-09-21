# Sweep expired chains from the trust database

This proposal closes the deferral [proposal
0015](/docs/proposals/0015-trust-verification-and-issuance-hardening.md)
recorded in its non-goals — "expired chains accumulate until a store with a
delete operation exists" — by giving the trust database the delete operation
the path database already carries and the periodic sweep that exercises it,
so a node's trust.db holds the chains its validity windows can still name
and nothing after.

[TOC]

## Summary

`trust.DB` has no delete: the interface reads and inserts chains and TRCs
and closes (`pkg/trust/db.go`), and nothing in the node ever removes a
chain. Every chain a node holds stays for the process's — and the file's —
lifetime. Three writers accumulate: the node's own re-enrollment, which
mints a fresh chain roughly every two days against the three-day
`ASValidity` and the day-ahead `ChainRenewalThreshold`; the core's CA
rollover, which rides each issued chain with a new CP CA certificate
whenever the current one cannot cover a full AS validity — about every
eight days against the eleven-day `CAValidity` (`pkg/trust/issuer.go`,
`ensureCACert`); and the network-backed provider, which inserts every
chain it fetches to verify a peer's signatures (`pkg/trust/network.go`).
Correctness is untouched — every query filters by validity, so an expired
chain is already invisible to every answer — but the file grows without
bound, and proposal 0015's rate cap bounds only how fast. A year of
operation leaves each node hundreds of chains no reader will ever accept.

The path database met the same question with `DeleteExpired`
(`pkg/pathdb/pathdb.go`), swept by the beaconer's own loop on its
registration interval (`pkg/controlplane/beacon.go`, `sweepOnce`). This
proposal gives the trust database the same pair — a delete on the store, a
sweep on the loop that owns the store's validity semantics, the enrollment
lifecycle of `pkg/controlplane/lifecycle.go`.

## Motivation

A store that only grows is an operational debt with a schedule: bbolt
rewrites are cheap while the file is small, and the chain bucket's layout
— one sub-bucket per ISD-AS, one entry per issued chain, keys carried by
the outer scan proposal 0015 made exact — keeps the dead entries in every
bucket the sweep of the cursor touches. The validity filter means no query
ever returns them; the file still carries them, backs them up, and hands
them to every future migration.

The delete changes no answer, and that is the whole argument for its
safety. Every read through the store filters by the query's validity — the
bbolt `Chains` comparison and the engine's selection alike — so a chain
past its validity is invisible whether present or absent, and a
verification that would have used it fails on validity either way. What
changes is the file's size, and nothing else.

What must not be swept is the TRC. The pinned base TRC anchors every
verification the node makes after its expiry as well as before it — a new
base TRC means redeploying (ADR-0003) — and deleting it gains storage and
loses the node's identity. The sweep touches chains alone.

### Goals

*   The delete: `DeleteExpiredChains` on `trust.DB`, the path database's
    `DeleteExpired` shape — a chain whose AS certificate expired before
    the given time leaves the store, its sub-bucket with it when the
    sub-bucket empties; TRCs are untouched.
*   The retention: deletion passes an expiry by a window — one hour — so a
    peer whose clock trails the node's still fetches from it the chain it
    can still verify.
*   The sweep: both enrollment loops run a sweep pass on its own interval,
    the beaconer's `sweepOnce` shape; every node runs one of the two
    loops, so every node sweeps.

### Non-goals

*   No TRC deletion — base and pinned, the TRC outlives its validity
    (ADR-0003); the sweep names chains.
*   No change to the path database's own sweep or its store.
*   No change to chain selection, validity filtering, issuance, or
    enrollment — the sweep only removes what every reader already
    refuses.
*   No archiving or export of expired chains before deletion.

## Proposal

### The delete operation

`trust.DB` grows `DeleteExpiredChains(ctx context.Context, t time.Time)
(int, error)`, the path database's `DeleteExpired` signature. A chain is
deletable when its AS certificate's `NotAfter` lies before `t`; the caller
passes `time.Now()` less a retention window. The bbolt implementation
walks the `chains` bucket's per-ISD-AS sub-buckets in one read
transaction, collects the expired keys, and deletes them in one write
transaction — the two-pass shape the path database's own `DeleteExpired`
carries (`pkg/pathdb/impl/bbolt/db.go`), so a malformed entry aborts the
sweep having deleted nothing. An ISD-AS sub-bucket left empty is deleted
with its last chain: the sub-bucket keys ride the outer scan, and a shell
that outlives its chains is the same accumulation wearing a smaller
shape. The `trcs` bucket is not opened.

### The retention window

`ChainRetention`, one hour, beside the validity constants in
`pkg/trust/certs.go`: a chain is deleted when it has been expired for the
window, not at the instant it expires. The window is skew tolerance, the
`signingBackdate`'s minute enlarged to cover the fetch it guards — a peer
whose clock trails by less than the window still obtains from the node the
chain under which, on that peer's clock, the node's signatures still
verify. The cost is plain: one hour of dead chains per name, a bounded and
idle residue.

### The sweep pass

Both enrollment loops — `RunEnrollment` on every node but the founding
core, `RunCoreEnrollment` on it (`pkg/controlplane/lifecycle.go`) — spawn
a sweep goroutine before their passes begin, the beaconer's own shape: a
ticker on `ChainSweepInterval`, one hour, whose every pass calls
`DeleteExpiredChains` with `time.Now()` less `ChainRetention`. The loops
already own the store's validity semantics — the renewal threshold, the
newest-chain read, the TRC expiry warning — and the sweep is the same
reading done for the store's size instead of the node's chain. Errors log
the beaconer's `sweepOnce` way; a successful sweep is silent, for it is
the common case. Every node runs one of the two loops, so the sweep needs
no wiring beyond them.

## Test plan

*   **Unit tests:** the dbtest harness gains the episodes the contract
    asks of every implementation — a chain expired past the window leaves
    the store, a chain within the window stays, an emptied ISD-AS
    sub-bucket leaves no shell, TRCs survive untouched, and the returned
    count names what left. The bbolt suite covers the two-pass shape: a
    malformed entry aborts the sweep with nothing deleted.
*   **Integration tests:** a lifecycle episode under `testing/synctest` —
    chains inserted, the clock advanced past expiry and window, one sweep
    pass — the store answers every valid query exactly as before and
    holds no expired chain; the join lab's behavior unchanged.
*   **Negative tests:** a chain still within its validity is never deleted
    by however many sweeps pass; the pinned TRC survives a sweep of a
    store whose chains are all expired.

## Implementation history

*   (To be recorded as the change lands.)
