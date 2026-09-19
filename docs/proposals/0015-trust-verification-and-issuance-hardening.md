# Harden the trust plane's verification and issuance

This proposal closes the distance between what
[ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md)
promises and what the code checks — an AS appears in a path only through
entries it signed itself — and hardens what
[proposal 0014](/docs/proposals/0014-pluggable-enrollment-authorizer.md)
built on top: every AS entry's signature is verified against the identity
the entry claims, a beacon is accepted only when its origin is a core the
TRC names, the chain database's name lookup matches the name exactly,
first issuance runs serialized behind a mutex with a rate cap at its
door, and the Telegram authorizer keeps its bot token out of the node's
logs and its decision map bounded.

[TOC]

## Summary

Four checks the trust plane claims to make are not on the code's books,
and one of proposal 0014's own claims outruns its machinery. A beacon's
AS entries are verified as signatures — the chain exists, the key signed
— but never bound to the identity the entry claims, so any chain holder
signs entries naming any ISD-AS and the fabric stores, propagates, and
registers the fabricated path (`verifySignatures` calls an engine verify
that builds its verifier with no bound ISD-AS, `pkg/controlplane/beacon.go`
and `pkg/trust/engine.go`). Beacon reception never asks whether the
origin is a core the pinned TRC names, so a non-core's beacons become up
segments and the lookup service treats their origin as a core for its
subtree. The chain database resolves an ISD-AS's chains by string prefix,
so the bucket of `20-ff00:0:1` answers for `20-ff00:0:1f` — an
extending name can block a victim's enrollment as taken, and a matching
fingerprint classifies a first issuance as a renewal, skipping the
enrollment authorizer proposal 0014 placed at that exact seam. And
`ChainRenewal` runs unserialized and uncapped: two concurrent first
issuances of one free name both succeed, the Telegram prompt's
network send widens the window from milliseconds to seconds, and an
unauthenticated requester with a path to the core mints unlimited
fresh identities — each prompt, each map entry, each held stream.
Beside these, the Telegram authorizer's Bot API errors carry the full
tokened URL into the node's log on every failed poll or send, and its
decision map grows one entry per stranger for the process's lifetime.

## Motivation

ADR-0004's operator sovereignty rests on one sentence: transit consent
is cryptographic, because "no AS entry exists that the node did not sign
itself." The signature check the beaconer runs verifies the signer —
the chain the entry references, the key that chain certifies — but the
claim inside the signed body, the entry's own ISD-AS, is never compared
to the signer's name. The mechanism is present and unused: the trust
engine's verifier carries a `BoundIA` field that makes exactly this
comparison against the key ID's ISD-AS, and the engine's `Verify`
constructs it with the field zero. One fabrication rides the gap: an
enrolled AS signs entries claiming its neighbors' or the core's names,
the arrival check only binds the last entry to the link it arrived on,
and the receiving node stores a segment whose every signature is valid
and whose every claim but one is false. Registration shares the
verification path, so the core's own down-segment store inherits the
fabrication.

The second gap is the draft's own core check, applied to the letter at
reception of a registered segment — the first entry must name the
receiving core — but never at beacon reception: nothing asks that the
first entry name a core at all. `coreASes` exists, reads the pinned TRC,
and is consulted for propagation pruning and core-beacon selection
alone. A non-core that originates beacons therefore seeds up segments
rooted at itself, and the lookup service's reachable-core derivation —
built from the stored up segments' first entries — repeats the
fabrication as routing fact.

The third gap sits in the store underneath the enrollment gate proposal
0014 built. `Chains` sweeps the chain database's bucket keys by string
prefix, and an ISD-AS's rendered name is a prefix of every name that
extends it. The name-taken check therefore reads a victim's name as
taken while an extending name holds a chain, and when the extending
chain's fingerprint happens to match the petitioner's, the check
reports a same-key renewal and the authorizer — asked exactly when the
name is free — is never asked at all. The engine's own chain selection
sweeps the same prefix, so a node can sign and handshake with a
neighbor's chain. The fix is one comparison; the seam it protects is
proposal 0014's.

The fourth gap is the seam's own arithmetic. `ChainRenewal` runs
check, authorize, issue, and insert with no serialization — two
concurrent first issuances of one free name both pass the check and both
insert — and with no cap at the door. Proposal 0014 narrowed the
question to verified facts but left the exchange unauthenticated at
first contact by design, and the Telegram method it shipped places a
network send of up to ten seconds between the check and the insert,
turning a race measured in local work into one measured in an
operator's API latency, and giving every stranger with a path to the
core a fresh operator-visible prompt per invented identity. The
Telegram authorizer's own comment — "the name-taken check settles the
loser on its next retry, exactly as it does today" — is true only
sequentially; this proposal makes it true.

The last two are operational. The Bot API client builds its URLs with
the raw token and returns transport errors untransformed, and a
`*url.Error` renders the whole URL; an API outage logs the token once a
second from the poll loop, and every failed prompt send logs it again.
The decision map never forgets: an entry per prompted identity, expired
verdicts included, for the process's lifetime.

### Goals

*   The binding: every AS entry's signature is verified with the
    entry's claimed ISD-AS bound to the signer — a signature whose
    verification key names another ISD-AS fails the entry. Beacon
    reception and segment registration share the bound check.
*   The origin: a beacon is accepted only when its first entry names a
    core the pinned TRC lists, with the bootstrap tolerance the
    propagation pruning already carries — an unpinned TRC waives the
    check, for the same reason it floods upward.
*   The name: the chain database's ISD-AS lookup matches the bucket
    key exactly; no name answers for another.
*   The serialization and the cap: `ChainRenewal` holds a mutex across
    the name check, the authorizer's question, and the insert, and a
    per-source rate cap bounds first-contact requests before the work
    begins, answering `ResourceExhausted`.
*   The token and the map: Bot API errors log the method and the
    failure, never the URL; the decision map drops entries whose
    window has passed.

### Non-goals

*   No protocol change: the PCB and its signatures, the drafts'
    RPCs, and the enrollment exchange are untouched — every change is
    to what the receiver concludes from the bytes it already parses.
*   No trust-database expiry sweep: expired chains accumulate until a
    store with a delete operation exists; the validity filter already
    keeps them out of answers, and growth is issuance-bounded once the
    cap lands.
*   No persistence and no per-user authorization in the Telegram
    authorizer: decisions stay in memory and every member of the
    configured chat decides, per ADR-0010.
*   No change to admission's mechanical bounds — the rendezvous
    exchange, the link service's authenticated channel, the candidate
    window's evidence rule — and no new per-link propagation policy:
    the deferred kill-switch stays deferred.
*   No hardening of the path layer's own stores — the lookup cache and
    the beacon store's keying are separate findings with separate
    proposals.

## Proposal

### Bind the entry to the signer

The trust engine's verify grows its bound form: `VerifyBound` takes the
ISD-AS the caller believes the signer must be, constructs the verifier
with `BoundIA` set, and lets the comparison the verifier already carries
— the key ID's ISD-AS against the bound one — decide. The beaconer's
`verifySignatures` verifies each AS entry with the entry's own claimed
ISD-AS as the bound: an entry signed by a chain naming another ISD-AS
fails with the mismatch named, index and both identities in the error.
Beacon reception, with its per-entry loop, and segment registration,
which shares the same verification helper, close together. The unbound
`Verify` keeps its callers — nothing else verifies a claim the bytes
make about a signer.

The comparison is the whole of the change: the signer's chain is
already TRC-anchored, its validity already checked, its key already
proved to sign the entry. What was missing is the sentence that reads
the claim back to the signer — `entry.IA` — and refuses the difference.

### Accept beacons only from cores

`checkBeacon` grows the draft's core check at reception: the first
entry's ISD-AS must be one the pinned TRC's core list names. The list
`coreASes` already builds — the same set propagation consults to prune
core-directed flooding — answers it; an empty set, the not-yet-pinned
bootstrap state, waives the check exactly as propagation's pruning
tolerates it, so first-contact enrollment and the two-node bootstrap
keep today's behavior. A beacon whose origin is not a named core is
dropped with the origin in the error, before signature verification
spends work on it.

Registered segments need no new check: `checkRegistered` already
requires the first entry to name the receiving core, and the bound
signature check above now makes that claim the signer's own.

### Match the name exactly

The chain database's `Chains` stops sweeping by prefix: the outer loop
seeks the ISD-AS's bucket key and accepts it only on equality — the
first key past the sought name is another name, and the scan ends
there. The inner fingerprint scan keeps its prefix, for a query without
a fingerprint asks for every chain the name holds. The name-taken
check, the engine's own chain selection, and every other query through
the store inherit the exactness without further change: a victim's
name is free while only an extending name holds chains, a matching
fingerprint from another name's chain no longer reads as a renewal,
and the authorizer is asked on every first issuance the name is
actually free for.

### Serialize first issuance and cap the door

`TrustService` grows the mutex its admission-side siblings already
carry: `ChainRenewal` holds it across the name check, the authorizer's
question, the issuance, and the insert — the check-then-insert the
race lives in becomes a transaction, whatever the authorizer's latency.
The cost is stated plainly: a Telegram prompt's send, up to its
ten-second timeout, holds a later renewal's issuance behind it, and
issuance is rare enough — days-lived chains, a day-ahead threshold —
that the queue is the honest price of one name, one chain. The
authorizer's comment about the name-taken check settling the loser
becomes true in the only sense it was meant: sequentially.

Ahead of the mutex, a rate cap bounds the unauthenticated door: one
admission per interval keyed by the request's SCION source address —
the return-routable fact the context carries — with the claimed
ISD-AS as the key when the context carries no address, answering
`ResourceExhausted` past it. The cap's work is bounding, not
authenticating; the rendezvous acceptor's own limiter is the shape.
A stranger with a path to the core may still invent identities, but
each costs one rate slot, one prompt at most per decision window, and
no second request in flight.

### Keep the token out of the logs

The Bot API client's errors name the method and the failure, never the
URL: the call helper wraps its transport errors before they return,
stripping the request line a `*url.Error` would render — the operator
reading the log sees `getUpdates failed` and the cause, not the
credential. The decision map gains its bound: entries whose window has
passed are dropped when the poll loop sweeps, so a stranger's
persistent identities cost their prompts and nothing after.

## Test plan

*   **Unit tests:** the binding — an entry signed by a chain naming
    another ISD-AS than the entry claims fails verification with both
    identities in the error, at reception and at registration; an
    honestly-signed entry passes as today. The origin — a beacon whose
    first entry names a non-core is dropped before verification; one
    from a TRC-named core passes; with no TRC pinned the check is
    waived. The name — a chain held under `20-ff00:0:1f` leaves
    `20-ff00:0:1` free for the name-taken check, a colliding
    fingerprint under the extending name does not read as a renewal
    and the authorizer is asked, and the engine's own chain selection
    returns the node's chain and never the neighbor's. The
    serialization and cap — two concurrent first issuances of one free
    name yield one chain and one `AlreadyExists`; requests past the
    rate answer `ResourceExhausted` and the mutex holder's issuance
    completes. The token and map — a failed send or poll logs no URL
    and no token; expired decisions leave the map.
*   **Integration tests:** the join lab unchanged in behavior —
    enrollment, renewal, and the authorizer's verdicts land as
    proposal 0014's episodes assert; the two-node bootstrap lab with
    no TRC pinned accepts beacons as today; a fabricating neighbor
    lab — an enrolled node signing entries in another's name —
    contributes no segment to any store and no path to any consumer.
*   **Negative tests:** a non-core originator's beacons are dropped
    with the origin named and never reach the path database; a
    stranger's identity flood draws one prompt per decision window
    and one rate slot per request; no log line produced by a Bot API
    failure contains the token.

## Implementation history

*   (To be recorded as the change lands.)
