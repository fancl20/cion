# Quiet a refused peer

This proposal settles
[ADR-0034](/docs/adrs/0034-verify-each-chains-membership-and-remove-cores-at-once.md)'s
decision 6, the last one open: a verifier refuses a forgery and logs the
core that issued it, and reports nothing to the founder. It also quiets a
refused peer: its refusal logs once an hour, and its beacon rounds stop
redialing a neighbor that refuses it.

[TOC]

## Summary

*   **A refusal logs every attempt.** The founder method logs each chain no
    membership backs, with the core whose CA certificate signed it
    (`refuse`, [founder.go](/pkg/modules/membership/impl/founder/founder.go)),
    and the founding core each renewal the binding refuses (`bound`).
*   **A refused peer redials at every call.** A refused handshake leaves no
    connection, so each call dials and is refused again. The directory's
    catch-up and the membership renewal back off, and registration runs
    each minute, but beacon propagation sends a round's beacons, up to five,
    a call each, and carries on past a failure (`propagateOnce`,
    [beacon.go](/pkg/core/controlplane/beacon.go)): about a handshake a
    second at each neighbor. In the labs' pacing, one peer whose membership
    fell behind logged about forty lines in three seconds. A removed node
    retries until its operator stops it.
*   **No report exists.** Decision 6 has the verifier report a forgery to
    the founder; nothing does.

## Motivation

### Goals

*   A refusal logs once an hour for each ISD-AS and key.
*   A refused peer dials each neighbor once per beacon round.
*   A forgery stays in the logs of the nodes it tried.

### Non-goals

*   Changing what a membership admits or refuses.
*   A dial backoff in the SCION-native client. A refused peer then costs a
    neighbor a handshake per beacon round, and a backoff would hold every
    caller's requests to a peer after a transient failure.
*   Collecting refusals across nodes.

## Proposal

*   **No report.** A report's chain proves which core's key signed it, not
    that the core forged it: a chain issued before its node's removal looks
    the same, so a report would let any member frame the core that issued
    it. Telling the two apart takes a history of the bindings, which the
    founder does not keep. Decision 6 becomes a refusal and a log line.
*   **One line an hour.** The founder method logs a refusal only when a
    keyed rate limit (`ratelimit.Keyed`,
    [ratelimit.go](/pkg/libs/ratelimit/ratelimit.go)) over the chain's
    ISD-AS and key admits it, once an hour; the refusal itself is returned
    every time. The founding core's binding refusals share the limit.
*   **A beacon round ends at its first failed call.** Propagation sends a
    neighbor its next beacon only after the neighbor answered the last: a
    beacon the neighbor rejects as invalid leaves the rest to go, and any
    other failure, a call that never reached the neighbor's handler, ends
    the neighbor's round. The next round retries.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/membership/impl/founder` | The refusal log's rate limit |
| `pkg/core/controlplane` | A beacon round ends at its first failed call |

## Compatibility

Nothing changes on the wire or in what a node admits.

## Test plan

*   **A repeated refusal logs once.** Refusing one unbacked chain again
    within the hour logs nothing more and still refuses; a chain for
    another key logs at once; the first chain an hour later logs again.
*   **The binding refusal shares it.** The founding core's refusals of an
    unbound name log once an hour likewise.
*   **A failed call ends the round.** A neighbor whose calls fail is sent
    one beacon a round, and one that rejects each beacon as invalid is sent
    every beacon.

## Implementation history

*   Landed as proposed: the refusal log's limit
    ([founder.go](/pkg/modules/membership/impl/founder/founder.go)) and the
    beacon round's end ([beacon.go](/pkg/core/controlplane/beacon.go)).
    ADR-0034 is accepted.
