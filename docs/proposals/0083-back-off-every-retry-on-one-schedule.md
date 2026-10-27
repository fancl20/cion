# Back off every retry on one schedule

This proposal gives the node one retry schedule in `pkg/libs/loops`:
exponential, capped, and jittered. It moves every retry of a failed
operation onto that schedule.

[TOC]

## Summary

Each retry site picks its own fixed pause, and none adds jitter:

| Site | Retries | Pause |
| :-- | :-- | :-- |
| The node directory's publish ([directory.go](/pkg/modules/topology/impl/measured/directory.go)) | a publication the core refused | `NodePublishRetry`, 5 s |
| WireGuard's publish ([directory.go](/pkg/apps/wireguard/directory.go)) | a publication the core refused | `PublishRetry`, 10 s |
| The Telegram authorizer ([telegram.go](/pkg/modules/enrollauth/impl/telegram/telegram.go)) | a failed long poll | `pollRetry`, 1 s |
| The follow loop ([provider.go](/pkg/modules/topology/impl/measured/provider.go)) | an entry's confirm | `FollowRetry`, 5 s |
| The re-punch loop (same file) | a link's failed re-punch | `RepunchRetry`, 5 s, then 10 s, 3 attempts |
| The confirm pass (same file) | an entry's unanswered confirm | the selection window |
| The join dials (same file) | an entry's unanswered rendezvous dial | `joinDialInterval`, 5 s |

A failure that persists is retried at a steady rate until something else
ends it. Nodes that failed together, for example when the founder
restarted, retry in step.

Measured on the change below, five runs each:

*   **NAT:** a rebound link recovered in 14.5 to 14.8 seconds, a restarted
    peer was reached again in 13.0 to 13.1 seconds, and a node behind a
    symmetric NAT joined in 44 to 109 seconds. In the settled network,
    every pair's best path over the formed links stayed at its reference.
    With the founder lost, the survivors reached each other in 0.7 to 11.6
    seconds, and the restarted node returned in 175 to 296 seconds.
*   **Cuts:** the regions network recovered from its cut in 7 to 294
    seconds and settled in 7 to 15 seconds over one link change. Without the
    change, it recovered in 262 seconds to past the scenario's 30 minutes
    and settled in 12 to 431 seconds over one to six. The stranded network
    recovered in 10 to 265 seconds, against 21 to 266.

## Motivation

### Goals

*   One schedule for every retry of a failed operation: exponential, capped,
    and jittered.
*   One way to track per-entry retries, which the event-driven loops that
    come next will reuse.

### Non-goals

*   No change to cadences: BFD ticks, the beacon interval, selection
    windows, directory refreshes, sweeps, and the join dials' pass.
*   No change to waits on the node's own state: a publication waiting for
    the chain that enrollment produces, or for a host to resolve, still
    polls at its retry. Waits on the node's own generation swap
    (`ConfirmRetryPause`, the data plane's bind retries) keep their pause
    too.
*   No change to attempts a protocol spaces as part of the exchange
    (`RendezvousAttempts`, `ResolutionAttempts`).

## Proposal

### The schedule

`loops.Backoff{Base, Max}` spaces the retries of a failed operation. The
wait before the first retry is `Base`, and each later wait doubles the one
before, capped at `Max`. Each wait is drawn uniformly from the upper half of
its value, so nodes that failed together retry apart, and no wait exceeds
its cap.

*   `Tries(ctx)` iterates over one operation's tries: the first at once, and
    each retry after its wait. It yields each try's number, counted from 1,
    and ends when `ctx` does. The caller breaks out of the loop once a try
    succeeds, or at a bound of its own:

    ```go
    for range backoff.Tries(ctx) {
        if err := publish(ctx); err == nil {
            break
        }
    }
    ```

*   `Attempts[K]{Backoff, Limit}` tracks retries per key, for loops that
    retry many entries at once:
    *   `Due(k, now)` reports whether `k` may try again.
    *   `Tried(k, now)` records a try. The key's next try comes after the
        wait for its count.
    *   `Forget(k)` resets the key once its operation succeeds or no
        longer applies.
    *   `Retain(keep)` forgets the keys a pass no longer retries.

    `Limit` bounds a key's tries; zero means no bound.

### The sites

| Site | Schedule |
| :-- | :-- |
| The node directory's publish | `Base` `NodePublishRetry`, `Max` `NodePublishInterval` (1 min) |
| WireGuard's publish | `Base` `PublishRetry`, `Max` `PublishRetryMax` (5 min) |
| The Telegram authorizer | `Base` `pollRetry` (1 s), `Max` `pollRetryMax` (30 s) |
| The follow loop | per entry: `Base` `FollowRetry`, `Max` `FollowRetryMax` (1 min) |
| The re-punch loop | per link, after `RepunchGrace`: `Base` `RepunchRetry`, `Limit` `RepunchAttempts` |
| The confirm pass | per entry: `Base` the selection window, `Max` `confirmPassWindows` (4) windows |
| The join dials | per entry: `Base` `joinDialInterval`, `Max` `joinDialRetryMax` (30 s) |

Notes on the sites:

*   A publisher separates a publication waiting on the node's own state
    (`errNotReady`) from one the core refused. Only a refusal backs off: a
    publication that is not ready breaks out of its tries and polls at the
    retry.
*   Each publication and each poll starts its tries over.
*   A per-entry site forgets an entry once its operation succeeds or the
    entry leaves the pass.

### Tests

Exact-timing tests take each retry at its wait's upper bound, and check
that it isn't due below its band's lower bound. No random source is
injected.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/loops` | The schedule, the per-key attempts |
| `pkg/modules/topology/impl/measured` | The publish, follow, re-punch, confirm pass, join dials |
| `pkg/apps/wireguard` | The publish |
| `pkg/modules/enrollauth/impl/telegram` | The poll |

## Compatibility

There is no wire change. While a failure persists, a node retries less
often, and each retry lands at a random point in the upper half of its
wait.

## Test plan

*   **The schedule:**
    *   The waits double from `Base` up to `Max`, each inside its band, and
        an uncapped schedule's late waits do not overflow.
    *   `Tries` yields the first try at once and each retry within its
        wait's band. A break ends it without a further wait, and so does the
        context's end, before the first try or during a wait.
    *   `Attempts` makes a key due again after its delay. It stops at
        `Limit`, a forgotten key is due at once, and `Retain` forgets the
        keys it rejects.
*   **The sites:** the re-punch loop's test takes each retry within its
    band. The other sites' tests pass unchanged.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs each. The NAT benchmarks and the regions
    and stranded cut benchmarks hold.

## Implementation history
