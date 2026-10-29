# Refresh fetched segments behind the lookup

This proposal keeps each core's last answer for a destination and serves it
at once, refreshing it in the background, where a lookup now blocks on a
fresh fetch from each core in turn every minute. A failed refresh leaves the
last answer in place and sets the core aside on the node's one retry
schedule. Only a destination no core has answered for yet waits, and it
asks every core at once. A core that stops answering then costs lookups
nothing.

[TOC]

## Summary

`LookupService.Down` fetches a destination's down segments from each core
the TRC names, in the TRC's order, one after another, each fetch bounded by
the caller's context alone
([lookup.go](/pkg/core/controlplane/lookup.go)). The source handler fetches
core segments the same way, from each core it holds an up segment to. An
answer is cached for a minute, after which the next lookup blocks on a new
fetch; failures and empty answers are not cached.

A core that does not answer holds every lookup whose answer from it expired:

*   **A caller with a deadline** spends what is left of it on that core: a
    dead core listed first leaves the cores after it no time, and their
    answers never arrive; one listed later still holds the caller after the
    others answered.
*   **A caller without one** waits out QUIC's handshake timeout, 5 seconds,
    before the next core is asked.

Every lookup composes through this path: the selection's probes (a
4-second budget), WireGuard's route refresh, the punch, ping, and the labs'
reads (2 seconds).

Measured on the NAT network, whose TRC names two cores, with the founder cut
from every other node, in three runs: once the cached answers expired, 24
to 65 seconds after the cut, the slowest lookup of every read took the whole
2-second budget and the mean lookup 0.67 to 1.02 seconds, and 27 to 30 of
the 30 surviving pairs reached, 29 in most reads. Pinged six minutes after
the cut rather than at once, every surviving pair answered only after 81 to
96 seconds, against under a second at once.

## Motivation

### Goals

*   A lookup that holds an answer from any core never waits on a fetch.
*   A core that stops answering costs lookups nothing; it is asked again on
    the retry schedule, and within a minute once it answers.
*   A destination no core has answered for yet waits only for the fastest
    core that answers.
*   One fetch per question at a time.

### Non-goals

*   The node directory and chain issuance, which the founder alone serves
    today: proposals of their own.
*   Telling a dead path apart. A dead core's last answer keeps composing
    until its segments read stale, as a cut link's segments do; which paths
    still deliver is path selection's concern.

## Proposal

### Each core's last answer, served at once

The cores are not replicas: a node registers its down segments with the
core that originated their beacons, so each core answers with its own. The
lookup keeps each core's last answer for a destination until its segments
expire, and serves the answers of every core together, in the cores' order,
without waiting.

### Refreshed behind the lookup

A lookup that serves a core's answer older than a minute, the cache's
lifetime today, starts a refresh of it and does not wait for it. The refresh
replaces the answer when it arrives. One refresh per core and destination
runs at a time, bounded by `SendTimeout`, the 5 seconds the beaconer already
bounds each registration by. An empty answer removes the core's answer: the
core holds nothing for the destination now.

### A core set aside

A refresh that fails — an error, not an empty answer — leaves the core's
last answer in place and sets the core aside on the node's one retry
schedule
([proposal 0083](/docs/proposals/0083-back-off-every-retry-on-one-schedule.md)),
from `SendTimeout` doubling up to the minute. No refresh asks it until its
retry is due; an answer clears it.

### The first lookup

A destination for which no core holds an answer waits: the lookup asks every
core not set aside at once, returns with the first answer or when its
context ends, and the other answers land for the next lookup. Its fetches
are the refreshes above, so one that outlives the caller still lands. An
empty answer is not kept, as today, so the next lookup asks again: a
registration that raced the fetch lands any moment.

### The founder-down benchmark

The NAT founder-down benchmark reads, after its survivors' first pings,
every surviving pair's path each sample for `natWatch`, each lookup bounded
by the labs' 2 seconds as the other reads are. It reports the fewest pairs
reached in a read, and the slowest and the mean lookup.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/core/controlplane` | Each core's last answer served at once and refreshed behind the lookup; a failing core set aside; the first lookup asks every core at once |
| `internal/testnetwork/behavior` | The founder-down benchmark reads the surviving pairs' paths |

## Compatibility

Nothing changes on the wire. A core is asked the same questions as before,
at most once a minute per question while answers keep arriving, and not at
all while set aside.

## Test plan

*   **The lookup:**
    *   an answer older than a minute is served at once and refreshed behind
        the lookup, and the refresh's answer replaces it;
    *   a failed refresh keeps the last answer and sets the core aside until
        its retry is due; an answer clears it;
    *   an empty refresh removes the core's answer;
    *   with no answer held, the lookup asks every core at once and returns
        with the first answer, and a caller whose deadline ends first
        returns empty while the fetches land for the next lookup;
    *   one refresh per question at a time;
    *   answers return in the cores' order;
    *   the source handler's core segments follow the same rules.
*   **The labs:** the behavior labs pass.
*   **The benchmarks:** five runs of the NAT founder-down benchmark against
    the node before it: every surviving pair reached in every read, and no
    lookup after the cut waiting on the dead core. The settled, cut, and
    other NAT benchmarks hold.

## Implementation history

*   Landed as proposed: each core's last answer, its refresh behind the
    lookup, the core set aside, and the first lookup
    ([lookup.go](/pkg/core/controlplane/lookup.go)), and the founder-down
    benchmark's reads
    ([nat_test.go](/internal/testnetwork/behavior/nat_test.go)). Beside the
    plan:
    *   A core holding no answer is refreshed behind a lookup that serves
        another core's answer, not only by the first lookup.
    *   Refreshes of one core that fail together count as one try of its
        retry schedule.
    *   A fetch that finds no route to the core sets nothing aside: it asked
        nothing, and the next lookup asks again. A send with neither a path
        nor a link to its destination fails with `scion.ErrNoLink`
        ([conn.go](/pkg/libs/scion/conn.go)).
    *   `StaleAfter`'s comment states the refresh
        ([provider.go](/pkg/libs/scion/provider.go)).

    Five runs each against the node before it, ten of the symmetric join and
    of the regions network's settling:
    *   **Founder down:** every read reached all 30 surviving pairs, and no
        lookup waited, against 28 or 29 pairs, the slowest lookup taking the
        read's whole 2 seconds and the mean 0.61 to 0.68. The survivors
        answered in 0.73 seconds as before, and the restarted node returned
        in 195 to 292 seconds against 218 to 293.
    *   **NAT network:** it settled in 2m10s to 2m50s on paths as short, as
        before. A rebind recovered in 16.5 seconds against 16.5 to 18.4, and
        a restarted peer in 12.9 against 13.0 to 13.1. A node behind a
        symmetric NAT joined in 43 to 54 seconds in nine runs and 170 in one,
        against 33 to 55 in nine and 175 in one: the slow run waits for a
        link to the authoritative core.
    *   **Settled networks:** the regions network's worst pair reached 1.13
        to 1.23 times the reference in four runs, the fifth failing at boot
        on a port another socket held, against 1.13 to 1.36 in ten runs, four
        of them 1.23 or more. The stranded network settled in 2.5 to 2.7
        minutes with its worst pair at 1.3, against 2.0 to 2.5 and 1.15 to
        1.3. The site network settled as before.
    *   **Cut networks:** the stranded network recovered from its cut in 110
        to 300 seconds against 122 to 285. The regions network recovered in
        260 to 280 seconds in three runs and in 500 and 540 in two: the tail
        in which a link promoted after the cut retires as useless, seen at 460
        to 488 seconds in one or two of five runs before.

    A refresh behind the lookup serves an answer up to one caller's period
    older than a lookup that waits for the fetch: the selection asks every 30
    seconds, so its windows read down segments 31 to 62 seconds old, against
    0 to 31.
