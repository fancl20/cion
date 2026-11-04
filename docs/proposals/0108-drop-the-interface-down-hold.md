# Drop the interface-down hold

This proposal implements the rest of
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 4:
an interface-down signal makes the paths through its link suspect until an
answer decides, and prompts a verification. No path is set aside for a
fixed ten seconds any more.

[TOC]

## Summary

Today:

*   **A signal holds its link for ten seconds.** The conns record each SCMP
    External Interface Down signal with a lapse ten seconds after it
    arrives ([conn.go](/pkg/libs/scion/conn.go),
    [ifdown.go](/pkg/libs/scion/ifdown.go)). While it holds, composition
    flags every path through the link `Crossing`
    ([provider.go](/pkg/libs/scion/provider.go)). The picks rank a flagged
    suspect after the other suspects, the topology selection counts a
    flagged route as no route
    ([queries.go](/pkg/modules/topology/impl/measured/queries.go)), and
    health reads a path suspect while the signal holds and the path has not
    answered since ([health.go](/pkg/libs/scion/health.go)).
*   **Ten seconds on, the signal is gone.** The prober bursts the requested
    paths through the link as the signal arrives
    ([prober.go](/pkg/apps/ping/prober.go)), and the burst decides them
    within seconds, so the hold decides nothing the burst does not. Without
    the ping application, a path through a link that died elsewhere returns
    to its rank when the hold lapses, and traffic tries it until the next
    signal.

## Motivation

### Goals

*   Probes are the authority and the signal a prompt: a signal makes the
    paths through its link suspect until an answer decides, and moves no
    lease.
*   One rule for every doubt: a signal stands as a caller's loss does,
    until an answer since or its lapse.
*   Without the ping application, the paths through a dead link stay
    suspect while the signal stands, not for ten seconds.

### Non-goals

*   Authenticating signals. A forged one costs a burst, or, without the
    ping application, ranks idle paths after the others until it lapses.
*   The prober's bursts on a signal and the conns' recognition of signals,
    which stay as they are.
*   The node's own down or retired links, whose paths composition drops at
    once, as today.

## Proposal

*   **A signal stands until it lapses** ([ifdown.go](/pkg/libs/bus/ifdown.go)).
    The interface-down state keeps when each link's latest signal arrived,
    for `RequestLapse`, the lapse of the callers' reports. The conns record
    each signal at its arrival. The quoted destinations go: nothing has read
    them since the WireGuard route cache went
    ([proposal 0106](/docs/proposals/0106-lease-each-peers-path.md)).
*   **Health reads the signal.** A path is suspect while a signal on a link
    it crosses is newer than its last answer, as a caller's loss newer than
    it makes it. An answer since, a probe's or a caller's, clears it.
*   **Composition reads no signal.** `Crossing` goes. Health flags a path
    that a signal names since its last answer `Signaled`, and the picks rank
    it after the other suspects, as they rank a crossing path today: right
    after a cut, a path a router reported failing is the least likely to
    serve.
*   **The selection counts a signaled route as a suspect one.** It counts
    and prices while its request decides it, and a tier whose routes the
    measurements all doubt is stranded, as today.
*   **The prober** bursts the requested paths through a link when a signal
    newer than the last one it saw arrives, as today.

Without the ping application, a signal makes the paths through its link
suspect until it lapses or a caller's delivery answers. Meanwhile new picks
prefer healthy and unknown paths, and no lease moves.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | Signals by arrival, kept for `RequestLapse`; the quotes go |
| `pkg/libs/scion` | The hold and `Crossing` go; health reads signals by arrival and flags signaled paths |
| `pkg/apps/ping` | Reads signals by arrival |
| `pkg/modules/topology/impl/measured` | Counts a signaled route as a suspect one |

## Compatibility

Nothing on the wire changes.

## Test plan

*   **The state.** A signal stands until `RequestLapse` after its arrival, a
    later one on its link replaces it, and each update leaves out what
    lapsed.
*   **Health and picks.** A path through a signaled link is suspect until
    it answers after the signal, past ten seconds; once the signal lapses,
    the other evidence decides. A signaled suspect ranks after the other
    suspects.
*   **The selection.** A signaled route counts and prices as a suspect one.
*   **The paths lab.** With the ping application, the pick and the lease
    leave the cut link and stay off it while it is cut. Without it, the
    pick leaves on the signal and stays off for a minute, past the ten
    seconds a signal once held.
*   **The labs and benchmarks** pass; the regions cut and the stranded cut
    benchmarks hold against the commit before.
