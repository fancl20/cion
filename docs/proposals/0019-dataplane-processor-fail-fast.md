# Fail the data plane's processors fast

This proposal gives the data plane's processor goroutines the honest
death [ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
gives whole generations: today a processor's panic is recovered, logged,
and left dead — the flows that hash to its queue drop for the process's
remaining lifetime while the node looks healthy. The recover comes out:
a processor's panic crashes the process, the operator's process
supervisor restarts it, and the crash's own report names the cause — a
processor's death is either impossible or loud, never a silent fraction
of the node's forwarding.

[TOC]

## Summary

`DataPlane.Serve` spawns `RunConfig.NumProcessors` fast and
`RunConfig.NumSlowPathProcessors` slow-path goroutines, each with
`handlePanic` deferred (`pkg/dataplane/dataplain.go`); `handlePanic`
recovers the panic, logs it with its stack, and the goroutine terminates
— its own comment says the rest: "The goroutine terminates, but the
process survives." Nothing restarts it. The underlay hashes each received
packet to its queue (`computeProcID`, `pkg/dataplane/udpip.go`) and sends
without blocking — a full queue drops as busy-processor — so the dead
slot's queue fills once and drops forever: every flow hashing to the slot
is blackholed for the node's remaining lifetime. The panics on offer are
the inherited invariants of the upstream router — the hop-field indexing
and the slow-path dispatch in `processor.go`, the address-type assertion
and the random-value failure in `udpip.go`.

The slow path's arithmetic is the worse half. The production assembly
runs a single slow-path processor (`NumSlowPathProcessors: 1`,
`internal/services/dataplane.go`), so its goroutine's death ends the
whole slow path — the SCMP replies the drafts' diagnostics ride — while
fast forwarding continues, and the drop counter that would say so counts
against a meter provider nothing installs.

## Motivation

The security model's asymmetric failure draws its line at the node's
edge: "an application's death degrades what the node offers, never its
forwarding" (`/docs/design/security.md`). A processor left dead moves the
sentence's subject inside the node — forwarding itself degrades, a
fraction of flows at a time, and quietly: the log carries one error line
at the moment of death and the counters are no-ops. Of the three
postures before a processor's panic, this status quo is the only one the
model refuses outright.

The second posture is failing fast — letting the first panic kill the
process, the operator's process supervisor restarting it. It is honest
and it is loud, and this proposal takes it. Its charges are accepted as
stated: one invariant breach, perhaps one packet, stops all forwarding
for the restart's duration, and a persistent offender crashloops a node
that was forwarding nine-tenths of its traffic. What the charges buy is
the point: the process supervisor the deployment already runs is the
whole of the machinery — nothing to implement, nothing to tune, no
constants whose values are the node's guess — and no violation is
absorbed. Rare or recurring, each breach is a process death carrying the
runtime's own report of the value and the stack, the shape a bug hunt
starts from.

The third posture is supervised restart under a budget: a transient
violation costs one bounded pause, and a persistent one exhausts the
budget and becomes the second posture's loud death, with a log that says
why. This proposal's first shape, declined on review: the pause, the
budget, and the sliding window are a second supervisor built beside the
one the deployment already runs, and they hide — a violation rare enough
to fit the window is an error line beside live forwarding, a bug made
quiet exactly when it is easiest to overlook. The generation supervisor
already reasons one level up (ADR-0008) — a data plane that stops serving
is replaced, not mourned — and the crash this proposal prefers hands the
same signal to the level above the process: the node's monitor replaces
the node.

### Goals

*   The recover's removal: every processor slot `Serve` spawns runs with
    no `handlePanic` — fast and slow-path slots alike — so a slot's panic
    unwinds unwritten by any recover, the runtime prints the panic and
    its stack, and the operator's process supervisor restarts the node
    into a log that names the cause.
*   The shape preserved: shutdown drains exactly as today — the WaitGroup
    entries stay on the slot goroutines, a normal return ends the slot,
    and cancellation drains as before.

### Non-goals

*   No audit or conversion of the inherited panic sites — the hop-field
    invariants, the slow-path dispatch, and the address assertions stay
    as they are; a breach's cost is now a whole restart, and any
    conversion lands as its own finding.
*   No change to the generation supervisor's semantics (ADR-0008): it
    still swaps generations on the link store's changes; a crash is the
    process's death, the process supervisor's to restart — not a
    generation swap.
*   No metrics for crashes — [proposal
    0017](/docs/proposals/0017-expose-metrics-and-log-discards.md) owns
    the exporter that would carry them; a crash's visibility is the
    crash itself.
*   No knobs — there is nothing to tune; the posture is the absence of
    machinery, the socket-buffer precedent
    (`internal/services/dataplane.go`) taken to zero.
*   No conversion of the node's other recover-and-die loops — the
    underlay's receiver and forwarder tasks and the internal link's
    dispatch loop (`pkg/dataplane/udpip.go`) keep `handlePanic`; their
    conversion is its own finding.

## Proposal

The `handlePanic` deferrals come out of `Serve`'s two spawn loops
(`pkg/dataplane/dataplain.go`): each processor goroutine keeps only the
WaitGroup `Done` it always deferred — run on the unwind, spent an instant
before the process ends — and a panic in either loop, fast or slow-path,
propagates to the runtime, which prints the value and the stack and
exits the process. The drain on cancellation is untouched: underlays
stop, queues drain, `Wait` returns, `Serve` returns nil. `handlePanic`
itself stays, serving the loops the non-goals leave alone.

The costs are stated plainly. If one of the inherited invariants turns
out reachable from crafted input, one packet buys one process restart —
all forwarding stops for the restart's duration, and a sender with a
poison packet can buy it again and again; the posture accepts a remotely
repeatable whole-node stop over a silently degraded fraction, betting
the breach is a bug worth stopping for. A rare violation crashes rather
than logging — the exposure bought on purpose. A panicking slot's held
buffers spend with the process, returned by no one.

## Test plan

*   **Integration tests:** the data plane suite — `Serve` serves traffic
    through its processor slots and drains on cancellation exactly as
    today; the testnetwork labs are unchanged, for no honest episode
    wills a processor to panic on real traffic.
*   **Negative tests:** a served plane whose slots never panic never
    crashes — the suite's existing runs.

The crash path itself has no test of its own: the mechanism is the
absence of a recover — the runtime's guarantee, not the node's code —
and the guard against its quiet return is the comment at the spawn site.

## Implementation history

*   The recover's removal: `Serve`'s two spawn loops
    (`pkg/dataplane/dataplain.go`) defer only the processors WaitGroup
    `Done`, and a comment at the site says why no recover guards the
    slot. `handlePanic` stays for the underlay's receiver and forwarder
    tasks and the internal link's dispatch loop.
*   The reversal: the proposal first specified supervised restart under a
    budget — `restartPause`, `restartBudget`, and `restartWindow` beside
    a `testing/synctest` suite for them — and it was implemented so;
    review reversed the decision before either landed, the budget and its
    tests came out entire, and the document was rewritten to the posture
    above.
*   Tests: the data plane suite gained the serving-and-drain episode
    (`pkg/dataplane/serve_test.go`) — traffic driven through several fast
    and slow slots, cancellation into `Serve`'s nil return, the counters
    settled in between.
