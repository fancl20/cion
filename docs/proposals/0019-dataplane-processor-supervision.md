# Supervise the data plane's processors

This proposal gives the data plane's processor goroutines the supervision
[ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
gives whole generations: today a processor's panic is recovered, logged,
and left dead — the flows that hash to its queue drop for the process's
remaining lifetime while the node looks healthy. A dead slot restarts
under a budget, and the budget's exhaustion kills the process, so a
processor's death is either a blip or loud — never a silent fraction of
the node's forwarding.

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
and it is loud, and it charges the full restart for the first violation:
one invariant breach, perhaps one packet, takes down all forwarding for
the restart's duration, and a persistent offender crashloops a node that
was forwarding nine-tenths of its traffic.

The third posture is this proposal: supervised restart under a budget. A
transient violation costs one bounded pause; a persistent one exhausts
the budget and becomes the second posture's loud death, with a log that
says why. The generation supervisor already reasons this way one level up
— a data plane that stops serving is replaced, not mourned (ADR-0008) —
and the processor slots are the level it does not reach.

### Goals

*   The supervisor: every processor slot `Serve` spawns runs under a
    goroutine that restarts it after a recovered panic, on the same
    queue, after a fixed pause — fast and slow-path slots alike.
*   The budget: restarts are counted per slot in a sliding window, and a
    slot that exhausts the budget re-panics its last value — the process
    dies where today it survives degraded, and the operator's process
    supervisor restarts it into a log that names the cause.
*   The shape preserved: shutdown drains exactly as today — the WaitGroup
    entry moves to the supervisor, a normal return ends the slot without
    restart.

### Non-goals

*   No audit or conversion of the inherited panic sites — the hop-field
    invariants, the slow-path dispatch, and the address assertions stay
    as they are; the budget bounds what their violation costs, and any
    conversion lands as its own finding.
*   No change to the generation supervisor's semantics (ADR-0008): it
    still swaps generations on the link store's changes; a budget's
    exhaustion is the process's death, not a generation swap.
*   No metrics for restarts — [proposal
    0017](/docs/proposals/0017-expose-metrics-and-log-discards.md) owns
    the exporter that would carry them; a restart's visibility here is
    the error log it writes.
*   No new flags — the pause, the budget, and the window are constants,
    the socket-buffer precedent (`internal/services/dataplane.go`): a
    flag would promise tuning the node's failure arithmetic does not
    want.
*   No supervision of the node's other background loops — the assembly's
    recover-and-die loops are the same disease in a milder form, and
    their supervision is its own finding.

## Proposal

### The supervisor

The spawn loop in `Serve` wraps each slot: the goroutine it starts is the
supervisor, and the `processors` WaitGroup entry moves to it, so the
drain on cancellation — underlays stop, queues drain, `Wait` returns — is
exactly today's. The supervisor runs the processor function; on a
recovered panic it logs the panic and its stack at error level —
`handlePanic`'s own line — waits out the pause, and runs the function
again on the same queue it owned. A normal return — the context's
cancellation, the drain — ends the slot without restart. The pause is
`restartPause`, a hundred milliseconds — `bindRetryPause`'s scale: enough
that a poison packet at a queue's head cannot spin the slot at full
speed, little enough that live traffic recovers within one pause.

### The budget

Restarts are counted per slot in a sliding window — `restartBudget`
inside `restartWindow`, the shape of proposal 0015's source limiter — and
a slot whose restarts exhaust the budget logs the exhaustion and
re-panics its last value, unwritten by any recover: the process dies, the
process supervisor restarts the node, and the log the operator reads
carries the panics, the count, and the stack. The constants are fixed —
the budget's arithmetic is the node's, not the operator's, in the same
spirit the generation supervisor's retry bounds are.

The costs are stated plainly. A slot that panics on recurring input
forwards at a stop-clock of one restart per pause until the budget ends
it — bounded loss made loud, in place of today's unbounded silent loss.
A panicking slot's held buffers return to the pool on restart's next
drain or stay spent until then; the pool is sized with headroom for a
generation's queues, and a slot's worth is within it.

## Test plan

*   **Unit tests:** the supervisor suite — a function that panics once
    runs twice and the slot serves after; a function that returns is not
    restarted; a slot that exhausts the budget panics through; a
    cancellation during the pause ends the slot without another start;
    the pause and the window advance under `testing/synctest`.
*   **Integration tests:** the data plane suite — `Serve` spawns one
    supervisor per configured slot and drains on cancellation exactly as
    today; the testnetwork labs are unchanged, for no honest episode
    wills a processor to panic on real traffic.
*   **Negative tests:** a slot whose function returns normally on the
    first pass never logs a restart; a cancellation arriving with a
    restart pending leaves the WaitGroup drained and the process whole.

## Implementation history

*   (To be recorded as the change lands.)
