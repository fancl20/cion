# Run the fabric labs on virtual time

The fabric labs wait on the wall clock. Every lab polls a budget it spends
in real time ([network.go](/internal/testnetwork/network.go)), and every
node it boots runs the labs' shrunken intervals
([join_test.go](/internal/testnetwork/join_test.go)). [Proposal
0063](/docs/proposals/0063-give-the-integration-labs-a-userspace-fabric.md)
laid one clock under the fabric, the seam a deterministic network later
builds on, and left exploiting it to a later day. This proposal runs the
fabric labs inside `testing/synctest` bubbles. Virtual time advances only
when every goroutine in a lab is parked, so the node's own production
intervals cost nothing but their work, and no runner load can spend a
budget early. Three walls stand in the way, and none needs a fork: the
fabric's stacks carry UDP alone, name resolution moves into the socket
source, and a bubble boot replaces the parts of the harness that assume a
real clock. No ADR: no boundary moves.

[TOC]

## Summary

The labs prove the node's protocols on a shrunken schedule. Selection
windows of two seconds, registration every two hundred milliseconds, and
propagation every hundred are what let a real-time lab watch a link form
within its budget. The schedule is also what the labs cannot prove: a
behavior that depends on the ratio between the node's intervals shows
only at the ratio production runs. Nine nodes replaying a three-region
latency matrix churned links for about 155 seconds and then settled under
the labs' pacing. The same nodes at production pacing kept churning for
the full hour a bubble ran them, about three retirements a minute. A
real-time run at production pacing churned at the same rate for the 20
minutes it ran.

A bubble runs production pacing at a useful speed. On the fabric, booted
through the labs' own `bootOnFabric`, nine nodes run sixty virtual
minutes in six wall minutes, and two nodes run seven virtual hours, past
the six-hour segment expiry, in under two. Runner load cannot stretch an
interval, so a poll that times out reports a schedule that never
converged, not a busy machine.

Three walls hold today, each verified by probe on this repository's pins:

*   **gVisor's TCP dispatchers park out of the bubble's sight.**
    `tcp.NewProtocol` starts a pool of dispatcher goroutines sized by
    `GOMAXPROCS`, each parked in a `sleep.Sleeper` through a raw
    `sync.Gopark` whose wait reason the runtime does not count as durably
    blocked. A fabric stack with TCP freezes virtual time at its first idle
    moment. The fabric labs need only UDP: the node's underlay, the
    rendezvous exchange, and the QUIC control channel all ride UDP sockets.
    TCP carries the founder's HTTPS surface, which no fabric lab loads.
*   **Name resolution reaches the kernel from inside the bubble.** The
    founding core publishes its own domain's resolution, retried every
    thirty seconds while the lookup fails
    ([external.go](/pkg/modules/topology/impl/measured/external.go),
    [provider.go](/pkg/modules/topology/impl/measured/provider.go)). The
    kernel resolver's sockets are not durably blocked, so a slow resolver
    stalls virtual time. Its lazily built configuration channel belongs to
    the first bubble that touches it, so the next bubble in the same
    process dies on a cross-bubble send. The test domain never resolves at
    all, so today a lab's founder publishes no directory entry and no lab
    probes the founding core, which production always does.
*   **The harness assumes a real clock.** The fabric's clock and the test
    CA must be created inside the bubble: the clock's monotonic base and
    the CA's validity window are both read from the time at creation. The
    address draws probe kernel ports the fabric never binds, and the
    solo re-execution cannot run inside a bubble.

## Motivation

The fabric labs already fail in the way virtual time removes. CI skips the
stranded lab because it "outpaces the shared runner"
([ci.yaml](/.github/workflows/ci.yaml)), and with the skip in place the lab
failed at HEAD without anyone noticing: its premise contradicted the
selection policy, and nothing ran it. The labs keep BFD at its production
interval because a stalled runner otherwise takes every link down
([join_test.go](/internal/testnetwork/join_test.go)), which means the labs
already run a mix of two schedules. And the selection loop's convergence
across a region boundary is visible at production pacing alone, so no
real-time lab can hold it as a regression.

### Goals

*   The fabric family (the fabric, stranded, and translation labs) runs in
    bubbles, at production pacing, with its assertions unchanged.
*   A convergence lab replays a multi-region latency matrix at production
    pacing and holds the selection loop's settling as an assertion.
*   No fork, no `replace` directive, and no production behavior change.

### Non-goals

*   No TCP inside bubbles: the coordination, portal, and other
    application labs keep real time until their sockets and gVisor's
    dispatchers allow otherwise.
*   No kernel-family conversion: the labs whose subject is the kernel's own
    socket surface keep the kernel and real time.
*   No scheduling determinism: virtual time orders timers, not goroutines,
    and the node's own randomness (segment IDs, BFD discriminators,
    selection jitter) stays. A convergence lab asserts properties that hold
    across interleavings, not one run's exact link set.
*   No clock injection: the `time` package is the seam, and no `pkg` code
    reads a clock it did not read before.

## Proposal

### UDP-only fabric stacks

`fabric.New` gains an option that boots every stack with the UDP transport
alone. The bubble boot sets it. A real-time lab keeps both transports, so a
lab that binds the founder's HTTPS surface still can. A stack without TCP
starts no dispatcher, and the UDP path blocks only where a bubble sees it:
gonet's reads select on channels the bubble created, its deadlines are
`time.AfterFunc` timers, and the channel endpoint's `ReadContext` selects
on its queue.

### Resolution through the socket source

The socket source, `underlay.Sockets`, is already the one seam the node's
underlay sockets construct through. It gains a name resolver beside the two
listeners, with the same zero-value rule: a nil resolver is
`net.DefaultResolver.LookupNetIP`. The measured provider builds the
founder's domain resolution from its config's socket source, where today
it reaches the system resolver directly; `domainHost` already takes its
lookup as a function. The fabric's source answers from names the lab
draws — the test domain resolving to the founder's fabric host. A fabric
founder then publishes the host its peers reach and joins the directory,
as a production founder does, and no lookup leaves the bubble.

### The bubble boot

A helper runs a lab body inside `synctest.Test` with the fixtures created
inside it:

*   The fabric, with UDP-only stacks, on the bubble's clock.
*   The test CA, whose validity window then covers a run of up to its
    twenty-four hours.
*   Fabric nodes drawing their control and internal addresses on the
    fabric, with no kernel probe.

The solo re-execution stays outside: a lab that needs a process of its own
re-executes first and enters the bubble in the inner run. Polls keep their
shape, with sleeps coarse enough for production pacing. Cleanups registered
on the bubble's `t` run inside the bubble before it drains, so a goroutine
a lab leaks fails the lab at its exit with the bubble's own error.

### Production pacing

Bubble labs boot the node with the zero `NodePacing` — the daemon's own
intervals. Under virtual time the labs' fast pacing is the slow mode: a
lab's cost is the work each virtual second carries, and the fast intervals
carry fifty times the beacons and fifteen times the selection windows per
second that production does. Fast pacing also changes behavior inside a
bubble. Real time stretches a two-second window by the milliseconds each
probe really takes, and a bubble does not, so a fast-paced lab can churn
in a bubble where it settles in real time. At production intervals the
difference vanishes.

### The labs

*   **The fabric family** moves into bubbles: the fabric join, the stranded
    lab, and the translation lab, whose boundary's idle expiry already runs
    on the fabric's clock. Their budgets are virtual, sized for production
    pacing.
*   **The regions lab** is new: nine nodes over a three-region latency
    matrix, joined outward from the founder along a spanning tree, run at
    production pacing. It asserts that every node holds its floor
    throughout and that the link set settles within a bounded number of
    selection windows. Today it fails: the selection loop retires as
    useless the links its peers buy for their floors, and the peers buy
    them back. It lands with the change that settles it, and holds that
    settling as a regression from then on.

### Packages touched

| Package                              | Change                                                   |
| :----------------------------------- | :------------------------------------------------------- |
| `pkg/libs/underlay`                  | The socket source's name resolver                        |
| `pkg/modules/topology/impl/measured` | The founder's domain resolution reads the source's resolver |
| `internal/testnetwork/fabric`        | The UDP-only option; the fabric's names                  |
| `internal/testnetwork`               | The bubble boot; the fabric family's move; the regions lab |

### Migration

Each commit keeps the tree green:

1.  **The resolver.** The socket source's resolver, the founder's domain
    resolution through it, and the fabric's names. Production behavior is
    unchanged: the kernel source resolves as before. The fabric family
    re-runs in real time with the founder in the directory.
2.  **The bubble boot.** The UDP-only option and the helper, with the
    fabric's own proofs in a bubble: a thirty-second delay tap returning a
    round trip at exactly one virtual minute, and loss and cut taps
    dropping on schedule.
3.  **The fabric family.** The fabric join, stranded, and translation labs
    move into bubbles at production pacing. The stranded lab leaves CI's
    skip list.
4.  **The regions lab** lands with the selection change that settles it.

## Compatibility

Production behavior is identical: the kernel socket source resolves names
through the system resolver as it does today, and nothing outside the labs
selects the UDP-only option. The moved labs prove protocol behavior at the
daemon's own intervals on a modeled network, a stronger claim than the
shrunken schedule made. They also see the founding core in the directory,
as production does. They give up the incidental damping real time added
under load, and they no longer wait out their windows on the wall clock.
The regions lab costs five to six wall minutes per virtual hour without the
race detector; under `-race` it runs in a process of its own, and its CI
budget is measured when it lands.

## Test plan

*   **The resolver:** the kernel source resolves as before; the fabric's
    source answers its drawn names and refuses others; a fabric founder
    publishes its fabric host and appears in every node's directory.
*   **The bubble boot:** a delay tap spaces a round trip by exactly its
    virtual time, at microseconds of wall time; a poll on a condition that
    never converges fails by virtual schedule in milliseconds; a lab that
    leaks a goroutine fails at its exit.
*   **The fabric family:** each moved lab's assertions pass unchanged at
    production pacing under `go test -race -count=2`, and two labs run in
    one process without a cross-bubble fault.
*   **The regions lab:** every node holds its floor throughout, and the
    link set settles within its window bound across repeated runs.
*   **The suite:** the full gate passes with the real-time labs beside the
    bubbles.

## Implementation history
