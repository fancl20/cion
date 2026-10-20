# Run the integration labs on virtual time

The labs wait on time. Every convergence the harness polls for — a registry
entry landing, a link turning live, a mapping standing — is watched through
a budget the poll spends in wall clock
([network.go](/internal/testnetwork/network.go)), and every behavior the
polled system performs is paced by intervals the labs shrank for exactly
this ([join_test.go](/internal/testnetwork/join_test.go)). On a loaded
runner under the race detector the two drift apart: a poll's budget expires
or a liveness window closes before the event it watches for, and the lab
fails or sticks though the node never diverged — the stuck class the suite's
history keeps recording. The fabric [proposal
0063](/docs/proposals/0063-give-the-integration-labs-a-userspace-fabric.md)
laid one clock under everything a lab boots and named the seam "a
deterministic network later builds on"; that proposal's non-goals left the
exploit to a later day. This is that proposal: the convertible labs run
inside `testing/synctest` bubbles, where virtual time advances only when
every goroutine in the lab is parked, so a deadline fires by schedule
rather than by wall clock and a missed window stops being something a
runner can cause. Two prerequisites stand in the way and fall here: gVisor's
sleeper parks where a bubble cannot see it — a fork of one file carries the
fix — and most labs still boot the kernel family, whose standing sockets
freeze a bubble's clock outright.

[TOC]

## Summary

What virtual time buys is the stuck class itself. In a bubble every timer
in the process reads one virtual clock: the node's loops, BFD's detection,
the taps' delays, the boundary's idle windows, netstack's retransmits, the
polls' own sleeps and budgets. Virtual time advances only at quiescence, so
a budget is spent by the system's own schedule — a poll times out only when
the schedule it observed never converged, a liveness window closes only
when its intervals truly lapsed — and no amount of runner load can spend a
budget early. The labs' real-time waits collapse with it: windows the
harness waits out in wall seconds cost nothing, which also lifts the crawl
that keeps the heaviest labs in processes of their own
([solo_test.go](/internal/testnetwork/solo_test.go)).

Two walls hold today, both verified by probe on this repository's pins.

First, the sleeper wall. A bubble advances time only when every goroutine
in it is durably blocked, and the Go runtime decides that by a whitelist —
`isIdleInSynctest` in `runtime2.go` — that a raw `Gopark` park never
enters. gVisor's `pkg/sleep` parks its sleeper exactly that way, through a
raw `Gopark` passing a stale vendored constant, `waitReasonSelect = 9`,
where upstream Go's ninth reason is `GC scavenge wait` — so every netstack
transport dispatcher, parked in its sleeper whenever the stack is idle,
counts as active forever. The bubble never quiesces; virtual time freezes;
the lab hangs at its first delayed tap or retransmit. A two-stack
handshake whose first SYN a tap drops never reaches the retransmit that
would complete it. The fix is local to the sleeper: park it on a plain
channel, waker asserts becoming channel sends, all inside whatever bubble
the stack runs in. One file, carried as a `replace` fork until upstream
takes it.

Second, the kernel-port wall. A goroutine parked on a kernel socket is
never idle either — a standing kernel read freezes the bubble's clock until
real I/O or a real deadline releases it, and no deadlock error names the
hang. Today only the fabric, stranded, and translation labs boot on the
fabric; the rest boot `underlay.Kernel`, and the resident applications —
the WireGuard host port, the SOCKS outbound leg — bind kernel loopback
directly, outside the socket seam. The labs that convert move onto the
fabric first, the seam's TCP side already carrying the control-plane
listeners, and the resident applications' ports construct through it.

What moves: the fabric family into bubbles, then the labs that boot no
resident application, then the app-carrying labs once their ports ride the
seam. What stays: the coordination suites and the vendored client engine
that owns them — its magicsock binds kernel sockets through no seam the
labs can reach — beside the wildcard lab, whose subject is the kernel's own
socket surface. What retires: the wall-clock waits, the solo processes and
host bands of every converted lab, and the `replace` fork itself when a
released gVisor carries the fix.

## Motivation

The stuck class is a timer class. The harness's polls sleep thirty
milliseconds against budgets of one timeout or three
([network.go](/internal/testnetwork/network.go)), and the systems they
watch converge on intervals the labs drew small for the watching:
propagation at a hundred milliseconds, registration at two hundred,
rendezvous at ten, the selection window at two seconds, the candidate
window at five ([join_test.go](/internal/testnetwork/join_test.go)). The
windows the proofs ride are wider still: a BFD session holds its verdict
over three transmission intervals — three seconds at the production
interval the labs deliberately keep
([bfd.go](/pkg/core/liveness/bfd.go)) — and a boundary mapping lives two
seconds past its last packet
([boundary.go](/internal/testnetwork/fabric/boundary.go)). A runner that
stalls a second between a link's BFD packets takes the link down in the
labs' own fast-pacing terms; a stall inside a restart's serial stages
spends the restart lab's sixty-second budget while the pipeline still
progresses — the budget's own comment records the stretch. The solo
re-execution bought the heaviest labs a process of their own to run at
their own pace, which is palliative: the runner still shares the machine,
and the wall clock still spends the budgets.

Virtual time removes the terms in which the class lives. Under a bubble a
stalled runner cannot stretch an interval, because intervals advance only
when the system itself is parked; a loaded machine changes when virtual
seconds pass, never how they order. What remains flaky is scheduling, not
time — goroutine interleaving stays nondeterministic, the race detector's
own province — but the deadline and window sensitivity, the observed stuck
class, is gone by construction.

The seam is already laid. Every stack and every tap's scheduler read one
`tcpip.Clock`, the fabric's own `NewStdClock` — pure delegation to the
`time` package — which inside a bubble is virtual time for free: the taps'
delayed packets, the boundary's idle retirement, netstack's retransmission
timers, the gonet deadlines the conns carry, all of it, with no fabric
change at all.

### Goals

*   The gVisor sleeper parks bubble-visibly — one file's park mechanics,
    nothing else — carried as a `replace` fork and offered upstream.
*   The convertible labs run in `testing/synctest` bubbles, their polls and
    assertions unchanged: a timed-out poll reports a schedule that never
    converged, a liveness verdict reads intervals that truly lapsed.
*   The labs that still boot the kernel family and convert move onto the
    fabric, continuing [proposal
    0063](/docs/proposals/0063-give-the-integration-labs-a-userspace-fabric.md)'s
    migration.
*   The resident applications' kernel binds — the WireGuard host port, the
    SOCKS outbound leg — construct through the socket seam, so the
    app-carrying labs convert and their resident ports leave the shared
    kernel loopback.
*   A converted lab's teardown is complete: the bubble's drain turns a
    leftover goroutine into an immediate, named failure — the leak gate
    today's suite lacks.

### Non-goals

*   No scheduling determinism: virtual time orders timers, not goroutines;
    interleaving-sensitive flakes remain the race detector's to catch.
*   No coordination conversion: the vendored client engine binds and dials
    kernel sockets with no seam the harness can reach; its suites keep real
    time and their solo processes.
*   No kernel-family conversion: the wildcard lab's subject is the kernel's
    own socket surface ([wildcard_test.go](/internal/testnetwork/wildcard_test.go));
    it keeps the kernel, the namespace, and real time.
*   No new pacing or budgets: the intervals and timeouts stand as written —
    under virtual time they cost nothing, and changing them would change
    what the labs prove.
*   No clock injection into the node: the `time` package is the seam — the
    point of bubbles over a manual clock is that no `pkg` code changes at
    all.

## Proposal

### The sleeper fork

gVisor's `pkg/sleep/sleep_unsafe.go` parks its sleeper through
`sync.Gopark` with a custom commit and the vendored constant
`waitReasonSelect = 9`; upstream's ninth wait reason is `GC scavenge wait`,
and the runtime's bubble idle test — the `isIdleInSynctest` whitelist in
`runtime2.go` — admits no raw-`Gopark` park regardless of its reason. The
fork rewrites the sleeper's park onto a plain channel: the sleeper blocks
in a channel receive, and a waker's assert sends on it. Every assert comes
from a goroutine or a timer already inside whatever bubble the stack runs
in, so the park is durably blocked exactly when the bubble's own rules say
— no constant to keep in step with upstream, no runtime internals named.
Waker semantics, ordering, and the sleeper's public shape are untouched;
nothing netstack observes changes.

The fork enters `go.mod` as the repository's first `replace` directive,
pinned to the upstream commit it forks. The directive is module-wide, so
the fork's diff stays park mechanics and nothing else — no wire bytes, no
netstack behavior — and it retires the day a released gVisor carries the
fix upstream.

### The bubble

A lab's test body runs inside `synctest.Test`, and the fixtures keep the
shape they have: cleanups registered on the bubble's `t` run inside the
bubble before `synctest.Test` drains it — the standard library's own
ordering, verified here — so `fabric.New`'s stop, the nodes' `Close`, and
the conns' releases execute where they must. The drain is the new gate,
and it fails fast: a goroutine still standing when the lab ends parks the
bubble into the runtime's own verdict — `main bubble goroutine has exited
but blocked goroutines remain` — an immediate, named failure carrying the
leftover's stack, where today the goroutine lingers silently for the
suite to trip over. The one shape the drain cannot see is a goroutine
that never parks bubble-visibly — spinning, or wedged in a syscall —
which holds the bubble open until the suite's own time alarm, the same
panic-with-stacks the testing package has always given. No converted lab
holds one by construction: it holds no kernel socket, and the sleeper is
forked. The fabric's own teardown already joins its forwarders and
stacks; the supervision group already joins the node's loops; the drain
makes that discipline load-bearing.

The polls need no change at all. A poll's thirty-millisecond sleep and its
budget are timers like any other: each iteration advances virtual time by
its sleep, the budget is reached only by the schedule, and a timeout
becomes a fact about the system rather than a fact about the runner. The
kernel touches that remain — the address draws' probe binds, the state
directory's file writes, the logs — are completing syscalls, which a
bubble sits fine beside; the rule the converted labs keep is no standing
kernel socket.

### The fabric migration

The labs that convert but still boot `underlay.Kernel` move onto the
fabric through the boot the fabric family already uses: bfd, static,
corepath, enrollauth, rotation, and the join and corejoin suites' labs
that load no resident application. The seam's TCP side carries their
founders' HTTPS binds as it carries the coordination endpoint's today; the
QUIC transports ride the SCION conns the fabric already serves, their
retransmits reading the same virtual clock. The kernel family keeps every
lab whose assertion names the kernel's socket surface, per [proposal
0063](/docs/proposals/0063-give-the-integration-labs-a-userspace-fabric.md)'s
own compatibility terms.

### The resident applications' ports

The WireGuard application's host port binds kernel loopback directly
([app.go](/pkg/apps/wireguard/app.go)); the SOCKS outbound leg does the
same ([serve.go](/pkg/apps/socks/serve.go)). Both construct through the
socket seam, the underlay source they already take shape beside: a fabric
node's host port becomes its stack's own, and the fixed-port collisions
that keep app-carrying labs in solo processes and host bands
([solo_test.go](/internal/testnetwork/solo_test.go)) stop being possible
for them. Their labs convert once the ports ride; the coordination suites
do not follow — the engine beside the application holds kernel sockets of
its own through no seam.

### Packages touched

| Package                     | Change                                                  |
| :-------------------------- | :------------------------------------------------------ |
| `go.mod`                    | The gVisor `replace` fork, pinned and commented          |
| `pkg/apps/wireguard`        | The host port binds through the socket seam              |
| `pkg/apps/socks`            | The outbound leg binds through the socket seam           |
| `internal/testnetwork`      | The labs' bubbles; the kernel-boot conversions; the solo retirements |

### Migration

Each commit keeps the tree green:

1.  **The fork.** The sleeper parks on a channel; `go.mod` carries the
    replace; the fabric package gains the bubble proof — two stacks, a
    delay tap, a dropped first SYN, the handshake completing through the
    retransmit with no wall time spent.
2.  **The fabric family.** The fabric, stranded, and translation labs run
    in bubbles, assertions untouched; their real-time waits collapse.
3.  **The apps-less kernel labs.** They move onto the fabric and into
    bubbles; the kernel family keeps the socket-surface proofs.
4.  **The ports, then their labs.** The resident applications' binds take
    the seam; the app-carrying labs convert; the converted labs' solo
    processes and host bands retire.

## Compatibility

Production behavior is unchanged: the fork's diff is park mechanics, the
seam's new constructs open the same sockets the applications open today on
the kernel default, and no `pkg` code beside the constructors moves. The
`replace` directive binds the whole module to the fork until upstream
carries the fix — the price of one file, paid deliberately and named in
`go.mod`.

The failure surface shifts, honestly: a converted lab that leaks a
goroutine fails at its own exit — the bubble's named deadlock error, the
leftover's stack attached — instead of lingering for the suite to trip
over, and a converted lab that times out reports a real divergence — the
budget it spent was spent by a schedule the lab can reprint. Parallelism is
unchanged — a bubble per test, the real-time family beside it — and the
suite's wall time falls by every window the converted labs once waited
out: three-second BFD verdicts, two-second idle expiries, sixty-second
restart budgets, all virtual now.

## Test plan

*   **The fork:** the fabric package's bubble proof — the handshake through
    the dropped SYN completes on virtual time — and the fabric family's
    taps and boundary behave identically under real time, `go test -race
    -count=2`.
*   **The bubbles:** each converted lab's assertions pass unchanged; a
    poll pointed at a condition that never converges fails by virtual
    schedule in milliseconds, proving the budget is the schedule's, not
    the runner's.
*   **The drain:** a converted lab whose teardown is deliberately broken
    fails at once with the bubble's deadlock error, the leftover named
    where it parks — the leak gate doing its work.
*   **The real-time family:** the coordination, wildcard, and namespace
    labs pass untouched, their solo processes intact.
*   **The suite:** the full gate passes with both families beside each
    other, faster by the retired waits.

## Implementation history

*   None yet; the proposal is a draft. The gVisor sleeper freeze, the
    kernel-socket freeze, the bbolt compatibility, and the cleanup
    ordering were verified by throwaway probes against the repository's
    pins before drafting; the probes are not part of this change.
