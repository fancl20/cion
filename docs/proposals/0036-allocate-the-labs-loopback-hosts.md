# Allocate the labs' loopback hosts

Every node the integration harness boots sits on a hand-picked
`127.0.0.x` literal — fifty-eight of them across the labs — and the
literals form one shared namespace: a node binds its fixed ports (the
conventions [proposal
0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)
set) on its host, so two labs whose lifetimes overlap and pick the same
host collide at the bind, and with `t.Parallel()` overlap is the norm.
The guard is discipline — grep the literals before adding a lab — and it
has already failed once. This proposal replaces the literals with one
allocator: a lab draws each host it boots from a shared pool, uniqueness
holds by construction, and the discipline retires. Where proposal 0030
settled the ports, this settles the hosts beside them.

[TOC]

## Summary

The harness's two boot paths take the node's host from the caller: the
hand-wired `StartNode` reads `NodeConfig.Host`
([network.go](/internal/testnetwork/network.go)), the assembly labs pass
a control address whose host the node serves on
([join_test.go](/internal/testnetwork/join_test.go)). Both trace back to
`addrIP(n)`
([network_test.go](/internal/testnetwork/network_test.go)), the helper
that names the n-th `127.0.0.x` address, and every lab picks its n by
hand. Because proposal 0030's ports are conventions — the control
endpoint's, the rendezvous acceptor's, the shared host port's — a host
and its ports are a package the labs share: the addresses are free for
the taking only as long as no two labs take the same one.

That discipline failed on 2026-09-26: the socks lab booted on the static
lab's hosts, most runs passed by scheduling luck, and under `go test
-race -count=2 ./internal/testnetwork/` the static lab failed instantly
at its boot with `bind: address already in use` on the control
endpoint's fixed port. The repair moved the socks lab to unused
literals. The class remains: adding a lab still means grepping for a
free slot, and nothing in the code holds the choice.

The harness already holds the answer in miniature. The failed-boot proof
deliberately leaks its node's endpoint socket past the test's cleanup,
so it cannot reuse a static slot across a repeated run — it draws from
`heldHostSlot`
([join_test.go](/internal/testnetwork/join_test.go)), one atomic counter
handing out the hosts above the labs' static slots, one per run.
Allocation is the shape the harness reaches for wherever discipline
cannot hold; this proposal makes it the shape for every host.

One boundary comes with the pool. The measured provider's own tests
mount fixed loopback hosts (`127.0.0.119` and `127.0.0.120`,
[provider_test.go](/pkg/modules/topology/impl/measured/provider_test.go)),
and `go test` runs the packages' processes in parallel — the namespaces
are coordinated today by the same hand discipline, across packages. The
allocator's pool starts above `127.0.0.0/24`, so the draws and every
other package's hand mounts cannot meet: the boundary becomes a stated
fact of the pool rather than a habit of the grepper.

## Motivation

Proposal 0030 chose fixed ports precisely because a port a peer depends
on is an address, not an assignment — the conventions stand. The hosts
were left to the labs' own hands, and a host under a fixed port is half
of the same collision: the incident above was a host clash, not a port
clash. Completing the stability work at the host side is the one move
left that touches no protocol surface: no production code changes, the
drafts' resolution and the directory untouched, the ports exactly where
proposal 0030 put them.

### Goals

*   One allocator, shared by the package's labs, hands each booted node
    a loopback host from a pool no draw repeats: two labs overlap
    freely, a repeated run draws fresh hosts, and the boot-time
    `bind: address already in use` from slot sharing cannot occur.
*   The pool starts above `127.0.0.0/24` and the boundary is stated
    where the allocator lives: other packages' fixed loopback mounts
    keep the /24, the harness's draws never enter it.
*   The hand-picked literals retire, and with them the grep-before-you-
    add-a-lab discipline; the held-host counter folds into the same
    allocator, its never-reissued-in-a-process property preserved.
*   Exhaustion refuses loudly at the draw — no wraparound, for a wrapped
    hand-out could meet a socket a prior lab leaked past its cleanup,
    the failed-boot proof's own leak being the standing example.

### Non-goals

*   No change to the ports: the conventions of proposal 0030 — the
    control endpoint's port
    ([transport.go](/pkg/controlplane/transport.go)), the rendezvous
    port ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)),
    the shared host port's default
    ([wireguard.go](/pkg/apps/wireguard.go)) — stand untouched, as do
    the binds that serve them.
*   No change to the reserve-release helpers: `freeUDPPort` and
    `FreeUDPAddrOn` pick ephemeral ports by reserve-and-release, and
    their windows — the wildcard-binder interaction
    [proposal
    0033](/docs/proposals/0033-stabilize-the-tests-by-convergence-and-consolidation.md)
    ranked tolerable — are untouched.
*   No cross-process coordination beyond the stated /24 boundary: the
    allocator does not probe, lock, or discover; uniqueness within the
    process plus the boundary is the whole guarantee.
*   No change to the labs' own shape: a lab still names its hosts
    explicitly — as drawn values it holds in variables, which the
    restart labs already do for their re-boots — rather than the boot
    helpers drawing silently on the lab's behalf.
*   No move of the measured mounts: `127.0.0.119` and `127.0.0.120`
    stay where proposal 0033 left them; the boundary protects them
    rather than relocating them.

## Proposal

### One allocator hands out the pool

`addrIP(n)` — the n-th address of `127.0.0.0/24` — becomes `hostSlot(t)`:
the next address of a pool the package shares, drawn from one atomic
counter. The pool walks `127.0.X.Y` above the reserved /24 — X from 1,
Y skipping the all-zero and all-one bytes that read as network and
broadcast — nearly sixty-five thousand draws before it ends. The counter
never resets and never wraps: a draw past the pool's end fails the test
at the draw, for a wrapped hand-out could name a host whose sockets a
prior lab leaked past its cleanup, and a wrong-reason failure is what
the allocator exists to prevent. A test binary would need more than a
thousand full passes of the package's labs to reach the refusal.

### The call sites draw

Every `addrIP(0xNN)` literal in the labs becomes a `hostSlot(t)` draw —
the boot helpers (`StartNode`, the assembly and coordination boots, the
static line) keep their signatures and take the drawn values exactly
where they take the literals today. A lab that re-boots a node — the
restart and held-port proofs — holds its drawn host in a variable and
passes it to each boot, the shape the restart labs already use for their
literals. Incidental loopback literals that are not node hosts stay as
they are: the stranger the unrouted-destination ping dials, the DERP
relay's advertised address, the source the CIDR-gate comment names.

### The held-host proof folds in

`heldHostSlot` deletes; the failed-boot proof draws from the same
allocator as every lab. The property its comment records — one host per
run, because the failed boot's endpoint socket outlives the test — is
the allocator's own never-reissued-in-a-process property, now stated
once where the counter lives instead of beside its single customer.

### The boundary below the pool

The pool starts at `127.0.1.1`, and the allocator's comment states the
boundary: `127.0.0.0/24` belongs to the other packages' fixed loopback
mounts. The boundary holds by construction — no draw can name an
address below it — so the cross-package coordination that today lives
in a maintainer's habit becomes a fact of the code, and a future
package mounting its own fixed hosts knows which half of the loopback
space is whose.

## Compatibility

No production code changes, and no lab changes shape: the diffs replace
literals with draws and delete a counter. The addresses become
run-relative — a failure's logs name the drawn host wherever they named
the literal, and the bind errors that motivated this proposal already
print the full address — but a lab is no longer findable at its
historical address across runs, which was never a promise the harness
made. The standing suites' commands are unchanged; the parallel and
`-count` regimes that exposed the incident become harder to fail, not
differently run.

## Test plan

*   **The allocator:** draws are pairwise distinct; no draw names an
    address in `127.0.0.0/24`; the pool's end refuses at the draw.
*   **The labs:** the full package passes `go test -race -count=2
    ./internal/testnetwork/`, the command that reproduced the incident,
    with every lab drawing its hosts; the deliberately overlapping
    pairs — the socks and static labs that collided — run parallel
    without sharing a host.
*   **The proofs that lean on uniqueness:** the failed-boot proof
    refuses on a held shared port on each of its draws across a
    `-count` rerun; the restart labs re-boot on their held hosts and
    converge as before.

## Implementation history

*   The allocator lives where `addrIP` did
    ([network_test.go](/internal/testnetwork/network_test.go)): one atomic
    counter walking the 255 × 254 hosts of `127.0.X.Y` from `127.0.1.1`,
    the reserved-/24 boundary and the never-reissued-in-a-process property
    stated beside it, and the pool's own proof walking every draw —
    distinct, above the boundary, the end refusing.
*   The held-host counter deleted with its comment folded into the pool
    counter's ([join_test.go](/internal/testnetwork/join_test.go)); the
    labs' slot-discipline notes, the socks lab's incident comment the
    first, retired with the literals they explained.
*   The hand-wired restart lab still draws a second host for its re-boot:
    the first node's endpoint socket lives to the test's cleanup, its
    fixed port held against the reboot
    ([network_test.go](/internal/testnetwork/network_test.go)).
