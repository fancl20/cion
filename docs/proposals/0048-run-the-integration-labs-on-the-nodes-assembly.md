# Run the integration labs on the node's assembly

This proposal retires the integration harness's own node assembly,
`testnetwork.StartNode`, and boots every lab through `services.BootApp`,
the assembly the run command and 29 labs already use.
[Proposal 0043](/docs/proposals/0043-supervise-the-nodes-loops-and-resolve-its-role-once.md)
left the production assembly one boot with each role's parts built in one
switch, and named this retirement as the next proposal. The labs keep their
topologies and their assertions; the harness keeps only helpers over the
booted node, and `services.App` gains the two accessors the labs read and
it lacks.

[TOC]

## Summary

`StartNode` ([network.go](/internal/testnetwork/network.go)) wires a node
by hand, in about 400 lines beside its helpers, and has drifted from the
node's own setup ([node.go](/internal/services/node.go),
[controlplane.go](/internal/services/controlplane.go)). It builds no
topology provider, no echo responder, no interface-down cache, no rotation
watch and no TRC decider; its beaconer has no link latencies and its trust
service no authorizer; and every loop it starts absorbs its panics. Eleven
labs run on it, so the line, fork, origins, ping, fabrication, and
WireGuard mesh proofs exercise wiring that no node runs.

Here those labs boot through `BootApp` as the others do. Their links come
from the static topology provider's link sets, each node's ISD-AS written
to its state before any boot so that every file names its neighbors up
front. `services.App` gains `Engine` and `PeerClient`; the forwarding key,
the link table, and the labs' conns come from what the node already
exposes. `StartNode` and its types go.

## Motivation

The harness's assembly today:

*   Wires no topology provider: its links are written to the store once,
    and the data plane is built from them once, so no lab on it sees a
    generation swap.
*   Starts no echo responder unless a lab adds one by hand
    (`StartPingResponder`), and `TestPingLossSummary` relies on a node
    without one, which no production node is
    ([responder.go](/internal/services/responder.go)).
*   Shares no interface-down cache between its conns and its path
    provider, and gives its beaconer no link latencies.
*   Runs the founding core without its rotation watch, its TRC decider, or
    the authorizer its trust service consults, and has no authoritative
    core at all.
*   Opens its stores without the lock timeout and never closes two of
    them; its loops run detached, each absorbing its own panic, where the
    node's supervisor lets a Fatal loop's panic crash the process.
*   Holds the third copy of self-issuance, beside the founder's renewal and
    the node's own.

The labs on it pass while the wiring they were written to prove has moved
on without them.

### Goals

*   Every integration lab boots through `services.BootApp`.
*   The harness wires nothing of a node: no data plane, control plane,
    store, or application of its own.
*   Each migrated lab keeps its topology and its assertions — the hop and
    segment counts, the fabricated beacon's refusal, the shared segment
    ID — or the change says why one moves.
*   Production gains accessors on `services.App` and nothing else.

### Non-goals

*   No new run argument or `NodeConfig` field: a lab's identities, and the
    two-core genesis, are seeded into the state directory, the form a
    deployment's state takes.
*   No data plane options for tests: `BootApp` keeps
    `DefaultDataplaneOptions`.
*   No change to the topology providers.
*   No merger of the two self-issuance copies left.
*   No new record.

## Proposal

### The static builder

The labs' links come from the static topology provider
([provider.go](/pkg/modules/topology/impl/file/provider.go)): a link set
the operator vouches for, reconciled into the store, with no rendezvous
acceptor, no node directory, and no selection loop. A lab's topology is
then exactly the one it names, and its hop counts hold; the measured
provider would promote links of its own.

A builder in the harness, generalizing `bootStaticLine`
([static_test.go](/internal/testnetwork/static_test.go)):

1.  draws each node's host and pinned link addresses, and writes each
    node's ISD-AS to its state directory with `trust.PersistIA`, so the
    node boots on it instead of drawing one;
2.  writes every node's link set before any boot, each entry naming its
    neighbor's ISD-AS and addresses, with the interface ID where a lab
    crafts hop fields against it;
3.  boots each node through `bootAssembly`, the founding core first.

`TestStaticLabByLinkSet` stays the proof of a drawn identity's completion
and of the link set's edits at run time.

### The two-core genesis

`TestTwoOriginsShareOneSegmentID` needs a base TRC naming two cores. Before
the founder's first boot the lab opens its trust database, loads or creates
its core keys, and runs `trust.Genesis` with the fellow core; the founder's
setup then finds the base and anchors its issuer in it. The rotation labs
seed a founder's trust database before its boot too
([rotation_test.go](/internal/testnetwork/rotation_test.go)). An
authoritative join cannot stand in: a link set refuses neighbors
([config.go](/internal/services/config.go)).

### The accessors

`services.App` ([app.go](/internal/services/app.go)) is the in-process form
"tests and embedded use share". It gains:

*   `Engine`, the node's trust engine: the labs sign with it and verify
    segments bound to the node's chain.
*   `PeerClient`, the node's verified peer channel: the origins and
    fabrication labs deliver beacons over it.

Everything else the labs read the node already exposes: the link table
through `Links`, conns through `Conn`, the stores, the path provider, and
the WireGuard application through `Application`. The forwarding key a lab
crafts hop fields with is read from the node's state with
`trust.LoadOrCreateForwardingKey`, which finds the key the boot wrote.

### The labs

*   **The ping labs** run on the builder's line, fork, and sibling
    topologies; the production responder answers on every node, and the
    labs' own go. A node's link seeding leaves one link change pending at
    boot, so the node swaps its first generation once after it starts; each
    lab's first echo is a warm-up the swap may lose.
*   **The crafted-path labs** run two non-core nodes whose link sets pin
    interface 1 on each side, the interface their crafted segments name.
*   **The line control plane labs** read the path databases where they read
    the beacon store; the stores' unit tests cover the beacon store's own
    keying.
*   **The restart lab** stops its node and boots it again on the same
    state, host, and link set, as `TestCoreRestartsInPlace` does; the
    harness's teardown by hand goes.
*   **The WireGuard mesh lab** loads the WireGuard application by name on a
    host port from the pinned band, and seeds its host entries through the
    application's registry.

### Packages touched

| Package                | Change                                     |
| :--------------------- | :----------------------------------------- |
| `internal/services`    | `App.Engine`, `App.PeerClient`             |
| `internal/testnetwork` | The builder, the labs, `StartNode` retired |
| `pkg/modules`          | The import walk's allowlist                |

No record is needed: the labs move onto the assembly ADR-0013's topology
source and proposal 0043's boot already define.

### Migration

Each commit keeps the tree green and deletes what its labs no longer use:

1.  **The ping labs.** The builder and a conn helper;
    `TestPingForkTopology`, `TestPingLineMiddleNode`, and
    `TestPingSiblingNodes` move.
2.  **The crafted-path labs.** `TestPingReresolvesExpiredPath`,
    `TestPingUnreachable`, and `TestPingLossSummary` move;
    `StartPingResponder` goes.
3.  **The line control plane and the restart.** The accessors;
    `TestLineTopology`, `TestFabricatingNeighbor`, and
    `TestRestartedNodeServesUpSegments` move; `startLine` goes.
4.  **The two-core genesis.** `TestTwoOriginsShareOneSegmentID` moves.
5.  **The WireGuard mesh.** `TestWireguardMeshExchange` moves.
6.  **The retirement.** `StartNode`, its types and helpers, and the
    harness's entry in the import walk's allowlist go.

## Test plan

*   **The migrated labs:** each passes on the production assembly with its
    assertions: the fork's four hops over two segments and two hops over
    one, the line's three hops, the sibling's four; the crafted path's
    re-resolution, the unreachable destination, and the loss summary; the
    line's chains, segments, and bound verification; the fabricated
    beacon's refusal; the restarted node's up segments; the two origins'
    shared segment ID; and the WireGuard mesh's exchange.
*   **The accessors:** the line lab's bound verification runs through
    `App.Engine`, and the fabrication lab's delivery through
    `App.PeerClient`.
*   **The suite:** the full suite, `-race -count=2`, passes at every step.

## Open questions

1.  **Keep the origins lab?** Seed the founder's trust database for its
    two-core genesis, or retire it: `TestPathLayerServesTwoCores` and the
    beacon store's unit test cover two cores and the origin-keyed store,
    though only this lab forces two origins onto one segment ID.
2.  **The loss summary's premise?** Aim the lab's echo at an address in
    the destination's AS where no socket listens, or add a configuration
    that runs no responder, which the responder's place in the core
    argues against.
3.  **The WireGuard mesh lab?** Migrate it, or retire it: its registry
    hand-off stands in "until the coordination suites drive real logins",
    which `TestCoordinationOpenJoin` now does, though it alone drives a
    raw wireguard-go client.
4.  **The publication retry?** The harness retries a failed publication
    every 100 ms; the node every 10 s, with no knob. Accept the wait, or
    let the directory pacing tests already set pace the retry too.
5.  **The knobs only the harness set?** `CoreClient.SetLocator`, the
    beaconer's send timeout, and the enrollment timeout have no other
    setter. Remove them in the last step, or keep them.
