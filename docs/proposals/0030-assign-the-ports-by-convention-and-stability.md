# Assign the ports by convention and stability

This proposal makes two moves on the node's port assignments. The
host-facing port defaults to 51820 — the WireGuard ecosystem's conventional
port, unregistered with IANA — so
serving hosts stops being an argument about a number: zero remains the
explicit refusal. And the node's three bespoke underlay ports renumber into
a ladder beside the SCION endhost port, each step down the block a surface
fewer parties bind: the control endpoint takes 30042, the rendezvous
acceptor 30043, the internal link 30044. Nothing migrates — the numbers are
run arguments and store-recorded rendezvous addresses, and a network
reforms around them.

[TOC]

## Summary

The block today, and the block after:

| Port | Carries today | Carries after |
| :--- | :--- | :--- |
| 30041 | the SCION endhost underlay port | unchanged |
| 30042 | the internal link | the control endpoint |
| 30043 | — | the rendezvous acceptor |
| 30044 | the control endpoint | the internal link |
| 30045 | the rendezvous acceptor | retired |

The ladder's rule is blast radius — how many parties a change to the number
binds:

*   30041 binds every SCION deployment. It is scionproto's constant, copied
    verbatim into [defs.go](/pkg/dataplane/defs.go), and moves only with
    standardization.
*   30042 binds every CION peer. The control endpoint serves the drafts'
    own services, the surface the control service name delivers to — the
    most settled protocol the node carries.
*   30043 binds joiners only, and only before identity. The rendezvous
    exchange is this network's own, and the one under active redesign
    ([proposal 0028](/docs/proposals/0028-learn-the-external-address-from-rendezvous.md)
    reworks it).
*   30044 binds the node alone. The internal link carries no protocol at
    all — a peer cannot observe the number — and is free to become a unix
    socket or an in-process seam without anyone off the host noticing.

Today's numbers invert the ladder: the most private socket holds the slot
beside the most public convention, the block's one gap sits between them,
and a reader cannot tell which number carries a wire obligation. After the
renumber, whatever the drafts fix first already sits nearest the inherited
constant, and each retirement or redesign candidate sits further down.

The host-facing port is the one serving argument left without a default.
The tests standardize on 51820
([run_test.go](/cmd/cion/run_test.go),
[dbtest.go](/pkg/apps/wireguard/impl/dbtest/dbtest.go)) — the value the
ecosystem's tooling ships. The default makes it every node's value, with
`--host-port=0` the explicit refusal and a collision at 51820 a loud boot
failure the override remedies.

## Motivation

The block's order is an accident of registration order, and ordered numbers
get read. A port adjacent to 30041 reads as SCION's own business; today
that slot belongs to the internal link, the one socket whose number is most
likely to change — it binds nothing off the host — while the two surfaces
joiners and peers actually depend on sit above and below the gap. Renumbering
costs one constants edit and a network re-forming, which is exactly the
trade pre-standard numbering exists to spend: the block should tell the
truth about its surfaces while it is still cheap to tell it.

The host port's requirement is a residue of the configuration era, not a
safety the node needs. Every other serving argument has a default a restart
needs none of ([config.go](/internal/services/config.go)); the shared port
alone demands an operator's arbitrary pick, and every deployment and test
picks the same one. The failure the requirement guarded against — a node
unwittingly binding a port another WireGuard interface holds — is better
served by the bind failing loudly at boot than by demanding a number, and
that failure is what a fixed default produces.

### Goals

*   The ladder: `EndpointPort` 30044 → 30042
    ([transport.go](/pkg/controlplane/transport.go)), `RendezvousPort`
    30045 → 30043
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)),
    and the internal address's default 30042 → 30044
    ([config.go](/internal/services/config.go)), each constant's comment
    restated to the ladder it sits in.
*   The defaults: `DefaultControl` names the control host at 30042 and
    `DefaultInternal` the loopback at 30044, the flag help unchanged in
    grammar.
*   The host port's default: `--host-port` defaults to 51820, zero remains
    the explicit refusal, and the validator's pairing with `--slice` keeps
    its shape against the zero test.
*   The retirements: 30045 leaves the codebase entirely; no port of the
    node's carries it after the renumber.

### Non-goals

*   No IANA registration for the block: 30041's fate belongs to SCION's
    standardization, and 30042–30044 stay private conventions — peers reach
    the endpoint by service name, joiners by argument.
*   No change to the internal link's transport: the unix-socket and
    in-process alternatives stay out; the ladder only renumbers, and the
    renumbering is what keeps that freedom visible.
*   No migration of stored rendezvous addresses: state carries identity and
    keys, no ports to rewrite; entries that name 30045 age out as dead
    candidates.
*   No accommodation for
    [proposal 0029](/docs/proposals/0029-assign-the-node-slice-from-the-directory.md)
    beyond its gate reading `--host-port=0`, whichever lands first.

## Proposal

### The ladder

Three constants move; nothing else does. The endpoint's number crosses no
wire — peers address the control service by its SVC destination and the
node's own data plane delivers to the registered socket, so
[scionConn](/internal/services/controlplane.go) rebinding at 30042 is the
node's private affair. The rendezvous number is the one with holders off
the host: the acceptor binds it, joiners dial it, and the selection loop
derives it from a recorded remote when an entry carries no rendezvous
address ([selection.go](/pkg/modules/topology/impl/measured/selection.go))
— all readers of the one constant, all moving together.

The labs bind through the constants
([network.go](/internal/testnetwork/network.go)), so the integration
harness moves without edits; the tests that spell literals — the command
tests' `--neighbor` arguments, the store fixtures' seeded rendezvous
addresses — restate to the new numbers beside the constants they mirror.

### The host port's default

`DefaultHostPort = 51820` joins the run defaults, the flag's help naming
zero as the refusal. With `--slice` today, the operator stops passing a
number the deployment was going to repeat anyway; under
[proposal 0029](/docs/proposals/0029-assign-the-node-slice-from-the-directory.md),
where the port alone gates the host-serving applications, the gate becomes
the zero test rather than the flag's presence. A port 51820 already held —
the machine's existing WireGuard interface — fails the application's bind
at boot, and the operator overrides with the argument that was always
there.

### Compatibility

A renumbered binary against an unrenumbered network fails at the edges the
ladder predicts. A joiner's `--neighbor` naming 30045 finds no acceptor;
a stored link entry's recorded rendezvous address names the retired port,
its liveness probe fails, and the candidate ages out unproven — a re-seeded
argument at 30043 lands beside the stale entry, deduplicated by address,
and serves while the old one sweeps. Mixed versions on one host meet a
loud bind failure, not a misdelivery: the new internal link's 30044 and an
old endpoint's 30044 cannot both bind, and the error names the collision.
Pre-standard networks re-form; that is the trade the block's privacy pays
for.

## Test plan

*   **The constants:** the endpoint, rendezvous, and internal-link tests
    move with the numbers — the transport, resolution, and lookup suites
    against 30042; the rendezvous and selection suites against 30043; the
    configuration suite against the swapped defaults.
*   **The literals:** the command tests' `--neighbor 192.0.2.7:30043` and
    the store fixtures' seeded `127.0.0.1:30043` restate, and no literal
    30045 remains in the tree.
*   **The default:** the run suite asserts 51820 as the parsed default,
    `--host-port=0` beside `--slice` refuses, and a boot against a held
    51820 fails loudly — the lab proof binds the port first.
*   **The proofs:** the integration labs pass with renumbered defaults and
    defaulted host ports — rendezvous joins complete, control serves, and
    hosts dial the shared port unasked.

## Implementation history

*   Proposal 0029 landed first, so the accommodation is its branch: the
    host port's gate reads the zero test alone
    ([wireguard.go](/internal/services/wireguard.go)), no pairing left to
    keep its shape.
*   The literals the plan left unnamed found their numbers: the wireguard
    bind suite's peer underlay addresses and the SCION address suite's
    string fixture left the block for an arbitrary port
    ([bind_test.go](/pkg/apps/wireguard/bind_test.go),
    [conn_test.go](/pkg/scion/conn_test.go)), and the retired-shape
    fixture's gatewayPort carries the conventional 51820
    ([db_test.go](/pkg/apps/wireguard/impl/bbolt/db_test.go)).
*   The defaulted-port proofs live in the coordination and wireguard labs
    ([coordination_test.go](/internal/testnetwork/coordination_test.go),
    [wireguard_test.go](/internal/testnetwork/wireguard_test.go)), the
    held-port refusal in
    [join_test.go](/internal/testnetwork/join_test.go).
