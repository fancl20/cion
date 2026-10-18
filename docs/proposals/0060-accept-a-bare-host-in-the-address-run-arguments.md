# Accept a bare host in the address run arguments

This proposal hardens the first contact
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
places at the rendezvous exchange — "a plain underlay round trip to a peer's
advertised rendezvous address" — at the argument that spells it. The three
address run arguments (`--control`, `--internal`, `--topology.neighbor`)
accept a bare host, naming their default port: the control endpoint's 30042,
the internal link's 30044, the rendezvous acceptor's 30043. And a rendezvous
dial aimed at the control endpoint's port — the address an operator copies
when the help names no rendezvous port — names the confusion in its error.
No port changes number, no wire message changes, and every spelled
`host:port` keeps its meaning.

[TOC]

## Summary

The rendezvous port is fixed by the block's ladder
([proposal 0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)),
but nothing an operator reads names it: the neighbor flag's help said
"rendezvous underlay address" without the number, and the one address every
deployment spells — the control address — carries a different port the flag
grammar demanded and no socket read. A joiner dialed to the control port
found the SCION control endpoint, which drops rendezvous packets without a
trace; the join then fails as silence.

Three changes:

*   `ParseRendezvousAddr`
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go))
    parses the neighbor argument: `host:port` as spelled, a bare host at the
    fixed rendezvous port. `resolve`
    ([config.go](/internal/services/config.go)) validates through it, and
    the provider's bootstrap and seed parses read the same rule.
*   `ResolveAddrPortDefault`
    ([underlay.go](/pkg/libs/underlay/underlay.go)) resolves the control and
    internal addresses, a form without a port naming the argument's default.
*   `RendezvousEcho`'s unanswered-dial error carries a hint when the target
    holds the control endpoint's port: the endpoint drops rendezvous
    packets, the acceptor binds another. Derived probe targets — the fixed
    port or an entry's recorded address — never trigger it.

## Motivation

A droplet join failed for a day behind three causes stacked
(stale identity, version skew), and the last to fall was the simplest: the
joiner's `--topology.neighbor` named the control port, because that was the
address the run arguments had taught the operator to spell. The grammar
invited the mistake three ways:

*   `--control` demands a port its semantics discard — `controlAddr`'s port
    has no reader; every socket on the control host binds a port the ladder
    fixes. The flag requires a number and then ignores it.
*   `--topology.neighbor`'s help named no port, and the fixed 30043 lives
    nowhere an operator reads — the flag's grammar offers no spelling that
    leaves the number out.
*   An unanswered dial reports silence, indistinguishable from a firewall
    drop, when the datagrams reached a live socket that serves another
    protocol.

Fail-fast says the arguments' grammar should refuse what it cannot honor,
and affordance says the common spelling should be the short one. The bare
host gives both: the number a joiner cannot mis-spell is the number it never
spells.

## Proposal

*   `ParseRendezvousAddr` sits beside `RendezvousPort` and carries the one
    grammar the neighbor argument has: `netip.ParseAddrPort` first, a bare
    host through `netip.ParseAddr` at the fixed port. `resolve`'s validation
    loop and the provider's `CompleteIdentity` and `Seed` parses all read
    it — one rule, three sites, no normalization to store.
*   `ResolveAddrPortDefault` takes the form and the default port: a form
    `net.SplitHostPort` reads keeps the port it spells; a form without one
    is re-spelled through `net.JoinHostPort` — IPv6 bracketed on the way —
    and resolves as before. `resolve` defaults the control address to the
    endpoint's port and the internal address to the port `DefaultInternal`
    carries, derived, not restated. A spelled port on either keeps its
    meaning: the internal address binds it, the control address carries a
    host for sockets the ladder places.
*   The silence hint is a helper the echo's terminal error appends, empty
    for every target but the endpoint port's. Bootstrap and join-dial logs
    surface it; the probes' derived targets never carry the endpoint's port.
*   The flag help restates the grammar: the neighbor argument names "host or
    host:30043", the control argument names the host its sockets share and
    the ports the ladder fixes.

### Non-goals

*   No port moves and none becomes configurable: the ladder's numbers stay
    the conventions [proposal 0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)
    fixed, and the rendezvous port stays a constant every reader shares.
*   No change to what `--control` binds: the wildcard default and the
    argument's retirement are
    [proposal 0059](/docs/proposals/0059-bind-the-default-control-address-on-every-interface.md)'s
    seam — this proposal only spells the grammar the argument carries while
    it exists.
*   No refusal of a spelled control port: the integration harness places
    nodes by passing free addresses through the same resolve, and the port
    is the host's carrier, inert by design.
*   No name resolution for the neighbor argument: it names a literal
    address, as it did.

## Compatibility

Every previously valid spelling resolves to the address it did; the bare
host is a new form, not a reinterpretation. A neighbor spelled at the
control port still fails — now as silence with the confusion named, the
error carrying both ports. State holds no port to migrate: entries record
rendezvous addresses as spelled, and a network reforms around them
unchanged.

## Test plan

*   **The grammar:** `ParseRendezvousAddr` keeps a spelled port, defaults a
    bare IPv4 and IPv6 host, refuses garbage
    ([rendezvous_test.go](/pkg/modules/topology/impl/measured/rendezvous_test.go));
    `ResolveAddrPortDefault` passes a spelled port through, defaults both
    host forms, refuses a port out of range
    ([underlay_test.go](/pkg/libs/underlay/underlay_test.go)).
*   **The resolve:** bare hosts resolve — the control address at 30042, the
    internal at 30044, a neighbor accepted
    ([config_test.go](/internal/services/config_test.go)) — and the
    unparsable refusals keep holding.
*   **The hint:** a dial to a silent endpoint-port target carries it, a dial
    to any other silent port carries none.
*   **The proofs:** the command surfaces parse a bare-host neighbor
    ([run_test.go](/cmd/cion/run_test.go)), and the rendezvous join lab
    boots its middle node with one — the join, enrollment, and directory
    publish land exactly as the spelled form's
    ([join_test.go](/internal/testnetwork/join_test.go)).

## Implementation history

*   `ParseRendezvousAddr` and the silence hint live in
    [rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go);
    `ResolveAddrPortDefault` in
    [underlay.go](/pkg/libs/underlay/underlay.go); the resolve's defaulting
    and validation in [config.go](/internal/services/config.go); the flag
    help in [run.go](/cmd/cion/run.go),
    [run_local.go](/cmd/cion/run_local.go), and
    [run_core.go](/cmd/cion/run_core.go); the bare-host join in
    [join_test.go](/internal/testnetwork/join_test.go).
