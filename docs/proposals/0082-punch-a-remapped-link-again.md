# Punch a remapped link again

This proposal punches a link again once a NAT's remap has taken it down. The
link keeps its interface ID, so the routes through it carry again within
seconds. It changes the remap consequence that
[ADR-0030](/docs/adrs/0030-punch-through-both-nats.md) records: the link no
longer waits for both ends to retire it.

[TOC]

## Summary

When a NAT remaps a node behind it, most of the node's links move with the
new flow ([ADR-0029](/docs/adrs/0029-follow-each-links-own-flow.md)): its
peers outside NATs and behind full-cone NATs follow it. A punched link to a
node behind a port-restricted NAT cannot follow. That NAT drops what the new
mapping sends, so no flow arrives to follow. The link stays down until both
ends retire it on its verdict, after `DemoteWindows` selection windows: 75
to 90 seconds in the NAT lab, and at least 90 in production.

Until then, the routes through the down link keep their interface IDs and
rank first at other nodes. The router at the link answers each packet with
the interface-down signal, and the source holds the interface for ten
seconds (`IfDownCacheTTL`). The source's next packet after that takes the
dead route again. The rebinding benchmark samples every ten seconds, and in
two runs of five it took 108 seconds for every pair to answer again.

Measured on the change below, five runs each, in the NAT network of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md):

*   **Rebinding:** once node 3's NAT dropped its mappings, every pair with it
    answered again within 14.5 to 15 seconds in every run, where the slowest
    run took 108 before. Node 3's links to the nodes behind port-restricted
    NATs were punched again, ten times in all, none failing, and node 3 held
    all six of its links when the pings answered.
*   **Settled, restart, symmetric:** no link was punched again.
    *   Every pair's best path over the formed links is its reference.
    *   The worst chosen path stood at 1.0 to 1.75 times its reference.
    *   The network settled in 2.8 to 4.8 minutes, against 3 to 3.5.
    *   A restarted dialable node was reached again in 13 to 13.2 seconds.
    *   A node behind a symmetric NAT enrolled in 23 to 55 seconds.
*   **Founder down:**
    *   The survivors reached each other within a second in four runs and
        within 36 seconds in the fifth. Ten runs without this change gave
        0.73 to 15.9 seconds, three of them past five: the slow runs wait
        out segment lookups to the lost founder.
    *   Node 5 returned in 208 to 292 seconds.
    *   While node 5 was stopped, its peers punched each of its links again
        three times, then left the links to retirement.

## Motivation

### Goals

*   A punched link that a remap took down is up again within seconds, on
    its interface IDs.
*   The routes through it carry again without waiting for new beacons.

### Non-goals

*   No change to how a source treats the interface-down signal.
*   No re-punch through an address-and-port-dependent NAT.

## Proposal

### The re-punch loop

The provider runs a loop beside the follow loop, on its `FollowInterval` of
one second. The loop considers a link punched when both ends report their
published rendezvous address unanswered: the node's own report, and the
peer's directory entry. Of a punched link's two ends, the one with the lower
ISD-AS punches the link again. The other end's handler takes its own down
entry, so the two ends never punch toward each other at once.

Once a punched link's verdict has stayed down for `RepunchGrace`, the loop
punches it again. If that fails, it tries again after `RepunchRetry`, then
after twice that, up to `RepunchAttempts` attempts in one down period. A
peer that stays unreachable leaves the link to the selection's retirement.
`RepunchGrace` is three seconds, one BFD detection time past the verdict;
`RepunchRetry` is five seconds; `RepunchAttempts` is three.

### Punching again

While the entry stands, the link's own socket stays bound, so the punch
leaves from a fresh link address:

1.  It learns that address's reflexive address from the reflector.
2.  It asks the peer for a link's punch that names the entry's interface
    ID.
3.  It sends its opens toward the peer's reflexive address.

The entry then takes the fresh address and the peer's reflexive address and
keeps its interface ID, and the entry's link request confirms it. A failed
punch changes nothing. If another loop moved or retired the entry during the
punch, that change stands.

### The reflector

A punch learns its socket's reflexive address from a reflector: a neighbor
that reports itself dialable. The reflector now has to be a neighbor whose
link is up. Previously, an established neighbor whose link was down could
be chosen, and with the founder away, such a neighbor answered no binding
request.

### The handler

When a link's punch arrives from a caller whose standing entry is down, and
the request names the interface that entry pairs with, the punch is for the
same link and the handler takes that entry. It moves the entry to a fresh
link address, keeping its interface ID, binds the address, sends its opens
toward the caller's reflexive address, and records that address as the
entry's locator.

As before, the handler refuses a caller whose standing entry is up, and
also one whose down entry pairs with another of the caller's interfaces.
The second case is a new link from a caller that retired the old one, and
the old entry stands until its own verdict retires it. `LinkService` gains
`Verdicts`.

### The labs

*   **The recovery lab:** a NAT drops node 3's mappings. Node 3's link to
    node 5, behind a port-restricted NAT, goes down. Within 30 seconds it
    stands again at both ends, established, up, and on its interfaces, as
    does node 3's link to node 4.

### Packages touched

| Package                              | Change                                                     |
| :----------------------------------- | :--------------------------------------------------------- |
| `pkg/modules/topology/impl/measured` | The re-punch loop, the handler's down entry, the reflector |
| `internal/testnetwork/behavior`      | The recovery lab's re-punch                                |

## Compatibility

*   A peer of an earlier release refuses the punch for a standing link, as
    before, and the link waits for both ends to retire it.
*   The wire does not change.

## Test plan

*   **Which links are due:**
    *   A punched link is due once it has been down for `RepunchGrace`, then
        again after `RepunchRetry` and after twice that, `RepunchAttempts`
        times in all, and only at the end with the lower ISD-AS.
    *   A link to a dialable peer, a candidate, an entry naming no locator,
        or a link without a verdict is never due.
    *   A link whose verdict comes back is forgotten, and its next down
        period counts its attempts from zero.
*   **The reflector:** the reflector is a neighbor that reports its address
    answering and whose established link is up. A neighbor whose link is
    down is never chosen, nor is a candidate, nor a node that reports itself
    undialable.
*   **Punching again:** the entry keeps its interface ID, moves to a fresh
    link address aimed at the peer's reflexive address, and sends one link
    request. A failed punch leaves the entry unchanged.
*   **The handler:**
    *   A link's punch from a caller whose standing entry is down, naming
        the interface that entry pairs with, moves the entry to a fresh
        address, keeping its interface, and aims it at the caller's
        reflexive address. The opens leave from the fresh address.
    *   A link's punch from a caller whose standing entry is up, or whose
        down entry pairs with another interface, is refused.
*   **The labs:** the recovery lab passes in the behavior labs' runs.
*   **The benchmarks:** five runs each. In every run of the rebinding
    benchmark, every pair answers again in about the time the follow loop
    takes. The other benchmarks hold.

## Implementation history

*   Landed as proposed: the re-punch loop and the reflector
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)), the
    handler's down entry
    ([punch.go](/pkg/modules/topology/impl/measured/punch.go)), and the
    recovery lab
    ([nat_test.go](/internal/testnetwork/behavior/nat_test.go)). The
    Summary's figures are the benchmarks' five runs each.
