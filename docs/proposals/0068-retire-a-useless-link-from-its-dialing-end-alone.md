# Retire a useless link from its dialing end alone

This proposal grounds on the promise
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)
makes that links change only on sustained evidence, and narrows its
decision 6 to one judge per link: the useless retirement passes over every
link whose entry records no rendezvous address — a link its peer dialed —
and a stranded node's revival records the address it dials, so the
entries that record one are exactly the links their end dialed. No wire
message, stored field, run argument, or constant changes.

[TOC]

## Summary

`prune` ([selection.go](/pkg/modules/topology/impl/measured/selection.go))
retires at most one up link per window as useless: an up link whose
useless count reached `DemoteWindows`, while up links exceed the floor.
It reads every established entry alike, so the end that accepted a link
retires it on the same test as the end that dialed it, each against its
own tiers. Below the floor, promotion admits the fastest reachable
candidate with no utility test, and the candidate's end — above its own
floor — finds the link useless three windows later. The dialing end's
verdict then goes down, its side retires on the down verdict, and it
dials the same candidate again.

Nine nodes over a three-region latency matrix, joined outward from the
founder and run at the daemon's own intervals on the fabric, never
settled in an hour of virtual time: 100 establishments and 172
retirements. With the useless retirement confined to the entries that
record a rendezvous address — a one-line guard in `prune` — two runs of
the same replay settled within ten virtual minutes and held their links
for the remaining fifty.

An entry records the peer's rendezvous address exactly where its node
dialed, with one exception. The selection's `recordEntry` and the
provider's seeds record the address they dial; the rendezvous acceptor
and the link service record none. A stranded node's revival re-dials a
retired entry at its recorded rendezvous address or, for an entry the
acceptor minted, at the fixed rendezvous port on its recorded remote's
host (`rendezvousTarget`), and the revived entry records nothing of
that dial.

## Motivation

The labs' two-second windows hide the churn: the same nine nodes settle
after about 155 seconds under them. At production pacing every cycle
re-mints an interface ID, swaps a data plane generation at both ends,
renews a BFD session, and leaves the departed link's segments composable
until they expire. A network that never settles spends that on every
link it has, and the routes over the departing link vanish while the
replacement establishes.

Confining the useless retirement to the dialing end removes the second
judge, and with it the cycle. A hold on repeated promotions treats only
the repeat: a node held off one peer dials its next-fastest, whose end
retires that link too, and such holds settled three replays of six. A
utility test below the floor, or a retirement negotiated with the peer,
needs the peer's judgment — an exchange the design does not have. The
cost is an accepting end that holds links it measures useless, bounded by
its cap and its eviction.

### Goals

*   A link a node dialed stands at its peer's end while it is up, until
    its dialer finds it useless.
*   The nine-node replay settles at production pacing, every node at or
    above its floor and the network connected.
*   No wire message, stored field, run argument, or constant changes.

### Non-goals

*   No change to promotion: the floor's reachability rule, the stranded
    clause, and the priced cases stand.
*   No change to the down-verdict retirement or to the cap's least-harm
    eviction, which keep reading every link.
*   No hold on repeated promotions.

## Proposal

### The dialing end

The entry's rendezvous address marks the end that dialed. The
`Rendezvous` field's doc in [links.go](/pkg/modules/links/links.go)
states it: the address this node's first contact targeted, recorded on
the entries this node dialed and on no other. The revival in
`dialJoins` ([provider.go](/pkg/modules/topology/impl/measured/provider.go))
records the target it dialed as the revived entry's rendezvous address,
so a revival owns the link it brings back. The address it records is the
one the dial reached, and the store's lookups by remote address already
match a rendezvous address, so a later seed of the same address finds
the revived entry as it finds any seeded one.

### The useless retirement

`prune` passes over an up link whose entry records no rendezvous address
in its useless loop. The down-verdict loop before it reads every
established entry, as it does today. The useless count still advances
at both ends, for `evict` reads the same window's test and the count
costs nothing; `evict` is unchanged.

### Packages touched

| Package                              | Change                                                   |
| :----------------------------------- | :------------------------------------------------------- |
| `pkg/modules/topology/impl/measured` | The useless loop's guard; the revival's recorded address |
| `pkg/modules/links`                  | The `Rendezvous` field's doc                             |
| `internal/testnetwork`               | The regions lab of proposal 0067                         |

## Compatibility

Nothing on the wire or in the store changes. An entry persisted before
the change keeps the rendezvous address its end dialed, so a link
established before an upgrade keeps its dialer as its owner. A revival
from before the change left its entry no address, and neither end
retires that link as useless until it is established again, it goes
down, or a cap evicts it. A node running the change beside one that
does not converges no worse than today: the older end still retires
the links it accepted.

## Test plan

*   **The useless retirement:** a dialed up link above the floor whose
    window decides it useless for `DemoteWindows` retires; an accepted
    one under the same measurements stands; an accepted link whose
    verdict stays down still retires; and an accepted useless link is
    still the cap's eviction victim.
*   **The revival:** a stranded node's revival of an entry the acceptor
    minted records the rendezvous target it dialed.
*   **The regions lab** of
    [proposal 0067](/docs/proposals/0067-run-the-fabric-labs-on-virtual-time.md):
    nine nodes over three regions at production pacing, every node
    holding its floor throughout and the link set settling within its
    window bound across repeated runs.

## Implementation history

*   Landed as proposed: the useless loop's guard and `dialed` in
    [selection.go](/pkg/modules/topology/impl/measured/selection.go), the
    revival's recorded address in
    [provider.go](/pkg/modules/topology/impl/measured/provider.go), and the
    field's doc in [links.go](/pkg/modules/links/links.go). The regions lab
    of
    [proposal 0067](/docs/proposals/0067-run-the-fabric-labs-on-virtual-time.md)
    settled in 13 of 17 runs with the change; without it, its link set
    changed 163 times in the hour and never held. Of the four runs that did
    not settle, three froze partitioned — the request for the link across
    the cut rode a connection the child had dialed to the parent it joined
    through before it held a chain, and the parent refused it
    unauthenticated each time — and one kept churning across four nodes, an
    accepting end lifted above its floor retiring a link it had dialed. The
    lab lands skipped until both heal.
