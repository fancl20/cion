# Make the path layer multi-core

This proposal implements the path seam of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md):
the authoritative core takes the core tier's path duties — originating
beacons on its links, propagating the beacons it verifies, terminating
core beacons into core segments, and serving the core's segment-lookup
handler — and the nodes around it stop assuming a single core: down
segments register with every core that originated them, and segment
fetches ask the core the question names. It lands on the second core
[proposal 0037](/docs/proposals/0037-onboard-an-authoritative-core-by-sensitive-trc-update.md)
adds and on the origin-keyed beacon store
[proposal 0034](/docs/proposals/0034-key-the-beacon-store-by-origin-and-bound-the-lookup-cache.md)
landed before it — two origins sharing a link into one child is the
collision that keying exists for, and the ADR names its landing this
proposal's prerequisite. No trust behavior changes: the join and
rotation seams land as their own proposals.

[TOC]

## Summary

The path layer's core behaviors are selected for the founding tier, and
their comments say so. The beaconer's loops branch on one flag: the
core originates and terminates core beacons, everyone else propagates
and registers (`Run`, [beacon.go](/pkg/controlplane/beacon.go));
`Core` "marks the founding core, which originates beacons," and
`registerCoreOnce` records why its own path is dead — "No core beacons
exist while the ISD has a single core; the path is exercised by the
same termination code." The lookup's `IsCore` "selects the core's
handler behavior," and the wiring derives both selections from
`ASTypeCore` alone ([controlplane.go](/internal/services/controlplane.go))
— the tier 0037 derives, `ASTypeAuthoritative`, still selects nothing
in the path layer, exactly as its non-goals record: the `Core` and
`IsCore` selections "keep selecting the founding tier until the path
proposal widens them."

Registration and fetch assume the one core the route resolves to. The
registration loop already groups its terminated segments by origin —
`peers[terminated.FirstIA()]` — and then talks only to the core
`coreRoute` names, warning "No route to the originating core; segment
not registered" for every other origin: a node standing under two cores
registers with one of them, and the queriers the wildcard expansions
send to every core of the destination ISD
([lookup.go](/pkg/controlplane/lookup.go)) find nothing at the other.
The fetch asks the one route every question whatever core the question
names — `fetchCached` sends to `s.CoreRoute()` with the asked core as
the request's source — and the core handler refuses a request whose
source is not itself, so the down-segment question addressed to the
second core, routed to the founder, is refused rather than answered.

What exists of multi-core beaconing is the harness's stand-in. Proposal
0034's lab teaches genesis to name a fellow core and runs the fellow on
the non-core assembly, the lab itself standing in for both cores'
origination loops and delivering each origin's beacon by hand
([origins_test.go](/internal/testnetwork/origins_test.go)) — the shape
0037 keeps in place beside its own join lab. On the real path, no node
but the founder originates anything.

## Motivation

ADR-0015 lands through proposals split along its seams, and the path
seam is where the tier
[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md) promised
becomes visible to data movement. Everything the join built — the
successor TRC, the named core, the newest-TRC reads — is bookkeeping
until a beacon originates from the second core, and everything rotation
keeps fresh expires again unless the path layer carries it. The ADR's
own positive consequence names the arrival: a second beacon origin and
real core segments.

The per-core registration and fetch belong here because their failure
modes are the path layer's, not the trust layer's. A down segment
registered with one core only is invisible exactly where the drafts'
lookup sends queriers — every core of the destination ISD (Section
4.2.1, Table 4) — so the second origin costs availability at the point
of use. The fetch addressed to the second core dies at the founder's
source check, a refusal the issuer routing of 0037 cannot repair, for
it routes enrollment and renewal, not lookups.

The authoritative propagates as well, on the drafts' own sentence for
cores — "Core ASes propagate PCBs over both core and parent-child
links; additionally, they originate new PCBs over these same links"
(Section 2.3.5) — and the chain topology needs it. A node standing only
under the authoritative hears its originated beacons and nothing else;
without the founder's beacons propagated down, such a node holds no
route to the issuer at all and its first enrollment never completes.
Propagation is also where the ADR's named prerequisite bites: the
founder's propagated beacon and the authoritative's originated one
arrive over the same link into that child — two origins on one ingress
— the collision 0034 keyed the beacon store against.

### Goals

*   The core selections widen: the beaconer's and the lookup's
    selections take the authoritative tier beside the founding one; the
    authoritative originates beacons on its links, propagates the
    beacons it verifies to its non-core neighbors, terminates core
    beacons into core segments, and serves the core's segment-lookup
    handler (Section 4.2.3) from its own database.
*   The founder's loops complete symmetrically: its propagation — an
    empty pass while nothing originates toward a lone core — serves the
    authoritative's beacons to the founder's own children, and its core
    termination stores the segments the single-core comment declared
    absent. Core segments stay local, as Section 3.2 directs: each core
    terminates what it receives, and none registers core segments with
    another.
*   Down segments register per origin: the grouping the registration
    loop already builds becomes the send — each origin's segments to
    that core's control service, over the route the node holds to it by
    construction, for the same pass stored the up segment. The
    receiving core's checks are unchanged.
*   Fetches ask the core they name: each wildcard expansion sends its
    question to the core it names — the peer client's dial routing it,
    one hop over a link or over the freshest up segment's reversal —
    and the handler's source check matches on every core the
    expansions land on.
*   No new run arguments, flags, or configuration: the tier 0037
    derives selects everything.

### Non-goals

*   No trust-layer change: enrollment, renewal, pinning, and the issuer
    routing are 0037's; the rotation watch is 0038's; the authoritative
    still issues and signs nothing, and a chain renewal sent to it by
    mistake still answers Unimplemented.
*   No multi-hop core segments: propagation keeps its pruning toward
    cores — beacons never travel toward a core — so core segments form
    only between linked cores; the drafts' trans-core beaconing arrives
    if ever a topology needs it.
*   No core-segment legs in path composition: the provider keeps
    composing up and down segments at their common ancestor; the
    propagated core-link beacons put both cores on one up segment, so
    cross-core paths meet without a core leg, and core segments serve
    the drafts' lookup answers.
*   No policy and no new stores: `BestSet`'s size and freshness
    ordering, the per-interface cap, and the origin keying are
    unchanged; no per-origin preference orders what registers or
    fetches where.
*   No harness migration: the `GenesisCores` crutch and the labs that
    stand on it keep their shape, as 0037 recorded; the path lab stands
    beside them on the real join.

## Proposal

### The core selections take the tier

Both selections in `buildBeaconing` widen from `ASTypeCore` to the core
tiers, and the comments they carry update with them — the `Beaconer`
doc's founding-core sentence, the `Core` field's, `registerCoreOnce`'s
single-core remark, `IsCore`'s. The beaconer's branch re-forms around
what the drafts say cores do: the core tiers originate, propagate, and
terminate core beacons, normal nodes propagate and register as today,
and propagation runs on every tier. Nothing else moves between the
roles: the founder keeps its trust assembly — genesis, issuer,
self-enrollment, the WebPKI identity — and the authoritative keeps
0037's node assembly; only the path loops change sides.

### The authoritative serves the core's handler

`IsCore` widened, `coreLookup` answers from the node's own database:
the core segments its termination stored for core and wildcard
destinations, the down segments registered with it for the ISD's other
destinations, under Section 4.2.3's validation — the source must be
this core. The RPCs are mounted on every node's endpoint already; the
selection decides what the handler serves, and the source check is
what makes the per-core fetch below honest.

### Down segments register per origin

The registration loop's grouping is already per origin; the send
becomes so. Each origin's terminated segments go to that core's control
service — the drafts' own rule: down segments register "with the
Control Services of the core ASes that originated the corresponding
PCBs" (Sections 3.1.3 and 3.3) — the peer named by ISD-AS and service,
and the peer client's dial resolves the route per destination
([peerclient.go](/pkg/controlplane/peerclient.go)): the one-hop path
over the link when the core is a neighbor
([conn.go](/pkg/scion/conn.go)), the freshest up segment's reversal
when it is not — and the reversal exists by construction, for the same
pass stored the up segment the registration terminates. The receiving
side changes nothing: `checkRegistered`'s first-entry check already
names the origin. The single-route guard and its warning leave; a dial
that fails logs per origin and the next pass retries. `CoreRoute`
leaves the beaconer's config — the registration names its peer, and no
route the beaconer resolves stands between.

### Queriers ask the core they name

`fetchCached` sends each question to the core the question names. The
down expansion asks every core of the destination ISD, the core
expansion every reachable core, and each request's peer is that core
with that core as its source — so the handler's check that the source
be this core matches everywhere the expansions land, where today the
request addressed to the second core reaches the founder and is
refused. The dial routes as the registration's does; a core the node
holds no route to fails the dial and logs, the same silence a nil route
returns today. `CoreRoute` leaves the lookup's config, and the cache
key keeps the asked core it already carries.

## Test plan

*   **Unit, the selections:** the wiring derives both selections from
    the tier — an authoritative beside a founder; a beaconer of the
    core tier originates, propagates stored candidates to non-core
    neighbors only, and terminates core beacons received over core
    links; a normal node's loops are unchanged; the lookup of the
    authoritative tier serves the core handler.
*   **Unit, registration per origin:** candidates of two origins in the
    store register each origin's segments at that core's own address,
    the sender asserting the peer; the up segments store first; one
    origin's failed dial leaves the other's registration delivered.
*   **Unit, the fetch:** the down expansion asks each core of the
    destination ISD at its own address and the core expansion each
    reachable core; a request whose source names another core is
    refused by the handler that receives it.
*   **Integration, the path lab:** beside the join lab in
    [testnetwork](/internal/testnetwork), a founder and an
    authoritative core joined per 0037, with a node under each: both
    cores originate, and each core's path database holds a core segment
    of the other; the node under the authoritative holds up segments of
    both origins over its one ingress — the collision 0034 keyed
    against, arrived on the real path — and registers its down segments
    with both cores; a third node's lookups fetch down segments from
    each core and compose paths to either child; a node first started
    under the authoritative alone enrolls and pins the successor, its
    retries riding the alternation of the bootstrap slot to the
    founder's fresher beacon.
*   **Negative:** a segment request whose source names the founder,
    sent to the authoritative, is refused; a registered segment whose
    first entry is not the receiving core is refused; a fetch with no
    route to the asked core logs and answers nothing.

## Implementation history
