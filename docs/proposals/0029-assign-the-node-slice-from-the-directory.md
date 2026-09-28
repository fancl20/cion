# Assign the node's slice from the directory

This proposal retires `--slice`: the node's slice of the tailnet range stops
being an operator's placement and becomes the directory's assignment, made
the way the coordination gate already places a host's address. The
publication stops claiming a subnet; the core's store assigns the publisher
the first free /24 of the tailnet range, keyed by the ISD-AS the channel
already authenticates — unique by construction, stable per ISD-AS,
idempotent to repeat, nothing ever freed — and the response carries the
assignment back, so a node learns its slice from the directory the way it
learns every other routing fact. The WireGuard application assembles
without a subnet; the SOCKS application waits for the assignment and claims
the slice's first address as it always has; `--host-port` alone decides
whether a node serves hosts at all. The allocator's overlap refusal retires
— two publishers can no longer construct the operator error it existed to
name — and with it the one network-wide planning task the arguments carried:
disjoint prefixes, chosen per node, coordinated across all of them.

[TOC]

## Summary

The flag's entire reach today is a value baked at assembly and published
once: the [shared registration](/cmd/cion/run.go) parses `--slice` into
`NodeConfig.Slice`, [Validate](/internal/services/config.go) checks its
grammar — an IPv4 prefix inside 100.64.0.0/10 — and its pairing with
`--host-port`, [setupWireguard](/internal/services/wireguard.go) parses it
into the application's subnet, and
[selfEntry](/pkg/apps/wireguard/directory.go) publishes that subnet as the
entry's overlay, keyed by the publisher's ISD-AS in the core's store. Every
consumer beyond the publication reads the value back from the directory: a
mesh device takes its peer's slice as the AllowedIPs of the tunnel
([app.go](/pkg/apps/wireguard/app.go)), the router holds one route per
slice, the coordination gate places a new host in the freest slice
([allocator.go](/pkg/apps/coordination/allocator.go)), and the netmap lists
each node's own address — its slice's first — among the routed /32s
([netmap.go](/pkg/apps/coordination/netmap.go)).

Of all these consumers, exactly two read the local value: the publication
that claims it, and the SOCKS netstack that claims its first address as the
node's serving address. The code's own structure already treats the
directory as the slice's home — the flag's claim becomes the store's record
one publish later, and the only thing standing between them is who writes
the field. This proposal makes three moves on that fact:

*   The store assigns. The core's store — the directory's single writer —
    places each publisher's slice at its first publication: the first free
    /24 of the tailnet range by address order, keyed by the ISD-AS the
    channel's verified chain names, carrying the durability grammar the
    gate's host allocation already carries: unique by construction, stable
    per key, idempotent to repeat, nothing ever freed.
*   The publication asks. The publish request loses its subnet claim and
    the response gains the assigned slice. A node asks again on every boot
    and every cadence, the answer never moves, and nothing of the
    assignment persists node-side — nothing can drift.
*   The applications wait. The WireGuard application stops taking a subnet
    — its devices consume the peers' slices, which arrive by directory —
    and the SOCKS application assembles when the assignment arrives,
    claiming the slice's first address exactly as before. `--host-port`
    alone gates the pair.

## Motivation

Every other address in the tailnet is already allocated by the network. A
host's /32 is placed by the coordination gate at the registration login;
the node's own address is derived from its slice; the client protocol this
network serves was built around a control that assigns every address its
devices hold — the package's own name for the coordination application is
"the network's headscale" ([doc.go](/pkg/apps/coordination/doc.go)).
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
left the node's slice to the operator deliberately — "one slice per node —
the routing anchor the directory already distributes" — and kept it there:
the node's configuration emptied of hosts but kept the subnet slice. It is
the network's last hand-placed address.

The task the flag hands the operator is network-wide planning on every
node's command line: each slice must be disjoint from every other's, so
placing one node's argument means holding the whole allocation in mind. The
failure mode is the overlap the allocator refuses to arbitrate — "the
operator's error, not the joiner's"
([allocator.go](/pkg/apps/coordination/allocator.go)) — surfacing as a
registration failure at a third node's gate, far from either command line
that constructed it. Uniqueness over a shared space is a fact a single
writer owns; the network already has the writer, the authenticated channel
to it, and the distribution of its record. The tailnet range holds 16,384
/24s at 253 hosts each, and the gate already balances hosts by the freest
slice — a pool that wide serves a sequential assignment as well as it
serves a planned one, because the planning bought nothing but the overlaps.

### Goals

*   The store-side assignment: the core's store places a publisher's slice
    at its first publication — the first free /24 of the tailnet range,
    keyed by the authenticated ISD-AS — unique by construction, stable per
    ISD-AS, idempotent to repeat, nothing ever freed.
*   The claim-free publication: the subnet claim retires from the publish
    request, the response answers with the assigned slice, and the listed
    entry carries its assigned slice where every reader already looks.
*   The waiting applications: the WireGuard application assembles without a
    subnet; the SOCKS application assembles when the assignment arrives and
    claims the slice's first address; `--host-port` alone gates the pair.
*   The retirement: `--slice`, `NodeConfig.Slice`, the validator's slice
    grammar and port pairing, and the allocator's overlap refusal leave the
    tree, the applications' validation of the value reduced to a fail-fast
    check on what the core assigned.
*   The record amendment: ADR-0011's allocation decision extends to the
    node's slice.

### Non-goals

*   No slice sizing: one fixed /24 per node, no per-node width requests.
    The gate spreads hosts by the freest slice, so capacity is the range's,
    not a node's, and a wider slice is a knob nothing needs.
*   No reclamation: a departed node's slice stays reserved, the durability
    grammar host addresses already carry — membership removal is the later
    milestone [ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
    defers, and slice reclamation would follow it.
*   No default host port: whether a node serves hosts stays the operator's
    explicit `--host-port` choice; a zero-conf serving default can stand on
    its own proposal.
*   No enrollment coupling: assignment rides the directory publication the
    chain authenticates, not the trust plane's issuance — the slice is a
    routing fact and lands in the routing registry.
*   No routing change: a mesh peer's AllowedIPs stay its entry's slice, the
    netmap's routed addresses stay /32s, no default route is advertised
    anywhere — the consumers read the same field from the same fetch.
*   No node-side persistence of the assignment: the node re-asks at every
    boot and the store answers; a cached copy could only drift from the
    record every other node already reads.
*   No accommodation for [proposal
    0028](/docs/proposals/0028-learn-the-external-address-from-rendezvous.md)
    beyond rebasing: its learned host and this assigned slice are
    neighboring edits to the same publication, composable in either order.

## Proposal

### The assigned entry

The store's publish gains one rule: an entry whose ISD-AS holds no slice
gains the first free /24 of the tailnet range by address order, and an
ISD-AS that already holds one keeps it. The rule inverts today's record
path — the publisher's claimed overlay, whatever it is, is ignored in
favor of the assignment, where today the store records the claim verbatim
and the contract suite proves a re-publish can move a node's slice. Under
assignment a slice never moves: renumbering retires with the claim, and
the only event that renumbers a network is the loss of the core's store,
which already loses every host record with it.

The authenticated ISD-AS is the key, so a publisher cannot take another
node's slice — it cannot take any slice, only receive its own. The
founding core's publication rides its local store through the same rule;
a joiner can hold no chain the core did not issue, so every publisher
reaches the store already named. The allocator's eligibility filter and
overlap refusal retire with the error they existed to report; the
freest-slice choice stands unchanged, now over assigned slices that
cannot overlap.

### The claim-free publication

The wire change is two fields in the [directory
protocol](/proto/wireguard/v1/directory.proto): the claimed entry's
`overlay_subnet` retires — a server reading an old client's claim ignores
it, the tolerance proto3 already gives every unknown field — and the
response, empty today, answers the publication with the assigned slice.
The listed entry keeps carrying its slice: the readers — the mesh
AllowedIPs, the router routes, the gate's placement, the netmap's routed
addresses — are untouched, reading the field where they read it today.

The client surfaces the answer to the application that published, and the
application holds it as the node's subnet. Every re-publication on the
hourly cadence asks again and receives the same answer; a boot asks once
and proceeds. The application keeps one fail-fast check on the assigned
value — a /24 the tailnet range contains — so the core's own bug surfaces
at the seam nearest it rather than deep in the netstack.

### The applications that wait

The WireGuard application's assembly consumes no local subnet: the mesh
socket, the host device, the directory wiring, and the devices the
directory diffs program all read the peers' entries, never the node's
own. Its configuration loses the subnet field; the publish loop — already
waiting for enrollment to produce the chain — waits for the answer too,
and the assignment's arrival is the signal the node's assembly waits on
for the SOCKS application: the netstack claims the slice's first address
and the SOCKS listener binds it, exactly as at today's assembly, one
publication later.

The serving address's availability thus rides the directory channel
exactly as the tunnels' always has — a node whose core is unreachable has
no mesh either.

### The retired surface

`--slice` leaves the shared registration, so both run commands and
`cion ping` shed it together, and `NodeConfig.Slice` and the node's parsed
subnet field go with it. The validator's slice grammar and port pairing
collapse to `--host-port`'s presence — a node that sets it serves hosts,
one that does not runs neither application — and the allocator's overlap
refusal and eligibility filter retire with the error they existed to
report, the freest-slice choice standing unchanged over assigned slices.

### Outcomes

| Address | Placed today by | Placed after by |
| :--- | :--- | :--- |
| A host's /32 | the coordination gate at registration | unchanged |
| A node's slice | the operator's `--slice` | the core's store at first publication |
| A node's own address | derived — the slice's first | unchanged, derived from the assigned slice |

ADR-0011's sixth decision is amended to match: the coordination service
allocates addresses for nodes as it does for hosts — the slice of the
tailnet range is assigned at publication, keyed by the authenticated
ISD-AS — and the operator's residue shrinks from the subnet slice and the
shared port to the shared port alone. The decision's negative consequence
"operator-chosen subnets retire for hosts" extends to the nodes;
[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)'s
note that renumbering a slice moves the service's address stays true with
a narrower trigger: the loss of the core's store, not an operator's
argument.

## Test plan

*   **The assignment:** the store's contract suite covers the rule — the
    first free /24 by address order, uniqueness across publishers,
    stability per ISD-AS across re-publications, and a claimed overlay
    ignored in favor of the assigned one.
*   **The answer:** the publish response carries the assigned slice, the
    core answering its own local publication through the same path, and a
    re-publication answering the same slice.
*   **The waiting applications:** the WireGuard application assembles and
    serves its sockets before any assignment exists; the SOCKS application
    assembles when the assignment arrives, claiming the slice's first
    address; a node that sets no `--host-port` assembles neither.
*   **The retired grammar:** the validator carries no slice grammar and
    pairs no port, the allocator places hosts without an overlap path, and
    the shared registration parses without `--slice` on both run commands
    and ping.
*   **The proofs:** the integration labs place their nodes by publication
    — the harness sets the host port and waits for each node's entry to
    carry its assigned slice — and the coordination, SOCKS, and
    wireguard-only proofs pass over assigned slices.

## Implementation history

*   The assignment rule is [AssignSlice](/pkg/apps/wireguard/directory.go),
    placed over the entries the store holds, and the store applies it at
    [Publish](/pkg/apps/wireguard/impl/bbolt/db.go); the claim-free
    publication and its answered slice are the wire's two fields
    ([directory.proto](/proto/wireguard/v1/directory.proto)), the
    application's waiting surface is
    [Subnet](/pkg/apps/wireguard/directory.go), and the SOCKS assembly
    waiting on it is [socks.go](/internal/services/socks.go); the
    allocator's overlap refusal and eligibility filter left
    [allocator.go](/pkg/apps/coordination/allocator.go), `--slice` the
    shared registration ([run.go](/cmd/cion/run.go)), and the contract
    suite covers the rule
    ([dbtest.go](/pkg/apps/wireguard/impl/dbtest/dbtest.go)).
*   Divergence: [ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
    stands as written — the sixth decision's extension this record's
    Outcomes names lands here, not as an in-place amendment, a landed
    record's body being immutable
    ([docs/README.md](/docs/README.md)); the same holds for
    [ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)'s
    renumbering note.
