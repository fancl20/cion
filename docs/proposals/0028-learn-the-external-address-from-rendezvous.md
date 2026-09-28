# Learn the external address from the rendezvous exchange

This proposal retires `--behind-nat`: the reachability class stops being an
operator's declaration and becomes a fact the network arrives at itself. The
rendezvous reply gains the observed source address of the request — the one
fact address translation cannot hide — so every dial teaches the dialer its
external host; the node directory publishes that host beside the control
address's fixed ports while every socket keeps binding the control host; and
the selection loop replaces the `Private` skip with a scope filter, probing
whatever remains as it always has. Nodes behind a provider's one-to-one
mapping — the cloud deployment, publicly reachable through an address the NIC
never sees — become joinable with no operator input; nodes behind address and
port translation publish a public-looking host no mapping serves and are
never promoted, the same treatment the flag used to declare. NAT traversal
stays out of scope: no hole is punched and no mapping is kept alive.

[TOC]

## Summary

The flag's entire reach today is one bit's walk: `--behind-nat` sets
`NodeConfig.BehindNAT`, which sets the `Private` field of the node's own
directory entry at assembly, which the selection loop reads at exactly one
place — the candidate skip beside the self-skip — to keep the node out of
everyone's probing and everyone's floor. The class it publishes is an
operator's claim about a fact the network measures continuously: whether the
address a node publishes answers a dial.

The claim is wrong in both directions, and the worst direction is silent. A
cloud VM's NIC carries a private address while the provider maps a public one
to it one-to-one; CION derives the published rendezvous and control addresses
from the control host — the bind address — so the node can only publish the
private one and is joinable by no one, flag or no flag, on a machine that is
publicly reachable the moment its mapping is named. The honest operator of a
home node behind port-restricted translation, meanwhile, is asked to know
what the network discovers on its first failed probe.

The observation that resolves both is already in the code and discarded: the
rendezvous acceptor reads each request's mapped source address and replies to
it, but records the address the request claims. This proposal makes three
moves on that fact:

*   The reply echoes the observed source. The dialer keeps the host — the
    port belongs to the now-closed ephemeral dial socket — and records it as
    its learned external host, latest observation winning, persisted beside
    the identity so a restart republishes it.
*   The published entry carries the learned host. The bind host and the
    published host split: everything keeps binding the control host, the
    directory's publication resolves the learned host at each cadence, and
    the founding core — which dials no rendezvous — derives its published
    host from its `--domain`, the name its certificate machinery already
    resolves to itself.
*   The consumer filters by scope and verifies by probe. The selection loop
    skips entries whose published rendezvous address cannot route to it —
    private, shared, or link-local scope — unless the entry shares the
    viewer's scope, the loopback exemption the integration labs run on;
    everything else is probed as today, and promotion still requires the
    answer, which remains the only ground truth.

`--behind-nat`, `NodeConfig.BehindNAT`, the measured provider's `BehindNAT`,
`DirectoryEntry.Private`, and the proto field retire. The rendezvous
establishment gains the one guard the probing path lacked — the reply's
ISD-AS checked against the entry's — closing the mis-answer a colliding
subnet could otherwise mint.

## Motivation

The flag asks for knowledge the exchange already holds. Every rendezvous
dial leaves the node through its mapping and the acceptor answers the mapped
address — the return-routability check the nonce echo exists for. The
acceptor's handler receives the mapped source and writes the reply to it;
only the entry keeps the claim. A STUN server's single function — tell the
node what the network saw of it — is served by every peer a node dials,
which a measured node does from its first bootstrap contact onward.

The classification the flag held is not a fact about the node but a fact
about the address it publishes:

*   A public address that answers is joinable. A provider's one-to-one
    mapping preserves ports, so the learned host with the rendezvous port
    reaches the private bind; the security group, not the node, decides, and
    a closed group degrades to an unanswered probe — the same outcome the
    flag produced, by evidence instead of declaration.
*   A private address is not routable from the internet, whatever sits
    behind it. The viewer can see this from the entry alone; no declaration
    is needed.
*   A public-looking address no mapping serves — port-restricted or
    symmetric translation — is indistinguishable from a closed security
    group until dialed, and the probe already refuses to promote what does
    not answer.

In every case the probe is the decider. What the flag added was a filter on
which addresses get tried, and a filter can be built from the addresses
themselves.

### Goals

*   The reply's observed field: `RendezvousReply` carries the request's
    observed source address; dialers keep its host as the learned external
    host, latest observation winning.
*   The learned host's persistence: recorded beside the identity in the
    state directory, so a restart republishes it — a stable small network
    sends no further rendezvous dials to relearn it.
*   The bind/published split: the directory entry's rendezvous and control
    addresses carry the learned host (the founding core's: its `--domain`'s
    address) with today's fixed ports, while every socket keeps binding the
    control host.
*   The scope filter: the selection loop's candidate skip admits entries
    whose published rendezvous address is globally routable or shares the
    viewer's scope — the loopback pairing the labs run on — and skips the
    rest, replacing the `Private` skip.
*   The retirement: `--behind-nat` and the `Private` field it fed leave the
    run arguments, the node configuration, the measured provider's
    configuration, the directory entry, and the wire.
*   The establishment guard: the rendezvous establishment in the selection
    loop refuses a reply whose ISD-AS is not the entry's.

### Non-goals

*   No NAT traversal: the rendezvous socket punches no hole and holds no
    keep-alive; nodes behind address and port translation join but cannot be
    joined, exactly as [ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
    draws it. The learned address only lets a one-to-one mapping publish
    truthfully.
*   No joiner-side return-path repair: the entry an acceptor records for a
    translated joiner keeps the claimed address; learning the observed source
    of data-plane traffic is traversal work.
*   No advertised-address argument: the learned host and the core's domain
    derivation cover the cases; an explicit override can come when a
    deployment needs one.
*   No probe backoff for never-answered candidates: an unreachable published
    address costs one echo run per window, the same cost as a dead node, and
    the existing promotion gate already contains it.
*   No accommodation for [proposal 0027](/docs/proposals/0027-split-the-run-command-by-the-nodes-role.md)
    beyond its tables losing the flag's row, whichever lands first.

## Proposal

### The observed address in the reply

`RendezvousReply` gains one length-prefixed field: the source address the
acceptor observed the request arrive from — the address it already replies
to. The writer appends it; the reader reads it tolerantly, a reply that
carries no such field being one that does not echo it, so the appended form
crosses a version boundary in both directions. The dialer discards the port
and keeps the host: the mapping's port belongs to the ephemeral socket the
dial opened and closed, while the published rendezvous and control addresses
sit at fixed ports on the host. The host is what translation varies least —
a port-restricted or symmetric NAT rewrites the port per destination, not
the host — so the latest observation suffices and no agreement among
observers is needed.

The exchange's own trust posture covers the field. An off-path spoofer
cannot echo the nonce; an on-path liar or a malicious acceptor can publish a
node a wrong host, and the worst case is an address that does not answer —
unreachable, never promoted. The publisher's identity is already
authenticated by its chain; the host claim is self-asserted and inert until
a probe confirms it.

### The published host

The directory's own publication stops being a value baked at assembly. The
publish loop resolves the entry's host at each cadence: the learned external
host when one is recorded, else the control host — and on the founding core,
the address its `--domain` resolves to, the name its certificate machinery
already stands behind, beside the control host as the fallback. A non-core's
first publication can already carry the learned host: the bootstrap dial in
identity completion precedes assembly, and the join dials and selection
probes re-observe it for as long as the node keeps dialing.

The learned host persists in the state directory beside the identity. The
rendezvous dial is the only carrier, and a node whose neighbors are all
established sends none — its peers are measured by SCMP echo over the
one-hop path, not by rendezvous — so the host must survive a restart to be
republished. Entries refresh on the publication cadence regardless, and the
directory's expiry keeps the fallback honest.

### The scope filter

The candidate skip in the selection loop trades its `Private` test for an
address test performed by the viewer: an entry is probeable when its
published rendezvous address is globally routable, or when it shares the
viewer's scope — a loopback viewer probes loopback entries, which is the
form the integration labs take, every node bound to its own loopback
address on one host. Private scope (RFC 1918 and IPv6 unique-local), the
CGNAT shared range, and link-local scope are not probeable from a global
viewer; an entry that publishes one is skipped, whoever published it. Both
published addresses sit on the same host, so the one test covers the
control address the baseline and establishment use.

Everything the filter admits is probed exactly as today, and the existing
gates stand unchanged: a candidate is promoted only on an answered run, so
an entry whose public-looking address has no mapping behind it — the
port-restricted home node, the closed security group — costs one echo run
per window and never joins a floor.

### The establishment guard

The rendezvous establishment in the selection loop checks the reply's
ISD-AS against the directory entry's before recording the link, refusing
the mismatch. The probe already dials the published address and trusts the
answer; once the published address can be a learned public host, an answer
arriving from a different node — a colliding subnet's real peer, a loopback
collision — must not mint an entry naming one ISD-AS at another's address.
The reply already carries its acceptor's ISD-AS; the check is a comparison.

### Outcomes

| Node's situation | Published host | Peers' probes | Result |
| :--- | :--- | :--- | :--- |
| Public on the NIC | the bind host | answer | joinable, as today |
| Provider one-to-one mapping, open | the learned host | reach the bind through the mapping | joinable — new |
| Provider one-to-one mapping, closed | the learned host | time out | never promoted, as the flag declared |
| Port-restricted or symmetric NAT | the learned host | no mapping serves the bound socket | never promoted, as the flag declared |
| Loopback (the labs) | the bind host | answer, same host | joinable, as today |

ADR-0008's reachability paragraph is amended to match: the class is
inferred — the published address's scope and answer — and nodes behind a
one-to-one mapping are joinable through the host they learn; the nodes that
join but cannot be joined are the translated ones no mapping serves.

## Test plan

*   **The echo:** a rendezvous round trip carries the request's observed
    source in the reply, and a reply without the field reads as absent.
*   **The publication:** an entry's host follows the learned host across
    publication cadences, a restart republishes the persisted host, and the
    core publishes its domain's address.
*   **The filter:** the selection loop skips a private-scope entry for a
    global viewer, probes a loopback entry for a loopback viewer, and never
    promotes a public-looking entry that does not answer.
*   **The guard:** a rendezvous establishment whose reply names another
    ISD-AS than the entry refuses the link.
*   **The proofs:** the integration tests pass unmodified — every lab node
    publishes and probes loopback-to-loopback, the exemption's own case.

## Implementation history

*   The observed field and its tolerant parse live in
    [rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go),
    the learned host's record and persistence and the core's domain
    resolution in [external.go](/pkg/modules/topology/impl/measured/external.go),
    the publication's resolved host in
    [directory.go](/pkg/modules/topology/impl/measured/directory.go),
    and the scope filter and the establishment guard in
    [selection.go](/pkg/modules/topology/impl/measured/selection.go);
    `--behind-nat` retires from the local registration
    ([run_local.go](/cmd/cion/run_local.go)) and `private` from the wire
    ([directory.proto](/proto/node/v1/directory.proto)).
*   Divergence: [ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
    and [proposal 0027](/docs/proposals/0027-split-the-run-command-by-the-nodes-role.md)
    stand as written — a landed record's body is immutable, and the
    narrowing lands in this record alone
    ([docs/README.md](/docs/README.md)).
