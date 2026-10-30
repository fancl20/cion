# Fetch a registered segment's chains from its registrant

This proposal has a core verify a registered down segment with the chains its
registrant serves, fetched over the reverse of the path the registration
arrived on. Today the core reads only its own database and the founder's. The
proposal grounds on
[ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md): once every core
issues chains, no core holds them all. The founder fetches from no one, so it
could verify only the registrations whose chains it issued. The control plane
draft names the source: the receiver of a message obtains the material that
verifies it from the sender (Section 1.6).

[TOC]

## Summary

A core verifies a registered segment as it verifies a received beacon: every
AS entry's signature against the chain the entry references
([beacon.go](/pkg/core/controlplane/beacon.go)). The two differ in where a
missing chain comes from:

*   **A beacon** names its sender, the neighbor it arrived from, and the
    trust provider asks that neighbor over the link.
*   **A registration** names no one, so the provider reads its database,
    then its remote ([network.go](/pkg/core/trust/network.go)). The founder
    has no remote: it holds the chains it issued and the ones it fetched
    while verifying beacons. The authoritative core's remote is the founder,
    over the bootstrap channel.

This works today because the founder issued every chain. Under ADR-0033 a
node renews at any core, and the chain its next registration needs sits with
the core that issued it and with the node itself. The founder would refuse
every registration of a node that renewed elsewhere once the chain the
founder issued expired, at most three days later. The node's down segments
would then age out of the founder's path database, and lookups answered there
would no longer find the node.

## Motivation

### Goals

*   A core verifies a registration whichever core issued the chains it
    references, over a route that exists whenever the registration arrived:
    the reverse of the registration's own path.
*   A core depends on no other core to verify a registration.

### Non-goals

*   Chain issuance at every core: future work.
*   The trust fetches of a node that is not enrolled yet, which reach the
    founder over the bootstrap channel.

## Proposal

### The registration names its registrant

`SegmentsRegistration` hands `HandleRegistration` the registrant's control
service as the server its verification asks
([segmentservice.go](/pkg/core/controlplane/segmentservice.go)). The server
is the request's remote ISD-AS, addressed to its control service, over the
reverse of the path the request arrived on. When the registrant is a
neighbor, the request arrived over a one-hop path, and the server names the
link it arrived on instead.

The verification asks the registrant first and the provider's own source
after, as a beacon's verification asks its sender. The registrant holds every
chain its segment references: its own, and the ones it verified the beacon
with before extending it. The provider keeps what it fetches, so a core asks
for each chain once.

### The channel dials the path a server names

The provider asks a server through the peer client's fetcher, which rides
the one-hop channel. The channel keys its connections by the peer authority,
an encoding of the peer's address that drops the path, and dials one hop to
the peer ([client.go](/pkg/libs/scionrpc/client.go)). Two changes let it
reach a registrant:

*   **`scionrpc.RouteAuthority`** encodes the path beside the peer's
    address. The fetcher names a server whose address carries a path by it.
*   **The channel dials the path an authority names,** and one hop when it
    names none.

`PeerAuthority` stays as it is: its callers resolve a path at dial time.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scionrpc` | `RouteAuthority`; the one-hop channel dials the path an authority names |
| `pkg/core/controlplane` | A registration's verification asks the registrant over the reversed path; the fetcher names a server's path |

## Compatibility

Nothing new on the wire. A registrant answers the trust material requests
every node already serves, and a core asks only for the chains and TRCs it
lacks.

## Test plan

*   **The authority:** an authority naming a path decodes to the same peer
    and path; one naming none decodes as before.
*   **The registration:** a core whose database lacks the registrant's chain
    and an intermediate AS's chain, and which has no remote, the founder's
    shape, verifies the registration with the chains the registrant serves.
    It asks the registrant's control service over the reversed path, or
    over the arrival link for a neighbor, and keeps the chains. A
    registration whose chains the registrant does not serve is refused, and
    nothing is stored.
*   **The channel:** a fetch from a server two hops away rides the server's
    path and returns its chain.
*   **The labs:** the labs pass. Chain issuance at every core, future work,
    proves the route end to end: the founder verifies the registrations of
    a node that renewed at the authoritative core.

## Implementation history
