# Treat the neighbor's locator as an observation

This proposal realizes
[ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md):
the neighbor's identity is certified by possession on the SCION-native
channel, and its underlay locator is an observation the network rewrites as
the peer moves. The rendezvous exchange dials from the link's own address
and the acceptor records the observed host and port; the chain-existence
evidence retires in favor of the authenticated link request, which
establishes a link and re-aims its locator; and the external link's socket
turns unconnected, the kernel's filter moving into two software tiers. No
wire message changes — the request already carries the claim and the reply
already echoes the observation
([proposal 0028](/docs/proposals/0028-learn-the-external-address-from-rendezvous.md))
— and no timer, channel, or keepalive enters.

[TOC]

## Summary

The claim rule is one function, `recordedLinkAddr`
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)): the
claimed address when its host is named, else the observed host beside the
claimed port — the observed port never. Five writers apply it — the
acceptor's admission, the selection's two establishments, the provider's
bootstrap and join dials — and the in-band link service, authenticated and
already refusing an unverified channel, records the peer's claimed
`local_addr` all the same
([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)).

The dial that creates the mapping discards it. `RendezvousEcho` binds the
control host on port 0, so a translated joiner's mapping is created by an
ephemeral socket and dies with it, while the entry keeps the port the
claim named. Each external link is then a connected socket aimed at the
recorded address
([udpip.go](/pkg/core/dataplane/udpip.go)): the kernel delivers nothing
from anywhere else, so the peer's true next address is dropped unwitnessed
— the source the receive loop reads is thrown away — and the only symptom
is the BFD silence that times the session down. The socket table keys on
the remote address, every store write retires the serving generation and
rebinds
([dataplane.go](/internal/services/dataplane.go),
[links.go](/pkg/modules/links/links.go)), and the sweep promotes a
candidate on `linkEvidence` — a chain for the ISD-AS existing locally or
answered by the node's core
([node.go](/internal/services/node.go)) — which proves the subject, not
the speaker.

This proposal makes four moves on those facts:

*   The exchange observes. The establishment dial leaves from the entry's
    local address, and the acceptor records the request's observed source,
    host and port both; the claim survives as the dialer's fallback and
    the measurement probe keeps its ephemeral dial.
*   Possession confirms. The authenticated link request establishes a
    candidate and re-aims a live entry, installing the source the link
    observes; the chain-existence evidence and its wiring retire.
*   The socket opens. External links keep exclusive unconnected sockets,
    arrivals are processed on the discriminator's echo, the locator
    becomes live state the serving generation reads at egress, and the
    data plane answers each link's last observed source.
*   The returning node re-reaches. A confirm pass over the entries a node
    holds re-registers its locator on every former neighbor, the far side
    polling nothing.

## Motivation

The ADR argues the failures; the mechanisms are these. A joiner behind
port-remapping translation mints a locator nothing can reach, and the
round trip that minted it succeeds — the failure is silent because the
connected socket's filter keeps the evidence out of the process. A node
that returns at a new address waits out three down windows of retirement
before the network can relearn it, and while an entry sits unproven or
absent, a third party claiming the absent node's ISD-AS is established on
the victim's own chain existing. The floor works around translated nodes;
it does not make them joinable.

### Goals

*   The establishment exchange dials from the entry's local address; the
    acceptor records the observed host and port; the claim remains the
    dialer's fallback for a reply that echoes no source.
*   A link establishes — and a live link's locator refreshes — only by the
    authenticated link request; `linkEvidence`, the contract's `Evidence`
    field, and the sweep's evidence promotion retire.
*   The confirm installs the source the link it rode observes — the
    request's own arrival the latest witness — and a request whose
    observation disagrees moves nothing.
*   External links keep their own unconnected sockets: classification by
    receiving socket is unchanged, arrivals process on the discriminator's
    echo, and bare arrival never moves a locator.
*   A locator change crosses the store without a generational
    replacement; the local address keeps its per-generation binding.
*   The data plane answers each link's last observed underlay source.
*   A returning node's confirm pass re-reaches every entry it holds.

### Non-goals

*   No relay for both-ends-translated peers: where neither side of a
    would-be link holds an address the other can punch at, the host-mesh
    relay remains the instrument (ADR-0021, point 7).
*   No new cadence: the BFD stream that already transmits through its own
    down verdict is the keepalive (ADR-0021, point 6).
*   No trust-continuity change: the bootstrap window's degraded exchanges
    and first enrollment's application-layer proof of possession stand
    (ADR-0021, point 8).
*   No wire change: the request's claim and the reply's echo carry
    everything, and the version tolerance proposal 0028 built remains the
    boundary. A deployment upgrades its nodes together — an acceptor that
    observes records the mapping of whatever socket dialed it, and a
    pre-change joiner dials ephemeral.
*   The file provider's vouched addresses stand as the operator writes
    them; its reconciliation is untouched.

## Proposal

### The exchange dials from the link's own address

Every exchange that records an entry's locator dials from that entry's
local address: `RendezvousEcho`'s bind becomes the link address it already
carries as the claim, in place of the control host's port 0. The socket is
held for the round trip alone and released before the store write lands
and the generation binds — the same probe-and-release the band allocation
performs
([linkports.go](/pkg/modules/topology/impl/measured/linkports.go)).
The selection's measurement probe, which records nothing, keeps its
ephemeral dial.

The acceptor's record inverts: the admission records the request's
observed source, host and port both, for the joiner dialed from the socket
that will serve — the observation names its mapping, whatever the middle
made of it. The dialer's record of its peer keeps `recordedLinkAddr` as it
stands: the reply leaves the acceptor's rendezvous socket, whose
observation names no link, so the claimed link address is the record and
the peer's confirm corrects it. The reply's echo keeps feeding the
external-host learning proposal 0028 built; a reply that echoes no source
changes nothing, the tolerance that crossing a version boundary already
requires.

### Possession confirms

The link request the selection's establishment already sends becomes the
only establishment. Its dial rides the one-hop path of the entry it
confirms — naming the entry's interface, the egress form a reply already
takes, so the link's verdict gates nothing: the confirm is the instrument
that restores the locator a down verdict waits on — and the request's
underlay source, the channel observes, is the peer's link socket and not a
transit's address.

The service installs what the link observes. The handler reads the
request's remote underlay and the link's last observed source; they agree
exactly when the request rode the direct hop, and the agreement licenses
the move: the entry takes the observed source as its locator, the
identity and the peer's interface ID refresh whatever the path, and a
request whose observation disagrees proves the identity without moving
anything. A candidate the confirm lands on establishes; `admit`'s
candidate-stage claim retarget and the service's re-establishment refresh
are the two records the exchange keeps, neither rewriting a live entry's
address unauthenticated.

The evidence retires. `linkEvidence`, the contract's `Evidence` field,
and the sweep's promotion on it leave
([node.go](/internal/services/node.go),
[selection.go](/pkg/modules/topology/impl/measured/selection.go)); a
candidate that no confirm lands on retires at the candidate window, and
the impostor's claim on an absent node's ISD-AS mints an entry nothing
establishes. The rendezvous establishment seeds and names — the plaintext
exchange stays beneath every path and every identity, as ADR-0017
decision 10 holds — but no longer establishes: the state it leaves is the
candidate the confirm waits on.

### The link's socket is unconnected, its locator live

`NewExternalLink` binds the entry's local address and connects nothing:
the connected branch of the socket factory, the `connected` flag, and the
build-time refusal of a duplicate remote leave
([udpip.go](/pkg/core/dataplane/udpip.go)) — the store's write-time rules
stand, and two unconnected sockets may send at one address. The socket
table re-keys on the interface ID, the remote address having stopped
naming the link. The send path's per-packet destination branch becomes
the only path, reading the link's live locator; the BFD session's raw
write follows the same locator, for the prebuilt control packet carries
no destination of its own.

The kernel's filter moves into two tiers. Every arrival pays the software
check the connected socket paid the kernel: the BFD branch's discriminator
echo — return-routability plus the blind-guess barrier — processes
arrivals from any source, and nothing else in the receive path reads the
source except to record it. The record is the re-aim tier's evidence and
the answer tier's address: each link answers its last observed underlay
source — the BFD session's stream and the link's one-hop sends, replies
and the confirm's dial alike, the only one-hop traffic an external link
carries, for the router forwards no one-hop packet but the local AS's own
— while that observation stands apart from the locator, so a peer that
moved keeps reaching the link whose entry still names its former address;
transit carries the locator, the authenticated record alone steering the
traffic that forwards through the node; and only the authenticated confirm
of the preceding section moves the locator the record names.

The locator is live state within the serving generation — a second
mutable edge beside the verdict, read at egress — so the generation loop
diffs the store's signal: the same interface set with changed locators
re-aims each link in place, and only a membership change retires the
serving generation and rebuilds. The local address keeps decision 15's
binding, rebound identically by every generation; the monitor's sessions
follow the store's entry as they already do. A re-aim is therefore one
store write and one field, not a generational replacement — retiring the
plane per locator change would gap the very session stream the design
leans on.

### The returning node's confirm pass

Relocation rides the same confirm from the other end. A node's start and
identity completion run a pass over the entries it holds: each entry gets
the link request over its one-hop path, the dial the establishment
already makes — naming the entry's interface, ungated by the link's
verdict, its answers riding the observation the arrival itself just
recorded — and each answered request leaves a confirm behind it, the far
side polling nothing. Entries the pass cannot yet reach retry on the
selection's cadence until they answer or retire; the exchange's replies
retarget the returning node's own entries on the way, as they already do.
A former neighbor's stale entry retires on the existing down-window rule
until the confirm lands, and the returning node's enrollment is never
re-run.

### Steps

1.  The observed record: the acceptor records the request's source, the
    establishment dial leaves from the entry's local address, and the
    tests of the claim rule invert. The connected socket still stands,
    aimed at the mapping the record now names — this step alone carries
    joiners behind port-remapping translation whose mapping is stable.
2.  The confirm: the one-hop dial, the agreement rule, the installation
    of the observed source, the evidence's retirement, and the
    establishment flip in the link service. Re-aims still ride the
    generational swap.
3.  The unconnected socket: the tiers, the live locator with in-place
    re-aim, the observed-source answer, and the socket table's re-keying.
4.  The confirm pass for held entries.

## Test plan

*   **Unit, the exchange:** the establishment dial leaves from the
    entry's local address and holds it for the round trip alone; the
    acceptor records the observed host and port of a request dialed from
    the link socket; the measurement probe keeps its ephemeral dial; a
    reply that echoes no source changes the dialer's record nothing.
*   **Unit, the confirm:** the service refuses the unverified channel,
    establishes a candidate on the verified one, installs the observed
    source when it matches the link's observation, and refreshes the
    identity without the locator when it does not; the sweep retires a
    candidate no confirm lands on at the candidate window.
*   **Unit, the impostor:** a claim on an absent node's ISD-AS mints a
    candidate that no path establishes — the chain's existence no longer
    promotes.
*   **Unit, the data plane:** an unconnected external link processes a
    discriminator's echo from a source the entry does not name and moves
    no locator; a re-aim changes the send destination — queued and raw —
    without a generational replacement; the last observed source reads
    back through the new answer; two links whose locators coincide both
    build.
*   **Unit, the store:** the write-time rules stand — one live entry per
    neighbor, one serving entry per remote — with an observed locator in
    the entry.
*   **Integration, translation:** a lab places a joiner behind a
    port-remapping translator; it joins, is joined, and its link stays up
    past the mapping's idle timeout.
*   **Integration, relocation:** a node restarts at a new address; its
    former neighbors' entries re-aim on its confirm pass, without
    re-admission and without a generational replacement.
*   **The proofs:** the existing labs pass — a plain join now runs both
    confirms, and the convergence-based tests absorb the added round
    trip.

## Implementation history

*   The observed record, the confirm, the unconnected socket, and the
    confirm pass all landed together, realizing
    [ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md):
    the exchange dials from the entry's link address and the acceptor
    records the observation whole for named claims
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go));
    the link service installs the arrival link's observation under the
    agreement rule, the selection seeds by rendezvous and confirms over
    the peer's control service, the chain-existence evidence is retired,
    and the provider confirms its held entries at start
    ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go),
    [selection.go](/pkg/modules/topology/impl/measured/selection.go),
    [provider.go](/pkg/modules/topology/impl/measured/provider.go));
    the external links bind unconnected, their locators live state the
    serving generation re-aims in place and reads at egress, each link
    records its last observed source through the seam the confirm reads,
    and the socket table keys on the interface
    ([udpip.go](/pkg/core/dataplane/udpip.go),
    [dataplane.go](/internal/services/dataplane.go)).
*   The relocation the confirm pass promises landed after a cycle the first
    landing left: the returning node's one-hop dial resolved its egress
    through the usable set, whose verdict waited on the peer's replies, and
    the peer's replies — BFD and the confirm's own handshake alike —
    followed the recorded locator, the very address the confirm would
    re-aim, so no re-aim could complete against a standing entry. The dial
    now names the entry's interface — the peer authority carrying it beside
    the service destination, the egress form the replies and the core
    route's shortcut already take — so the verdict gates nothing
    ([client.go](/pkg/libs/scionrpc/client.go),
    [provider.go](/pkg/modules/topology/impl/measured/provider.go)); and
    the link's own conversation — its BFD session's stream and its one-hop
    sends — answers the last observed source rather than the recorded
    locator, transit alone carrying the locator
    ([udpip.go](/pkg/core/dataplane/udpip.go)). The translated return lab
    proves the standing entry's re-aim — same interface, fresh mapping, no
    re-admission — beside the fresh-mapping record the retirement path
    keeps ([translate_test.go](/internal/testnetwork/translate_test.go)).
*   The full-fidelity translation lab — the mapping-carried data path held
    up by the BFD stream alone, and the restarted node's fresh mapping
    re-aiming its former neighbor — wanted a translation the packets
    traverse without being addressed to it, which the userspace relay the
    exchange-level lab once rode could not stand in for;
    [proposal 0063](/docs/proposals/0063-give-the-integration-labs-a-userspace-fabric.md)'s
    boundary stands in, and the translation labs prove the record, the
    mapping ride, and the restart's fresh record beside the re-aim above
    ([translate_test.go](/internal/testnetwork/translate_test.go)).
