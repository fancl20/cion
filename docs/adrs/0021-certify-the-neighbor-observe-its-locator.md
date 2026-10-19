# Certify the Neighbor, Observe Its Locator

*   Status: proposed
*   Date: 2026-10-19

[TOC]

## Context and problem statement

A link today binds the neighbor's identity to one underlay address. The
rendezvous exchange records the *claimed* address when the claim names a
host, and otherwise the observed host beside the claimed port — the port
the joiner's socket binds, on the assumption that address translation,
where it stands between the peers, preserves it; the observed port is
never recorded. Each external link is a connected socket aimed at that
recorded address, so the kernel delivers nothing from anywhere else.
And the selection's
evidence that a candidate is its claimed self is a chain for that
ISD-AS existing — not a chain the speaker holds.

Three failures follow, all observed or derivable:

1.  A joiner behind translation that remaps source ports records a
    locator nothing can reach. The exchange's own round trip succeeds —
    it rides the mapping it created — while every later arrival from
    the peer's link socket dies at the connected socket's filter, the
    link never hears its peer, and no path, enrollment, or publication
    ever completes behind it.
2.  A node that returns at a new address waits out the stale entry's
    down-window retirement before the network can relearn it, and —
    worse — while an entry sits unproven or absent, a third party can
    claim the absent node's ISD-AS at a new address and be established
    on the strength of the victim's own chain existing.
3.  ADR-0017 (decision 17) declared translation out of scope: nodes
    behind it join but cannot be joined, their floor met from publicly
    reachable candidates. The floor works around the exclusion; it does
    not lift it, and every instrument the exclusion spares — the claim
    rule, the connected socket, the existence evidence — is shared with
    the relocation failures above.

What exists to build on: the SCION-native channel verifies both peers'
chains against the TRC anchors on every request
(ADR-0020), so a request that arrives names its sender by possession;
the in-band link service already refreshes a returning neighbor's
recorded addresses over that channel without re-admission, though from
the peer's claimed address rather than the channel's observed one; and
every link's BFD session already transmits each interval through its
own down verdict (data plane draft, Section 6.1) — a standing keepalive
stream at a cadence no translation's idle timeout starves. The drafts
themselves configure neighbors out of band (control plane draft,
Section 2.2.5), so the underlay's address semantics are CION's own
seam, as ADR-0017 already holds for the instruments the drafts hand to
configuration.

## Decision drivers

*   **Identity is the ISD-AS:** The neighbor's name is its certified
    identity, already provable on an authenticated channel; nothing
    about the underlay adds to or subtracts from it.
*   **Locators are observations:** An underlay address is a fact about
    a path through the internet at a moment, learned from the arrival
    that proved it, revisable without ceremony.
*   **Possession over existence:** Trusting a claim because a chain
    exists trusts the wrong party; the speaker, not the subject, must
    hold the key.
*   **No regression in source discipline:** Whatever filtering the
    connected socket bought for free, the replacement must buy
    deliberately — the blind spoofer's and the on-path observer's
    positions may not improve.
*   **Spec-native posture unchanged:** BFD, its SCION framing, and the
    one-hop paths it rides stay exactly as the drafts define them; the
    change is beneath and beside the drafts' instruments.
*   **Almost-zero config preserved:** No operator configures mapping
    hints, port forwards, or keepalive cadences to make a node
    reachable behind translation.
*   **Relocation is not re-admission:** A returning node's enrollment
    stands (ADR-0010's gate is not re-run); only its locator renews.

## Considered options

How the recorded locator is derived:

*   **The claim's port, as today:** The exchange records the address
    the claim names — the observed host standing in only where the
    claim binds a wildcard — the observed port never.
*   **The observed mapping, from the receiving socket:** The dial
    leaves from the link's own port, and the reply's observation names
    host and port both.
*   **A relay beneath the underlay:** The host-mesh relay generalized
    to carry link traffic between translated peers.

What establishes and retargets a link:

*   **Existence, as today:** Evidence is a chain for the claimed
    ISD-AS existing somewhere the node can read.
*   **Possession on the native channel:** Establishment and every
    retarget of a live entry require a request whose channel verified
    the requester's chain.

Where the source filter lives:

*   **The kernel, as today:** A connected socket per link delivers
    only from the recorded address.
*   **Software tiers on unconnected per-link sockets:** Every link
    keeps its own socket and port, arrivals are processed on the
    discriminator's echo, and only authenticated confirmation moves the
    recorded address.

The stance on translation:

*   **Out of scope, as ADR-0017 holds:** Translated nodes join but
    cannot be joined.
*   **Endpoint-independent translation in scope:** Observed recording
    alone carries joiners whose mappings are stable per socket.
*   **Full roaming:** Per-flow translation included, the recorded
    address following the authenticated observation.

## Decision outcome

Chosen options: **the observed mapping, recorded from the receiving
socket**, **possession on the native channel**, and **software tiers on
unconnected per-link sockets** — the stance **roaming in scope wherever
one side of a link holds a stable address**, withdrawing ADR-0017
decision 17's exclusion and narrowing decision 15's identically
rebound address to the link's local side. Realized as follows:

1.  **The neighbor's identity and its locator are separate facts.** The
    identity is certified, proven only by the chain on the native
    channel, and survives every change of address. The locator is
    observed, recorded from the arrival or reply that proved it
    reachable, and revisable at any time. No layer treats the two as
    one name.
2.  **First contact still mints; it never retargets.** The rendezvous
    exchange stays a plaintext round trip beneath every path and every
    identity — it completes identities, seeds entries, and measures
    candidates, exactly as ADR-0017 decision 10 holds. Its dial leaves
    from the link's own port, so the reply's observation reports the
    receiving socket's own mapping, and the recorded locator takes the
    observed host and port both; the claim's port survives as the
    fallback for a reply that echoes no source. The exchange never
    rewrites a live entry's address — an unauthenticated claim retains
    no lever over a serving link.
3.  **Confirmation is possession.** A link is established — and a live
    link's locator refreshed — only by a request that arrived over a
    channel verifying the requester's chain against the TRC anchors,
    naming the peer the handshake proved. The request rides the
    one-hop path of the link it confirms, and the locator it installs
    is the source that link observes — its own arrival the latest
    witness — for the channel's observation names the egress of the
    path the request traveled: the peer's link socket exactly when the
    hop is direct, a transit's address on any composed path, so a
    confirm over a composed path proves the identity without moving a
    locator. A joiner behind first contact has no composed path to pay
    the round trip on; its confirm rides the link the exchange seeded,
    which serves ingress while the entry waits unproven, and the far
    side's entry establishes when the confirm lands. The selection's
    chain-existence evidence retires in favor of it. A third party may
    still claim an absent node's ISD-AS at a new address; what it can
    no longer do is make the claim stick.
4.  **Relocation rides the same confirm.** A returning node's
    enrollment stands; its authenticated request re-registers the
    locator on every former neighbor it re-reaches, refreshing the
    recorded address without a new interface. The re-reach is the
    returning node's own dial pass over the entries it holds — the
    loop that already re-dials them on start, each answered dial
    leaving a confirm behind it — for the far side polls nothing. The
    stale entry on the far side retires on the existing down-window
    rule until then, and the returning node's own entries retarget on
    the exchange's reply, as they already do.
5.  **The link's socket is unconnected and per-link.** Each link keeps
    its own socket bound to its own port — classification by receiving
    socket, and therefore by interface and neighbor, is unchanged —
    sends carry the entry's current locator, and arrivals are accepted
    from any source. The connected socket's kernel filter is replaced
    by two tiers: processing on the BFD discriminator's echo, which is
    return-routability plus a blind-guess barrier no weaker than the
    address match it replaces — a spoofer who knows the recorded
    address passes the kernel today — and re-aim, the moving of a live
    entry's locator, only on the authenticated confirmation of point 3.
    Bare arrival never moves a locator. The locator those sends carry
    is live state within the serving generation — a second mutable edge
    beside ADR-0017 decision 13's verdict, read at egress — so a
    re-aim crosses the store without a generational replacement:
    retiring and rebuilding the plane per locator change would gap the
    very session stream point 6 leans on and price each move beyond
    one round trip. The local address keeps ADR-0017 decision 15's
    binding, rebound identically by every generation.
6.  **The keepalive stream is the one BFD already runs.** The
    interval-long transmissions through down verdicts hold each
    direction's mapping open; no new cadence, probe, or keepalive
    enters the design.
7.  **Both ends translated remains out of scope.** Where neither side
    of a would-be link holds an address the other can punch at, the
    relay is the remaining instrument, and it stays a host-mesh one;
    this record does not generalize it to the underlay.
8.  **Trust continuity is untouched.** The WebPKI bootstrap channel,
    the TRC anchors, the degrade-without-pinned-TRC window, and the
    un-enrolled endpoint's ephemeral certificate stand as ADR-0020 and
    ADR-0003 left them; the first enrollment keeps its
    proof-of-possession at the application layer.

### Positive consequences

*   Joiners behind port-remapping translation join and can be joined;
    the measured-selection floor stops standing in for reachability.
*   Relocation converges on one authenticated round trip per former
    neighbor, with no re-admission, no new state, and no generational
    rebuild.
*   The impersonation of an absent node loses its establishment path:
    existence was the impostor's currency, and it is retired.
*   Nothing new runs: no new channels, keepalives, or exchanges — the
    confirm rides the native channel, the refresh rides the existing
    link service, and the mapping warmth rides the existing sessions.

### Negative consequences

*   The kernel's free per-packet source filter is surrendered; every
    link arrival pays a software check, and blind-spoofing resistance
    rests on the discriminator where the address match stood — equal in
    strength to what the connected socket actually bought, but no
    longer the kernel's to enforce.
*   The control plane must read each link's last observed underlay
    source from the data plane — a new seam between the two, with the
    usual cost of crossing it.
*   The recorded locator becomes live state rather than configuration;
    diagnosing where a link points reads observation, not argument.
*   The recorded address stops naming the link: the socket table, the
    duplicate refusal, and the store's by-address lookups key on the
    interface and the neighbor instead, and two neighbors behind one
    shared translation may collide on a single observed address.
*   The both-ends-translated case is named and left unsolved; operators
    behind symmetric translation on both sides of a would-be link still
    need a relay this design does not provide.

## Pros and cons of the options

### The claim's port, as today

*   Good, because the recorded address names the socket the peer
    intends to receive on — stable wherever translation preserves
    ports or stands absent.
*   Bad, because translation that remaps ports is common, and the
    recorded locator then names a port nothing maps to — the exchange
    succeeds while the link it seeds can never hear its peer.
*   Bad, because the failure is silent: the round trip proves a
    mapping the claim then discards.

### The observed mapping, from the receiving socket

*   Good, because the record is the address the exchange itself proved
    answers, taken from the very socket that will receive — no
    assumption about the middle survives to be wrong.
*   Good, because relocation needs nothing further: the observed host
    is simply the new one.
*   Bad, because a per-flow mapping is only valid for the flow that
    created it — observed recording alone carries endpoint-independent
    translation, and the per-flow case waits on the software tiers.

### A relay beneath the underlay

*   Good, because it alone carries both-ends-translated peers.
*   Bad, because it puts a hop on every packet of every link that uses
    it, and a standing service on the relay's operator — a price the
    one-stable-side majority should not pay.
*   Bad, because it duplicates, beneath the underlay, what the
    host-mesh relay already is above it.

### Existence, as today

*   Good, because it needs no round trip — the node's own trust store
    or a core's answer settles it.
*   Bad, because it proves the subject, not the speaker: the chain's
    existence is exactly what an impostor of an enrolled node leans on.

### Possession on the native channel

*   Good, because the channel's verification is already paid for on
    every request — the identity arrives with the message, and
    establishment inherits it for free.
*   Good, because it is the same proof relocation wants: one
    authenticated round trip re-registers a locator.
*   Bad, because it prices confirmation at a round trip the
    un-enrolled cannot pay — the bootstrap window's degraded exchanges
    must keep their existing role in first enrollment.
*   Bad, because the observation rides the path: only a request over
    the direct hop names the peer's link socket, so the confirm's dial
    cannot take a composed path.

### The kernel, as today

*   Good, because a connected socket filters per packet at no cost to
    the forwarding path.
*   Bad, because the filter matches an address, not an identity —
    spoofable by anyone who knows the recorded address — while
    structurally deaf to the peer's true next address, which is the
    whole of the roaming failure.

### Software tiers on unconnected per-link sockets

*   Good, because classification keeps the socket, the interface, and
    the neighbor bound as they already are — only the source policy
    moves, in two explicit grades of trust.
*   Good, because the re-aim tier inherits the native channel's
    verification rather than inventing an authentication of its own.
*   Bad, because every arrival pays the software check, and the
    data plane must expose what it observes for the control plane's
    confirmations to read.
