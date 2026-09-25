# Serve Hosts with a Tailscale Coordination Service

*   Status: draft
*   Date: 2026-09-24

[TOC]

## Context and problem statement

[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md) served
endhosts with standard WireGuard clients and left their membership manual:
every host public key is pasted by hand into its node's configuration, with
an address the operator invents for it — a cost the record itself carried
("Host membership is manual: every host public key is configured on its node
by hand until a later milestone distributes it") and
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md)
deferred. Meanwhile everything node-shaped already flows: a node's identity
keys generate locally, its certificate arrives by enrollment behind a policy
gate, and its WireGuard key and overlay subnet travel by directory. The host
is the last thing in the network whose joining is a configuration edit.

What the ceremony costs beyond the editing: the address is invented per host
with uniqueness enforced only by the operator's attention — validation
refuses a duplicate key but not a duplicate address; the list is one node's
secret, invisible to the rest of the network; and a pasted key is admitted
forever — no moment ever re-decides it, so a lost device is a revocation
nobody can perform.

And the bespoke way out costs more than it looks. Admission cannot ride the
WireGuard handshake itself: the protocol's reply fields are fixed and carry
no address, so a client can never learn what the node allocated — any
homegrown admission means a new protocol beside the client, challenge
machinery, and a helper to run it, while NAT traversal stays deferred
regardless, for it is client-side machinery the network cannot ship. That
trio — joining, configuration delivery, NAT traversal with roaming — is
exactly what a Tailscale client already does, against a control plane
headscale proved implementable, with client libraries that vendor like any
other dependency and compatible client lines beside the vendor's own
(mihomo embeds one).

What exists to build on:
[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
already built the admission shape — a pluggable authorizer deciding on
verified facts, with two postures that translate unchanged; the mesh
directory distributes entries to every node on cadence; the node's
host-facing devices already program peers and /32 routes from a list — only
the list's origin is manual; and the core holds a WebPKI identity — domain
and certificate machinery — a coordination endpoint can ride.

This ADR decides how a host joins, what the host runs, where membership
lives, and who assigns addresses. Egress is none of these: the subject
stays
[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)'s,
though its ground moves under this record — the SOCKS service was drafted
against the plain-WireGuard host boundary replaced here, and must be
re-grounded on the tailnet boundary this record draws.

## Decision drivers

*   **Almost-Zero Config:** Adding a host is a login, not a configuration
    edit. Nothing per-host is written by hand, anywhere, ever.
*   **Third-Party Clients:** The host runs a widely deployed client that
    already speaks the protocol — the vendor's own or a compatible line —
    and no CION software runs on the host, not even a one-shot helper. This
    supersedes ADR-0005's standard WireGuard client as the access client;
    the no-CION-software promise it carried is kept whole.
*   **Verified Facts Only:** ADR-0010's rule at the registration boundary:
    admission decides on what the exchange proves — the keys presented, a
    return-routable source, and any credential the joiner carried — all of
    it handed to the plugin in the clear, nothing else considered.
*   **Mechanism over Policy:** The join is mechanism; who may join is policy
    at a seam, swappable by run argument without touching protocol — and
    the policy's own instruments, the credentials it issues and retires,
    live behind the seam with it, never in the network.
*   **One Seam, Every Boundary:** Admission is one question wherever it is
    asked: the plugin that answers serves node enrollment and host
    registration alike, distinguished only by the context it is handed.
*   **One Gate, Not a List and a Gate:** The decision that admits a host
    and the record that keeps it must not be two artifacts to keep aligned.
*   **Distributed on What Exists:** Membership travels the directory and
    programs devices the nodes already program — no new distribution
    machinery, no per-node host state.
*   **NAT Traversal Arrives or Never:** The deferred milestone is
    client-side machinery; choosing a client that carries it is cheaper than
    building it.
*   **Scope Stays Minimal:** The coordination service is minimal by
    decision — no ACL engine, no naming, no user management, no key expiry,
    no credential minting of its own — and the mesh is untouched.

## Considered options

How a host joins, and what it runs:

*   **Status Quo, Operator-Pasted:** Keep the static per-node peer list.
*   **Authorized Join Protocol:** A bespoke exchange on the node — a host
    presents a public key, answers a challenge, receives its configuration —
    with a one-shot helper to run it.
*   **Tailscale Coordination Service:** A minimal coordination application
    on the core speaks the client protocol; hosts run Tailscale clients and
    log in.

What vouches for a joiner at the gate:

*   **The Source Address:** The CIDR posture, ADR-0010's.
*   **The Operator's Phone:** The Telegram posture, ADR-0010's.
*   **The Plugin's Own Credential:** The plugin issues keys through its
    channel — the phone — and validates them itself; invitations precede
    joiners.
*   **An Identity Provider:** OpenID Connect — Google, or an
    organization's SSO — vouches for the human behind the registration.

Where admission's instruments live:

*   **In the Service:** The coordination service mints and stores keys,
    and an administrative surface manages them — headscale's shape.
*   **In the Plugin:** The policy mints, delivers, validates, and retires
    its own credentials through its channel; the network never sees one
    it did not hand over as context.

Where membership lives:

*   **The Node's Store, Published:** Each node keeps its hosts in its own
    store and publishes the entries to the directory.
*   **The Coordination Registry, Distributed:** The core's coordination
    application holds the registry, and the host entries distribute by the
    directory.

Who assigns the host's address:

*   **The Operator:** Invented per host and validated for uniqueness, as
    today.
*   **The Node, at Join:** Allocated from the node's subnet and recorded
    against the key.
*   **The Coordination Service, at Registration:** Allocated from the owning
    node's subnet slice, keyed by the host's key.

## Decision outcome

Chosen options: the **Tailscale coordination service**, membership as the
**coordination registry distributed by the directory**, addresses
**allocated by the coordination service at registration**, and admission's
instruments **in the plugin** — realized as follows:

1.  **Hosts are Tailscale-protocol clients.** The host runs the vendor's
    client or a compatible line — mihomo's — and joins by logging in against
    the core; the netmap that returns is the client's entire configuration:
    its address, its node's key and endpoint. No CION software runs on the
    host, not even a one-shot helper. ADR-0005's standard-clients promise is
    kept whole and narrowed in mechanism — from standard WireGuard clients
    to standard tailnet clients, both third-party and widely deployed — and
    the annotation lands beside the record's line.
2.  **The coordination service is a minimal core application.** It lives
    beside the WireGuard application on the core, speaks the client protocol
    from vendored packages — the control channel riding the core's WebPKI
    identity, the domain and certificate machinery that already exists — and
    serves beside it the relay fallback a client expects, for the paths a
    public endpoint cannot reach directly. Minimal by decision: no ACL
    engine, for admission is the tailnet's one policy and the packet filter
    admits the tailnet; no naming; no user management; no key expiry. The
    service is this network's headscale, and its smallness is a decision
    this record makes.
3.  **Registration asks one question of one plugin.** The admission seam
    of ADR-0010, generalized: the caller hands the plugin its context —
    named facts in the clear, the boundary that asks, the keys the
    exchange presented, the return-routable source, and any credential
    the joiner carried — and the plugin answers approve, deny, or pending,
    with a note of its own the registry records beside the entry. One
    interface serves every boundary; the same plugin may answer enrollment
    and registration, and the enrollment seam migrates to it, the
    narrowing annotated beside ADR-0010 at landing. The CIDR plugin
    approves by source. The Telegram plugin is the control plane, and the
    control reverses: instead of the network asking a human per joiner,
    the operator issues invitations ahead of joiners — asking the bot for
    a key, handing it to the headless client — and a registration
    presenting a key the plugin minted approves on the plugin's own
    records, while a bare joiner still prompts, fingerprint and source,
    with approve and deny. The coordination service holds no admission
    logic and no credentials: not the minting, not the store, not the
    retirement. The plugin's instruments are its own to keep — the keys
    it has minted and not yet spent persist beside the material the core
    already holds, an invitation surviving a restart, while its transient
    asks stay in memory where ADR-0010 put them. Approve issues the netmap; deny refuses the registration;
    pending leaves it unanswered, and the client's own polling carries the
    wait. The selector is a run argument on the core; unset is open, the
    zero-conf default.
4.  **The netmap holds one peer: the node.** Each host's netmap names
    exactly its node — public key, host-facing endpoint, and allowed IPs
    covering the tailnet and nothing else — so the client's data plane is
    the access leg and CION's mesh is everything beyond: host to node is
    the client's own WireGuard over the internet, node to node the SCION
    mesh, and a host reaches any peer through its node, same-node peers
    hairpinning locally. The mesh is untouched. No default route is
    advertised: the tunnel carries the tailnet alone, internet egress is
    not a property of the join but a service on the overlay, and how that
    service is served is ADR-0012's to decide on this boundary.
5.  **Membership is the coordination registry, distributed by the
    directory.** The registry is the single record — one gate, one
    artifact: the key, the address, the owning node — and, where the
    plugin named its approval, the note. Host entries publish
    to the core directory beside node entries over the authenticated
    channel, and every node programs its host devices from the fetched set
    exactly as it programs mesh devices from node entries — no per-node
    host store, no configuration edit. Admission is durable: nothing lapses,
    nothing renews, and a lost or stolen host stays a member, visible in
    the directory, until a later milestone adds removal.
6.  **The coordination service allocates addresses.** Keyed by the host's
    key: the next free address in the owning node's subnet, the same key
    re-registering to the same address, a new key a new host — unique by
    construction, stable per key, idempotent to repeat. The overlay's host
    space becomes the tailnet range (100.64.0.0/10), one slice per node —
    the routing anchor the directory already distributes — and the node's
    configuration empties of hosts: the subnet slice, the shared port, and
    the egress mark remain; the peer list and exit fields go.

### Positive consequences

*   Adding a host is a login the client already knows how to perform, and
    the netmap is the whole configuration — no key, address, or file is ever
    copied between machines.
*   The operator's channel is the console: prompts, invitations, and
    retirements are conversational; the network's mechanism holds no
    credential and serves no administrative surface — the policy keeps
    both, where it chooses.
*   NAT traversal and roaming arrive with the client: the milestone
    proposal 0006 deferred dissolves rather than lands, and a host roams
    because its client does.
*   No CION software on a host, ever — not even the one-shot helper the
    bespoke path needed: ADR-0005's original promise, kept whole.
*   One record holds admission and membership — the netmap and the
    directory are both views of the registry — and every node's view is the
    directory's, fetched on cadence.
*   Addresses are unique by construction and stable per key; a
    re-registering host changes nothing.
*   The host tunnel carries the tailnet alone: no routing decision hides
    inside the join, and egress stays a service the egress record decides
    rather than a property of membership.
*   One plugin answers every boundary: enrollment and registration ask the
    same question with different context, and a single selection serves
    both.
*   The zero-conf default stands: no argument, open registration, a network
    whose hosts log in and run.

### Negative consequences

*   The client protocol is a standing commitment: the coordination service
    pins a capability range and is verified against the client lines it
    serves — the vendor's and mihomo's. Older-server compatibility is the
    protocol's own design goal, but compatibility is now a maintained
    property of this network, absorbed here rather than upstream.
*   The plugin's channel is the control plane: whoever holds the
    operator's account or the bot's token admits and invites at will —
    total authority, where the enrollment gate alone was per-joiner.
*   The plugin keeps state of its own: the keys it has minted persist
    with it, and a backup of the state directory carries unspent
    invitations — beside material strictly worse to lose, but a surface
    the plugin now owns. And a key is a bearer secret: leaked, it admits
    until the operator retires it in the channel.
*   The coordination endpoint is the most privileged host-facing surface in
    the network: clients trust the netmap, so whoever answers registrations
    dictates host tunnels. It rides the core's WebPKI identity and the
    admission gate, but the core's compromise grows from signing identities
    to shaping the data plane.
*   Raw WireGuard clients can no longer join: the access client is a
    tailnet client or nothing, and a host that cannot run one has no path.
*   The overlay's host space renumbers into the tailnet range;
    operator-chosen subnets retire for hosts, and deployments renumber.
*   The vendored tree grows the client-protocol packages — the wire format,
    the Noise channel, the relay — real weight beside wireguard-go and
    gvisor, and one more upstream to track.
*   Admission stays durable with no removal mechanism: a lost host is a
    member until a later milestone adds its revocation, the directory the
    audit.
*   Transparent internet egress through the tunnel ceases: no default
    route is advertised, so a host reaches the internet only through
    whatever service ADR-0012's re-grounding lands — SOCKS-aware
    applications or a local forwarder until then — and the netstack egress
    and echo relay the exit model built stand unfed.
*   ADR-0012's ground moves: its SOCKS service was drafted against the
    plain-WireGuard host boundary this record replaces, and the record
    must be re-grounded on the tailnet boundary — its overlay-only tunnel
    and destination-addressed service surviving nearly intact, but until
    it is, its text describes the old host.
*   A registration completes at the directory's cadence — the node programs
    a joined host when its next fetch lands — a pacing question the
    implementing proposal owns.

## Pros and cons of the options

### Status quo, operator-pasted

*   Good, because it is built, and validation already refuses what the
    operator gets wrong.
*   Good, because nothing listens for joiners — no unauthenticated
    surface, no protocol to track.
*   Bad, because adding a host is an edit on a node, addresses are
    invented, and the list is one node's secret kept forever.

### Authorized join protocol

*   Good, because it keeps the boundary free of external protocols: a small
    bespoke exchange beside the client, nothing upstream to track.
*   Good, because raw WireGuard clients stay — every client an operating
    system already ships.
*   Bad, because the join must be invented whole: the handshake cannot
    carry the reply, so a new protocol, challenge machinery, and a helper
    land for this one purpose.
*   Bad, because NAT traversal stays deferred — it is client-side
    machinery, and the client that carries it is the one this option
    declines to run.

### Tailscale coordination service

*   Good, because joining, configuration delivery, NAT traversal, and
    roaming arrive with the client — the deferred and the bespoke problems
    become none of CION's.
*   Good, because the control plane is proven implementable — headscale
    demonstrates it, and the client libraries vendor like any other
    dependency — while the client base is bounded and older-server
    compatible by the protocol's own design.
*   Bad, because it costs the standing protocol commitment, the vendor
    packages in the tree, and the single most privileged host-facing
    endpoint.
*   Bad, because raw WireGuard access ends and the host space renumbers
    into the tailnet range.

### The source address

*   Good, because it is ADR-0010's standing posture, instant and
    stateless — a prefix list, nothing more.
*   Bad, because addressing vouches for the machine, never for the
    person, and a prefix shared with strangers admits the strangers.

### The operator's phone

*   Good, because a human decides per machine with the fingerprint in
    hand — ADR-0010's posture, translated unchanged.
*   Bad, because every join and every question is the operator's
    attention, and a fleet outgrows the phone.

### An identity provider

*   Good, because the vouch is a human identity the operator already
    administers, and the join is a login the user already knows.
*   Bad, because the service would carry the flow — a callback endpoint,
    a client registration, token verification — admission machinery
    re-entering the network through a side door.
*   Bad, because it is unnecessary to decide: a provider-vouching plugin
    is expressible behind the seam later, without the service ever
    learning what an identity provider is.

### The plugin's own credential

*   Good, because invitations precede joiners: the operator hands keys out
    ahead, browserless clients — the mihomo line — join unattended, and
    the mint, the store, and the retirement all live with the policy.
*   Bad, because a key is a bearer secret — leaked, it admits until
    retired — and the minted set is state to persist, back up, and
    protect, where ADR-0010's records were only a window to forget.

### In the service

*   Good, because it is headscale's proven shape, with an administrative
    interface the operator already knows.
*   Bad, because the coordination service re-grows what this record strips
    from it: a credential store, an admin surface, a second thing to
    secure.

### In the plugin

*   Good, because policy and its instruments stay together, the network
    holds no credentials, and the operator's channel is the only console.
*   Bad, because the channel becomes the control plane — its compromise
    is admission — and its instruments are state to keep, persist, and
    protect rather than a window to forget.

### The node's store, published to the directory

*   Good, because membership stays node-sovereign — ADR-0009's ownership
    rule absolute — while the directory gains the visibility.
*   Bad, because the netmap must be built where registration lands — the
    core — so the gate and the record sit apart: two artifacts to keep
    aligned, the exact shape this record refuses.

### The coordination registry, distributed by the directory

*   Good, because one artifact holds admission and membership — the netmap
    and the directory both derive from it — and nodes keep no host state of
    their own.
*   Good, because the directory's existing fetch-and-program shape serves
    host entries exactly as it serves node entries.
*   Bad, because the registry centralizes: the core's availability gates
    new joins network-wide — standing tunnels survive — and per-node
    membership is no longer the node's to own.

### Operator-assigned addresses

*   Good, because an operator can number meaningfully, and meaning is
    sometimes worth the attention.
*   Bad, because uniqueness is the operator's attention, charged per host
    forever, and no registration can promise an address nobody invented
    yet.

### Node-allocated at join

*   Good, because keyed allocation is idempotent by construction: unique
    without vigilance, stable without record-keeping discipline.
*   Bad, because it belongs to the option that invents a join protocol —
    the registry allocates as well, without the protocol.

### Coordination-allocated at registration

*   Good, because keyed allocation at the single gate is unique by
    construction and stable per key, and the netmap can promise the address
    it just issued.
*   Bad, because an address stops being something chosen and becomes
    something issued — a host is a key, not a number with a story — and the
    host space is the tailnet range's, not the operator's.
