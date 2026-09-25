# Implement the Tailscale coordination service

This proposal implements
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md):
a minimal coordination application on the core speaks the tailnet client
protocol — the control channel riding the WebPKI identity the core already
holds — hosts join by logging in with a standard tailnet client, and
membership becomes the coordination registry the directory distributes as
host entries beside node entries. Admission generalizes to the one seam of
[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md):
the same plugin answers node enrollment and host registration, distinguished
only by the context it is handed, and the Telegram method grows the
invitations that let headless clients join unattended. The node's host
devices program themselves from the fetched set; the peer list, the exits,
and the per-exit devices retire; the overlay's host space renumbers into
the tailnet range; and
[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)
keeps its subject — egress as a service on the overlay — against a host
boundary this landing replaces, re-grounded rather than re-decided.

[TOC]

## Summary

What exists is everything but the join. The WireGuard application of
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md)
serves hosts from an operator's hand-edited list — `HostPeer` keys and
invented addresses, one exit each — with validation refusing a duplicate
key but not a duplicate address; the mesh directory publishes and fetches
entries on a cadence every node already runs; the admission seam of
proposal
[0014](/docs/proposals/0014-pluggable-enrollment-authorizer.md) asks one
plugin at first issuance with verified facts; and the core holds a WebPKI
identity — certmagic's domain machinery behind `--domain`, ACME by default
with certificate files as the offline fallback — a coordination endpoint
can ride.

This proposal builds the missing piece and rewires the list's origin: a
`pkg/apps/coordination` application on the core serves the tailnet client
protocol from vendored packages — the noise channel inside WebPKI HTTPS,
registration, the netmap, and the relay fallback beside them — and a host
is a login, not a configuration edit. Registration asks the generalized
seam; approve allocates the next free address in the owning node's slice
of the tailnet range, keyed by the host's key, and records one registry
entry: the key, the address, the owning node, and the approving plugin's
note. The registry is distributed, not duplicated: host entries land in
the directory store beside node entries, ride the same authenticated
`List` to every node, and each node programs its single host device from
the entries it owns — exactly as it programs mesh devices from node
entries. The netmap carries the tailnet and nothing else — no default
route is advertised, internet egress stays a service on the overlay, and
the question of how it is served remains ADR-0012's. The peer list, the
`exits` and `exit` configuration fields, and the per-exit host devices are
deleted; the subnet becomes a slice of 100.64.0.0/10; deployments
renumber.

## Motivation

ADR-0011 decided the shape; the tree is ready for it in a way ADR-0005's
record was not. The ceremony the old record carried as an accepted
consequence — "every host public key is configured on its node by hand
until a later milestone distributes it" — is now the last manual
membership act in a network where nodes generate keys locally, enroll
behind a policy gate, and learn each other from a directory. The costs are
concrete in the code: the address is invented per host with uniqueness the
operator's attention (`validatePeers` checks subnet containment, offered
exits, and duplicate keys — never duplicate addresses), the list is one
node's secret, and a pasted key is admitted forever with no moment that
re-decides it.

Everything the coordination service needs already stands:

*   The seam. `EnrollmentAuthorizer` sits at first issuance with
    `EnrollmentFacts` — the claimed ISD-AS, the possessed subject key, the
    return-routable source — and verdicts of allow, deny, and pending,
    with two implementations in `pkg/enrollauth` chosen by `--enroll-auth`.
    Registration is the same question with different facts; ADR-0011
    generalizes the seam rather than adding a second gate beside it.
*   The distribution. The core's application serves the directory from its
    own store over an authenticated channel; every node re-fetches on the
    `RefreshInterval` cadence and diffs the result against its devices.
    Host entries are one more kind of entry in the same flow.
*   The identity. The core's endpoint already presents a WebPKI
    certificate for its domain (`webpki.ManageTLSCert`, the TLS-ALPN
    challenge answered on port 443). The coordination channel is an
    internet-facing HTTPS server presenting the same certificate — the
    domain and certificate machinery that already exists, consumed where
    the SCION control endpoint cannot be: hosts are plain internet
    clients.
*   The data plane. The node's host-facing devices program peers and /32
    routes from a list behind one shared UDP port; only the list's origin
    is manual. The host's client brings NAT traversal and roaming of its
    own — the milestone proposal 0006 deferred dissolving rather than
    landing.

ADR-0012's ground moves, not its subject. Its SOCKS service was drafted
against the plain-WireGuard host boundary this landing replaces; over the
tailnet the service survives — a host reaches any node's slice through
its node, so an egress node's overlay address is a destination a
SOCKS-aware application can name — and the overlay-only tunnel that
record decided is the tunnel this landing already carries. What the
record needs is re-grounding, not re-deciding: the mechanism text
restated for tailnet clients, the egress mark's advertisement, and the
endhost's per-flow choice by destination. This landing annotates the
moved ground; the re-grounding is that record's own follow-up.

### Goals

*   A coordination application, `pkg/apps/coordination`, on the core
    alone, speaking the tailnet client protocol from vendored packages
    (`tailscale.com` joins the module, vendored like the rest): the noise
    channel over WebPKI HTTPS on the core's domain, registration, the
    netmap, and the DERP relay a client expects — minimal by ADR-0011's
    decision: no ACL engine, no naming, no user management, no key
    expiry, no credential minting.
*   The seam generalizes: one admission interface serving enrollment and
    registration, the boundary named in the facts, the plugin's note in
    the answer. The trust service's call site stands; the enrollment
    implementations migrate; `--enroll-auth` remains the one selector,
    unset open.
*   The Telegram method grows invitations: the operator asks the bot for
    a key, hands it to the headless client, and a registration presenting
    a minted, unspent key approves on the plugin's own records — the keys
    persisting in the core's state directory, an invitation surviving a
    restart, while transient asks stay in memory where ADR-0010 put them.
*   The registry is one artifact: the host's key, its address, the owning
    node, and the approving note, recorded in the directory store beside
    node entries and served by the same authenticated `List` every node
    already fetches.
*   Addresses issue, they are not invented: allocated by the coordination
    service at registration, keyed by the host's key, the next free
    address in the owning node's slice of 100.64.0.0/10 — unique by
    construction, stable per key, idempotent to repeat.
*   The node programs itself: one host device behind the shared port,
    peers from the host entries it owns, reprogrammed as fetches land; the
    node entry gains the host-facing endpoint the netmap names; and no
    default exists anywhere — the tunnel carries the tailnet alone, and
    the egress machinery stands as it is, unfed until the egress record's
    service lights it.
*   The relay fallback: the core serves DERP beside the coordination
    endpoint, and the node holds a DERP presence bridged into its shared
    host port, so a host on a network where UDP to the node cannot pass
    still reaches its node.
*   The records: ADR-0005 annotated with the narrowed access client;
    ADR-0010 annotated with the generalized seam; ADR-0012 annotated with
    the moved ground, its re-grounding its own follow-up; ADR-0011
    accepted at landing; the design documents' endhost sections rewritten
    for tailnet clients.

### Non-goals

*   No ACL engine, naming, user management, key expiry, or credential
    minting in the coordination service — the packet filter is a single
    rule admitting the member's traffic, admission is the tailnet's one
    policy, and the policy's instruments live behind the seam with it.
*   No host removal or revocation: admission is durable, a lost or stolen
    host stays a member until a later milestone adds its revocation, and
    the directory is the audit.
*   No IPv6 overlay addressing, no DNS configuration in the netmap, and
    no STUN: the netmap's peer carries no disco key — the node is a
    wireguard-only peer with a static endpoint, and NAT traversal is the
    client's outbound-initiated session, not a discovery protocol.
*   No change to the mesh: the SCION transport, the mesh devices' slice
    routing, the trust fabric's artifacts, and the data plane stand as
    they are.
*   No per-node host state and no push channel: the directory's fetch
    cadence bounds when a joined host's node programs it, and the join's
    tail latency is owned here as a consequence, not papered over.
*   No egress service and no default route: the netmap carries the tailnet
    only, internet reachability through the tunnel is not a property of
    the join, and how egress is served on the tailnet — SOCKS by
    destination, or a default route after all — is the re-grounded
    ADR-0012's to decide.
*   No file indirection for the bot token — ADR-0010's accepted
    consequence stands — and no interactive identity-provider flow, the
    option ADR-0011 declined as expressible behind the seam later.
*   No renaming of `--enroll-auth` or `pkg/enrollauth`: the argument a
    deployment already carries now loads the one authorizer both
    boundaries ask.

## Proposal

### The coordination application on the core

`pkg/apps/coordination` is the network's headscale, minimal by decision.
It runs beside the WireGuard application on the core alone and serves
three things on the core's domain:

*   **The control channel.** An internet-facing HTTPS server on port 443
    presenting the WebPKI certificate certmagic manages — the same
    `GetCertificate` machinery the endpoint's TLS rides, now answering
    the TLS-ALPN challenge beside the noise endpoints so the dedicated
    challenge listener retires on a coordination-serving core. Inside the
    TLS session the client speaks the protocol's noise handshake — the
    server's noise key generated on first start and persisted in the
    application's own state, the `LoadOrCreateKey` pattern — and then
    registration and netmap requests over the established channel.
*   **Registration.** A joiner presents its keys — the machine key the
    noise channel authenticated and the node key the data plane will
    use — and, when it carries one, a credential. The service asks the
    seam (next section); approve allocates and records; deny refuses;
    pending leaves the request unanswered and the client's own polling
    carries the wait, the registration retry loop the protocol's clients
    already run.
*   **The relay.** A DERP server on the same HTTPS identity, named in
    every netmap's DERP map as the one region, for the paths a public
    endpoint cannot reach directly.

The service pins a capability range — one advertised capability version,
verified against the client lines it serves, the vendor's and mihomo's —
and answers each map poll with the full netmap. No delta compression, no
peer change machinery: the tailnet holds one peer per host, CION is
non-scalable by design, and a full map is the smallest correct answer.

### Registration asks the one seam

ADR-0010's seam generalizes to ADR-0011's, in `pkg/controlplane` where it
lives today. The facts become the boundary-neutral set the ADR names —
all of it in the clear, handed to the plugin, nothing else considered:

*   `Boundary`, the boundary asking: enrollment or registration.
*   `Keys`, fingerprints of the keys the exchange presented — the CSR's
    subject key at enrollment; the machine and node keys at registration.
*   `Source`, the return-routable source: the SCION underlay address at
    enrollment, the internet address the completed TLS connection names
    at registration — bound by the handshake in both cases, the joiner's
    own claim otherwise.
*   `Credential`, what the joiner carried: the registration's auth key,
    empty at an enrollment exchange that carries none and at a bare
    registration alike.
*   `Claim`, enrollment's ISD-AS; zero at registration.

The answer grows the note: `Admission`, a verdict of deny, allow, or
pending — deny still the zero value — beside a string of the plugin's
own words the registry records with the entry. The one-method interface
and the trust service's call site stand where proposal 0014 put them —
asked exactly at first issuance, never on a renewal — with enrollment now
naming its boundary; `pkg/enrollauth`'s implementations migrate to the
generalized facts, and `--enroll-auth` remains the single selector, unset
open, refused without `--core`, the argument loading the authorizer that
both the trust service and the coordination application ask.

### The two postures at registration

The CIDR authorizer is unchanged in behavior and wider in scope: a
registration whose source falls in a listed prefix approves, a miss or a
missing address denies, and the posture that admitted joiner nodes by
addressing admits joiner hosts by addressing — the same prefix list, now
answering both boundaries.

The Telegram authorizer keeps ADR-0010's prompt and gains ADR-0011's
invitation. A bare registration still prompts the configured chat — the
presented fingerprints, the source, approve and deny buttons — keyed by
key, one prompt per identity, decisions in memory, a restart re-asking
what it never answered. The invitation reverses the flow: the operator
asks the bot for a key in the configured chat, the bot mints a one-time
credential and replies with it, and the operator hands it to the
headless client — the mihomo line — whose registration presents it. A
registration presenting a key the plugin minted and has not spent
approves on the plugin's own records and spends it; a spent or unknown
key is a bare joiner's, prompted as ever — a stale invitation fails
toward the human, not closed. The minted set is the plugin's own
instrument: unspent keys persist in a file under the core's state
directory, an invitation surviving a restart, and retirement is
conversational — the bot retires a key on request, the answer it gives
the operator the same audit the registry's notes are. Enrollment
prompts exactly as it does today; nodes carry no credential to present.

### The registry is the directory

One gate, one artifact. The registry is not a second store beside the
directory — the host entries are the registry, recorded in the core's
directory store beside node entries and distributed by the `List` every
node already fetches on cadence. The store's contract gains host entries
keyed by the host's public key — the address, the owning node, the
plugin's note — with the bbolt implementation and the shared contract
tests (`impl/dbtest`) growing the kind beside node entries. The
`ListResponse` carries both; the authenticated channel stands.

The node entry gains what the netmap must name: the host-facing endpoint,
the underlay address and shared port the host's client dials. The mesh
needs it not; the netmap needs it. The egress mark's advertisement stays
unwired here — it is the egress record's instrument, and publishing it
before that record decides the service would presume its shape.

The coordination service reads node entries and writes host entries in
the same store it sits beside: slices, keys, and endpoints for the
netmap; the owning node's slice for allocation. The registry is the
single record, and the netmap and the directory are both its views.

### Addresses issue at registration

The overlay's host space is the tailnet range, 100.64.0.0/10, and each
node's configuration names its slice within it — the subnet field kept,
its grammar narrowed by validation from any IPv4 prefix to one the range
contains. The slice's first address is the node's own, the netstack's
claim on an egress node, and allocation starts after it.

Allocation is keyed by the host's key: the next free address in the
owning node's slice, the same key re-registering to the same address, a
new key a new host — unique by construction, stable per key, idempotent
to repeat, nothing ever freed. The owning node is chosen at registration
— the node whose slice holds the most free addresses, ties to the lowest
ISD-AS — and recorded, and the record never moves: a re-registering host
changes nothing. Two live node entries claiming overlapping slices are an
operator error the allocator refuses to arbitrate: registrations into
either fail with the pair logged, the error surfacing at the gate it
would corrupt. A full slice refuses its node new hosts the same way.

### The netmap holds one peer

Each host's netmap names exactly its node: the node's WireGuard public
key — the same key the directory entry carries and the host device holds
— the host-facing endpoint from the entry, and allowed IPs covering the
tailnet and nothing else: 100.64.0.0/10, no default route advertised. A
client whose tunnel carries no default acquires none in its routing
table, so internet-destined packets never enter the tunnel — the drop
rule the egress record drafted for its overlay-only tunnel holds
vacuously under a client that cannot be told to send them. The peer
carries no disco key: the node is a wireguard-only peer with a static
endpoint, the model the client lines already serve for third-party
exits, and the data plane is the client's own WireGuard over the
internet — outbound-initiated, NAT traversal and roaming the client's.
The packet filter is a single rule admitting the member's traffic:
membership is the tailnet's one policy, and no engine stands behind the
rule to configure. The host's own address is the entry the registry
allocated.

### The node programs itself from the fetched set

The per-exit host devices, the `exits` and `exit` fields, the
`HostPeer.Exit` distinction, and the mesh devices' `0.0.0.0/0` exit
routes retire: there is one host device, behind the shared port the
configuration names, carrying the node's key pair as every host device
does today. On each fetched directory the application diffs the host
entries it owns against the device's peers — new keys gain their /32,
departed keys lose theirs (a later milestone's removal arriving as this
same diff), the diff reprogramming the device and rebuilding the router
table, the same diff shape `applyDirectory` gives mesh devices.

The router's table simplifies with its policy gone: each owned host's
/32 to the host device, each node entry's slice to its mesh device —
longest prefix first — and no default anywhere: the exits map and the
per-device defaults retire with the fields that fed them, a destination
no slice claims counts unroutable, and the netstack egress and the echo
relay the exit model built stand as they are, unfed — the egress
record's service the thing that lights them. The mesh is untouched.

A join completes at the directory's cadence: the client holds its netmap
before any node knows the key, its first handshakes are dropped by a
device that has not fetched the peer yet, and the WireGuard retry
completes the join within one `RefreshInterval` of the registration —
the login's tail latency, stated rather than papered over, the pacing
knob (`NodePacing.Directory`) already in the configuration.

### The relay fallback

The core's DERP server is one more path on the coordination endpoint's
HTTPS identity, and the node holds a presence on it: a DERP client keyed
by the node's own WireGuard public key — the key the netmap's peer
already names — whose received datagrams feed the shared host socket and
whose sends carry the replies. A DERP-sourced datagram reaches the host
device with a synthetic endpoint naming the sender's key, and WireGuard's
own roaming carries the leg switch: the peer's endpoint is whichever
leg's authenticated packet arrived last, UDP or relay, no discovery
protocol beside the transport. A host on a UDP-blocked network reaches
its node through the relay; a host that can dial directly never touches
it. The bridge is the application's only new data-carrying code, and it
is bounded: one connection, one feed, one send path.

### Configuration, renumbering, and the records

The application's configuration file empties of hosts: `subnet` (now a
slice of the tailnet range), `listenPort`, and `egress` remain; `peers`
and `exits` go, with `ConfigWireguardPeer` and the peer validation they
carried. `RejectUnknownMembers` does the retirement's bookkeeping — a
file still naming a deleted field stops the boot, so the upgrade is
coordinated: deployments renumber into 100.64.0.0/10, replace pasted
keys with logins, and drop the per-key exit assignments in the same
step, the operator's sovereignty moving from the node's file to the
plugin's channel. The run arguments gain nothing; `--wireguard-config`
names the same file, and the coordination application starts beside the
WireGuard application on the core — the only node holding the directory
store, whose shape already implies the service.

The records follow the code: ADR-0005's standard-clients line is
annotated with the narrowing — standard tailnet clients, both
third-party and widely deployed, the no-CION-software promise kept
whole; ADR-0010 is annotated with the generalization — its seam is
ADR-0011's admission seam, one interface serving every boundary;
ADR-0012 is annotated with the moved ground — its host boundary
replaced, its overlay-only tunnel and destination-addressed service
surviving, the re-grounding that record's own follow-up; ADR-0011
is marked accepted, its implementing proposal landed; and the design
documents' gateway and endhost sections are rewritten — hosts as
tailnet clients of their node, the coordination application beside the
WireGuard application among the core's applications and policy.

## Test plan

*   **Unit, the seam:** the generalized facts carry the boundary, the
    presented keys, the source, the credential, and the claim; the note
    rides the verdict; deny remains the zero value; and every enrollment
    episode of the trust suite answers as it did under the narrowed
    facts — the migration is a renaming, not a behavior change.
*   **Unit, the postures:** the CIDR authorizer approves and denies at
    both boundaries by source, failing closed on a missing address. The
    Telegram authorizer against the Bot API double: a bare registration
    prompts and pends, retries do not re-prompt, approve and deny decide
    for the window, another chat's press is ignored; a minted key
    approves and spends, a spent key prompts as a bare joiner's, an
    unspent key survives a restart and is answerable after it, a retired
    key prompts, and only the configured chat can mint or retire.
*   **Unit, allocation:** the sequence starts after the slice's first
    address and takes the next free; the same key re-registers to the
    same address; a new key takes the next; a full slice refuses; a
    slice another live entry overlaps refuses with the pair logged;
    placement takes the freest slice and breaks ties to the lowest
    ISD-AS.
*   **Unit, the registry and netmap:** the store's contract tests grow
    host entries beside node entries — round-trip, keyed by public key,
    listed together; the netmap builder names the owning node from its
    entry — key, host endpoint, allowed IPs covering the tailnet and
    nothing else — no disco key, a single packet filter rule, and the
    DERP map naming the core's region.
*   **Unit, the node side:** the directory diff programs the one host
    device — a new owned key gains its /32, a departed key loses it, a
    foreign-owned key changes nothing — and the router rebuilds; the
    table carries hosts and slices only, a destination no slice claims
    counts unroutable, and the mesh devices gain no default route. The
    relay bridge:
    a DERP-sourced datagram reaches the device with the sender's key as
    its endpoint, and a reply to a DERP endpoint leaves over the relay
    while a UDP-sourced peer keeps the UDP leg — roaming by last
    arrival. Configuration: a slice outside the tailnet range, and a
    file still naming `peers` or `exits`, fail the load.
*   **Integration:** the vendored client engine is the host double — a
    real tailnet client in-process against the coordination service on
    the two-node topology harness, the way real wireguard-go clients
    served as the hosts of proposal 0006's proofs. A host registers
    through the open default, receives its netmap, completes its
    handshake within one fetch cadence, and exchanges traffic through
    the mesh to the far node's host — the tunnel carrying the tailnet
    only, the egress machinery left to its own suites. The same lab with
    the Telegram double: a bare host pends through prompts until the
    operator approves, an invited host joins unattended, a core restart
    mid-join re-prompts while an invitation already minted still
    answers. A CIDR-gated lab: a host outside the prefix never
    registers. The relay: a client with UDP to the node disabled joins
    and exchanges traffic through the core's DERP. The compatibility
    pin: the served capability range verified against the vendored
    client engine's current line, and the mihomo line exercised per its
    documented tailnet endpoint.
*   **Negative:** a denied registration records nothing and no netmap
    issues; a registration under an overlapping-slice directory fails
    with the pair logged; no route exists for a destination outside the
    tailnet and no default is advertised anywhere; the retired fields,
    `--enroll-auth` without
    `--core`, and an unparsable spec refuse as before; and no per-node
    host configuration exists anywhere in the tree.

## Implementation history
