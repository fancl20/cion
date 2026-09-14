# Implement trust bootstrap and neighbor trust exchange

This proposal outlines the implementation of the trust foundation decided in
[ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md): local
key generation, TRC genesis by a founding core, a WebPKI-anchored control
endpoint, in-network chain enrollment, and discovery greetings cross-checked
against the configured neighbor identity.

[TOC]

## Summary

CION currently has no trust material: the ported trust database, signer, and
verifier in `pkg/trust` are uninstantiated, and neighbor discovery greetings
are unauthenticated. This proposal makes them live. The founding core AS of an
ISD self-issues the base TRC on first start and serves its control services
over HTTP/3 (QUIC) riding the SCION network — one-hop paths to direct
neighbors — with TLS secured by an ACME-managed certificate for its DNS
domain; a fresh node configured with just that domain and a neighbor link
fetches the TRC and requests a certificate chain over that channel. Nodes
need a direct SCION link to the core in this milestone; enrollment over
multi-hop paths follows in proposal 0004.

## Motivation

Signed control-plane messages are the precondition for the next milestone,
beaconing with cryptographically verified path segments (proposal 0004; see
[`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt)).
Independently of beaconing, the neighbor identity advertised in a greeting
must be bound to the physical link; this proposal keeps greetings
unauthenticated but cross-checked against the configured neighbor, with
cryptographic enforcement deferred to the signed beacons of proposal 0004.
The
existing interfaces (`trust.Provider`, `trust.DB`, `trust.Signer`,
`trust.Verifier`) and ConnectRPC scaffolding in `pkg/controlplane` define the
boundaries; this proposal fills them with a concrete implementation.

### Goals

*   Generate and persist AS key material locally on first start.
*   Self-issue and validate an ISD base TRC on the founding core
    (`ASTypeCore`).
*   Serve control RPCs over HTTP/3 (QUIC) riding the SCION network, with an
    ACME-managed certificate for the core's domain (certmagic) and explicit
    certificate files as fallback. This includes a QUIC-over-SCION transport
    (a `net.PacketConn` adapter over the data plane's one-hop path channel,
    the same plumbing greetings use). HTTP-01 and TLS-ALPN-01 challenges
    come first, answered on dedicated TCP listeners (ports 80 and 443);
    DNS-01 support follows later.
*   Issue AS certificate chains over the network to nodes reaching the core
    endpoint, with an optional ISD-AS allowlist.
*   Keep the TLS channel end-to-end: nodes reach the core over the same
    one-hop SCION paths greetings use. Enrollment of nodes not directly
    linked to the core is deferred to the multi-hop paths of proposal 0004.
*   Implement a network-backed `trust.Provider` that serves and fetches trust
    material, backed by the bbolt trust DB.
*   Validate greetings against the configured neighbor identity, per the
    specification's link-bootstrap model.
*   Wire the above into the `cion` binary behind the existing configuration.

### Non-goals

*   TRC updates, voting ceremonies, and grace-period handling (base TRC only).
*   Certificate renewal and expiry rollover.
*   Multi-hop path construction and enrollment of nodes not directly linked
    to the core — deferred to proposal 0004, which extends this proposal's
    QUIC/SCION transport to multi-hop paths.
*   Signed greetings; neighbor authentication moves to signed beacons in
    proposal 0004, mirroring the specification (control plane draft,
    Sections 2.2.5, 2.3.1, and 2.3.5).
*   Multi-core ISDs and cross-ISD trust.

## Proposal

### Key material and TRC genesis

Extend `pkg/trust` with the issuance side of trust material: key generation
and persistence in a state directory (path from the node configuration;
created on first start), TRC genesis, and CA chain signing. `pkg/trust`
already owns the trust-material types (`Signer`, `SignedTRC`, chains) and
their storage, so issuance lives in the same package and no separate `pkg/pki`
is re-introduced.

Per the specification's certificate model (PKI draft, Section 2.5, Table 2),
the founding core generates the three self-signed certificates that make up
the base TRC: a sensitive voting certificate, a regular voting certificate,
and a CP root certificate (a CA certificate carrying `id-kp-root`). Nothing
else may appear in the TRC's certificate list — CA certificates are
explicitly excluded (PKI draft, Section 3.2.11), and
`cppki` rejects them. Separately, the core creates a CP CA certificate signed
by the CP root key — never placed in the TRC — and uses it to sign AS
certificates; the resulting chain is `[AS certificate ← CP CA certificate ←
CP root certificate ∈ TRC]`. (ADR-0002 speaks of "root voting certificates";
the draft has no such type — its CP root certificate is a CA certificate
that signs CA certificates and never votes.)

Genesis follows the draft's base-TRC rules: the ID is `ISDx-B1-S1`,
`gracePeriod` is zero, `votes` is empty, and `votingQuorum` is 1 — valid only
because the single core holds one sensitive and one regular voting
certificate (`cppki` requires the quorum to be no larger than the count of
each). The TRC is CMS-signed by both voting keys, as `cppki`'s base-TRC
verification requires a signature for every voting certificate in the TRC,
and voting and root certificate validity must cover the TRC's. The base TRC
is validated with `cppki` and inserted into the trust DB. TRC genesis is
idempotent: an existing TRC in the DB is never silently replaced.

### Core control endpoint

The founding core runs its ConnectRPC services on an HTTP/3 (QUIC) listener
reachable over the SCION network: a QUIC-over-SCION transport (a
`net.PacketConn` adapter that carries QUIC datagrams as SCION packets over
one-hop paths and reverses received paths for the return direction, reusing
the data-plane plumbing greetings use), registered like the discovery
service so packets addressed to the control service reach it. The configured
domain is a TLS identity, not a locator — no DNS resolution is involved in
serving or fetching. The TLS certificate is managed by certmagic
(`github.com/caddyserver/certmagic`, new dependency) fed into `http3.Server`;
certificate files on disk remain a fallback for offline deployments. ACME
challenges are answered on dedicated TCP listeners (ports 80 and 443); ACME
servers validate over TCP, never QUIC. The endpoint exposes
`TrustMaterialService` and `ChainRenewalService`.

### Chain enrollment

Every node creates its AS key pair and a certificate signing request (CSR). A
node with `ASTypeCore` implements the `ChainRenewalService` handler in
`pkg/controlplane`, delegating CA signing to `pkg/trust`. Chains are
two-certificate chains `[AS certificate, CP CA certificate]` (PKI draft,
Section 4.2.2; enforced by `cppki.ValidateChain`), verified against the root
pool extracted from the TRC. The core signs chains for its own certificate
and for requests from any node that reaches the verified endpoint, unless
the operator configured an ISD-AS allowlist (unlisted requests are rejected
and logged). First-issuance requests are accepted on a self-signed CSR —
proof of possession of the subject key (PKI draft, Section 4.3) — plus the
optional allowlist; the `ChainRenewalRequest`'s signed wrapper, which the
reference implementation verifies against the requester's existing chain, is
honored for renewals only, as fresh nodes have no chain yet. Chains are
validated and inserted into the trust DB of both parties.

Validity periods use the draft's recommended values (TRC, voting, and root
certificates one year; CA eleven days; AS three days — PKI draft, Section
2.1.6). There is no automated renewal; an expired node re-runs enrollment,
which is acceptable for a development network.

### Core reachability

Control traffic rides SCION — one-hop paths to direct neighbors in this
milestone (control plane draft, Section 5: neighboring ASes craft one-hop
paths directly and respond by reversing them), multi-hop paths in proposal
0004 — TLS-verified end-to-end against the core's domain; nothing in between
terminates or needs trust. A node therefore needs a direct SCION link to
the core to fetch trust material and enroll in this milestone; nodes whose
links do not include the core wait for multi-hop paths. Using the SCION
network requires no trust material: the data plane forwards on hop-field
MACs alone, so a fresh node's first TRC fetch is authenticated by the WebPKI
certificate alone (ADR-0003, decision 6).

### Trust exchange

Implement `trust.Provider` as a DB-first resolver: on a miss, query the
`TrustMaterialService` of the core endpoint over the SCION channel and
insert the result into the bbolt DB. Serving trust material from non-core
nodes is deferred until neighbor-to-neighbor exchange is needed (proposal
0004).

### Neighbor authentication

Greetings stay unauthenticated link-bootstrap messages, mirroring the
specification's link-bootstrap model: neighbor identity is configured
out-of-band (control plane draft, Section 2.2.5) and initial exchanges ride
one-hop paths without signatures (Section 2.3.5). (The drafts define no
greeting message; what follows the specification is the model.) The greeting
handler continues to cross-check the advertised IA against the configured
neighbor IA of the receiving interface and drops mismatches. Cryptographic
neighbor authentication is enforced on the first signed control-plane
message — the beacons of proposal 0004 — whose signatures are verified
against TRC-anchored chains and matched to the configured neighbor, mirroring
the PCB reception checks of control plane draft Section 2.3.1 (which also
presuppose configured neighbor link types: core, parent, child, or peer). A
fresh node with no trust material therefore bootstraps and enrolls without a
chicken-and-egg dependency; greeting signatures may be added later as
hardening.

### Node wiring

The `cion` binary gains the following configuration fields: `asType` (`core`,
`authoritative`, or `normal`), the state directory, the core's domain (for
non-core nodes), and the domain plus certificate mode (`acme` or file paths,
for core nodes). ISD numbers should come from the private range 16-63
(control plane draft, Section 1.5.1); the PKI draft does not constrain the
TRC's ISD number, and nothing in `cppki` enforces the choice.
Startup order: trust DB, key material, TRC genesis (core only), control
endpoint (core) or trust fetch and enrollment (non-core), then discovery as
today. The data plane and its forwarding `key` configuration are unchanged.

## Test plan

*   **Unit tests:** TRC genesis produces a TRC that passes `cppki` validation
    and is rejected when tampered with or when a CA certificate is placed in
    the TRC; issued chains verify against the TRC's root pool; chain issuance
    rejects allowlisted-out and malformed requests and first-issuance CSRs
    that are not self-signed; the QUIC-over-SCION transport delivers
    datagrams over one-hop paths in both directions; the network-backed
    provider falls back to remote fetch on DB miss and caches the result.
*   **Integration tests:** a two-node topology where a core and a normal node
    discover each other, the normal node fetches the TRC and enrolls over the
    one-hop SCION channel (TLS-verified against the core's domain), and both
    trust DBs converge. Indirect topologies (core A — B — C with no direct
    link from C to the core) are deferred to proposal 0004: without
    multi-hop paths, C's enrollment would only repeat the two-node case over
    a one-hop path elsewhere, and nothing exercises a second SCION hop.
*   **Negative tests:** TLS verification fails against an endpoint presenting
    a certificate for the wrong domain; greetings advertising an IA that does
    not match the configured neighbor are dropped; stale or mismatched trust
    material is refused.

## Implementation history

*   Implemented: key generation and persistence (`pkg/trust/keys.go`), TRC
    genesis and chain issuance (`pkg/trust/genesis.go`, `certs.go`,
    `issuer.go`), the QUIC-over-SCION transport (`pkg/controlplane/transport.go`),
    the HTTP/3 control endpoint with certmagic and file-certificate fallback
    (`pkg/controlplane/server.go`, `tls.go`), the trust material and chain
    renewal RPCs (`pkg/controlplane/trustservice.go`), the network-backed
    provider and enrollment (`pkg/trust/network.go`, `renewal.go`), and the
    `cion` binary wiring (`internal/services`). Tests cover genesis, issuance,
    the transport, the RPCs, and a two-node integration test with TLS
    verified against a test CA standing in for the WebPKI.
