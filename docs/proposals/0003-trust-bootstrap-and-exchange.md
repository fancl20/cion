# Implement trust bootstrap and neighbor trust exchange

This proposal outlines the implementation of the trust foundation decided in
[ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md): local
key generation, TRC genesis by a founding core, a WebPKI-anchored control
endpoint, in-network chain enrollment, neighbor relays to the core, and
authenticated discovery greetings.

[TOC]

## Summary

CION currently has no trust material: the ported trust database, signer, and
verifier in `pkg/trust` are uninstantiated, and neighbor discovery greetings
are unauthenticated. This proposal makes them live. The founding core AS of an
ISD self-issues the base TRC on first start and serves its control services
over HTTP/3 (QUIC) at a DNS domain secured by an ACME-managed certificate; a
fresh node configured with just that domain and a neighbor link fetches the
TRC and requests a certificate chain. Neighbors without a direct link to the
core relay control traffic to it.

## Motivation

Signed control-plane messages are the precondition for the next milestone,
beaconing with cryptographically verified path segments (see
[`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt)).
Independently of beaconing, discovery greetings should be authenticated so a
node can bind the advertised neighbor identity to the physical link. The
existing interfaces (`trust.Provider`, `trust.DB`, `trust.Signer`,
`trust.Verifier`) and ConnectRPC scaffolding in `pkg/controlplane` define the
boundaries; this proposal fills them with a concrete implementation.

### Goals

*   Generate and persist AS key material locally on first start.
*   Self-issue and validate an ISD base TRC on the founding core
    (`ASTypeCore`).
*   Serve control RPCs over HTTP/3 (QUIC) with an ACME-managed certificate for
    the core's domain (certmagic), with explicit certificate files as
    fallback. HTTP-01 and TLS-ALPN-01 challenges come first; DNS-01 support
    follows later.
*   Issue AS certificate chains over the network to nodes reaching the core
    endpoint, with an optional ISD-AS allowlist.
*   Relay control traffic to the core through discovered neighbors, keeping
    TLS end-to-end to the core's domain.
*   Implement a network-backed `trust.Provider` that serves and fetches trust
    material, backed by the bbolt trust DB.
*   Validate greetings against the configured neighbor identity, per the
    specification's link-bootstrap model.
*   Wire the above into the `cion` binary behind the existing configuration.

### Non-goals

*   TRC updates, voting ceremonies, and grace-period handling (base TRC only).
*   Certificate renewal and expiry rollover.
*   In-band control-plane messaging over SCION paths (the relay is the interim
    bridge until multi-hop control traffic exists).
*   Signed greetings; neighbor authentication moves to signed beacons in the
    beaconing proposal, mirroring the specification (control plane draft,
    Sections 2.2.5, 2.3.1, and 2.3.5).
*   Multi-core ISDs and cross-ISD trust.

## Proposal

### Key material and TRC genesis

Extend `pkg/trust` with the issuance side of trust material: key generation
and persistence in a state directory (path from the node configuration;
created on first start), TRC genesis, and CA chain signing. `pkg/trust`
already owns the trust-material types (`Signer`, `SignedTRC`, chains) and
their storage, so issuance lives in the same package and no separate `pkg/pki`
is re-introduced. The founding core generates its voting certificates and
regular CP CA certificate, self-issues the base TRC per ADR-0002's tiered
model, validates it with `cppki`, and inserts it into the trust DB. TRC
genesis is idempotent: an existing TRC in the DB is never silently replaced.

### Core control endpoint

The founding core runs its ConnectRPC services on an HTTP/3 (QUIC) listener at
its configured domain. The TLS certificate is managed by certmagic
(`github.com/caddyserver/certmagic`, new dependency) fed into `http3.Server`;
certificate files on disk remain a fallback for offline deployments. The
endpoint exposes `TrustMaterialService` and `ChainRenewalService`.

### Chain enrollment

Every node creates its AS key pair and a certificate request. A node with
`ASTypeCore` implements the `ChainRenewalService` handler in
`pkg/controlplane`, delegating CA signing to `pkg/trust`. The core signs
chains for its own certificate and for requests from any node that reaches
the verified endpoint, unless the operator configured an ISD-AS allowlist
(unlisted requests are rejected and logged). Chains are validated and inserted
into the trust DB of both parties.

### Neighbor relay

A node whose links do not include the core forwards control traffic through a
discovered neighbor acting as a UDP relay: the neighbor shuttles datagrams
between the node's link and its own route to the core's public endpoint, with
QUIC connection IDs tolerating the address translation. The relay terminates
no TLS and needs no trust; the client's TLS session is verified against the
core's domain end-to-end. Relaying is enabled by default and requires no core
involvement.

### Trust exchange

Implement `trust.Provider` as a DB-first resolver: on a miss, query the
`TrustMaterialService` of the core endpoint (directly or through the relay)
and insert the result into the bbolt DB. Serving trust material from
non-core nodes is deferred until neighbor-to-neighbor exchange is needed.

### Neighbor authentication

Greetings stay unauthenticated link-bootstrap messages, as in the
specification: neighbor identity is configured out-of-band and initial
exchanges ride one-hop paths without signatures. The greeting handler
continues to cross-check the advertised IA against the configured neighbor IA
of the receiving interface and drops mismatches. Cryptographic neighbor
authentication is enforced on the first signed control-plane message — the
beacons of the next proposal — whose signatures are verified against
TRC-anchored chains and matched to the configured neighbor, mirroring the
PCB reception checks of control plane draft Section 2.3.1. A fresh node with
no trust material therefore bootstraps and enrolls without a
chicken-and-egg dependency; greeting signatures may be added later as
hardening.

### Node wiring

The `cion` binary gains the following configuration fields: `asType` (`core`,
`authoritative`, or `normal`), the state directory, the core's domain (for
non-core nodes), and the domain plus certificate mode (`acme` or file paths,
for core nodes). Startup order: trust DB, key material, TRC genesis (core
only), control endpoint (core) or relay setup, chain enrollment, then
discovery as today. The data plane and its forwarding `key` configuration are
unchanged.

## Test plan

*   **Unit tests:** TRC genesis produces a TRC that passes `cppki` validation
    and is rejected when tampered with; chain issuance rejects allowlisted-out
    and malformed requests; the network-backed provider falls back to remote
    fetch on DB miss and caches the result; the relay maps QUIC datagrams
    correctly in both directions.
*   **Integration tests:** a two-node topology where a core and a normal node
    discover each other, the normal node fetches the TRC and enrolls over the
    verified endpoint, and both trust DBs converge. A three-node chain
    topology (core A — B — C) where C enrolls through B's relay.
*   **Negative tests:** TLS verification fails against an endpoint presenting
    a certificate for the wrong domain; greetings advertising an IA that does
    not match the configured neighbor are dropped; stale or mismatched trust
    material is refused.

## Implementation history
