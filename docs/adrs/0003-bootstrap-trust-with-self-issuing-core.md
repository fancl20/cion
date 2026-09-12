# Bootstrap ISD Trust with a Self-Issuing Core

*   Status: accepted
*   Date: 2026-09-10

[TOC]

## Context and problem statement

CION's data plane forwards SCION packets between one-node ASes, and directly
connected nodes discover each other by exchanging greetings (see
`pkg/controlplane/discovery.go`). However, no trust material exists anywhere in
the system: the trust database, signer, and verifier in `pkg/trust` are ported
from the reference implementation but uninstantiated, the former `pkg/pki` was
removed during the ConnectRPC migration, discovery greetings are not
authenticated, and the data plane's forwarding key is a static shared secret in
the configuration file.

The next milestone, beaconing with cryptographically verified path segments,
requires verifiable AS certificate chains anchored in a Trust Root
Configuration (TRC) as defined in
[`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt). We must
decide two things: how trust material comes into existence in a network of
one-node ASes operated by independent operators, and how a fresh node obtains
its first TRC over a channel that does not yet benefit from SCION trust. The
base TRC is self-signed — its voting signatures are made by certificates
contained in the TRC itself — so it cannot authenticate itself. This ADR
builds on the tiered AS model defined in
[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md).

## Decision drivers

*   **Zero-Ceremony Deployment:** Nodes must come up without copying files
    between machines or running an offline signing ceremony.
*   **Single Binary:** All PKI operations happen inside the CION binary.
*   **Authenticated Bootstrap:** A fresh node must obtain its first TRC over a
    channel whose authenticity does not depend on SCION trust material.
*   **Unblocks Beaconing:** Signed control-plane messages (beacons, segment
    registrations) must be verifiable in the near term.
*   **Spec-Compatible Artifacts:** TRCs and certificate chains follow the
    SCION CP-PKI wire formats, so the existing `cppki` validation and the
    reference tooling remain usable.
*   **Incremental Delivery:** Trust between direct neighbors is delivered
    before multi-hop path construction exists.

## Considered options

How trust material is created:

*   **Manual Offline PKI:** Generate TRC and chains out-of-band and distribute
    the artifacts to every node.
*   **Trust-on-First-Use Between Neighbors:** No TRC; pin the neighbor's key on
    first greeting.
*   **Self-Issuing Core with In-Network Enrollment:** The founding core AS
    self-issues the base TRC and signs chains for other ASes over the network.
*   **Full SCION CP-PKI:** Voting ceremonies, TRC updates, authoritative AS
    sets, and grace-period handling.

How a fresh node authenticates its first TRC:

*   **TRC Fingerprint in Configuration:** Pin a hash of the base TRC in the
    node configuration.
*   **Trust-on-First-Use:** Fetch the TRC from any neighbor and pin whatever
    arrives first.
*   **WebPKI-Anchored Core Endpoint:** The core serves its control services
    over HTTPS with a certificate for a DNS domain, issued by a public
    certificate authority.

## Decision outcome

Chosen options: **self-issuing core with in-network enrollment**, bootstrapped
by a **WebPKI-anchored core endpoint**, realized as follows:

1.  **Local key generation:** On first start, a node generates its AS key pair
    and persists it in a local state directory. No secrets appear in the
    configuration file; the existing `key` field remains data-plane-only.
2.  **TRC genesis:** The first `ASTypeCore` node of an ISD (the *founding
    core*) generates its sensitive voting certificate, its regular voting
    certificate, and a self-signed CP root certificate, and self-issues the
    ISD's base TRC containing exactly those three, CMS-signed with both voting
    keys — the specification admits only voting and CP root certificates in a
    TRC (PKI draft, Sections 2.4 and 3.2.11). The TRC is validated
    with `cppki` and persisted through the trust DB.
3.  **Core control endpoint:** The founding core serves its control services
    (ConnectRPC over HTTP/3/QUIC riding the SCION network, reached the same
    way greetings are) at a DNS domain with a WebPKI certificate managed
    via ACME (for example, certmagic; challenges answered on public TCP
    ports). The domain is a TLS identity, not a locator — a fresh node never
    resolves it; the node's locator is the SCION link. Explicit certificate
    files remain supported as a fallback for offline deployments.
4.  **Initial trust and TRC fetch:** A fresh node is configured with the
    core's domain and a neighbor link; it needs nothing else. It fetches the
    base TRC from the core over the TLS-verified channel. After the first
    fetch, the TRC is pinned in the trust DB and SCION-native verification
    takes over; WebPKI is a bootstrap-only anchor.
5.  **Chain enrollment:** Every AS (including the core itself) holds an AS
    certificate chained to the core's CP CA certificate, which the core signs
    with its CP root key; the CP CA certificate is never placed in the TRC. A
    joining node sends a certificate request to the core over the verified
    channel; the chain is `[AS certificate ← CP CA certificate ← CP root
    certificate ∈ TRC]`, verified against the root pool extracted from the
    TRC (PKI draft, Section 4.2.2). Enrollment is open to any node that can
    reach the core's endpoint; operators who want tighter control configure
    an ISD-AS allowlist on the core. This deviates from the specification's
    issuance flow, where the first certificate signing request is sent out
    of band as part of the formalities of joining an ISD and only renewals
    are automated (PKI draft, Section 4.3); CION automates the first
    enrollment deliberately, trading the joining formality for zero-config
    deployment.
6.  **SCION-native control traffic, one-hop first:** Control RPCs ride the
    SCION network from day one, TLS end-to-end against the core's WebPKI
    certificate, so nothing in between can tamper with or impersonate the
    core. Using the SCION network requires no trust material — the data
    plane forwards on hop-field MACs alone, exactly as any SCION
    application — so a fresh node reaches the core over the same one-hop
    SCION path greetings use, and its first TRC fetch is authenticated by
    the WebPKI certificate alone. After that fetch, verification is
    SCION-native, anchored in the TRC. Until beaconing provides multi-hop
    paths, enrollment therefore requires a direct SCION link to the core.
    An IP-underlay channel to the core's endpoint and a neighbor UDP relay
    were both considered and rejected: SCION forwarding provides the
    transport natively in every phase, so either would be a second,
    throwaway channel beside the data plane.
7.  **Unauthenticated discovery, authenticated beacons:** Greetings remain
    unauthenticated link-bootstrap messages, mirroring the specification:
    neighbor identity is configured out-of-band (control plane draft,
    Section 2.2.5), initial exchanges ride one-hop paths (Section 2.3.5), and
    the binding of identity to link is enforced when the first signed
    control-plane message — a beacon — is checked against the configured
    neighbor (Section 2.3.1). Greetings carry hints (control address,
    interface ID) and are cross-checked against the configured neighbor IA;
    a fresh node therefore bootstraps with no trust material at all. Signed
    greetings may be added later as hardening.

Control RPCs ride SCION packets (Connect over HTTP/3/QUIC per control plane
draft, Sections 1.7 and 5) — one-hop paths until multi-hop paths exist. The
WebPKI certificate anchors a fresh node's first TRC fetch on that channel,
because SCION forwarding requires no trust material.

TRC updates, voting workflows, certificate renewal, and cross-ISD operation are
out of scope for now. The system is anchored to a single base TRC; changing the
trust roots means reissuing the base TRC and redeploying, which is acceptable
at CION's target scale. New `ASTypeNormal` nodes join at any time through
enrollment (membership is dynamic); only the anchor set — cores, CAs, voters —
is frozen.

### Positive consequences

*   A fresh node's entire bootstrap configuration is a domain name and a
    neighbor link.
*   The ported trust DB, signer, and verifier become live without new
    abstractions.
*   End-to-end TLS keeps intermediate networks untrusted, with no forwarding
    component to operate.
*   Spec-formatted artifacts keep the door open to reference tooling and
    future TRC updates.
*   Greetings follow the specification's link-bootstrap model; a fresh node
    bootstraps with no trust material and no chicken-and-egg dependency on
    enrollment.

### Negative consequences

*   Bootstrap and enrollment depend on an external certificate authority, DNS,
    and a publicly reachable core (or DNS-01 validation). The dependency is
    bounded: ongoing operation and verification are SCION-native.
*   Open enrollment by default: any node that can reach the core can join the
    ISD; the allowlist is opt-in.
*   Until multi-hop SCION paths exist, nodes without a direct SCION link to
    the core cannot bootstrap.
*   The founding core is a single point of trust: its CA key can issue for the
    entire ISD, and its loss halts enrollment.
*   No TRC update path exists yet; trust-root evolution requires redeployment.
*   Until signed beacons exist, a spoofer with access to a direct link can
    poison the neighbor table; this is bounded by cross-checking the
    configured neighbor IA, the same trade the specification makes for link
    bootstrap.
*   A second ISD requires a second founding core; there is no cross-ISD story
    yet.

## Pros and cons of the options

### Manual offline PKI

*   Good, because it matches the reference implementation's scion-pki tooling
    and needs no protocol work.
*   Good, because the trust surface is fully reviewed before deployment.
*   Bad, because it violates the zero-config goal: artifacts must be generated
    and copied to every node by hand.
*   Bad, because every membership change repeats the manual ceremony.

### Trust-on-first-use between neighbors

*   Good, because it is trivial to implement and needs no TRC at all.
*   Bad, because it provides no ISD-wide anchor; beacon signatures could not be
    verified beyond direct neighbors.
*   Bad, because a man-in-the-middle on the first greeting is undetectable.

### Self-issuing core with in-network enrollment

*   Good, because a new node needs only the core's domain and a link to any
    node in the ISD to obtain verifiable trust material automatically.
*   Good, because it reuses the existing ConnectRPC scaffolding and the
    standard trust material RPCs.
*   Bad, because the core's CA key becomes a high-value target.
*   Bad, because open enrollment relies on the optional allowlist for
    restrictive operators.

### Full SCION CP-PKI

*   Good, because it handles trust-root evolution, voting quorums, and grace
    periods per the specification.
*   Bad, because the ceremony and state-machine complexity contradicts CION's
    simplicity goals for an initial release.
*   Bad, because most of it is unused at one-node-per-AS scale.

### TRC fingerprint in configuration

*   Good, because it has no external dependencies.
*   Bad, because the operator must copy a hash out-of-band, and mistakes fail
    silently.
*   Bad, because anchor rotation repeats the manual distribution.

### Trust-on-first-use TRC fetch

*   Good, because it requires no configuration at all.
*   Bad, because a man-in-the-middle on the first fetch is undetectable: the
    base TRC cannot authenticate itself.

### WebPKI-anchored core endpoint

*   Good, because a domain name is a natural, operator-friendly identifier and
    ACME automates certificate management.
*   Good, because end-to-end TLS works over untrusted paths, on any
    transport.
*   Bad, because bootstrap depends on an external CA and public DNS
    reachability.
*   Bad, because offline deployments must fall back to manual certificates.
