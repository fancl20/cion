# CION security model

CION's security model rests on few assumptions and a small set of controls,
each enforced at a boundary the node itself owns. This document states the
boundaries, the assumptions on each side of them, and the mechanisms that
enforce them; the reasoning lives in the [decision records](/docs/README.md)
under `/docs/adrs/`, and the [architecture
overview](/docs/design/architecture.md) names the components involved.

[TOC]

## Security boundaries

*   **Host to node.** Hosts are tailnet clients of their own node, and what
    crosses this boundary is already protected end to end: the node holds no
    key that could undo that protection. The join itself rides the core's
    WebPKI identity — the coordination endpoint is the one host-facing
    surface where the WebPKI appears a second time.
*   **Joiner to core, once.** The joiner's first fetch of the core's endpoint
    is anchored in the WebPKI through the core's identity, the only place the
    WebPKI appears. Every exchange after it rides the network's own trust.
*   **Node to node, first contact.** The rendezvous exchange is
    unauthenticated: a matched nonce proves return routability and nothing
    more, bounded by admission limits.
*   **Node to node, established.** Every control exchange is mutually
    authenticated with TRC-anchored chains, each backed by the membership
    the founder issued its node, and a forwarded packet's path is verified
    hop by hop under each AS's own key.
*   **In transit.** Other operators' nodes are trusted to forward and
    nothing else: they see the traffic they carry, because protection is end
    to end, not on the path.

## Trust assumptions

Trusted:

*   Each node's own key material — generated locally at first start, never
    leaving the node, never in a configuration file.
*   The founding core's act of self-issuing the base TRC. Every node extends
    this one act of trust to the whole TRC-anchored chain system, and the
    WebPKI vouches only for the single fetch that delivers it.

Untrusted:

*   The underlay and every speaker on it. Received failure signals included:
    a node treats its own measurements as authoritative and any received
    signal as a prompt to re-measure.
*   Every claim a joiner makes about itself before enrollment proves it.
*   Transit ASes as readers of traffic. They are trusted to carry, not to
    keep secrets — confidentiality is the application's own.

## Control mechanisms

*   **One root, anchored once.** The TRC authenticates every control-plane
    exchange after bootstrap; the WebPKI has no role past the first fetch.
*   **Consent is a signature.** An AS appears in a path only through the
    entries it signed itself — declining to sign is declining transit, and
    the data plane verifies each hop under the signer's key.
*   **Admission decides on verified facts.** One seam serves every
    boundary: a node's first issuance, a host's registration, and a core's
    TRC submission that needs the founder's sensitive vote ask the same
    plugin with the keys the exchange presented and a return-routable
    source, never the joiner's claims about itself. No boundary is open by
    default — the founding core does not start without a plugin — and a
    gate that cannot reach its signal denies. The approving plugin's note
    is recorded with the entry — the registry's own audit.
*   **Membership binds a name to its key.** A peer's chain passes a
    handshake only where a membership the founder issued binds its ISD-AS
    to its key, so a core's key links no identity the founder never
    admitted. Each node presents its membership beside its chain and
    renews it at the founder, and a membership counts by its distance from
    the checker's own, so a founder outage lapses none. A network may go
    without memberships, alike on every node, back at the TRC's checks
    alone.
*   **Bounds rather than revocation.** No revocation exists: admission rate
    caps bound strangers at the doors, expiration retires stale trust, and
    liveness is the node's own probe.
*   **Protection is end to end.** The network authenticates forwarding
    state, not traffic; hosts protect their own traffic with keys the path
    never sees.
*   **Asymmetric failure.** Gates fail closed; the node fails open — an
    application's death degrades what the node offers, never its
    forwarding.

## Accepted residual risk

*   The founding core is a single point of trust: a compromised founder
    speaks for the network's trust, and only its sensitive key votes on the
    TRC updates that change roots or membership. Losing the founder halts
    enrollment and every TRC update, while every core keeps renewing chains;
    losing its sensitive key halts the updates that need its vote, the
    founder's own roll among them. Recovery from either is a redeploy.
*   Every core holds its CA key online. A compromised core's chains for a
    name or key the founder never bound pass no handshake wherever
    memberships load, but a member holding the key signs messages under
    them that verify against the TRC alone, and the core stays a member
    until a TRC update removes it. Without memberships, a compromised core
    can issue a chain for any ISD-AS, and only expiration retires it.
*   A membership counts by its distance from the checker's own: after a
    founder outage longer than the membership window, a node that has
    renewed refuses its peers that have not, until they renew, and a node
    that cannot reach the founder accepts what its renewed peers refuse.
*   The founder's sensitive vote on a core's TRC submission rests on the
    admission plugin's answer alone, whatever the submission changes. An
    address-based policy lends that vote to every enrolled core inside its
    prefixes.
*   Admission policy decides on addressing, not identity: a location is
    self-claimed and weakened by NATs. A fabricated location still
    completes no enrollment, but address-based admission is a policy about
    networks, not about nodes.
*   A node cannot be more restrictive than its core's admission policy; the
    model assumes one operator per ISD.
*   First contact is unauthenticated at the underlay — bounded, but a
    stranger can always knock.
*   Compromise and staleness age out by expiration, not revocation: until
    then, the network accepts what it signed.
*   The model holds at small scale only; per-joiner human decisions and
    probe fan-out are affordable because the network itself is bounded.

## See also

*   [CION architecture](/docs/design/architecture.md) — the components these
    boundaries and controls ride on.
*   [Decision records](/docs/README.md) — each decision's negative
    consequences, where this ledger originates.
