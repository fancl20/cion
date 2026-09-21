# CION security model

CION's security model rests on few assumptions and a small set of controls,
each enforced at a boundary the node itself owns. This document states the
boundaries, the assumptions on each side of them, and the mechanisms that
enforce them; the reasoning lives in the [decision records](/docs/README.md)
under `/docs/adrs/`, and the [architecture
overview](/docs/design/architecture.md) names the components involved.

[TOC]

## Security boundaries

*   **Host to node.** Hosts are ordinary clients of their own node, and what
    crosses this boundary is already protected end to end: the node holds no
    key that could undo that protection.
*   **Joiner to core, once.** The joiner's first fetch of the core's endpoint
    is anchored in the WebPKI through the core's domain — the only place the
    WebPKI appears. Every exchange after it rides the network's own trust.
*   **Node to node, first contact.** The rendezvous exchange is
    unauthenticated: a matched nonce proves return routability and nothing
    more, bounded by admission limits.
*   **Node to node, established.** Every control exchange is mutually
    authenticated with TRC-anchored chains, and a forwarded packet's path is
    verified hop by hop under each AS's own key.
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
*   **Admission decides on verified facts.** The single gate is a joiner's
    first issuance: policy sees possession of the joiner's key and a
    return-routable address, never the joiner's claims about itself.
    Admission is open by default, and a gate that cannot reach its signal
    denies.
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

*   The founding core is a single point of trust: a compromised core speaks
    for the network's trust, a lost one halts enrollment, and no TRC update
    path exists — changing roots means redeploying.
*   Admission policy decides on addressing, not identity: a location is
    self-claimed and weakened by translation. A fabricated location still
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
