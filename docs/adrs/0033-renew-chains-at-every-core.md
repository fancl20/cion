# Renew Chains at Every Core

*   Status: accepted
*   Date: 2026-10-30

[TOC]

## Context and problem statement

A node's AS certificate lives three days, and the node renews it once less
than a day remains. It renews at an issuer: a core whose root certificate
the newest TRC carries
([ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md),
decision 7). Only the founder is one. ADR-0015, decision 6, gives the
authoritative core no CA keys, so it renews its own chain at the founder
like any node.

With the founder down, every chain lapses within three days of its last
renewal. A node whose chain lapsed signs no beacon and authenticates no
channel, so path discovery stops, and the control plane with it. With
[proposal 0093](/docs/proposals/0093-refresh-fetched-segments-behind-the-lookup.md)'s
lookups and
[ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)'s
directory, the network keeps serving through a founder outage of hours.
Renewal bounds the outage it survives at about two days.

The SCION PKI draft expects several issuers in an ISD:

*   **Root certificates name the issuers.** The root certificates in an
    ISD's TRC "determine which ASes act as Issuing CAs in an ISD" (Section
    2.1).
*   **Several issuers keep renewal alive.** "Should an AS not be able to
    renew certificates, it would be cut off from the network. It is
    therefore recommended to deploy multiple, independent CAs within an
    ISD" (Section 5.1). The security considerations name several CAs as
    the mitigation against a denied CA (Section 6.2).
*   **The current chain authorizes a renewal.** The renewal request is
    signed "using the existing private key corresponding to one of the
    AS's currently active and valid AS certificate" (Section 4.3), so any
    issuer of the ISD can check it.

CION departs from the draft on the last two points. Its issuer assumes the
TRC holds exactly one root certificate. It recognizes a renewal by its own
records, the name's current chain under the same key, rather than by the
requester's chain. First issuance is where admission happens
([ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)):
the founder's authorizer, and its check that no other key holds the
self-picked ISD-AS.

## Decision drivers

*   **Renewal survives the founder:** while any core serves, every node
    renews its chain, for as long as the TRC is valid.
*   **Spec-native:** the draft's own model of several issuers in an ISD,
    and its renewal authorization.
*   **Admission stays put:** the admission policy and the check that keeps
    one key per ISD-AS remain one decision, made in one place.
*   **No new trust:** each issuer enters by the TRC's sensitive vote, as
    each core does.
*   **Nothing between cores:** the issuers need no protocol among
    themselves.

## Considered options

Who issues chains:

*   **The founder stays the sole issuer,** as today.
*   **Proxied renewals:** any core forwards a renewal to the founder, an
    option ADR-0015 considered.
*   **A CA certificate per core from the founder's root:** each core issues
    under a CA certificate that the founder's root signs, and the TRC does
    not change.
*   **A root certificate per core in the TRC:** each core issues under a
    root of its own.

Where first issuance happens:

*   **At every issuer,** each running the admission policy.
*   **At the founder alone.**

## Decision outcome

Chosen options: **a root certificate per core in the TRC**, with first
issuance **at the founder alone**. This re-decides ADR-0015's decision 6,
under which the authoritative core holds no CA keys:

1.  **Every core is an issuer.** A core holds a root key and a CA key of its
    own. Its root certificate enters the TRC with the sensitive update that
    onboards it, beside its voting certificate, and the core signs that
    update with its root key as proof of possession (Section 3.5.6). It
    issues its CA certificate from its root key, and again before the CA
    certificate runs short, as the founder does.
2.  **A core renews its own chain itself,** as the founder does, so no core
    depends on another for its own chain.
3.  **Any issuer renews any node.** The requester's current chain authorizes
    a renewal: the request carries a signature by the key that a currently
    valid chain certifies (Section 4.3), whichever issuer signed that chain,
    and that chain verifies against any root of the TRC. The renewed chain
    certifies the same key. No admission policy is asked, and the TRC does
    not change: AS and CA certificates live below the roots and travel
    outside the TRC (Section 3.4), so an issuer renews for as long as its
    root certificate and the TRC are valid.
4.  **First issuance stays with the founder.** Only the founder issues a
    chain to a name that holds none, and only after its authorizer allows
    and its check finds no other key holding the name. The founder binds
    each ISD-AS to its key at first issuance, for good, so a name that
    renews at other cores still refuses another key. Any other core refuses
    a request that no current chain authorizes.
5.  **A node renews at any issuer.** Renewal routes to the cores whose root
    certificate the TRC carries, as ADR-0015's decision 7 already provides,
    and a node whose issuer does not answer asks another. Enrollment routes
    to the founder.
6.  **TRC updates stay as they are.** Onboarding a core, and every change to
    the core set or to the voters, takes the founder's sensitive vote. A
    core's root certificate rolls by a regular update that its own regular
    voting key casts, signed with its old root key (Section 3.5.4), through
    the channel its other rolls take.

### Positive consequences

*   Every node renews at any core for as long as the TRC is valid: a founder
    outage no longer lapses the chains.
*   The design follows the draft: the TRC's roots name the issuers, and the
    current chain authorizes a renewal.
*   An authoritative core no longer depends on the founder for its own
    chain.
*   Admission is unchanged: one policy, one place, and one key per ISD-AS.

### Negative consequences

*   Every core holds CA keys online. A compromised core can issue a chain
    for any ISD-AS, as a compromised founder can today, and the number of
    keys that can do so grows with the cores.
*   While the founder is down, no node joins, no core is onboarded, and no
    TRC update lands, the TRC's own extension included. Renewal lasts as
    long as the TRC's remaining validity, at most a year: an outage longer
    than that still stops the network.
*   The founder keeps each name's key beyond the chains it issued, and a
    node keeps its key for the life of its ISD-AS.
*   An issuer picks its own root among the TRC's several.
*   A core's root certificate rolls through the founder's voting
    application, as its voting certificate does today, so a root roll waits
    for the founder. Root certificates and the TRC live a year.

## Pros and cons of the options

### The founder stays the sole issuer

*   Good, because only one core holds CA keys.
*   Bad, because every chain lapses within three days of a founder outage,
    the authoritative core's own included.

### Proxied renewals

*   Good, because no core but the founder holds CA keys.
*   Bad, because a renewal still needs the founder, so a founder outage
    still lapses every chain.

### A CA certificate per core from the founder's root

*   Good, because the TRC does not change.
*   Bad, because only the founder's root re-issues a CA certificate: an
    issuer outlasts the founder by eleven days, against the TRC's year.

### A root certificate per core in the TRC

*   Good, because each issuer lasts as long as the TRC, independent of the
    founder.
*   Good, because it is the draft's own model.
*   Bad, because the onboarding update carries one more certificate, and
    each root rolls by a TRC update.

### First issuance at every issuer

*   Good, because a node joins while any core serves.
*   Bad, because the admission policy and the one-key-per-name check would
    need agreement between the issuers: an operator's prompt answered once,
    a key spent once.

### First issuance at the founder alone

*   Good, because admission stays one decision in one place.
*   Bad, because no node joins while the founder is down.
