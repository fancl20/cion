# Onboard Authoritative Cores by Sensitive TRC Update

*   Status: proposed
*   Date: 2026-09-29

[TOC]

## Context and problem statement

[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md) tiers the AS
roles — the founding core holds the sensitive and regular voting
certificates, an authoritative core holds the regular one, a normal node
holds none — but only the outer tiers are wired. `ASTypeAuthoritative`
behaves like a normal node in this milestone and its parser has no caller
(`/pkg/trust/astype.go`); every node is either the founding core or a
joiner. [ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md)
froze the anchor set with it: the ISD is pinned to one base TRC, trust-root
evolution means reissuing the base and redeploying, and the trust
database's lookups take exact TRC IDs while its sweep never touches TRCs
(`/pkg/modules/trustdb/trustdb.go`).

Three costs follow. Path availability rests on a single beacon origin — a
second core can be listed in the TRC's core ASes, but no process originates
from it, so the core-segment registration has nothing to terminate while
the ISD has a single core (`/pkg/controlplane/beacon.go`). Trust material
expires with no rotation path: the TRC, the voting certificates, and the
root certificate live 365
days (`/pkg/trust/certs.go`), and outliving them means redeploying. And the
reference update rules are present but unused — `cppki`'s
`ValidateUpdate` is never called, and a fetched non-base TRC is rejected
outright because verification passes no predecessor (`/pkg/trust/network.go`,
`fetchTRC`).

This record extends ADR-0003's scope, which deferred updates "for now";
its decisions — the self-issuing core, the WebPKI-anchored bootstrap —
stand as written. It realizes the tier ADR-0002 defined.

## Decision drivers

*   **Zero ceremony stays:** no offline signing and no file exchange
    before a node starts; whatever joins, joins over the network
    (ADR-0003's driver).
*   **The founder remains the sole sensitive voter and the sole CA:** the
    deliberate coupling of ADR-0002 — one sensitive certificate, one root
    certificate in the TRC.
*   **Spec-compatible artifacts:** the update rules of the
    [`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt)
    govern what may change — a regular update leaves the quorum, core
    ASes, authoritative ASes, and sensitive voting certificates unchanged,
    everything else is a sensitive update (Sections 3.5.4 and 3.5.5), and
    every newly added voting certificate must sign the updated TRC as
    proof of possession (Section 3.5.6).
*   **Fail-closed verification:** a node never accepts a TRC it cannot
    verify against its pinned predecessor.
*   **One mechanism, two needs:** onboarding and certificate rotation ride
    the same update path, not two protocols.

## Considered options

How a second core joins:

*   **Pre-genesis ceremony:** collect the fellow cores' voting
    certificates before genesis — every voting certificate must sign the
    base TRC — and found with the complete set.
*   **Named-only fellow cores:** genesis lists fellow core ASes without
    their voting certificates.
*   **Sensitive-vote onboarding:** the second core joins as a node, and
    the founder casts a sensitive update that adds it.

How the joiner's role is gated:

*   **At enrollment:** the joiner presents its voting certificate with
    the chain request, and the authorizer is asked what to admit it as.
*   **At the cast:** the joiner enrolls as any node, and the authorizer
    is asked when the successor is submitted.

How enrollment finds a core that issues chains:

*   **Proxy renewals:** a non-issuing core forwards chain renewals to the
    founder.
*   **A CA on every core:** each core issues its own chains from its own
    root certificate in the TRC.
*   **The root-certificate signal:** enrollment routes to cores whose
    root certificate is in the TRC.

How trust material rotates:

*   **Redeploy:** reissue the base TRC and redeploy the ISD (the status
    quo).
*   **Regular updates:** periodic re-issuance voted by the regular voting
    certificates.
*   **Sensitive updates:** the founder votes alone.

## Decision outcome

Chosen options: **sensitive-vote onboarding**, the role gated **at the
cast**, enrollment routed by **the root-certificate signal**, and rotation
by **sensitive update** — realized as follows:

1.  **Joining decides the role.** `cion run core` without a neighbor
    founds, exactly as today; with `--topology.neighbor` it joins the
    neighbor's ISD as an authoritative core, its ISD completed from the
    neighbor's reply like any joiner's (`/internal/services/node.go`). The
    neighbor prohibition on the core role lifts
    (`/internal/services/config.go`) — neighbor presence becomes what
    distinguishes a joining core from a founding one, and no new command
    appears.
2.  **The cast admits the role.** The joining core generates its regular
    voting key at first start — a role-shaped loader beside the founder's
    all-or-nothing one (`/pkg/trust/keys.go`) — and enrolls exactly as a
    node does: the enrollment seam stays the one
    [ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
    established, its wire forms the drafts' own, asked nothing about the
    role. The certificate first travels inside the successor TRC the
    joiner submits, and the question — whether the submitter gains voting
    power — is asked there, of the same authorizer, by the founder's
    decision before the sensitive key signs. The gate stands where the
    power is granted: any chain-holder can assemble and submit an
    onboarding successor, so a question asked only of enrollments that
    present a certificate binds the honest alone.
3.  **The founder casts the update.** The joiner assembles the successor
    TRC from the founder's newest — serial incremented, its AS added to
    the core and authoritative AS lists, its regular voting certificate
    added to the certificate set — and signs it with its regular key, the
    proof of possession the draft requires of every new voter
    (Section 3.5.6) and `cppki` enforces. The founder's sensitive voting
    key signs beside it — the vote — and the completed artifact is
    verified against the pinned predecessor before anything pins. One
    online round trip; genesis itself stays the founder's local call.
4.  **Verification follows the chain.** A fetched update verifies against
    the pinned predecessor — `ValidateUpdate` wired into the fetch that
    today rejects every non-base TRC. Distribution rides what exists:
    signed control-plane messages carry their TRC's ID, the verifier
    reports it, and the provider pulls what it lacks
    (`/pkg/trust/verifier.go`, `/pkg/trust/network.go`); signers cite the
    newest TRC they hold instead of the base; the TRC request without
    numbers already asks for the latest (`/pkg/controlplane/trustservice.go`)
    and the trust database grows the newest-of-ISD query to answer it —
    the discovery duties of the draft's Section 4.1.2. Chain
    verification anchors in the newest pinned TRC's root
    pool rather than the base TRC's.
5.  **Rotation rides the same path.** The founder rolls its own voting
    and root certificates inside the same sensitive update it casts for
    onboarding — the keys are local, and each fresh certificate signs as
    proof of possession. The update's validity is bounded by the
    earliest-expiring certificate it carries, since every certificate must
    cover the TRC's validity; redeploy leaves the rotation story.
6.  **The authoritative behaves as a core.** It originates beacons,
    terminates core beacons into core segments, and serves the core's
    segment-lookup handler — the flag that gates these on the founder
    (`/pkg/controlplane/beacon.go`, `/pkg/controlplane/lookup.go`) selects
    the authoritative tier instead. It enrolls, renews, and pins trust
    material like any node, and it holds no CA keys: the founder stays the
    ISD's issuer. Two origins sharing a link into one child is the
    collision
    [proposal 0034](/docs/proposals/0034-key-the-beacon-store-by-origin-and-bound-the-lookup-cache.md)
    keys the beacon store against — that landing is this one's
    prerequisite.
7.  **Enrollment routes to issuers.** Both core-route paths — the
    one-hop shortcut over a neighboring core and the composed fallback
    over the freshest up segment (`/internal/services/controlplane.go`) —
    select cores whose root certificate is in the newest TRC: exactly the
    nodes that can serve chain renewal. Today that set is the founder
    alone; if issuing ever spreads, the signal follows it without further
    design.
8.  **Down segments register per origin.** A node holding up segments
    from several origins registers its down segments with each originating
    core, since queriers ask every core of the destination ISD
    (`/pkg/controlplane/lookup.go`) — today's registration talks only to
    the one core the route resolves to.

The quorum stays one. The single sensitive voter may change anything a
regular update may not — voting certificates of both kinds, the quorum,
the core and authoritative AS lists, the root certificates — everything
except `noTrustReset`, whose flip is a trust reset: a new base TRC, a
redeploy (Section 3.6). A regular update at quorum one is carried by any
single regular voter, the founder's or an authoritative's. Both are the
accepted price of ADR-0002's coupling.

Non-goals: adding sensitive voters — the founder is the sole sensitive
authority, and onboarding is founder-unilateral by design; a CA on the
authoritative tier — the issuer remains the founder's, so the founder is
still a single point of issuance failure, bounded by the three-day AS
certificate validity; and grace periods — the first updates only add
material, and the draft's grace machinery (Section 3.5) arrives with the
first removals.

### Positive consequences

*   Genesis is unchanged and stays a local call; the anchor set stops
    being frozen at deploy time.
*   Trust material rotates in place — the 365-day expiries stop being
    redeployment deadlines.
*   A second beacon origin and real core segments arrive with the tier
    ADR-0002 promised; the origin-keyed beacon store lands as its
    prerequisite.
*   One mechanism serves onboarding and rotation, and it is the drafts'
    own: the wire artifacts remain stock CP-PKI.
*   The voting-power gate is load-bearing: asked of every submission,
    whatever its submitter enrolled as.
*   Verification stays fail-closed — a TRC no predecessor vouches for
    never enters the database.

### Negative consequences

*   The sensitive key must be online to cast updates; ISDs that keep it
    offline (Section 3.5.6) trade automation for it. The exposure is
    inherited — the founder already signs genesis at startup.
*   Quorum one concentrates authority: one sensitive key can re-make the
    anchor set alone, and one regular key carries a regular update.
*   The update machinery arrives at once: predecessor-aware verification,
    newest-TRC discovery, and the anchoring move from base to newest.
*   Onboarding a second core requires the update path to exist first;
    until it does, the ISD stays single-core as today.
*   A pending answer from the authorizer parks voting power on an
    operator: the joiner's submission retries ask again, so onboarding
    waits on the reply.

## Pros and cons of the options

### Pre-genesis ceremony

*   Good, because the base TRC is complete from the first moment and no
    update mechanism is needed to grow it.
*   Bad, because it violates the zero-ceremony driver — files move between
    machines before genesis, and founding order becomes a deployment
    constraint.
*   Bad, because every later core repeats the ceremony; the anchor set is
    as frozen as before, only larger at founding.

### Named-only fellow cores

*   Good, because it is a one-line change to genesis and needs no
    protocol.
*   Bad, because a named core without a voting certificate is a name
    only — nothing originates from it, and promoting it later needs the
    same sensitive update anyway.
*   Bad, because it spends the one immutable artifact, the base TRC, on a
    half-member.

### Sensitive-vote onboarding

*   Good, because the founder assembles and votes alone, and the drafts'
    own control services carry the joiner's single co-signature.
*   Good, because the identical mechanism rotates certificates.
*   Bad, because it builds the update verification and discovery machinery
    before the first core can join.
*   Bad, because onboarding is founder-unilateral; there is no second
    opinion by design.

### Role gated at enrollment

*   Good, because the operator refuses a core joiner before any chain is
    issued.
*   Bad, because the drafts' renewal body must grow a CION field to carry
    the certificate.
*   Bad, because the gate binds only honest presentations — a node
    enrolled without the certificate reaches the cast ungated, and any
    chain-holder may submit.

### Role gated at the cast

*   Good, because the drafts' wire forms stay untouched: the certificate
    rides inside the successor, where the draft already requires it.
*   Good, because the question stands where the power is granted — every
    submission is asked, whatever its submitter enrolled as.
*   Bad, because the role is invisible at enrollment; the audit that
    would flag a core joiner early arrives only with the cast.

### Proxy renewals

*   Good, because it asks nothing new of trust material.
*   Bad, because it adds a hop to every renewal while the founder remains
    required at renewal time — availability does not improve.

### A CA on every core

*   Good, because it removes the founder as the single point of issuance.
*   Bad, because it departs from ADR-0002's coupling, gives every issuer a
    WebPKI identity to serve enrollment, and ends the issuer's
    single-root assumption (`/pkg/trust/issuer.go`).

### The root-certificate signal

*   Good, because the TRC already carries the answer and every node pins
    it — no new state, and the set tracks issuance wherever it spreads.
*   Bad, because it is an indirection: the router must know why the root
    certificate, not the voting certificate, is the signal.

### Rotation by redeploy

*   Good, because it exists and asks nothing new.
*   Bad, because redeploying a working ISD to outlive a certificate
    expiry stops being acceptable the moment a second member exists.

### Rotation by regular update

*   Good, because it is multi-party and the periodic case the draft
    designs it for.
*   Bad, because a regular update cannot touch the anchor set — it leaves
    the core ASes and sensitive voting certificates unchanged — so it
    cannot onboard a core, and at quorum one it buys no second opinion
    either.

### Rotation by sensitive update

*   Good, because one path serves onboarding and rotation, and the founder
    holds every key it needs.
*   Bad, because it is founder-unilateral, and the sensitive key it needs
    is online.
