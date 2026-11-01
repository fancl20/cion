# Remove cores and nodes

This proposal implements
[ADR-0034](/docs/adrs/0034-verify-each-chains-membership-and-remove-cores-at-once.md)'s
decisions 7 to 9:

*   The founder removes a core at once, by its vote alone, and the core
    never returns.
*   Honest nodes fall back on their memberships.
*   No core casts a TRC update alone.
*   What the core signed expires.
*   The founder ends a node's membership by not renewing it.

The operator removes either from the console's node list. The removal is the
PKI draft's sensitive update, so the trust engine casts it. How long the
removed root keeps anchoring, and whether a node leaves at all, are the
membership method's: under `none`, a core leaves with the roll's grace period
and no node leaves. Reporting forgeries (decision 6) follows in a later
proposal.

[TOC]

## Summary

Today:

*   **No code removes a core.** `AssembleOnboarding`
    ([update.go](/pkg/core/trust/update.go)) adds a core, and
    `AssembleRotation` ([rotation.go](/pkg/core/trust/rotation.go)) replaces
    certificates; nothing drops a certificate or an AS entry. The console's
    one write releases a host's address
    ([records.go](/pkg/apps/portal/records.go)).
*   **No node leaves.** The founder renews a bound key whatever the operator
    decides: a membership renewal (`bound`,
    [founder.go](/pkg/modules/membership/impl/founder/founder.go)) and a
    re-enrollment (`checkFirstIssuance`,
    [trustservice.go](/pkg/core/controlplane/trustservice.go)) read the
    binding alone.
*   **A node presents the chain it received last.** `Engine.Chain`
    ([engine.go](/pkg/core/trust/engine.go)) picks the newest valid chain
    without the anchor pool, so a chain whose root left the TRC is presented
    until another replaces it. The enrollment loop then rests its renewal on
    no chain and re-enrolls at the founder (`renewable`,
    [lifecycle.go](/pkg/core/trust/lifecycle.go)), and the membership
    renewal fails until it has (`renewMembership`,
    [membership.go](/internal/services/membership.go)). The signer already
    passes over a chain the pool does not anchor.
*   **A membership renews only as it runs short.** The founder method renews
    below the renewal threshold (`current`), so a membership under a founder
    root a roll replaced counts only while the roll's grace period runs.
*   **A core's issuer never unanchors.** `Issuer.Anchored`
    ([issuer.go](/pkg/core/trust/issuer.go)) stays true once set: a core
    whose root left the TRC self-issues a chain under it at every pass, and
    after a restart submits its onboarding again.
*   **The founder votes on whatever a core submits.** `DecideTRC`
    ([trccast.go](/pkg/core/trust/trccast.go)) checks only the certificates
    a submission adds. One that drops another core or adds the presenter's
    own sensitive voting certificate gets the founder's vote on the policy's
    allow, a risk [security.md](/docs/design/security.md) records.
*   **A core casts a regular update alone.** With a quorum of one, a core's
    regular voting key votes a regular update by itself, and a node pins the
    first update of a serial it meets (`verifyAndPinTRC`,
    [network.go](/pkg/core/trust/network.go)). A core racing the founder's
    update with its own forks the TRC wherever its update arrives first.
*   **The lookup asks every origin it holds.** Core segments are asked of the
    origins of the held up segments (`reachableCores`,
    [lookup.go](/pkg/core/controlplane/lookup.go)), whatever the TRC names.

## Motivation

### Goals

*   The operator removes a core from the console, and its root anchors
    nothing wherever the update arrives.
*   Honest nodes keep linking and renewing through a removal, on their
    memberships.
*   A removed core stays removed: it stops, and the founder decides nothing
    it submits.
*   The operator removes a node from the console, and the founder renews it
    no more.
*   The founder's vote alone removes any core: no core casts an update
    alone.
*   Under `none`, a removed core keeps the roll's grace period, and no node
    leaves.

### Non-goals

*   Reporting a forgery to the founder.
*   Purging or revoking anything a removed core or node holds: it expires.
*   Re-checking the channels a node opened before a removal reached it.
*   Watching staleness and expiry in the labs: the five-minute,
    fifteen-minute, and six-hour constants take no pacing.

## Proposal

### Removing a core

*   **The update.** The removal is a sensitive TRC update the founder's
    sensitive voting key alone votes. The successor carries its
    predecessor's certificates without the core's root and regular voting
    certificates, and both AS lists without the core; the quorum and
    noTrustReset stand. Its validity runs from the cast to the earliest
    expiry among the certificates it carries, so a grace period runs from
    the cast. The removed certificates sign nothing: cppki's rules for a
    sensitive update ask only the vote.
*   **The grace period.** The membership method names it: none under the
    founder method, whose memberships stand in for the removed chains; the
    roll's, the AS certificate validity of three days, under `none`, where
    nothing does.
*   **The cast.** The founder's TRC decision casts the update under the lock
    its submissions and the founder's roll take, verifies it against the
    newest pinned TRC, and pins it. A core the newest TRC does not name is
    removed already, and the founder never removes itself.
*   **The reach.** Nothing pushes the update. The founder's signed messages
    cite it, and a node fetches it from the message's sender, or from the
    founder when the sender refuses the node's channel, as it fetches a roll
    today. Once a node pins it, the core's root leaves the node's anchor
    pool. A removal cast inside an earlier update's grace period closes that
    period too: the pool holds one predecessor.

### Falling back on the membership

*   **The node's chain.** Wherever a node takes its own chain — its
    handshakes, its chain renewal, and its membership renewal — it takes the
    newest of its valid chains that verifies against its anchor pool. Once a
    removal pins, the removed core's chain drops out, and the membership, a
    chain the founder issued, takes its place, presenting nothing beside
    itself.
*   **Renewal.** The enrollment loop renews a chain the newest TRC alone
    does not anchor, as it does today, resting the request on the node's
    chain at an issuer the TRC still names. A node holding no anchored chain
    re-enrolls at the founder.
*   **The membership re-anchors.** The founder method renews the membership,
    as the loop renews a chain, once the newest TRC alone does not anchor
    it. A minute after a founder roll, every live node holds a membership
    under the new root, and a removal strands none.
*   **The update's spread.** A node that has not pinned the removal still
    presents the removed chain, and the peers that pinned refuse its new
    channels until it does. The update reaches it over the channels it
    holds, and from the founder.

### The removed core

*   **It stops.** A core that pins a TRC naming it no more, after an earlier
    one named it, stops with the removal as the cause, as a core without a
    voting application does. A restart stops it again: every node holds its
    ISD's TRCs back to the base.
*   **It never returns.** The founder refuses every submission of a core an
    earlier TRC named and the newest does not, before it asks the admission
    policy.
*   **Its node leaves with it.** Removing a core removes its node too, by the
    membership method's rule below.

### Removing a node

*   **The record.** Under the founder method, the founder's binding records
    the removal. The name stays bound to its key, so no other key takes it,
    and the founder refuses from then on the node's renewals, its
    re-enrollment, and every TRC submission it presents.
*   **The lapse.** Nothing else refuses the node at once. Its last membership
    counts at a node until that node's own is more than the window newer,
    within about five days while the founder is live, and until then any
    other core renews its chain. Its chains, which the TRC alone verifies
    behind signed messages, sign until they expire.
*   **Under `none`.** Memberships never lapse and no node leaves: removing a
    node records nothing, so removing a core removes the core alone.

### No core casts an update alone

*   **Every update carries the founder's signature.** A node pins a TRC
    update only where a sensitive voting certificate of its predecessor
    signed it, beside the signatures cppki requires: the vote of a sensitive
    update, or the signature the founder's decision adds to a regular update
    before pinning it. A core's update the founder never saw pins nowhere,
    so no core forks the TRC.
*   **The founder signs only a core's own material.** The presenter's
    certificates and its AS entries are its own: an onboarding adds a
    regular voting and a root certificate naming it and appends its AS to
    both lists, and a roll replaces those certificates. The decision refuses
    a submission changing anything else, before it asks the admission
    policy.

### What the core signed

Nothing is purged. Once a node pins the removal:

*   Nothing signed under the removed root verifies there.
*   The beacons the core originates fail the origin check, so the paths it
    originated stop being refreshed, read stale within five minutes, lose to
    any fresh path, and expire with their hop fields.
*   The lookup asks core segments only of the cores the newest TRC names.
*   Its node signs under its other chains until they expire, as any removed
    node does. Once it stops, its directory entries leave the views within
    the entry lifetime.

### The console

*   **The action.** Each row the operator can remove carries Remove: every
    core, and every node whose membership lapses, never the founder. The
    console asks for confirmation first.
*   **What it does.** The founding core removes the node from the TRC first
    when the TRC names it a core, then hands it to the membership method.
    Both steps are idempotent, so a repeat finishes what a failure left.
*   **The listing.** A removed node shows Removed in place of its expiry
    until its membership lapses and the row drops off. A removed core lists
    as a node from its removal on.
*   **The labs** call the same removal through the assembled node.

### Packages touched

| Package                  | Change                                                        |
| :----------------------- | :------------------------------------------------------------ |
| `pkg/core/trust`         | The removal and its cast, the founder's signature on every pin, the own-material gate, the anchored chain, the removed core's stop |
| `pkg/core/controlplane`  | Re-enrollment refuses a removed node; the lookup's cores by the TRC |
| `pkg/modules/trustdb`    | The removal recorded beside the binding                       |
| `pkg/modules/membership` | Removing a node, the removal's grace period, re-anchoring, the removed mark |
| `internal/services`      | The removal's assembly; the membership renewal on the anchored chain |
| `pkg/apps`               | The console's Remove and the removed mark                     |

## Compatibility

A node of this change pins only updates the founder signed, so a network
whose TRCs hold a regular update cast before it admits no new node: networks
start afresh, as none is in production.

## Test plan

*   **The removal update:** it drops the core's certificates and AS entries
    and keeps the rest, starts its validity at the cast, carries the
    method's grace period, and verifies against its predecessor as a
    sensitive update the founder's vote alone signs. Removing the founder is
    refused, and removing a removed core changes nothing.
*   **The pool:** without a grace period, the removed root anchors nothing
    from the pin; with three days, it anchors until they end.
*   **The founder's signature:** a regular update without it pins nowhere,
    fetched or completed; the decision signs a regular submission before
    pinning it.
*   **The own-material gate:** a submission dropping another core's
    certificate or entry, adding a sensitive voting certificate, a second
    root, or another holder's certificate, appending another AS, or changing
    the quorum is refused before the policy is asked; an onboarding and a
    roll pass.
*   **The removed core:** a core pinning its removal stops with it, after a
    restart too; the founder refuses its submissions.
*   **The anchored chain:** the handshake, the chain renewal, and the
    membership renewal take the newest chain the pool anchors, the
    membership once a removal pins.
*   **Re-anchoring:** the founder method renews a membership the newest TRC
    alone does not anchor.
*   **Removing a node:** the founder refuses a removed node's renewals,
    re-enrollment, and submissions; another core renews its chain while its
    membership counts; the listing marks it removed; `none` records nothing.
*   **The lookup** asks no core the newest TRC does not name.
*   **The console:** Remove removes a core and a node, refuses the founder
    and a membership that never lapses, and the list marks the removed.
*   **The labs:**
    *   Removing a core: in the core trio, the normal node holds a chain the
        authoritative core issued. Once the operator removes that core,
        every node pins the removal, the normal node keeps its handshakes on
        its membership and renews at the founder, a chain the removed core
        issues passes no handshake, and the removed core stops.
    *   Without memberships: with `none` on every node, the removed core's
        chains still pass handshakes inside the grace period, and the core
        stops.
    *   Removing a node: the founder refuses the removed node's renewals,
        and once its membership lapses, its handshakes.
    *   The console removes a node and lists it as removed.

## Implementation history
