# Verify Each Chain's Membership and Remove Cores at Once

*   Status: proposed
*   Date: 2026-10-31

[TOC]

## Context and problem statement

Since [ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md), every
core holds a CA key online. Verification checks only that a chain anchors
in a root certificate of the TRC: nothing limits the names a root's chains
certify. A core whose keys leak lets anyone join without the founder's
approval: its key mints a chain for a name the founder never admitted, or
for an admitted name under another key, and every verifier accepts either.
ADR-0033 accepted that risk: only expiration retires such a chain.

Standard SCION bounds that risk with people: an AS takes part only through
links its neighbors' operators configure, so a chain alone connects
nothing. CION forms links by itself
([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)):
a node meets its peers at the rendezvous exchange, and the selection keeps
the links it measures worth having. No operator stands between a chain and
the topology, so a node holding a forged chain links to any node that
answers it.

The founder already binds each ISD-AS to its key at first issuance, for
good (ADR-0033, decision 4). The binding gates re-enrollment at the founder
alone: no other node can read it, and a renewal checks none.

A leaked core is also removed slowly. A sensitive TRC update removes it,
but CION's updates keep the predecessor active for the AS certificate
validity, three days, so the leaked root keeps anchoring chains that long.

Nor does a node ever stop being a member. Any core renews it on its current
chain, so a node keeps its place for as long as the TRC is valid, whether
it is decommissioned or its key leaked; the SCION PKI draft instead lets an
issuer drop a node by not renewing it.

A node renews its chain once less than a day of the AS certificate's three
remains, so a chain renewed on time is at most two days old.

Since [ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md),
every node holds the directory of each scope it is in, and scopes follow
links: no directory reaches every node.

## Decision drivers

*   **Joining takes the founder's approval:** a leaked core key links no
    identity the founder did not admit, neither a name it never admitted
    nor another key for an admitted one.
*   **Founder outages stay survivable:** the network outlives a founder
    outage as long as ADR-0033 lets it, the TRC's validity.
*   **Checks need no founder online:** a verifier checks an identity from
    what it holds and what the peer presents.
*   **Today's trust anchors suffice:** a check needs no TRC but those the
    node already pins.
*   **A forgery is evidence:** a refused forgery names the core that
    issued it.
*   **Removal is prompt:** a removed core anchors nothing once the removal
    reaches a node, and what it signed retires on its own.
*   **The founder's vote alone:** a compromised core cannot block its own
    removal.
*   **The draft's formats:** chains and TRCs stay as the draft defines
    them.

## Considered options

How a verifier learns a name's key:

*   **Ask the founder online.**
*   **Constrain the names each issuer certifies.**
*   **An issuance log with proofs of inclusion.**
*   **A founder-signed binding the node carries.**

What the binding is:

*   **The first chain the founder issued,** kept for good.
*   **A membership the founder renews, valid for a fixed period.**
*   **A membership the founder renews, judged against the checker's own.**

How a core is removed:

*   **A TRC update with the roll's grace period.**
*   **A TRC update without a grace period.**

## Decision outcome

Chosen options: **a founder-signed binding the node carries**, which is
**a membership the founder renews, judged against the checker's own**, and
cores removed by **a TRC update without a grace period**. This narrows
ADR-0033's accepted risk:

1.  **Membership is the binding.** A node's membership is a chain the
    founder issued for the node's key under the founder's own CA. The
    first comes with first issuance. Only the founder issues one.
2.  **The node renews its membership at the founder,** as it renews its
    chain: before the membership runs short. The founder renews a member,
    and re-enrolls a node under the key its name is bound to, without
    asking the admission policy, unless the operator removed the node.
    While the founder is down, the renewal waits, and the membership the
    node holds still counts.
3.  **A membership is judged against the checker's own.** A membership
    counts at a node if it verifies through a founder CA certificate to the
    founder's root certificate in the node's anchor pool, and the founder
    issued it no more than three days before the node's own membership.
    While the founder is live, every member renews about every two days,
    so live members' memberships lie within two days of each other, and
    one its holder stopped renewing falls behind and lapses. While the
    founder is down, no node renews, so the latest memberships keep
    counting, whatever the date. The check compares two times the founder
    stamped and reads no node's clock. No other core's root certifies a
    membership, and no past TRC is needed.
4.  **Every peer's chain is checked against a membership.** The chain a
    peer presents in a channel's handshake, and the chain a renewal
    request rests on, are accepted only if a membership that counts binds
    its ISD-AS to its key, so a forged identity links to no node. A signed
    message's chain verifies against the TRC alone: the message reaches a
    node only over a channel whose handshake checked the peer, and a
    member signing under a forged identity is told apart no better than
    one holding a stolen key.
5.  **The node carries its membership.** A node presents its membership
    beside its chain in the handshake of the SCION-native channel.
6.  **A forgery is reported.** A chain that verifies against the TRC but
    no membership backs is a forgery, and the root it anchors in names the
    core that issued it. The verifier refuses it and reports the evidence
    to the founder; the operator answers with that core's removal.
7.  **The founder removes a core at once.** A sensitive TRC update, cast by
    the founder's vote alone, removes the core's root certificate, its
    voting certificates, and its core and authoritative entries, with no
    grace period: the core's root leaves a node's anchors as soon as the
    node pins the update. Every chain anchored in that root stops
    verifying, honest nodes' included. Those nodes fall back on their
    membership, itself a chain the founder issued: it verifies in the
    removed chain's place and authorizes their next renewal at another
    core. The founder is live when it removes a core, so their memberships
    are current.
8.  **What the core signed expires.** No node purges it. Once a node pins
    the removal, the core's new entries and beacons no longer verify there:
    its held directory entries leave the views within the entry lifetime,
    and the paths that cross it stop being refreshed, read stale within
    five minutes, and lose to any fresh path. They expire with their hop
    fields. Transit is trusted to forward and nothing else, so a path
    through the core exposes nothing a path through any other node does
    not.
9.  **The founder ends a membership by not renewing it.** A node the
    operator removes is refused its next renewal, and its chains stop
    verifying at a node once that node's own membership is more than three
    days newer than the removed node's last.
10. **A network may go without memberships.** Its operators decide for the
    whole network, alike on every node: a node that checks memberships
    refuses a peer that carries none. Without memberships, the network is
    ADR-0033's: a chain verifies against the TRC alone, a core leaves with
    the roll's grace period, and no node leaves. Links its operators
    configure bound that risk, as standard SCION's do.

### Positive consequences

*   Joining takes the founder's approval, whatever core keys leak: a chain
    for an unadmitted name has no membership, and one for an admitted name
    certifies another key. Every honest node refuses both in its
    handshakes, so neither links, with the founder down too.
*   The network outlives a founder outage for as long as the TRC is valid,
    as under ADR-0033: no membership lapses while no node renews.
*   A membership verifies against the TRCs a node already pins, and its
    check reads no node's clock.
*   Each forgery names the core whose key issued it.
*   A removed core anchors no chain once the update reaches a node, and
    its removal costs honest nodes nothing: their memberships stand in for
    the chains it issued.
*   The operator removes a node by a decision at the founder alone; while
    the founder is live, the node is out within about five days.
*   The founder issues every membership, so it knows each node's latest,
    whichever directory scope the node is in.
*   Memberships, chains, and TRCs keep the draft's formats.
*   A network whose links its operators configure can go without
    memberships, bounded as standard SCION is.

### Negative consequences

*   Every node renews its membership at the founder, beside its chain at
    any core.
*   A network takes memberships whole: a node that decides apart from its
    peers refuses them or is refused.
*   A membership counts by its distance from the checker's own rather
    than by its validity times, a rule the draft's path validation does not
    have.
*   A node that misses its renewals while the founder is live is refused
    once its peers' memberships are three days newer, until it renews.
    After a founder outage longer than three days, a node that has renewed
    refuses the peers that have not yet, until they renew.
*   A node that cannot reach the founder judges memberships against its
    own older one, and accepts what its renewed peers refuse.
*   While the founder is down, no node is removed and no core either.
*   A compromised founder still forges any membership: its CA key is
    online.
*   A member holding a leaked core key still signs messages under forged
    identities, and every node verifies them against the TRC alone, as it
    does the messages of a member whose own key leaked.
*   Each node keeps a membership for every peer it has met, and the
    handshake carries two more certificates.
*   A removal acts at a node only once the update arrives there; until
    then, the node accepts the core's chains.
*   After the removal, the core's directory entries linger up to the entry
    lifetime, fifteen minutes, and a path through it still serves, for up
    to its hop fields' six hours, where no fresh path reaches the
    destination.

## Pros and cons of the options

### Ask the founder online

*   Good, because the founder's own records answer.
*   Bad, because the founder returns to every verification: while it is
    down, no new peer verifies.

### Constrain the names each issuer certifies

*   Good, because a leaked key certifies only its own core's names.
*   Bad, because any core renews any node (ADR-0033), and only the founder
    admits names: a constraint ends renewal at every core.

### An issuance log with proofs of inclusion

*   Good, because every issuance is public, the founder's included.
*   Bad, because it binds an attacker only where verifiers demand a proof:
    a log, its proofs, and its monitors, for what a binding gives at this
    scale.

### A founder-signed binding the node carries

*   Good, because a verifier checks a name's key from what the peer
    presents, with no founder online.
*   Bad, because every verification carries and checks one more artifact.

### The first chain the founder issued, kept for good

*   Good, because first issuance already signs it: nothing to renew.
*   Bad, because checking it needs the TRC history: the root that signed
    it may have rolled since.
*   Bad, because a binding never ends: a node stays a member for good.

### A membership the founder renews, valid for a fixed period

*   Good, because it verifies by the draft's own validity rules.
*   Bad, because the network then outlives a founder outage only for that
    period, against the TRC's validity under ADR-0033.

### A membership the founder renews, judged against the checker's own

*   Good, because a founder outage lapses nothing, and a live founder still
    lets a membership it stops renewing lapse.
*   Good, because it verifies against today's anchors and reads no node's
    clock.
*   Bad, because a membership counts by its distance from the checker's
    own, a rule of CION's own: after a long founder outage, renewed nodes
    refuse the rest until they renew.

### A TRC update with the roll's grace period

*   Good, because the update rolls like any other.
*   Bad, because the removed root anchors chains for three more days.

### A TRC update without a grace period

*   Good, because the removed root stops anchoring at once.
*   Bad, because the honest chains under it stop verifying at once too,
    leaving their nodes to their memberships.
