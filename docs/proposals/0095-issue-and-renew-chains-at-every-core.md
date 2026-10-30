# Issue and renew chains at every core

This proposal implements
[ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md). Every core holds a
root key and a CA key, and its root certificate enters the TRC with the
update that onboards it. A core renews its own chain, and any node's chain on
the node's current chain. First issuance stays with the founder, which binds
each ISD-AS to its key for good. A node with a chain renews at any core and
enrolls at the founder without one. An authoritative core rolls its root by
regular update. It depends on
[proposal 0094](/docs/proposals/0094-fetch-a-registered-segments-chains-from-its-registrant.md):
once several cores issue, no core holds every chain.

[TOC]

## Summary

The founder is the ISD's only issuer. Its root is the TRC's only root, and
its issuer refuses a TRC that carries more than one
([issuer.go](/pkg/core/trust/issuer.go)). The authoritative core creates no
root or CA key ([keys.go](/pkg/core/trust/keys.go)) and renews at the
founder like any node ([lifecycle.go](/pkg/core/trust/lifecycle.go)).

A renewal rides the bootstrap channel, whose TLS identity is the founder's
domain ([remote.go](/pkg/core/webpki/remote.go)). The request is signed by
the CSR's key, under a certificate minted on the spot
([renewal.go](/pkg/core/trust/renewal.go)), and the trust service tells a
renewal from a first issuance by its own records: an unexpired chain of the
name under the same key
([trustservice.go](/pkg/core/controlplane/trustservice.go)). With the
founder down, renewal stops, and every chain lapses within three days of its
last renewal.

Beyond the issuer, five more places assume the founder is the only core with
a root:

*   **One route for everything.** The core client, the voting submitter, and
    both directory clients ride one route, to a core whose root the TRC
    carries ([controlplane.go](/internal/services/controlplane.go)). Once an
    authoritative core holds a root, an enrollment could reach a core
    without the founder's WebPKI identity, and a submission a core without
    the voting application. An onboarding submission that lands there stops
    the joining core.
*   **The founder's decision** admits a submission only from a presenter
    whose chain is in the founder's own database
    ([trccast.go](/pkg/core/trust/trccast.go)), which holds only the chains
    the founder issued.
*   **One name for every root.** Every root certificate is named `cp root`
    ([certs.go](/pkg/core/trust/certs.go)). cppki reads a certificate's
    name by its standard attributes alone and refuses a TRC whose roots
    share one.
*   **The rotation watch** rolls when the earliest expiry among the
    certificates the TRC names for the core nears
    ([rotationwatch.go](/pkg/core/trust/rotationwatch.go)). The
    authoritative core's roll replaces its voting certificate alone
    ([rotation.go](/pkg/core/trust/rotation.go)), so a root among its
    certificates would trigger a roll at every pass once due. Every TRC's
    validity ends at its earliest-expiring certificate, so that root would
    also cap the ISD's TRC.
*   **The name check** reads unexpired chains in the founder's database.
    Once a name renews elsewhere, its chain there expires and is swept, and
    the name reads as free.

## Motivation

### Goals

*   Every core's root certificate is in the TRC, entered by the sensitive
    update that onboards the core and signed by the root's key. A core
    onboarded before this proposal adds its root by a sensitive update of
    its own.
*   A core whose root is in the newest TRC renews its own chain itself.
*   Any core whose root is in the TRC renews any node whose current chain
    verifies against the TRC, for the same key, without asking an admission
    policy.
*   The founder alone issues a first chain, and binds the name to its key
    for good; every other core refuses one.
*   A node with a valid chain renews at any issuer and moves on from one
    that fails. A node without one enrolls at the founder, and every
    submission reaches the founder.
*   An authoritative core rolls its root and CA keys with its voting key, by
    a regular update its own keys sign.

### Non-goals

*   First issuance and TRC updates with the founder down, and the TRC's
    extension beyond its validity: ADR-0033 keeps both with the founder.
*   Limiting the names an issuer signs, and revocation. A compromised core
    can issue a chain for any name, a consequence ADR-0033 accepts.
*   The node directory's replication
    ([ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)):
    future work.
*   The renewal request's payload, which stays CION's request body rather
    than the reference implementation's bare CSR.

## Proposal

### Root certificates name their holder

A root certificate's common name carries its holder's ISD-AS,
`<ISD-AS> cp root`, as a voting certificate's does. A roll pairs each fresh
certificate with the predecessor's certificate of the same class naming the
same ISD-AS, where today it pairs by name. The founder's root, minted as
`cp root`, thus takes the new name at its next roll, a sensitive update,
which may rename a certificate. An authoritative core's root keeps its name
across rolls, as the regular update's rules require (PKI draft, Section
3.5.4).

### The authoritative core's issuing keys

*   **`LoadOrCreateIssuerKeys`** returns the root key and the CA key,
    creating them on first start in the files the founder uses
    (`cp-root.key` and `cp-ca.key`). The two tiers never share a state
    directory. The founder's `CoreKeys` carry the same `IssuerKeys` beside
    its voting keys.
*   **`LoadOrCreateRootCert`** mints the self-signed root certificate once
    the identity completes and persists it as `cp-root.crt`. A persisted
    certificate that does not cover the key or name the ISD-AS is refused.
    This is the voting certificate's construction, so a retried onboarding
    presents the same bytes.

### The onboarding carries the root

`AssembleOnboarding` appends the joiner's root certificate beside its voting
certificate, and the joiner signs the successor with both keys: the root's
signature is its proof of possession (PKI draft, Section 3.5.6). The
successor changes the number of roots, so it is a sensitive update, and the
founder votes on it on the admission policy's allow. The policy is told both
keys.

A core the predecessor already names but whose root it lacks was onboarded
before this proposal. For it, the assembly appends the root alone, signed by
the root key, and the founder's vote rests on the same policy, told the
root's key.

The joining core owes the onboarding until the newest pinned TRC names it
and carries its root ([lifecycle.go](/pkg/core/trust/lifecycle.go)).

### The founder's decision

*   **The presenter is the channel's.** The verified peer channel admits a
    chain only if it verifies against the founder's newest pinned TRC,
    whichever core issued it. The decision stops reading the presenter's
    chains from its own database.
*   **What a submission adds is its presenter's.** Every certificate a
    submission adds must name the presenter, and every root certificate it
    adds must have signed the submission. cppki checks a new voting
    certificate's proof of possession but not a root's.

### Every issuer picks its own root

The issuer takes the root and CA keys alone. It selects the root
certificate its root key covers among the TRC's roots: at construction, at
each re-issue of its CA certificate, and at each rekey. While the TRC
carries no root of its own, the issuer is unanchored and issues nothing.
`Anchor` hands it a TRC that carries its root.

The authoritative core builds its issuer at boot. The issuer is anchored
there when the newest pinned TRC carries the core's root, and otherwise when
the onboarding lands.

### A core renews its own chain

The authoritative core's renewal self-issues through its issuer once the
issuer is anchored, as the founder's does. Until then it renews as a normal
node does.

### Renewal on the current chain

*   **The request.** A node whose valid chain verifies against its anchor
    pool signs its renewal request with its AS key, and the request carries
    the chain: the AS and CA certificates (PKI draft, Section 4.3). The CSR
    certifies the same key. A node without one signs with the CSR's key
    under a minted certificate, as today.
*   **A renewal.** The trust service reads a request that carries a chain as
    a renewal. The chain must verify against the service's anchor pool, the
    newest pinned TRC and its predecessor in its grace period. Its AS
    certificate must have signed the request, name the CSR's ISD-AS, and
    certify the CSR's key. A renewal checks no name and asks no policy.
*   **A first issuance.** A request signed by the CSR's key alone is a first
    issuance. The founder serves it as described below; every other core
    answers `FailedPrecondition`.
*   **An unanchored issuer** answers `Unavailable`.

The issuer stores every chain it issues, as today, so its chains service
serves them.

### First issuance binds the name

The trust database gains the bindings: `BoundKey` reads the subject key an
ISD-AS is bound to, and `BindKey` binds a free ISD-AS to one. The bbolt
store keeps them in a bucket of their own that no sweep touches. The
founder's first issuance:

*   **A name bound to another key** is refused with `AlreadyExists`.
*   **A name bound to the same key** is issued without asking the policy: a
    holder whose chain lapsed re-enrolls.
*   **A free name** asks the policy and, on its allow, is bound to the key
    and issued.

The binding, the policy's question, the issuance, and the insert hold the
renewal mutex together, as the name check does today, and the binding
replaces the name check. At boot, the founder binds every ISD-AS that holds
an unexpired chain in its database: until this proposal, the founder issued
every chain.

### The founder's route, and the issuers'

*   **The founder** is the holder of the newest pinned TRC's sensitive
    voting certificate (`Engine.FounderAS`).
*   **The founder route** replaces the core route: a link to the founder
    when one is up, the freshest up segment from the founder, and the
    bootstrap beacon's route. Before the TRC is pinned, the bootstrap route
    takes turns among the beacons' origins as today; after, it takes the
    founder alone. The core client, the voting submitter, and both
    directory clients ride it.
*   **The issuer routes** list the cores whose root the newest pinned TRC
    carries: those a link reaches first, then the others by the freshness of
    their up segments.
*   **The issuer remote** (`PeerClient.Issuers`) serves TRCs, chains, and
    renewals over the verified peer channel to the issuer the routes list
    first. A call that fails moves its next call to the next issuer.

The enrollment loop hands the renewal the node's valid chain. A chain that
verifies against the node's anchor pool renews through the issuer remote,
and a node without one enrolls through the core client.

### The authoritative core rolls its root

The authoritative core's roll replaces its voting certificate and its root
certificate together, and rekeys its CA beside them, as the founder's roll
does:

*   **Staging.** The roll stages the fresh voting key and certificate, the
    fresh root key and certificate, and the fresh CA key in one write, and
    reuses them on every retry.
*   **A regular update.** While the live keys cover the newest TRC's
    certificates, the live voting key votes, the live root key signs (PKI
    draft, Section 3.5.4), and both fresh keys prove possession. The founder
    pins the update as submitted.
*   **A sensitive update.** When a live key no longer covers its
    certificate, the fresh keys alone sign, and the founder votes on the
    policy's allow.
*   **The pin.** Once pinned, the issuer rekeys onto the fresh root and CA
    keys, then the staged material promotes.

The rotation watch's check covers the root key beside the voting key.

### The design overviews

The [security model](/docs/design/security.md) lists the risk the issuing
cores add: every core holds CA keys online, and a compromised core issues
for any name. Losing the founder halts enrollment and TRC updates, no longer
renewal. The [architecture](/docs/design/architecture.md) follows: a node
renews at any core.

### The labs

*   **`NodePacing.RenewalThreshold`** overrides the renewal threshold, so a
    lab can renew at every inspection.
*   **The founder-down lab** runs a founder, an authoritative core, and a
    normal node linked to both, renewing at every inspection. Once the
    authoritative core's root lands, the founder stops. Both other nodes
    keep renewing: each one's newest chain is issued after the stop, under
    the authoritative core's root.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/core/trust` | Root names; the authoritative core's issuing keys and root certificate; the onboarding's root; the decision's gates; the issuer's own root and its anchoring; self-renewal; the request on the current chain; the founder's bindings at boot; `FounderAS`; the authoritative core's roll |
| `pkg/core/controlplane` | Renewal on the current chain at every issuer, first issuance at the founder alone; the issuer remote; the bootstrap route takes the founder |
| `pkg/core/webpki` | The core client's renewal carries the requester's chain when it holds one |
| `pkg/modules/trustdb` | `BoundKey` and `BindKey`, in the bbolt store and the shared test suite |
| `internal/services` | The authoritative core's keys, issuer, and trust service; the founder and issuer routes; the founder's bindings at boot; `RenewalThreshold` |
| `internal/testnetwork` | The founder-down lab; the join, rotation, and two-core path labs check the issuing cores |
| `docs/design` | The security model and the architecture |

## Compatibility

*   **The wire.** A renewal request may carry the requester's chain. First
    issuance and re-enrollment keep today's form, which the founder still
    accepts.
*   **State.** An authoritative core creates its root and CA keys and its
    root certificate. The founder's trust database gains the bindings.
    Roots minted before keep their name until they roll.
*   **Upgrade order.** Upgrade the founder first, then the normal nodes,
    then the authoritative cores. An older founder refuses a TRC that
    carries two roots, and would not boot on one. An older node renews over
    the bootstrap channel at any core whose root the TRC carries, and fails
    at an authoritative core. An authoritative core's root enters the TRC
    only once that core runs this version.

## Test plan

The episodes follow ADR-0033's decisions.

1.  **Every core is an issuer.**
    *   A root certificate names its holder. A TRC carrying the founder's
        and an authoritative core's roots validates, and the founder's
        `cp root` takes the new name at its roll.
    *   The onboarding carries both certificates and both signatures, and
        cppki classifies it a sensitive update that verifies. A core named
        without a root adds the root alone. The decision refuses an added
        root without its signature and a certificate naming another
        ISD-AS.
    *   The issuer picks its own root among several, and stays unanchored
        until its root lands.
    *   The join lab: once the core joins, the newest TRC carries its root,
        and both cores issue.
2.  **A core renews its own chain itself.** The authoritative core's
    renewal self-issues once its issuer is anchored and renews remotely
    before. In the join lab, the joiner's chain comes to issue under its
    own root.
3.  **Any issuer renews any node.**
    *   The trust service renews on a chain another issuer signed, without
        asking a policy that would deny. It refuses a chain that does not
        verify against its pool, a CSR for another ISD-AS or another key,
        and a request the chain's key did not sign.
    *   A node's request carries its chain when it holds a valid one, and
        the minted certificate when it does not.
4.  **First issuance stays with the founder.**
    *   An authoritative core refuses a request signed by the CSR's key
        alone, asking no policy.
    *   The founder binds a name at its first issuance. Once the name's
        chains expire and are swept, a request for it under another key
        is still refused, and its holder re-enrolls without the policy.
    *   The founder's boot binds every name holding an unexpired chain.
5.  **A node renews at any issuer.**
    *   The founder route names the founder alone, by link, up segment, or
        bootstrap beacon, and passes over an authoritative neighbor. The
        issuer routes list a linked issuer first, and a failed call moves
        to the next.
    *   The join lab's core joining through an authoritative neighbor
        submits to the founder.
    *   The founder-down lab: renewals keep succeeding with the founder
        stopped. Against the node before this proposal, with the
        threshold's override alone, they stop.
6.  **TRC updates stay as they are.**
    *   The authoritative core's roll is a regular update carrying the
        live voting key's vote, the live root key's signature, and both
        fresh keys' proofs, pinned as submitted. A live root key that no
        longer covers its certificate rolls by sensitive update. After
        the pin the issuer rekeys and the staged material promotes. The
        watch rolls on a mismatched root key.
    *   The rotation lab: the authoritative core's root rolls by regular
        update, and its chains issue under the fresh root.

Beside the decisions:

*   **Chains wherever issued.** The two-core path lab: the founder verifies
    the registrations of a node that renewed at the authoritative core, by
    proposal 0094's route.
*   **The labs and benchmarks** hold.

## Implementation history

*   Landed as proposed: the issuing keys and the root certificate
    ([keys.go](/pkg/core/trust/keys.go), [certs.go](/pkg/core/trust/certs.go)),
    the onboarding ([update.go](/pkg/core/trust/update.go)) and the
    decision's gates ([trccast.go](/pkg/core/trust/trccast.go)), the issuer
    ([issuer.go](/pkg/core/trust/issuer.go)), the renewals
    ([lifecycle.go](/pkg/core/trust/lifecycle.go),
    [renewal.go](/pkg/core/trust/renewal.go)), the bindings
    ([binding.go](/pkg/core/trust/binding.go),
    [trustdb.go](/pkg/modules/trustdb/trustdb.go)), the trust service
    ([trustservice.go](/pkg/core/controlplane/trustservice.go)), the issuer
    remote ([peerclient.go](/pkg/core/controlplane/peerclient.go)), the
    routes ([controlplane.go](/internal/services/controlplane.go)), and the
    authoritative core's roll ([rotation.go](/pkg/core/trust/rotation.go)).
    Beside the plan:
    *   The labs' threshold renews a node within seconds of each issuance
        rather than at every inspection: an authoritative core onboards only
        at a pass that renews nothing.
    *   The founder route has no unit test of its own. The join labs route
        an enrollment and a submission past an authoritative neighbor, and
        the bootstrap route's filter has its unit test.
    *   The two-core path lab checks nothing new. Within a lab's span the
        founder still holds each node's first chain, under the key every
        renewal keeps, so it verifies a renewed node's registrations without
        asking the registrant; proposal 0094's unit tests cover that route.
    *   Against the node before this proposal, with the threshold's override
        alone, the founder-down lab fails: both nodes renew while the
        founder runs, and neither renews in the minute after its stop, every
        attempt failing to reach the founder.
