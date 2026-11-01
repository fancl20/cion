# Check every chain against its membership

This proposal implements
[ADR-0034](/docs/adrs/0034-verify-each-chains-membership-and-remove-cores-at-once.md)'s
decisions 1 to 5 and 10:

*   A node's membership is the newest chain the founder issued for its key.
*   The node renews it at the founder.
*   A membership counts by its distance from the checker's own.
*   Every chain verification accepts only a chain a counting membership
    backs.
*   The node presents its membership beside its chain.
*   A network may go without memberships.

Memberships are CION's own, not the PKI draft's, so they live in a module
beneath the roof
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md) builds, and
the core's trust engine gains the seams the module plugs into. Beside them,
this proposal removes the founder's boot-time binding of held names, which
binds unverified chains, and brings the console's node list back to an
expiry: the membership's. Removing a core (decisions 7 and 8), and reporting
forgeries and removing nodes (decisions 6 and 9), follow in later
proposals. This one refuses and logs a chain no membership backs.

[TOC]

## Summary

Today:

*   **Any root certifies any name.** The handshake's check
    (`verifyChainAgainstTRC`,
    [mtls.go](/pkg/libs/scionrpc/mtls.go)) and the chain reads behind
    signed messages (`NetworkProvider.GetChains`,
    [network.go](/pkg/core/trust/network.go)) accept a chain that anchors in
    any root of the TRC. An issuer's renewal check (`checkRenewal`,
    [trustservice.go](/pkg/core/controlplane/trustservice.go)) checks the
    requester's chain the same way, and no binding. No seam lets anything
    else refuse a chain the TRC verifies.
*   **Only the founder reads a binding.** First issuance binds the name to
    its key (`checkFirstIssuance`), and nothing else reads the binding.
*   **A forged chain can bind its name.** At every boot, the founder binds
    every name holding a chain valid now in its database to that chain's
    key (`BindHeldNames`, [binding.go](/pkg/core/trust/binding.go)). Since
    [proposal 0096](/docs/proposals/0096-record-the-chain-each-verified-peer-presents.md),
    that database holds every chain a peer presents in a handshake, which
    need only verify against some root.
*   **A node holds a founder-issued chain by chance.** It holds its first
    chain, and later one only when the founder is the issuer of turn
    (`orderIssuerRoutes`,
    [controlplane.go](/internal/services/controlplane.go)). An anchored
    authoritative core issues its own chains under its own CA.
*   **The handshake carries two certificates.** `nativeCert` presents the
    chain alone, and `cppki.VerifyChain` requires exactly two.
*   **Expired chains vanish.** The hourly sweep deletes a chain an hour
    after its AS certificate expires (`RunEnrollment`,
    [lifecycle.go](/pkg/core/trust/lifecycle.go)), and the chain service
    serves only chains valid now (`Chains`).
*   **The console reads the directory.** Its node list shows each node's
    last directory report ([portal.go](/pkg/apps/portal.go)). A node in no
    scope the founder holds, such as a site node joined through its router
    ([proposal 0099](/docs/proposals/0099-observe-a-site-whose-router-runs-a-core.md)),
    reads as silent.

## Motivation

### Goals

*   A chain verifies only where a counting membership binds its ISD-AS to
    its key: in the handshake, behind signed messages, and at renewal.
*   Every node holds a membership and renews it at the founder, and the
    memberships keep counting through a founder outage.
*   Memberships live in a module; the trust engine stays the draft's
    mechanism, with seams.
*   A network may go without memberships and keep today's checks.
*   Only first issuance binds a name.
*   The console lists every node by its membership.

### Non-goals

*   Removing a core, and a node's fallback on its membership when its
    chain stops verifying.
*   Reporting a forgery to the founder, and removing a node.
*   Segments a core's lookup serves, which nothing verifies today.
*   A joiner learning the network's choice of memberships from the
    founder: the operator sets it on every node.

## Proposal

### The membership module

*   **The module.** `pkg/modules/membership` holds the contract and the
    store, two methods beneath them, `founder` and `none`, and a contract
    suite both run. Its kind is policy: the operator's choice of how a
    node's admission binds it network-wide.
*   **The run argument.** `--trust.membership` selects the method:
    `founder`, the default, or `none`. Every assembling command takes it,
    hidden from the help as `--topology.link-set` is, since it overrides a
    working default. One method always loads, so neither the core nor the
    console asks whether one did.
*   **The seam the core calls.** The trust engine hands the module:
    *   each chain the TRC verified, with the certificates the peer
        presented beside it and the server the chain came from; the module
        refuses a chain no counting membership backs;
    *   the question of what the node presents beside its chain;
    *   each chain the node issues.
*   **The store.** The module keeps one membership per ISD-AS in the
    node's state directory, apart from the trust database's chains: the
    newest its method accepted, replaced only by a newer, and never swept.
    The membership service on the control endpoint answers from it, and
    the console's listing reads it.
*   **What a method decides.** Which chains are memberships and when one
    counts, what the node presents, how a membership renews, and when one
    lapses.

### Founder memberships

*   **What a membership is.** A chain whose CA certificate a root
    certificate of the founder signed: the founder's own chain, and every
    chain the founder issues. A node's membership is the newest such chain
    for its key, by the AS certificate's issuance time. A node keeps its
    own, the founder every one it issues, and every node those its peers
    present or serve.
*   **When one counts.** A membership counts at a node when both hold:
    *   Its certificates form a chain whose CA certificate a founder root
        certificate in the node's anchor pool signed, verified at the
        membership's own issuance time. The founder's roots are the root
        certificates whose subject names the founder.
    *   The founder issued it no more than the membership window, the AS
        certificate validity of three days, before the node's own
        membership.

    A node that holds no membership yet judges by the first condition
    alone. A membership that no longer counts has lapsed.
*   **Its environment.** The method reads the trust engine's anchor pool,
    the founder's name, and the founder renewal.

### The none method

`none` is the network without memberships of ADR-0034's decision 10. Each
chain, whichever core issued it, stands as its own membership, so the
network keeps today's checks:

*   Every chain the TRC verified counts, and nothing is presented beside
    it: the method passes what the core already checked, renewals
    included. First issuance still binds each name to its key and
    re-enrolls that key alone.
*   Its renewal does nothing: the chain renews at the cores.
*   A membership never lapses, so the listing gives it no expiry. On the
    founder, the store holds every node from its first chain on, since the
    founder issues every first chain.

The choice is the network's: a node running the founder method refuses a
peer running `none` unless the founder issued the peer's chain within the
window, and the log shows the mismatch as refused chains. Under `none`,
the network carries
[ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md)'s accepted risk;
links its operators configure, by `--topology.link-set`, bound it as
standard SCION's do.

### Renewal

*   **At the founder.** Under the founder method, a node renews its
    membership over the founder's WebPKI channel, the one first issuance
    rides. The request is the renewal request of today, signed under the
    node's current chain, whichever issuer signed it. The founder checks
    the chain against the TRC and its key against the name's binding, and
    issues a chain: the new membership, which the trust database also
    keeps as the node's chain.
*   **When.** The method renews once less than the renewal threshold, a
    day, remains of the membership's AS certificate. A failed attempt
    retries on the retry schedule
    ([proposal 0083](/docs/proposals/0083-back-off-every-retry-on-one-schedule.md)),
    capped at a minute, so after a founder outage every node renews within
    a minute of the founder's return.
*   **Every role.** The founder's own chain, which it issues itself, is its
    membership. An authoritative core renews its membership at the founder
    beside issuing its own chain.

### Presenting

*   **In the handshake.** `nativeCert` presents the chain, then what the
    module adds: the membership where it differs from the chain, so four
    certificates. The check takes the first two as the chain and the rest
    as the membership; a chain the founder issued serves as its own
    membership.
*   **On request.** The module's membership service answers a membership by
    ISD-AS from its store: every node serves its own and those it holds,
    and the founder holds every one. The module asks for a missing
    membership where the chain read asks for chains: the server that sent
    the message or registered the segment, then the founder.

### The checks

*   **The handshake** hands the module the chain and the certificates
    presented beside it, on both ends of the channel, and refuses what the
    module refuses.
*   **Signed messages:** `NetworkProvider.GetChains` hands the module each
    chain it verified, with the server it would ask, and keeps only what
    the module accepts. Beacons, registrations, directory entries, and the
    node's own signer read chains there.
*   **Renewals:** `checkRenewal` hands the module the requester's chain;
    the handshake that carried the request stored the requester's
    membership. The founder reads its binding instead.
*   **The log.** The module logs a refused chain with the root it anchors
    in, the evidence a later proposal reports to the founder.

### The founder's bindings

`BindHeldNames` goes: since
[proposal 0095](/docs/proposals/0095-issue-and-renew-chains-at-every-core.md),
first issuance binds every name it issues.

### The console

The node list reads the module's listing on the founder: each node's newest
membership, its key, and its expiry, with "Not renewing" once less than the
renewal threshold remains. A lapsed membership drops off the list; under
`none`, memberships never lapse and show no expiry. The directory still
supplies the reach tag where the founder's views hold the node.

### Packages touched

| Package                    | Change                                                     |
| :------------------------- | :--------------------------------------------------------- |
| `pkg/modules/membership`   | Contract and store, the founder and none methods, suite    |
| `pkg/core/trust`           | The seams the module plugs into; `BindHeldNames` removed   |
| `pkg/libs/scionrpc`        | The handshake presents and hands over the membership       |
| `pkg/core/controlplane`    | The renewal and issuance seams                             |
| `proto/node/v1`            | The membership service's messages                          |
| `internal/services`        | The module's assembly, by the run argument                 |
| `cmd/cion`                 | The `--trust.membership` run argument                      |
| `pkg/apps`                 | The console's node list by membership                      |

## Compatibility

A node of this change refuses every chain no membership backs, so nodes
before it cannot join: the network upgrades together, as it is not in
production. A network that sets `none` on every node keeps today's checks.

## Test plan

*   **The contract suite,** which both methods run: a peer of the same
    method accepts a node's founder-issued chain with what the node
    presents beside it; the store keeps the newest membership per ISD-AS,
    a newer replacing an older and an older leaving a newer; the service
    answers what the store holds; the listing holds every membership the
    method accepted.
*   **The founder method:** a founder-issued membership counts; one under
    another core's root does not; one issued more than three days before
    the node's own does not, one within does, expired or not; a node with
    no membership judges by the signature alone.
*   **The none method:** every chain the TRC verified counts, whichever
    core issued it; nothing is presented beside it; its memberships list
    without an expiry.
*   **The run argument:** `founder` and `none` each load their method, and
    another value fails the boot.
*   **The handshake:** four certificates pass both ends; a founder-issued
    chain passes alone; a chain the module refuses is refused and logged.
*   **The chain reads:** a chain without a stored membership is kept once
    the server's membership arrives, and refused when none does.
*   **The service and renewals:** the membership service answers what the
    store holds; `checkRenewal` refuses a requester without a membership;
    the founder renews a bound key and refuses another.
*   **The renewal loop:** the module renews a day before the membership's
    expiry, retries on the schedule while the founder is down, and renews
    within a minute of its return.
*   **The labs:**
    *   Joining: every node holds a membership, and peers accept one
        another.
    *   A forged chain: an authoritative core's CA key issues a chain for a
        name the founder never admitted; every node refuses it, in the
        handshake and behind a signed message.
    *   The founder down for four days: chains renew at the authoritative
        core, memberships keep counting past their expiry, and every pair
        still answers its pings. Once the founder returns, every node
        renews within a minute.
    *   The console lists every node of the gateway site network by its
        membership, the site's nodes included.
    *   The none method: the static lab's line forms and answers its pings
        end to end with `none` on every node.
*   **The removal:** a forged chain recorded at the founder binds nothing
    across a founder restart.

## Implementation history

*   Landed as proposed: the module, its store, and its two methods
    ([membership.go](/pkg/modules/membership/membership.go),
    [store.go](/pkg/modules/membership/store.go),
    [founder.go](/pkg/modules/membership/impl/founder/founder.go),
    [none.go](/pkg/modules/membership/impl/none/none.go)) with their
    contract suite
    ([membershiptest.go](/pkg/modules/membership/impl/membershiptest/membershiptest.go)),
    the handshake's seam ([mtls.go](/pkg/libs/scionrpc/mtls.go),
    [engine.go](/pkg/core/trust/engine.go)), the renewal check's and the
    issuance's ([trustservice.go](/pkg/core/controlplane/trustservice.go)),
    the run argument and the assembly
    ([run.go](/cmd/cion/run.go),
    [membership.go](/internal/services/membership.go)), the console's node
    list ([portal.go](/pkg/apps/portal.go),
    [portal.js](/pkg/apps/portal/portal.js)), and the labs
    ([membership_test.go](/internal/testnetwork/membership_test.go),
    [static_test.go](/internal/testnetwork/static_test.go),
    [site_test.go](/internal/testnetwork/behavior/site_test.go)). Beside
    the plan:
    *   No check stands behind signed messages, and with it went the
        membership service and its messages: ADR-0034's decision 4, amended,
        checks the chains of peers alone — in the handshake and at renewal.
        A message reaches a node only over a channel whose handshake checked
        the peer, and a member signing under a forged identity is told apart
        no better than one holding a stolen key. `NetworkProvider.GetChains`
        and the verifier stay the draft's.
    *   The handshake records a peer's chain only once the membership
        admits it, so a refused chain never enters the trust database.
    *   The none method keeps the node's own chain as it presents it, so
        the founder lists itself.
    *   The founder-down lab paces the chain validity, and with it the
        membership window, to minutes: a pacing of the issuer's chain
        validity ([issuer.go](/pkg/core/trust/issuer.go)) stands in for the
        days the scenario names.
