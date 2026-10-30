# Replicate the node directory along links

This proposal implements
[ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)'s
decisions 1 to 4 and 6 for the network's one directory: every node holds the
node directory, signs its own entry, merges what it receives by the join,
and floods entries along its links. The founder's directory service
retires. Scopes, decision 5, are the next proposal; until then the network
is one scope, as it is today.

[TOC]

## Summary

Every node publishes its entry to the founder each minute and fetches the
whole directory every 30 seconds
([directory.go](/pkg/modules/topology/impl/measured/directory.go)):

*   **The founder holds the only copy.** Its store keeps an entry five
    minutes past its last publication, in memory, and serves the list to
    any caller. With the founder down, no publication lands, no fetch
    answers, and a node that restarts holds no directory at all.
*   **Entries are unsigned.** The founder records the publisher's ISD-AS
    from the channel's verified chain, and every fetcher trusts the founder
    for it.
*   **Each node publishes the fetched copy** on the node bus
    ([directory.go](/pkg/libs/bus/directory.go)), which the selection loop,
    the punch's reflector choice, the link echo
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)), and
    the console read.

## Motivation

### Goals

*   Every node holds the directory, and losing any node, the founder
    included, loses no other node's entry and stops no publication.
*   An entry is its signer's statement, verified against the signer's chain
    whatever route it took.
*   Entries travel the links' one-hop channel alone: no composed path, no
    lookup, no core.
*   A restarted node holds the directory once its first link comes up.
*   The node bus carries the directory as the node holds it, so its readers
    do not change.

### Non-goals

*   Scopes (ADR-0032, decision 5): the next proposal. Until then each node
    signs one entry and every node holds it, as with today's one directory.
*   The WireGuard directory of slices and hosts, which stays the founder's.
*   Keeping the directory across a restart: the first link refills it.

## Proposal

### The signed entry

*   **The form.** An entry travels as a SCION signed message, the type a
    beacon's AS entry carries, its proto vendored from SCION. The header
    names the signer's ISD-AS, its subject key, the TRC its newest chain
    verifies under, and the signing time; the body is the entry: the
    addresses and the reach report it carries today.
*   **The withdrawal.** An entry naming no address withdraws its signer.

### Acceptance

*   **Verified at the signing time.** The entry verifies against a chain of
    the signer valid at its signing time, its ISD-AS bound to the header's,
    and the body's ISD-AS must match. The engine's bound verification gains
    the time to verify at. A missing chain or TRC comes from the neighbor
    that sent the entry, over the one-hop channel, as a beacon's does.
*   **The order.** A signer's entries order by the TRC named, base then
    serial, then the signing time, then the signed bytes. An entry is
    accepted when it is greater than the one held. The comparison runs
    before the verification, so an entry that cannot win costs nothing.

### The directory and its view

*   **The directory** holds each signer's greatest entry, in memory. The
    join keeps the greater entry signer by signer and reads no clock.
*   **The view** is what the node bus carries: each signer's entry that is
    not a withdrawal and was signed no earlier than a lifetime before the
    node's clock and no later than a future bound after it, whatever TRC
    it names. A view entry's `Published` is its signing time. The view is
    published whenever it changes: at each accepted entry, and as entries
    enter and leave the window.
*   **Discarding.** An entry the view has left out for a lifetime is
    discarded from the directory; one that comes back is judged anew.

### The node's own entry

*   **Signing.** The node signs its entry once it holds a chain, at each
    change of its own state, and every refresh interval, each entry naming
    the newest TRC the node pins. The state is what today's publication
    reads: the host, the rendezvous report, and whether a NAT stands in
    front.
*   **Withdrawal.** A node that stops on purpose signs a withdrawal and
    pushes it to its neighbors before its links close, bounded by a short
    deadline.

### Flooding and catch-up

*   **The service.** `node.v1.DirectoryService` keeps its name and changes
    its two calls, served on every node behind the peer middleware:
    *   `Push` hands the receiver entries. It accepts the greater ones.
    *   `Sync` hands the receiver a summary: each signer's greatest entry by
        ISD-AS, TRC, signing time, and a digest of the signed bytes. The
        receiver answers with the entries the caller lacks or holds lesser,
        and with the signers whose entries it lacks or holds lesser itself,
        which the caller then pushes.
*   **Flooding.** An accepted entry greater than the one held is pushed to
    every neighbor a usable link reaches, the sender excepted, over the
    one-hop channel.
*   **Catch-up.** Both ends of a link sync their summaries when the link
    comes up, every summary period while it serves, and when the node first
    pins a TRC, before which no entry verifies.
*   **The forwarding bound.** A node forwards each signer's greatest entry
    at most once per bound. An entry superseded within the bound waits for
    its end, and the greatest then travels.

### The parameters

| Parameter | Value | Reasoning |
| :-- | :-- | :-- |
| Refresh interval | 5 minutes | One entry per node per interval crosses every link. |
| Lifetime | 15 minutes | Three refreshes; a departed node lingers as a candidate this long, against five minutes today. |
| Future bound | A beacon's clock-skew allowance | The allowance the node already grants a beacon's timestamp. |
| Summary period | 5 minutes | A missed flood heals within one. |
| Forwarding bound | 5 seconds | A signer looping costs each link one entry per bound. |

### The founder's service retires

The founder's store, its publish and list handlers, the publish client, and
the fetch loop go. The measured provider no longer takes the founder route,
and its core flag keeps only the domain lookup.

### The console shows the last report

Once no node calls the founder's directory, the founder sees a renewed chain
only when a node next connects to it for something else
([proposal 0096](/docs/proposals/0096-record-the-chain-each-verified-peer-presents.md)),
so the expiry the console shows can lag a renewal by days. Every node now
holds every node's signed report instead:

*   **The column.** The console shows each node's last report, the signing
    time of its entry in the view, in place of its chain's expiry, and
    "silent" for a node the view no longer holds. The "Not renewing" badge
    goes.
*   **The list.** The console lists the nodes holding a chain valid now that
    the founder knows, beside every node the view holds. A reporting node is
    always listed, a node that stopped reporting shows as silent, and it
    leaves the list once its chains expire as far as the founder knows.

### The design overviews

The [architecture](/docs/design/architecture.md) follows: the topology
source learns of candidates from the directory every node holds, and the
node bus carries the directory as the node holds it.

### Packages touched

| Package | Change |
| :-- | :-- |
| `proto/crypto/v1` | SCION's signed message, vendored for the directory's proto to import |
| `proto/node/v1` | The entry, signed; `DirectoryService`'s `Push` and `Sync` |
| `pkg/core/trust` | The bound verification at a given time |
| `pkg/modules/topology/impl/measured` | The replicated directory, its view, its service, and its flooding and catch-up; the founder's store and the fetch go |
| `pkg/libs/bus` | `DirectoryEntry.Published` names the signing time |
| `pkg/apps` | The console's records list the founder's chains beside the view, each with its last report |
| `pkg/apps/portal` | `Node.Reported` replaces `Expires`; the API's `reported`; the page's column |
| `internal/services` | The measured provider without the founder route |
| `internal/testnetwork` | The directory labs |
| `docs/design` | The architecture |

## Compatibility

*   **The wire.** The directory service changes its calls, so nodes of the
    two versions share no directory. Upgrade every node together, or
    bootstrap the network anew.
*   **State.** Nothing persists: a node's first link refills its directory.
*   **The console's API.** The node view drops `expires` and gains
    `reported`, omitted for a silent node.

## Test plan

The episodes follow ADR-0032's decisions.

1.  **Every node holds the directory.** The lab: nodes in a line hold every
    node's entry. With the founder stopped, a node's changed host reaches
    every other node, and a node that restarts holds the directory once its
    first link comes up.
2.  **A node signs its own entry.**
    *   An entry verifies against the chain valid at its signing time, its
        missing chain fetched from the sending neighbor.
    *   An altered entry, an entry whose body names another ISD-AS, and an
        entry no chain of the signer verifies are refused.
3.  **The join.**
    *   The join is commutative, associative, and idempotent over generated
        entry sets, and an entry that cannot win is never verified.
    *   The view shows an entry whatever TRC it names, leaves out one
        signed before the window or after its future bound and a
        withdrawal, and changes nothing in the directory. Its publication
        follows the clock with no entry arriving.
    *   The directory discards an entry the view left out a lifetime ago.
    *   A withdrawal outranks its signer's earlier entries, and an entry
        under a newer TRC outranks a runaway one.
4.  **Entries travel along links.**
    *   An accepted greater entry is pushed to every neighbor but its
        sender, and a lesser one to none.
    *   A sync sends each side what the other lacks.
    *   The forwarding bound holds a looping signer to one entry per bound,
        and its latest entry travels.
5.  **The node bus carries the view.** The selection, punch, and console
    labs hold.

Beside the decisions:

*   **The console's last report.** The console lists a reporting node whose
    chain the founder does not hold, with its last report, and a node with
    a valid chain that stopped reporting as silent.
*   **The benchmarks hold,** and a changed entry reaches the network within
    seconds, where today it waits for each node's next fetch, up to 30.

## Implementation history

*   Landed as proposed: the entry and the service
    ([directory.proto](/proto/node/v1/directory.proto)) over SCION's signed
    message ([signed.proto](/proto/crypto/v1/signed.proto)), the bound
    verification at a given time ([engine.go](/pkg/core/trust/engine.go),
    [verifier.go](/pkg/core/trust/verifier.go)), the replicated directory,
    its view, its flooding, and its catch-up
    ([directory.go](/pkg/modules/topology/impl/measured/directory.go)), the
    provider's wiring
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)), and the
    console's last report ([portal.go](/pkg/apps/portal.go),
    [api.go](/pkg/apps/portal/api.go)). Beside the plan:
    *   The verification at the signing time checks the chain's validity
        then, against the TRCs that anchor chains now: the provider's
        verification of a chain takes the time
        ([network.go](/pkg/core/trust/network.go)).
    *   The withdrawal needs the node's links to outlive its decision to
        stop. The node's supervision gains drains, run when the node stops
        on purpose, before its loops' context ends, within two seconds
        ([supervise.go](/internal/supervise/supervise.go)), and the topology
        provider's contract gains the drain the node runs
        ([topology.go](/pkg/modules/topology/topology.go)).
    *   A node's signing waits for its clock to pass the signing time of
        the node's entry it holds, by up to a second, so its entries grow:
        under the labs' virtual time a withdrawal, a restart's first entry,
        or a change at the instant of the last signing would otherwise tie
        with the entry before it, and lose to it by the signed bytes.
    *   The catch-up the first pinned TRC was to trigger runs at the node's
        first signing: before its chain the channel admits the node to no
        neighbor, and a node holds its chain only once it pinned the TRC.
    *   A failed sync retries from five seconds, doubling up to the summary
        period, rather than waiting a full period.
    *   A summary carries a digest rather than the signed bytes, so on a tie
        of TRC and signing time each side sends its own entry and the join
        picks.
    *   An entry the directory would discard is refused on arrival, before
        its verification: else a copy two nodes pass back and forth would
        never age out.
    *   The console's API omits the key of a node whose chain the founder
        does not hold.
    *   The labs pace the summary period at two seconds, beside the
        directory's other bounds.
    *   The view reads no TRC, where ADR-0032's decision 3 shows an entry
        only under the pinned TRC, or its predecessor while that one's grace
        period runs, and has a node sign anew at each newly pinned TRC.
        Onboarding a core is a TRC update with no grace period: under that
        rule every entry left the views at each onboarding until its signer
        signed anew. The order alone ends a runaway clock, as the signer's
        first entry under the next TRC outranks the runaway one wherever it
        arrives, so a node moves to a newly pinned TRC at its next signing.
        Two leftovers remain: a runaway entry of a signer that never signs
        again, at most a chain's validity ahead, shows for about a lifetime
        once the clock reaches it, as a crashed node's last entry does; and
        a revoking update leaves the revoked signers' entries in the views
        until they age out.
    *   The benchmarks, five runs each against the node before this
        proposal: the NAT network settles in 2.7–3.2 minutes against
        2.2–2.8, its topology optimal in every run; the site joined from
        outside settles in 1.8–3.3 against 2.2–2.8, and the one joined
        inside in 3.7–5.5 against 5.3–11.8, its worst pair at 4.5–26 and 3
        to 5 inside links against 1.35–26 and 3 to 6; the regions' worst
        pair is 1.20–1.23 against 1.23–1.40. The founder-down network
        survives as before and its founder returns in 177–273 s, against
        198–232 here and 196–276 in earlier batches; restart, rebind,
        symmetric join, and the stranded network hold.
