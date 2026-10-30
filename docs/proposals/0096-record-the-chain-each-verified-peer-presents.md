# Record the chain each verified peer presents

This proposal has every node record, in its trust database, the chain each
peer presents on the verified channel, once that chain verifies against the
TRC. It grounds on
[ADR-0033](/docs/adrs/0033-renew-chains-at-every-core.md): once every core
issues chains, the founder's database no longer holds every node's current
chain, and the operator's console, which lists the nodes holding a chain
valid now there
([ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md),
decision 6), loses nodes that run.

[TOC]

## Summary

The console lists one node per ISD-AS holding a chain valid now in the
founder's trust database, with the newest chain's expiry
([portal.go](/pkg/apps/portal.go)). A node that stops renewing shows "not
renewing" once less than 23 hours remain, and drops off when its chain
expires ([portal.js](/pkg/apps/portal/portal.js)). The expiry is the
removal: a node whose every chain expired can no longer sign or
authenticate anything, and returns only by enrolling again.

Since
[proposal 0095](/docs/proposals/0095-issue-and-renew-chains-at-every-core.md),
a node renews at any core. The founder holds a node's first chain for its
three days, and after that a chain of the node only once it verifies a
message the node signed and fetches the chain from the signer
([network.go](/pkg/core/trust/network.go)). A running node that renews
elsewhere and signs nothing the founder verifies shows "not renewing", then
drops off.

Every node already shows the founder its current chain, and the founder
drops it:

*   **The handshake verifies it.** Each handshake on the verified channel
    checks the peer's chain against the TRC
    ([mtls.go](/pkg/libs/scionrpc/mtls.go)), and records nothing.
*   **Every node talks to the founder.** Every node on the measured topology
    provider publishes to the founder's directory each minute over that
    channel
    ([directory.go](/pkg/modules/topology/impl/measured/directory.go)).
*   **Each handshake presents the newest chain.** The client's pool retires
    its connections every ten minutes ([client.go](/pkg/libs/scionrpc/client.go)),
    and each new handshake presents the node's newest chain.

## Motivation

### Goals

*   The founder's trust database holds the current chain of every node that
    talks to it over the verified channel, whichever core issued it, within
    ten minutes of each renewal.
*   The console's list follows: a running node stays listed with the expiry
    of the chain it uses, "not renewing" means a node stopped renewing, and
    a node whose chains all expired drops off.
*   Nothing changes on the wire or in the console's behavior.

### Non-goals

*   A node that never talks to the founder over the verified channel, such
    as a node on the file topology provider whose segments register
    elsewhere, stays as the founder sees it today.
*   Keeping a node out. A node whose chains expired returns by enrolling
    again, and its binding admits its key without the admission policy:
    revocation is future work.

## Proposal

### The handshake records the chain

*   **The hand-off.** `scionrpc.Credentials` gains `RecordChain`. The
    verification callback hands it every chain that verifies against the
    anchor pool: a server's check of its client, and a client's of its
    server alike. A chain the bootstrap window accepts unverified, before
    any TRC is pinned, is not recorded.
*   **The store.** The engine stores the chain in the trust database, as the
    provider stores a chain it fetched. It skips a chain it recorded within
    the last hour, so a handshake writes only a chain new to it. A failed
    store is logged and the handshake proceeds: the chain verified, and
    recording it is a cache.
*   **The sweep.** The expired-chain sweep deletes recorded chains like
    any other.

Every node records its peers' chains, not the founder alone. A node's later
verification of a peer's signed message then finds the chain in its own
database.

### The console

The console is unchanged. Its nodes view says "holding a valid chain"
rather than "holding a valid chain from this core", for the chains come
from every core, and the environment's comment on the chains it lists names
the recorded chains beside the issued and the fetched.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scionrpc` | `Credentials.RecordChain`; the verification hands it each chain that verifies |
| `pkg/core/trust` | The engine records a peer's chain in the trust database |
| `pkg/apps` | The chains comment |
| `pkg/apps/portal` | The nodes view's text |

## Compatibility

Nothing changes on the wire. A trust database holds one more chain per
renewal of each peer it talks to, until the sweep deletes it.

## Test plan

1.  **The verification hands over what verifies.** The callback hands the
    credentials a chain that verifies, whether or not it names the peer,
    and hands nothing for a chain naming another ISD-AS, a chain the pinned
    TRC does not anchor, or a certificate the bootstrap window accepts.
2.  **A handshake records both chains.** After one request on the
    SCION-native channel, the endpoint has recorded the chain the client
    presented, and the client the endpoint's.
3.  **The engine records a chain once.** A recorded chain lands in the
    trust database, and the same chain recorded again writes nothing.

No lab checks the founder's records: a node presents a renewed chain at its
next connection, up to ten minutes on, past a lab's span.

## Implementation history

*   Landed as proposed: the hand-off ([mtls.go](/pkg/libs/scionrpc/mtls.go),
    [scionrpc.go](/pkg/libs/scionrpc/scionrpc.go)) and the engine's store
    through its provider's local database
    ([engine.go](/pkg/core/trust/engine.go),
    [network.go](/pkg/core/trust/network.go)).
