# Admit hosts by keys bound to nodes

This proposal implements
[ADR-0023](/docs/adrs/0023-admit-every-host-by-a-key-that-names-its-node.md):
a host joins only by presenting an auth key, every key — the portal's and
the Telegram bot's alike — names the node its host lands on, and the
coordination application allocates in that node's slice and nowhere else.
Registrations without a key are denied under every policy, and the labs
place their hosts through a policy of their own.

[TOC]

## Summary

A host reaches the registry by four doors today. The portal and the
Telegram bot admit a host that presents a key they minted
([authkeys.go](/pkg/modules/enrollauth/impl/portal/authkeys.go),
[telegram.go](/pkg/modules/enrollauth/impl/telegram/telegram.go)) and
pend a bare one for the operator; the CIDR method admits by source
([cidr.go](/pkg/modules/enrollauth/impl/cidr/cidr.go)); and with no policy
the coordination application admits everyone
([register.go](/pkg/apps/coordination/register.go)). Whichever door
admits it, the host lands in the slice with the most free addresses
([allocator.go](/pkg/apps/coordination/allocator.go)).

The plan closes every door but the key and lets the key name the node:

*   the admission answer gains the node, and the coordination application
    allocates in it;
*   the portal and the bot deny a registration without a standing key —
    no ask, no prompt — and record a node with each key they mint;
*   the CIDR method and the policy-less founder deny every registration;
*   the console requires a node at minting and shows each key's and each
    host's node; the bot takes an optional ISD-AS;
*   the harness gains a field that loads a policy the labs build, and the
    labs' policy admits a host by a credential naming its node.

## Motivation

ADR-0023 decides how a host is admitted and who chooses its node; this
plan grounds both in the packages that carry them. The netmap already
names exactly the owning node and its host endpoint
([netmap.go](/pkg/apps/coordination/netmap.go)), and every node already
programs the hosts it owns from the directory
([app.go](/pkg/apps/wireguard/app.go)), so placing a host on a chosen node
changes where its address comes from and nothing downstream.

### Goals

*   A registration without a standing key is denied under every policy,
    without an ask or a prompt; node enrollment and the founder's vote
    still reach the operator.
*   A key minted in the portal names a node, chosen from the nodes holding
    a slice with the founding core preselected, and its host lands on that
    node.
*   `/create_auth_key [<isd-as>]` mints a key naming the given node, the
    founding core without one, and the reply names it.
*   A named node that cannot take the host refuses the registration until
    it can; the host never lands elsewhere.
*   The console shows each key's node, and each host's node with its host
    endpoint.
*   The labs place each host on the node their proof needs.

### Non-goals

*   No approval path for hosts, and no node choice anywhere but at
    minting.
*   No moving of an admitted host; a new key replaces it.
*   No keys for the CIDR method.
*   No change to the login server, the relay, or the netmap's shape.
*   No netmap caching and no directory persisted on the nodes.

## Proposal

### The seam

`enrollauth.AdmissionAnswer` gains one field:

```go
// Node is the node a registration's host lands on: its address from that
// node's slice, its one peer that node. The zero IA names the founding
// core; the other boundaries ignore it.
Node addr.IA
```

The package document says that a registration is admitted on a key alone.
`AdmissionFacts.Label` — the host's claims, shown beside a registration's
prompt or ask — goes: no implementation decides on it, and no
registration reaches a human any more.

### The coordination application

*   `Config` gains `IA addr.IA`, the founding core's ISD-AS, which the
    table's entry fills from the environment; `Config.Authorizer` nil now
    denies every registration.
*   `allocate(key, directory, node)` answers a key the registry holds from
    its record, as before; otherwise the named node's entry issues the
    slice's next free address. A node the directory holds no entry of, an
    entry with no host endpoint, and a full slice each refuse with an
    error naming the node. The freest-slice choice and its tie rule go.
*   `handleRegister` hands the allocator the answer's node, or `Config.IA`
    when the answer names none. A refusal answers 503 "no address to
    allocate", as a full slice does today, and the log names the node.

### The CIDR method

`Authorize` denies the registration boundary whatever the source, and
admits enrollment and the vote by source as before; the package document
names it a nodes-only posture.

### The portal method

*   At the registration boundary, `Authorize` admits a credential matching
    a standing key — the holder's retries included — with the key's node,
    and denies everything else. Asks hold enrollment and the vote alone.
*   `enrollauth.KeyRequest` and `enrollauth.AuthKey` gain `Node addr.IA`.
*   A key's record in `portal-auth-keys.json` gains `node`, the ISD-AS in
    text; a record without one names the founding core.

### The console

*   `POST /admin/api/keys` requires `node`: an ISD-AS among the nodes whose
    directory entry holds a slice. Anything else answers 400.
*   The keys' listing and the mint's response carry `node`; the mint's
    response also carries the node's host endpoint.
*   The hosts' listing drops its asks and gains each host's `endpoint`:
    `portal.Host` gains `Endpoint`, the owning node's host endpoint, which
    the table entry's adapter reads from the directory.
*   The page:
    *   The Hosts view drops its approval card and its rejected list.
    *   The Generate dialog gains a required Node select — each node
        holding a slice, shown as its ISD-AS, host endpoint, and free
        addresses — with the founding core preselected.
    *   The generated key's view names the node and its host endpoint.
    *   The keys table gains a Connects to column.
    *   The hosts table's Owning node becomes Connects to, the host
        endpoint beneath the ISD-AS.

### The Telegram method

*   At the registration boundary, `Authorize` admits a key it minted and
    has not spent, and the machine's retries while that approval stands,
    with the key's node; it denies everything else without a prompt.
    Prompts go out for enrollment and the vote alone.
*   `/create_auth_key [<isd-as>]` mints a key naming the ISD-AS given, or
    the founding core without one; a malformed ISD-AS answers the usage.
    The reply names the node — "connects to 1-ff00:0:111" or "connects to
    the founding core" — above the key. The bot holds no view of the
    directory, so a node is checked for its syntax alone.
*   `telegram-auth-keys.json` holds records —
    `[{"key": "cion-…", "node": "1-ff00:0:111"}]`, the node omitted for the
    founding core. A file in the earlier form, a list of keys, loads as
    keys naming the founding core.
*   The command menu reads "Mint a one-use auth key, optionally naming its
    node".

### The harness

`NodeConfig` gains a harness field beside `Coordination` and `RootCAs`:

```go
// Admission is the integration harness's stand-in policy, loaded in place
// of the method EnrollAuth names; the two refuse to combine, and it
// refuses to load off the founding core.
Admission enrollauth.AdmissionAuthorizer
```

The labs' policy lives in the labs' own test code: nodes enroll openly,
the founder's vote is denied, and a registration presenting `lab:<isd-as>`
is admitted onto that node — the stand-in for a key an operator minted —
while any other is denied.

### The documentation

The implementing commit updates the
[architecture](/docs/design/architecture.md) — the enrollment authorizer's
CIDR method admits nodes alone, and a host joins on a key naming its node
— the flag's help in [run_core.go](/cmd/cion/run_core.go), and
`EnrollAuth`'s comment, which no longer calls empty open registration; it
flips ADR-0023 to accepted.

## Test plan

*   **Unit, allocation (decisions 4 to 6):** the named node's slice issues
    the next free address; a node without an entry, an entry without a
    host endpoint, and a full slice each refuse; a key the registry holds
    answers its record whatever node is named.
*   **Unit, registration (decisions 2 and 4 to 5):** an answer naming a
    node lands the host there; an answer naming none lands it on the
    founding core; a named node without an entry answers 503 and records
    nothing, and the retry lands once the node publishes; with no
    authorizer, every registration is denied.
*   **Unit, the CIDR method (decision 2):** a registration from inside the
    listed prefixes is denied; an enrollment from inside them is admitted.
*   **Unit, the portal method (decisions 1 and 3):** a key's admission
    answers its node, the holder's retries too; a bare registration and
    one with a spent, expired, or revoked key are denied and list no ask;
    enrollment still pends; the state file keeps the node across a
    restart, and a record without one names the founding core.
*   **Unit, the console (decision 3):** minting refuses a missing node and
    a node without a slice; the listing and the mint's response carry the
    node; the hosts' listing carries each node's host endpoint and no
    asks.
*   **Unit, the Telegram method (decisions 1 and 3):**
    `/create_auth_key <isd-as>` mints a key naming it and the reply says
    so; without an argument the key names the founding core; a malformed
    ISD-AS gets the usage; the keyed answer and the machine's retries
    carry the node; a bare registration is denied and no prompt is sent;
    a list-form state file loads as keys naming the founding core.
*   **Unit, the harness:** `Admission` loads in place of a method, refuses
    to combine with `EnrollAuth`, and refuses off the founding core.
*   **Integration, the labs' policy:** the coordination, address-identity,
    and SOCKS labs present `lab:<isd-as>` credentials; the join lab keeps
    one host on each node and its echo across the mesh.
*   **Integration, the portal:** the console lab mints a key naming the
    leaf, and the host lands on the leaf — listed with the leaf's endpoint
    and programmed by the leaf — before its release.
*   **Integration, Telegram:** the auth-key lab mints a key naming the
    leaf and its host lands there; the prompt lab becomes a refusal: a
    bare host's login never completes, and no registration prompt reaches
    the chat.
*   **Integration, CIDR:** with a prefix covering the lab's loopback
    sources, the leaf enrolls and a host's login never completes.

## Implementation history
