# Admit Hosts with an Authorized Join

*   Status: draft
*   Date: 2026-09-22

[TOC]

## Context and problem statement

[ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md) served
endhosts with standard WireGuard clients and left their membership manual:
every host public key is pasted by hand into its node's configuration, with
an address the operator invents for it — a cost the record itself carried
("Host membership is manual: every host public key is configured on its node
by hand until a later milestone distributes it") and
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md)
deferred. Meanwhile everything node-shaped already flows: a node's identity
keys generate locally, its certificate arrives by enrollment behind a policy
gate, and its WireGuard key and overlay subnet travel by directory. The host
is the last thing in the network whose joining is a configuration edit.

What the ceremony costs beyond the editing: the address is invented per host
with uniqueness enforced only by the operator's attention; the list is one
node's secret, invisible to the rest of the network; and a pasted key is
admitted forever — no moment ever re-decides it, so a lost device is a
revocation nobody can perform.

What exists to build on:
[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
already built the admission shape — a pluggable authorizer deciding on
verified facts, with two postures that translate unchanged: admit joiners
from known addressing, admit joiners one by one from a phone. The mesh
directory already distributes entries to every node on cadence. And the
application already programs host devices and /32 routes from a list — only
the list's origin is manual.

This ADR decides how a host joins, where membership lives, and who assigns
addresses. NAT traversal remains deferred, and exit selection is
[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)'s
subject; neither depends on this record.

## Decision drivers

*   **Almost-Zero Config:** Adding a host is a join, not a configuration
    edit. Nothing per-host is written by hand, anywhere, ever.
*   **Standard Clients:** The host runs a standard WireGuard client.
    Joining may use a one-shot helper — a command that ends by emitting the
    client's configuration — but nothing resident, nothing bespoke carrying
    traffic afterward.
*   **Verified Facts Only:** ADR-0010's rule at the host boundary: admission
    decides on what the exchange proves — a public key and a
    return-routable source address — because a plain host has nothing else
    to claim.
*   **Mechanism over Policy:** The join is mechanism; who may join is policy
    at a seam, swappable by run argument without touching protocol.
*   **Local State, Network View:** The host's relationship is with its node
    — its tunnel terminates there, its /32 routes there — so membership is
    the node's own state, per ADR-0009's rule that applications own what
    they run. The network's view of membership is the directory every node
    already fetches.
*   **One Gate, Not a List and a Gate:** The decision that admits a host
    and the record that keeps it must not be two artifacts to keep aligned.
*   **Scope Stays Minimal:** No naming service, no per-host policy beyond
    admission, no allocation of the node's subnet — the subnet stays the
    operator's assignment, the routing anchor the directory already
    distributes.

## Considered options

How a host joins:

*   **Status Quo, Operator-Pasted:** Keep the static per-node peer list.
*   **Authorized Join Service:** A service on the node receives a host's
    public key, asks the authorizer seam, allocates an address, and returns
    the complete client configuration.

Where membership lives:

*   **The Node's Store Only:** Admitted hosts are node-local state, as the
    static list was.
*   **Node Store, Published to the Directory:** The node serves its
    admission from its own store and publishes the admitted entries to the
    core directory beside its own.

Who assigns the host's address:

*   **The Operator:** Invented per host and validated for uniqueness, as
    today.
*   **The Node, at Join:** Allocated from the node's subnet and recorded
    against the public key.

## Decision outcome

Chosen options: the **authorized join service**, membership as **node state
published to the directory**, addresses **allocated by the node at join** —
realized as follows:

1.  **Join is a service on the node.** The WireGuard application serves a
    join endpoint on its host-facing address. A host presents a locally
    generated public key and answers a challenge under it — possession
    proven in the exchange itself, on the static-static footing
    WireGuard's own cookie MACs rest on — beside a return-routable source
    address; those two facts are the whole request. This is the one
    unauthenticated exchange that grants something
    — ADR-0010's enrollment opening, transplanted to the host boundary —
    and it is gated the same way: an authorizer returns allow, deny, or
    pending, and the joiner's retry carries the wait. The response is the
    complete client configuration — the node's public key, the shared port,
    the allocated address — after which the host runs its standard
    WireGuard client and nothing else. The key may reach the endpoint from
    a one-shot helper on the host or carried by the operator; the seam
    decides on the key either way, and the helper is convenience, not
    infrastructure. The helper keeps its key the way the node keeps its
    materials: persisted in its own state, generated only when absent. A
    re-run re-joins the same identity — the same fingerprint, the same
    address — and never mints a second host; no key ever rides an
    argument.
2.  **Admission is the authorizer seam.** The pattern and its two
    implementations are ADR-0010's, decided on the facts a host exchange
    establishes: the CIDR authorizer admits hosts from known addressing —
    a private-range source being what a host behind translation presents,
    exactly as with nodes — and the Telegram authorizer prompts per key,
    showing the fingerprint with approve and deny. The selector is a run
    argument on the node; unset is open, the zero-conf default. Possession
    is proven in the exchange, so what admission grants — the key's
    usability — is worth nothing to whoever copied the public half.
3.  **The node allocates the address.** A joining host receives the next
    free address in the node's subnet, recorded against its public key: the
    same key re-joins to the same address, a new key is a new host.
    Uniqueness is enforced by the store rather than the operator's
    attention, and idempotency makes the join safe to repeat. The subnet
    remains the operator's assignment — the host-facing analogue of the
    ISD-AS a node claims at enrollment.
4.  **Membership is node state, published as the network's view.** The
    node persists its hosts in its own store and programs devices and /32
    routes from it — the list's origin changes, nothing downstream does.
    It also publishes the entries — public key, address, owning ISD-AS —
    to the core directory beside its own entry, riding the authenticated
    channel it already opens. No other node routes by a foreign /32 (the
    subnet prefix already carries it); the publication is the membership
    list the configuration file never gave the network: visible to every
    node at fetch cadence, revoked by disappearance, and the surface
    ADR-0012's exit advertisement extends to offers.
5.  **The record splits: the allocation is durable, the admission is
    leased.** The entry holds two facts with different lifetimes. The
    allocation — this key, this address — persists, so a re-joining host
    resumes its address rather than drawing a new one. The admission
    carries its renewal time and lapses without renewal, and the sweep
    runs where the devices program from — the node's store, not the
    directory: a lapsed lease closes the device, drops the /32, and stops
    the publication, and the directory follows because the node publishes
    what its store still holds. The renewal rule is the chain rule: a
    re-join by the same key under a live lease has proven possession and
    asks nothing; a lapsed lease or a new key passes the gate again. The
    helper is renewal's hands — a standard client cannot re-join — and
    expiry retires what nobody renews: the lost and the decommissioned.
    A stolen host carries its key and renews as its owner did, so the
    revocation for a speaking host is deletion. The constants belong to
    the proposal.
6.  **The configuration file empties of hosts.** The peer list is deleted.
    What remains of the application's configuration is the subnet, the
    shared port, and the egress mark — the node's own facts, never
    per-host ones. With ADR-0012 taking the exit fields, nothing per-host
    is configured anywhere in the network.

### Positive consequences

*   Adding a host is a join: a phone's approval or a source prefix, never
    an edit on a node — and the join's response is the client's entire
    configuration, so no key or address is ever copied between machines.
*   Addresses are unique by construction and stable per key; a re-joining
    host changes nothing.
*   The network holds one membership list — the directory — where the
    configuration held one per node, each invisible to the others.
*   Absence retires itself: a host nobody renews lapses, and a host that
    keeps speaking is revoked by deletion — time covers the lost, decision
    the unwanted.
*   The authorizer seam serves two boundaries — node enrollment and host
    join — with one pattern and one set of postures.
*   The zero-conf default stands: no argument, open join, a network whose
    hosts are usable the day they generate keys.

### Negative consequences

*   The join endpoint is an unauthenticated service on the node's
    host-facing address, one more instance of the boundary ADR-0010 set
    for enrollment. Passive capture grants nothing — the request carries
    no secret — but an in-path attacker can substitute a key and spend
    their own approval on it; the fingerprint the Telegram prompt shows is
    the defense that exists.
*   The one-shot helper is CION software where ADR-0005 promised none: the
    driver narrows from "no host software" to "no resident host software."
    The operator-carried key path keeps the original promise, at the price
    of the convenience.
*   Renewal is the helper's to perform: a standard client cannot re-join,
    so an unattended host lapses at the TTL and its next join passes the
    gate — under the Telegram posture, a prompt per lapse. And expiry is
    not theft revocation: a stolen host holds its key and renews as its
    owner did, so deletion is the only revocation that stops a speaking
    host.
*   A host that changes nodes changes addresses: entries are node-scoped
    and carry no migration.
*   The directory gains a second entry kind that most nodes fetch and
    never act on, and host admission becomes per-node policy where node
    enrollment is per-core — consistent with one operator per ISD, but a
    second place the pattern lives.

## Pros and cons of the options

### Status quo, operator-pasted

*   Good, because it is built, and validation already refuses what the
    operator gets wrong.
*   Good, because nothing listens for joiners — no unauthenticated
    surface, no expiry to manage.
*   Bad, because adding a host is an edit on a node, addresses are
    invented, and the list is one node's secret kept forever.

### Authorized join service

*   Good, because admission stands on verified facts with policy at a
    seam, exactly ADR-0010's shape — one pattern, two boundaries.
*   Good, because the join's response is the whole client configuration:
    the ceremony of copying keys and addresses between machines ends.
*   Bad, because it opens the one exchange that grants something, and a
    service must run on every node to receive it.

### The node's store only

*   Good, because it is the smallest thing that works: membership never
    leaves the node that consumes it, and ADR-0009's ownership rule holds
    absolutely.
*   Bad, because the network's membership is again one node's secret — the
    visibility the directory already gives nodes and subnets, denied to
    the hosts — and expiry has nowhere to be seen from.

### Node store, published to the directory

*   Good, because the directory becomes the network's single membership
    list on machinery that exists, and revocation propagates at fetch
    cadence.
*   Good, because publication gives expiry and renewal a home every node
    observes, and ADR-0012's offers a surface to extend.
*   Bad, because the core stores entries only their owning node consumes —
    size and availability on the availability point everything already
    shares.

### Operator-assigned addresses

*   Good, because an operator can number meaningfully, and meaning is
    sometimes worth the attention.
*   Bad, because uniqueness is the operator's attention, charged per host
    forever, and the join response cannot promise an address nobody
    invented yet.

### Node-allocated at join

*   Good, because keyed allocation is idempotent by construction: unique
    without vigilance, stable without record-keeping discipline.
*   Bad, because an address stops being something chosen and becomes
    something issued — a host is a key, not a number with a story.
