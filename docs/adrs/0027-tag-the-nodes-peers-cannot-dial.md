# Tag the Nodes Peers Cannot Dial

*   Status: accepted
*   Date: 2026-10-26

[TOC]

## Context and problem statement

The portal lists every node holding a chain valid now
([ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md),
decision 6), each beside its role. It does not show whether peers can dial a
node.

A node peers cannot dial still joins and links, but only over the links it
dials: its published rendezvous address answers no first contact, so no
other node's selection loop promotes it.
[ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md)
(decision 7) leaves links between two translated nodes out of scope. The
translated lab of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md)
shows the cost: each translated node links only to the public nodes, and two
translated nodes 2ms apart reach each other through a public node, 45ms
under the labs' penalty. Behind a symmetric translator a node never enrolls,
and a translator that drops its mappings strands the node behind it.

Two causes put a node in this state:

*   **A translator** stands between the node and its peers and forwards no
    port to it, as in most home and office networks.
*   **A filter or a fault:** the node holds its own address, but a firewall
    or the network drops what peers send it. The operator can fix this.

The console tells neither kind of node from the rest, nor one cause from the
other.

What exists to build on:

*   The rendezvous reply echoes the source it observed. The dialer keeps
    that host as its learned external host and publishes it (ADR-0021).
*   The selection loop's probe is a rendezvous echo: a datagram to a peer's
    published rendezvous address, and its answer.
*   The link request rides the channel both chains authenticate, from the
    node that dials the link to the node that accepts it.
*   Each node publishes its entry to the core-served directory, which every
    node fetches
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 11).
*   The control address defaults to the wildcard host, so the link address
    a node claims names a port alone.

## Decision drivers

*   **What peers meet:** a node is undialable when its published rendezvous
    address, the one every first contact dials, does not answer.
*   **The cause beside the effect:** a translator is expected; anything else
    is a fault to look at.
*   **The default bind:** detection works on a node that binds the wildcard
    host.
*   **Shown, never decided on:** like a joiner's claims (ADR-0022,
    decision 8), the observations inform the operator, and no loop acts on
    them.
*   **The instruments that exist:** no new exchange, message, or service.

## Considered options

*   **The founder's probes:** the founder's selection loop echoes every node
    it holds no link to, and a silent node is tagged.
*   **The acceptor's observations, reported to the core:** the node that
    accepts a link echoes the dialer's published rendezvous address,
    compares the link address the dialer claims with the source it observes,
    and reports both to the core.
*   **The acceptor's echo and the node's own check, in its entry:** the
    acceptor echoes the dialer and answers the outcome in its link reply;
    the node checks whether its published host is its own; its directory
    entry carries both.

## Decision outcome

Chosen option: **the acceptor's echo and the node's own check, in its
entry**, amending ADR-0017's decision 11:

1.  **A node is undialable when its published rendezvous address goes
    unanswered.** The node that accepts a link request echoes the
    requester's published rendezvous address, as the selection loop's probe
    echoes a candidate. Its reply says whether the echo was answered, and
    says nothing when the acceptor's directory names no address for the
    requester. The requester keeps the latest answer.
2.  **A node is translated when its published host is not its own.** At
    each publication the node checks the host its entry names: a host the
    node cannot bind is a translator's.
3.  **The directory entry carries both facts.** The directory serves them
    beside the addresses, and a zero fact reports nothing observed. They are
    the node's own report: shown, never decided on.
4.  **The console tags each node with its role, then at most one observed
    tag.**
    *   **NAT:** translated and undialable.
    *   **Degraded:** undialable and not translated.
    *   A translated node peers can dial, such as a one-to-one cloud address
        or a forwarded port, carries no observed tag.

### Positive consequences

*   The console shows which nodes reach the network only over links they
    dial, and tells a translator from a fault.
*   Detection works under the wildcard bind.
*   The facts reach every directory copy, not the founder's alone.
*   The wire grows by one optional field in the link reply and two in the
    directory entry, with no new message or service.

### Negative consequences

*   A node reports itself. A node that misreports carries a wrong tag, and
    nothing acts on it.
*   The answer follows the node's latest establishment and each start's
    confirm pass. A node whose links all stand keeps its last answer.
*   Each link request costs the acceptor one echo before it replies: a round
    trip when answered, the exchange's three attempts, 1.5 seconds, when
    not.
*   A system that lets a socket bind an address it does not hold reads as
    untranslated, and its undialable node as Degraded.

## Pros and cons of the options

### The founder's probes

*   Good, because it needs no wire change: the founder already probes every
    node it holds no link to.
*   Bad, because it sees from one place, and never probes the nodes linked
    to it.
*   Bad, because silence alone cannot tell a translator from a fault.

### The acceptor's observations, reported to the core

*   Good, because the observer reports, not the node observed.
*   Bad, because under the wildcard bind the claimed link address names a
    port alone. A translator that keeps ports, as many do, looks like none,
    and its nodes read as faults.
*   Bad, because every node reports to the core through a new service, and
    the core aggregates the reports.

### The acceptor's echo and the node's own check, in its entry

*   Good, because a node knows its own addresses whatever it binds.
*   Good, because the facts ride the reply and the entry that exist.
*   Bad, because the node reports itself, and its answer can go stale.
