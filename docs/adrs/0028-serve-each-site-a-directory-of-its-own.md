# Serve Each Site a Directory of Its Own

*   Status: proposed
*   Date: 2026-10-26

[TOC]

## Context and problem statement

Nodes behind one translator share a network of their own, a site, where each
reaches the others at addresses the outside cannot route. Sites nest: a home
behind its router can sit inside an office behind its own. CION keeps one
directory, and finds a site's addresses only by accident:

*   **Inside links by accident.** The directory publishes one host per node,
    the host its peers observe it at
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 11). For a node behind a translator that is usually the
    translator's outside address, which forwards no port, and
    [ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md)
    (decision 7) leaves links between two translated nodes out of scope. The
    site lab of
    [proposal 0078](/docs/proposals/0078-observe-a-site-behind-one-translator.md)
    measures both ways a site's nodes join:
    *   Joined through neighbors outside the site, no node learns another's
        address inside it. Site pairs 2ms apart reach each other through a
        node outside, the worst 22.5 times the reference under the labs'
        penalty.
    *   Once one joins through a neighbor inside, inside addresses spread:
        its first observed host is its address inside, which it publishes,
        and site peers probe it, link, and learn and publish their own. The
        site's pairs link inside within minutes, carried by the flip below.
*   **A host that follows the last observer.** A node keeps the host the
    latest rendezvous reply observed it at, whichever side of its translator
    the observer stands on. While it publishes its address inside, nodes
    outside the site dial an address they cannot route: in the site lab, the
    founder's directory held a site node's inside address for up to four
    minutes.
*   **Tags that follow it.**
    [ADR-0027](/docs/adrs/0027-tag-the-nodes-peers-cannot-dial.md)'s tags
    describe the published host and the echo of the acceptor of the node's
    latest link, whichever side that acceptor stands on. In the site lab, a
    node's tag changed up to five times before the network settled, and one
    node of twenty ended untagged behind its translator.

No class of address marks a site. Ranges repeat between sites, two homes
behind different translators both using 192.168.1.0/24, and when sites nest,
nothing in two ranges says which lies inside the other. Only the operator,
who knows each site's range, and reachability, which only a site's own nodes
have to its addresses, tell a site's members apart.

## Decision drivers

*   **Peers link inside:** two nodes link at their addresses inside the
    innermost site they share, not through nodes outside it.
*   **One view per scope:** a node's entry in a scope names the address that
    scope's nodes reach it at, whatever nodes elsewhere observe.
*   **Addresses stay in their scope:** no node is served addresses of a site
    it is not in.
*   **No address classes:** no rule depends on which range an address falls
    in by convention.
*   **Sites never mix:** a range two sites share names each site's nodes to
    that site alone.
*   **Approved servers:** a directory is served by a core the TRC names.
*   **Nodes in no site unchanged.**

## Considered options

*   **Inside candidates in the global directory:** each node publishes its
    inside address beside its outside one, and peers that share its outside
    address try it.
*   **Ranked observations:** a node ranks the hosts it is observed at by
    address class, public over private, so its global entry holds still.
*   **Discovery by multicast:** nodes announce their inside addresses on the
    local network.
*   **Nested site directories on site cores:** a core inside each site,
    given the site's range, serves the site's nodes at their addresses
    inside it, and sites nest within one another and within the network.

## Decision outcome

Chosen option: **nested site directories on site cores**, amending
ADR-0017's decision 11 and ADR-0027's decisions 1 to 3:

1.  **Scopes nest.** The network is the root scope, served by the directory
    every node reads today. A site is a scope inside another: a core inside
    it, joined by the TRC vote
    ([ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md))
    and given the site's range, serves its directory, whose entries publish
    and expire as the root's do. The core's entry in the enclosing scope
    names the range and the core's own address inside the site.
2.  **Membership is reachability.** A node belongs to every site whose core
    answers it at the core's address inside the site, naming the core's
    ISD-AS. A node reaches the cores of the sites around it, and no node
    reaches the core of a site it is outside of; a node joins its innermost
    site through a neighbor inside it. Each node thus holds a chain of
    scopes from the root inward, and sites that share a range never mix.
3.  **The ranges sort observations.** A node keeps an entry in each scope of
    its chain. An observed host feeds the entry of the innermost scope whose
    range holds it; any other feeds the root's. An entry no host has fed yet
    publishes nothing, so no scope is served an address of another.
4.  **Peers dial through the innermost scope they share.** A node draws its
    candidates from every directory of its chain, and probes and dials a peer
    at the peer's entry in the innermost scope both belong to. While a
    site's core does not answer, the node draws on the scopes around the
    site.
5.  **Each scope judges its own entry.** An acceptor echoes the requester at
    the requester's address in the innermost scope they share. The answer,
    and whether that entry's host is the node's own, are facts of the
    requester's entry in that scope. The console tags the root entry.

### Positive consequences

*   Peers of one site link directly, at every depth of nesting.
*   Each entry holds still whatever nodes elsewhere observe, the root entry
    and its tags among them.
*   A scope's addresses reach only its nodes; an enclosing scope carries one
    address per site inside it, its core's.
*   A site keeps a directory of its own while the root's is unreachable,
    though nodes outside still need the root's.
*   No address class decides anything: the same rules serve a home, an
    office, and their nesting.

### Negative consequences

*   A new role: each site needs a core inside it, joined by the TRC vote,
    with its range set by the operator. A translator whose network the
    operator cannot place a core in, such as a carrier's, adds no scope: its
    nodes stay in the enclosing one.
*   A node publishes once per scope of its chain.
*   A site without a core, or whose core is down, links as today: through
    nodes outside it.
*   A site's range must hold no address outside the site: an observed host
    the range holds is taken for an address inside it.

## Pros and cons of the options

### Inside candidates in the global directory

*   Good, because it needs no new role and no configuration.
*   Bad, because every node is served every inside address, most of which
    it cannot route.
*   Bad, because sharing an outside address does not mean sharing a site:
    behind a carrier's translator, unrelated homes share one.
*   Bad, because it serves one depth: a nested site needs a candidate per
    depth, and a rule for which one a peer tries.

### Ranked observations

*   Good, because it holds the global entry still with no new role.
*   Bad, because it bakes address classes into the design: which addresses
    count as public is a convention, and nesting orders no two private
    ranges.
*   Bad, because site peers still cannot find each other's inside addresses,
    and still link through nodes outside.

### Discovery by multicast

*   Good, because it needs no configuration.
*   Bad, because many networks block multicast, cloud networks among them,
    and it does not cross routed subnets.
*   Bad, because the announcements carry no authentication.

### Nested site directories on site cores

*   Good, because a site's peers find each other's addresses, and only they
    do, at every depth.
*   Good, because the operator's ranges and reachability split the views,
    with no guess and no address class.
*   Bad, because each site needs a core and a range.
