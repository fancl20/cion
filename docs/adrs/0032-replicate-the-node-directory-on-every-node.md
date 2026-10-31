# Replicate the Node Directory on Every Node

*   Status: accepted
*   Date: 2026-10-29

[TOC]

## Context and problem statement

The node directory tells every node which other nodes exist and how to reach
them. Each entry names a node's ISD-AS, its control and rendezvous addresses,
and its report of how its peers reach it. A node draws its link candidates
from the directory, and a node behind a NAT punches through a neighbor whose
entry reports that its rendezvous address answers
([ADR-0030](/docs/adrs/0030-punch-through-both-nats.md)).

[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
decision 11, has the core aggregate and serve the directory. Only the founding
core does: an authoritative core joins like any other node and serves none.
Every node publishes its entry to the founder every minute and fetches the
whole directory every 30 seconds. The founder drops an entry five minutes after
its last publication.

*   **The founder is the directory's single point of failure.** With the
    founder down, no publication lands and no fetch answers. Each node keeps
    the copy it fetched last. A node whose host or reach changes stays at its
    old entry everywhere. A node that restarts holds no entry at all, so it
    has no candidates and no neighbor to punch through until the founder
    returns.
*   **Every node already holds the whole directory.** The fetch delivers every
    entry to every node every 30 seconds. The copies exist; only their source
    is central. The founder sends all of them: every node's copy of every
    entry, each half minute.

Serving the directory from every core removes the single point of failure.
However, it multiplies the publishing and the fetching by the number of
cores, and the cores' copies differ wherever a node reaches only some of them.

[ADR-0028](/docs/adrs/0028-serve-each-site-a-directory-of-its-own.md), still
proposed, nests the directory in scopes. The network is the root scope, and a
site behind a translator is a scope inside another, served by a core inside
the site that the operator gives the site's range. Addresses inside a site
reach only the site's nodes. A directory held by every node has to keep that
layering: a site's entries must stay among the site's nodes, at every depth
of nesting.

Three properties of the directory make it easy to replicate:

*   **One writer per entry.** A node's entry is written by that node alone,
    and ordered by that node's own clock.
*   **Entries are hints.** The selection probes a candidate before linking it,
    so a stale entry costs a probe or a punch attempt, not a link.
*   **Entries age.** An entry that is not refreshed within its lifetime no
    longer counts.

## Decision drivers

*   **No server:** losing any node, cores included, loses no other node's
    entry and stops no publication.
*   **Authentic end to end:** an entry is its node's own statement, and every
    node can verify it, whatever route it took.
*   **Links only:** replication rides the links nodes already hold. It needs
    no composed path, no segment lookup, and no core.
*   **Scopes hold:** a site's addresses reach only the site's own nodes, at
    every depth of nesting.
*   **No configuration names a scope:** sites follow from the network, as
    ADR-0017's regions follow from measurements.
*   **Bounded traffic, no hotspot:** the traffic a node carries follows the
    directory's changes and refreshes. No uplink sends every node a full copy
    each half minute.
*   **Consumers unchanged:** the node bus topic
    ([ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md))
    publishes the directory as the node holds it.
*   **No new trust assumptions:** replication relies only on chains, the TRC,
    and each node's own clock running forward. Only a node's view of the
    directory reads its clock, as SCION's expiry times already do.

## Considered options

Where the directory lives:

*   **The founding core serves it,** as today.
*   **Every core serves it:** a node publishes to and fetches from every core.
*   **The cores replicate it among themselves:** a node publishes to one core
    and fetches changes from one.
*   **Every node replicates it:** each node holds the directory, and nodes
    exchange entries.

How entries travel between nodes:

*   **Gossip to random members:** SWIM-style membership, as in HashiCorp's
    memberlist and Serf.
*   **A Merkle-CRDT store:** a replicated key-value store over a DAG of
    changes, as in go-ds-crdt.
*   **Entries in beacons:** each node attaches its entry to the beacons it
    propagates.
*   **Flooding along links:** the pattern link-state routing uses in IS-IS
    and OSPF. A newer entry goes to every neighbor, and neighbors compare
    summaries when a link comes up.

How a site's directory is kept:

*   **Its core serves it,** as ADR-0028 proposes.
*   **Its members replicate it,** with its core as the anchor that carries
    the site's range and admits its members.
*   **Its scope emerges from links:** a node's links group by the host each
    peer sees it at, and links join the groups into scopes.

## Decision outcome

Chosen options: **every node replicates it**, with **flooding along links**,
and each site's **scope emerging from links**. This replaces ADR-0017's
decision 11 and supersedes ADR-0028: the founder's directory service
retires, and ADR-0028's site cores and ranges are never built.

1.  **Every node holds the directory.** The directory is the set of entries,
    one per node. Each node keeps the whole set, and no node serves it to
    others as their source. The cores hold it like every other node.
2.  **A node signs its own entry.** The entry carries the TRC the node has
    pinned, the time it was signed, and a signature by the node's AS key,
    which the node's TRC-anchored chain certifies. A node accepts an entry
    only after verifying it against the signer's chain, a chain valid at the
    entry's signing time, so acceptance reads no clock. It fetches a missing
    chain from the neighbor that sent the entry, over the one-hop channel,
    as it fetches a beacon's missing trust material. No node can forge or
    alter another node's entry, and only an enrolled node can sign one, as
    only an enrolled node can publish today.
3.  **The directory is a join-semilattice, and no merge reads a clock.**
    *   **Order:** a node's entries are ordered by the TRC the node had
        pinned when it signed, then by signing time, then by signed bytes.
        Holding no entry of a node is the bottom.
    *   **Join:** two directories merge node by node, keeping the greater
        entry. The join is commutative, associative, and idempotent, and it
        reads no clock. Nodes that received the same entries hold the same
        directory, whatever the order, the routes, or the repeats of
        delivery, and whatever their clocks read.
    *   **Updates only grow:** a node changes only its own entry, and only to
        a greater one: under the newest TRC it has pinned, at a later signing
        time. It signs a new entry at each change of its own state, a newly
        pinned TRC among them, and at a refresh interval well inside the
        lifetime. The order rests on each node's own clock running forward:
        it compares a node's signing times only with one another.
    *   **Validity is a view:** what a node presents of the directory is each
        signer's greatest entry, if two checks pass:
        *   the entry names the TRC the node has pinned, or its predecessor
            while that one's grace period runs;
        *   its signing time lies in a window around the node's own clock: no
            earlier than one lifetime before it, and no later than a small
            bound after it.

        The checks filter the view and never the directory, so expiry is no
        operation on it. A node may discard entries its view no longer shows
        to bound what it stores: an entry that comes back is judged by the
        view again.
    *   **Withdrawal:** a node that stops on purpose signs a withdrawal, an
        entry that names no address. It outranks the node's earlier entries,
        and it leaves the view with the window.
    *   **Recovery from a runaway clock:** a node whose clock ran far ahead
        signs entries that outrank its later ones. An entry under a newer
        TRC outranks every entry under an older one, and the view shows only
        entries under the current TRC once its predecessor's grace period
        ends. The network's next TRC update therefore ends the problem at
        the latest, along with any leftover copy of the runaway entries. A
        clock that far off fails certificate validation in the meantime as
        well.
4.  **Entries travel along links.** Every exchange rides the link's one-hop
    channel, with both ends authenticated by their chains, as beaconing does.
    *   **Flooding:** a node that accepts an entry greater than the one it
        held sends it to its other neighbors.
    *   **Catch-up:** when a link comes up, and periodically while it serves,
        the two ends exchange summaries naming each signer's greatest entry.
        Each sends the other the entries the other lacks or holds a lesser
        one of. A node that starts fills its directory from its first
        neighbor.
    *   **Forwarding bound:** a node forwards each signer's greatest entry at
        most once per bound. A node that signs in a loop costs its neighbors
        one entry per bound, not a flood, and its latest entry still travels.
5.  **Scopes emerge from links.** A link runs between two nodes on one
    network, so the links reveal the networks, and no range, core, or
    operator names a site.
    *   **Attachments:** a node groups its links by the host each peer sees
        it at. A node behind a home router inside an office has three
        attachments: its own address for its home peers, the router's office
        address for its office peers, and the office's public address for
        its internet peers.
    *   **Every directory has an ID:** a node keeps its directories keyed by
        ID, and each of its attachments names one. A new attachment starts
        with a fresh time-ordered random ID, a UUIDv7 minted from the node's
        clock. Each link carries the IDs of the attachments at its two ends,
        and both ends keep the lesser, so the IDs of attachments that links
        join converge to the oldest among them. A node that joins a scope, or
        restarts inside it, mints a later ID and adopts the scope's: a scope
        keeps its ID while any of its nodes holds it.
    *   **Merging IDs merges directories:** when an attachment's ID gives way
        to a lesser one, its directory joins the directory under the lesser
        ID, signer by signer, and the greater ID names no directory any more.
        IDs merge by keeping the lesser, directories by the join of decision
        3, and a directory whose ID gave way by joining another, so the whole
        remains one join-semilattice. The merge compares IDs and reads no
        clock. In what order a node merges entries and IDs makes no
        difference: nodes that saw the same links and entries hold the same
        directories under the same IDs.
    *   **Scopes are what the IDs join:** a scope is the set of attachments
        whose IDs links have merged into one. Two sites on the same private
        range never link at their inside addresses, so their IDs never
        merge, and nesting follows the translators. A node that one network
        sees at two hosts, behind a pool of translator addresses or on two
        uplinks, finds both attachments under that network's ID and their
        directories merged into one.
    *   **One entry per directory:** a node signs an entry in each directory
        it holds, naming the hosts that directory's peers see it at. Within
        a scope, decisions 1 to 4 apply as written, and an entry travels
        only over links whose attachments name its directory's ID, so it
        never leaves its scope.
    *   **Bootstrap:** a node inside a site is given neighbors inside it at
        its start, beside or instead of one outside, as the run arguments
        already allow several. Its first links inside the site merge its
        inner attachment's ID into the site's. The site's directory then
        names the site's other nodes, and the selection links them.
6.  **The node bus carries the node's view** of the directories it holds,
    as it carries the fetched copy today.

The lifetime and the future bound of the view's window, the refresh
interval, the summary period, and the forwarding bound are the implementing
proposal's to set. The lifetime bounds how long a departed node lingers as a
candidate. The refresh interval sets the traffic every node carries.

### Positive consequences

*   Convergence follows from the order alone. Nodes that received the same
    entries hold the same directory, however the entries traveled, and
    flooding with catch-up delivers every entry to every node a path of
    links reaches.
*   No clock decides a merge. A node's clock changes what it shows, and
    which old entries it may discard, never which entry wins, so clocks that
    disagree cannot keep the nodes' directories apart.
*   The directory survives the loss of any node, cores included. A partition
    leaves each side its own directory, and a healed link merges them.
*   One mechanism serves every depth of nesting, and no configuration names
    a site. A site's addresses stay among the site's nodes, two sites on one
    range never mix, and a site's directory needs no core: it lives while
    the site's nodes link inside it.
*   A restarting node holds a full directory as soon as its first link comes
    up.
*   A change reaches every node within about the network's diameter in link
    round trips.
*   Traffic spreads over every link and follows the entries and their
    refreshes: each new entry crosses each link about once, and no node
    sends a full copy to every other.
*   The founder no longer serves the directory. Issuance, enrollment, and the
    TRC vote remain its own.
*   Entries are authenticated by their writers, not by whichever server holds
    them.

### Negative consequences

*   Every entry carries a signature. Every new entry costs a verification,
    and a signer's first entry costs a chain fetch.
*   Every node carries the refresh traffic of the whole network: about one
    entry per node per refresh interval, growing with the network. That is
    within CION's target scale (ADR-0017, "Non-Scalable by Choice").
*   A node that crashes lingers as a candidate until its entry leaves the
    views' window. A longer lifetime saves refresh traffic and lengthens the
    linger.
*   A node whose clock is far off shows entries past their lifetime or hides
    fresh ones, the exposure SCION's segments and hop fields already carry.
    A node whose own clock steps backward signs entries below its earlier
    ones, which stay greatest: views show its last entry until that leaves
    the window, and nothing after, until its clock passes that entry or the
    next TRC update.
*   A node whose neighbors all withhold an entry never receives it. Such a
    node is cut off by those neighbors anyway.
*   A node signs and holds one entry per directory.
*   A site forms a scope only once a link runs inside it: a node inside a
    site needs a neighbor inside it at its start, or a site whose nodes all
    joined from outside never links inside.
*   A scope holds against outsiders, not against its members. A misbehaving
    member can pass the scope's entries to a node outside it, as a member
    served by a site core could. It can also merge two scopes it sits in,
    or relabel them, by giving them one ID or a very old one. A merge is
    never undone: two directories that joined stay joined.
*   A node whose clock runs far behind mints IDs that win every merge, and
    relabels each scope it joins. The clock costs the IDs' stability, never
    their convergence.
*   CION implements and maintains the replication protocol itself, where
    libraries exist for the other patterns.

## Pros and cons of the options

### The founding core serves it

*   Good, because one copy is the source and nothing replicates.
*   Bad, because losing the founder stops every publication and every fetch,
    and a restarted node holds no directory.
*   Bad, because the founder sends every node every entry each half minute.

### Every core serves it

*   Good, because the directory survives the loss of any one core.
*   Bad, because publications and fetches multiply by the number of cores.
*   Bad, because the cores' copies differ wherever a node reaches only some
    of them, and merging the copies needs timestamps that compare across
    cores.

### The cores replicate it among themselves

*   Good, because a node publishes once and fetches only changes.
*   Bad, because it adds a core-to-core protocol.
*   Bad, because it keeps the directory on servers a node must reach: a node
    cut off from every core holds a frozen copy.

### Every node replicates it

*   Good, because no server remains to lose, and every node already holds a
    copy.
*   Good, because traffic spreads over the links and follows the changes and
    refreshes.
*   Bad, because entries pass through other nodes, so they must be signed.
*   Bad, because every node carries the refresh traffic of the whole network.

### Gossip to random members

*   Good, because mature libraries implement it, failure detection included.
*   Bad, because a random member is reached over a composed path, and the
    path's segments come from the cores: the dependency this record removes.
*   Bad, because the libraries authenticate members with one shared key, so
    any member can make claims about another.
*   Bad, because their failure detection duplicates the links' BFD sessions
    and the selection's probes.

### A Merkle-CRDT store

*   Good, because it converges for any number of concurrent writers.
*   Bad, because the directory has one writer per entry, so the machinery for
    concurrent writers adds nothing.
*   Bad, because it keeps deletions as tombstones and the store only grows:
    every refresh would add to the DAG.
*   Bad, because it brings the IPFS stack alongside SCION.

### Entries in beacons

*   Good, because beacons already travel every link, signed by every AS they
    cross.
*   Bad, because beacons travel outward from the cores. A node learns only
    the entries of the nodes on its paths toward the cores, not the whole
    network, and beacons still start at the cores.

### Flooding along links

*   Good, because link-state routing has proven it for keeping one database
    on every node, refreshed and aged.
*   Good, because it rides the links and the one-hop channel that nodes
    already hold: no path, no lookup, and no core.
*   Good, because a link that comes up catches its two ends up with one
    exchange of summaries.
*   Bad, because CION implements and maintains the protocol itself.

### Its core serves it

*   Good, because each site has one source, as the root has today.
*   Bad, because a site's directory falls with its core, and a site is served
    by a mechanism other than the root's.
*   Bad, because each site needs a core and an operator-given range.

### Its members replicate it

*   Good, because one mechanism serves the root and every site, and a site's
    directory outlives its core.
*   Bad, because the core and its range are still needed to enter a site,
    and the core serves as the meeting point of its members until they link
    inside it. A core can hold only a few links, so it cannot link every
    member.

### Its scope emerges from links

*   Good, because no configuration, range, or role names a site: the links
    reveal the networks, at every depth of nesting.
*   Good, because a scope lives while its nodes link inside it, whichever of
    them is down.
*   Good, because two sites on one range never mix: no link joins them.
*   Good, because one join-semilattice holds every scope: IDs, directories,
    and their merges converge together.
*   Good, because the oldest ID wins, so a node that joins or restarts
    leaves its scope's ID as it was.
*   Bad, because a site's first inside link needs a neighbor named inside
    it.
*   Bad, because two scopes that a misbehaving node merged stay merged.
