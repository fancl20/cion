# Form directory scopes from links

This proposal implements
[ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md)'s
decision 5, and decision 6 for scopes, on top of the directory
[proposal 0097](/docs/proposals/0097-replicate-the-node-directory-along-links.md)
replicates:

*   A node groups its links by the host each peer sees it at.
*   Each group names a directory ID, and links merge the IDs to the least.
*   The node replicates one directory per ID, and each directory holds only
    the entries signed for it.

With proposal 0097, it completes ADR-0032.

[TOC]

## Summary

Every node holds one directory, and each node's entry in it names one host
([directory.go](/pkg/modules/topology/impl/measured/directory.go)):

*   **The host follows the last observer.** Every rendezvous reply's
    reflexive address feeds one learned host, and the latest reply wins,
    whichever side of a translator the replier stood on
    ([external.go](/pkg/modules/topology/impl/measured/external.go)). The
    bootstrap, the joiner's dials, and the selection's probes all feed it,
    and a file in the state directory keeps it across restarts.
*   **One reach report per node.** The acceptor of the node's latest link
    request echoes the node's published rendezvous address and answers in
    its link reply
    ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)).
*   **A rule by address class.** The selection skips private, shared, and
    link-local addresses for a viewer whose own address is global
    (`probeable`,
    [selection.go](/pkg/modules/topology/impl/measured/selection.go)).
*   **The learned host's other readers.** The node's own state carries the
    learned host
    ([self.go](/pkg/libs/bus/self.go)). The WireGuard entry's endpoint
    reads it
    ([directory.go](/pkg/apps/wireguard/directory.go)), and so does the
    wildcard bind's source resolution
    ([wildcardhost.go](/internal/services/wildcardhost.go)).

The site lab
([proposal 0078](/docs/proposals/0078-observe-a-site-behind-one-translator.md))
measures the result, five runs of each benchmark:

*   **Joined through outside neighbors:** no site pair links inside, and the
    founder's view only ever holds the site's gateway.
*   **Two joined through inside neighbors:** 3 to 5 of the site's 6 pairs
    link inside. Before the network settled, the founder's view, read every
    ten seconds, held a site node's inside address in up to 4 reads, and a
    node's host changed up to twice.

## Motivation

### Goals

*   Two nodes that share a network inside a translator find each other's
    addresses inside it, and no address leaves the networks that observed
    it.
*   A node's entry in each scope names the hosts that scope's peers see it
    at, whatever nodes elsewhere observe.
*   A node's reach in a scope is judged from inside that scope.
*   No configuration, range, or address class names a scope.

### Non-goals

*   Scoping the WireGuard directory, which stays the founder's.
*   Joining a site's islands that no given neighbor connects. ADR-0032
    accepts that a site forms one scope only where its links run.
*   Hairpinning.

## Proposal

### Attachments

*   **The observation.** Each end of a link tells the other the source its
    data plane last observed the link's packets arrive from: the link
    state's `Observed`. The host of what the peer reports is the host the
    peer sees the node at. The port is ignored.
*   **The attachment.** A node groups its links by that host. Each group is
    an attachment, which holds the host, a directory ID, and the host's
    reach. A link joins the attachment its latest report names, and moves
    when a report names another host.
*   **Its lifetime.** An attachment whose links have all gone stays, with
    its ID and its directory, while the directory holds an entry. A link
    that comes back at the same host rejoins it, and the node keeps the
    scope's candidates to link again.

### Directory IDs and the `Attach` call

*   **The ID.** A new attachment mints a UUIDv7 from the node's clock. IDs
    compare by their 16 bytes. Nothing persists them.
*   **The call.** `DirectoryService` gains a third call, `Attach`, served
    behind the peer middleware like the others.
    *   The request carries the caller's observation of the link and the
        ID of the caller's attachment for the link. The ID is empty while
        the caller knows no attachment for the link.
    *   The reply carries the callee's observation of the caller, the
        callee's ID after the merge, and the callee's echo of the caller.
    *   Each end keeps the lesser ID.
*   **The merge.** When an attachment's ID gives way to a lesser one, every
    attachment naming the greater ID takes the lesser. The greater ID's
    directory joins the lesser's, signer by signer. If the node holds no
    directory under the lesser ID, the greater's directory takes that ID.
*   **When it runs.** Each end calls `Attach` on a link before each of the
    link's syncs. That is when the link comes up, every summary period,
    when the node's own observation of the link changes, and when the node
    first holds its chain, before which no neighbor's channel admits it.
    A link whose attachment is not known yet carries no entries.

### Scoped directories

*   **One directory per ID.** The node holds a directory for each ID its
    attachments name. Each is proposal 0097's directory, with its order,
    join, view, discarding, and forwarding bound.
*   **Arrivals.** A pushed or synced entry joins the directory of the
    receiving end's attachment for the link it arrived over.
*   **Flooding and catch-up.** An accepted entry is pushed over the links
    whose attachments name its directory, except the one it came from. A
    sync summarizes the link's directory. An entry never leaves its scope.

### The node's entries

*   **The form.** An entry names its signer's addresses. Each address
    gives the control and rendezvous addresses on one host, whether a NAT
    stands in front of the host, and whether the host's rendezvous port
    answered. An entry that names no address is a withdrawal.
*   **One per directory.** The node signs an entry in each directory its
    attachments name. The entry names the hosts of those attachments that
    hold a link. The node signs again at each change of those hosts or
    their reach, at each merge, and every refresh interval. A directory
    that none of the node's links attaches to gets no new entry, and the
    node's last entry there ages out.
*   **Withdrawal.** A node that stops on purpose signs a withdrawal in each
    of its directories, and pushes each over that directory's links.

### Reach per host

*   **The echo.** Before answering an `Attach`, the callee sends a binding
    request to the caller's rendezvous port, at the host it observes the
    caller at. Its reply reports whether the port answered. The caller
    records the outcome on the attachment the reply's observation names,
    and the latest echo wins.
*   **The link reply's echo goes.** The link service's echo of a
    requester's published address retires, and with it
    `LinkReply.rendezvous_answered`. Every report now comes from a peer
    inside the scope it describes.
*   **NAT.** Whether a NAT stands in front of a host stays the node's own
    check: it tries to bind the host.

### The node bus

*   **The directory topic** carries the view of each directory the node
    holds, by directory ID. A peer that shares several scopes with the node
    has an entry in each. Each entry carries the peer's addresses, with
    their reach, and its signing time.
*   **The node's own state.** `SelfState.Host` becomes the host the node's
    peers see it at in the scope that holds the founder's entry. A node
    that holds no such scope, such as one given only inside neighbors,
    takes the host of its attachment with the least directory ID instead.
    On the founding core, it stays the core's domain address.
    `SelfState.RendezvousUnanswered` goes, since reach now lives per
    attachment.

### The consumers

*   **The selection** probes every address a peer's entries name, in every
    scope, and keeps the fastest one that answers. A promotion dials the
    address that won. A peer none of whose addresses answers is punched in
    the scope of its first address. `probeable` goes, since a node holds
    only addresses that its scopes' peers observed.
*   **The punch** runs within one scope. Each side's reflector is an up
    neighbor whose address in that scope answers. `PunchRequest` and
    `PunchProbeRequest` name the directory, and the target picks its own
    reflector in it.
*   **The re-punch** reads the node's reach, and the peer's, in the scope of
    each punched link. A punched link needs no re-punch where the node's own
    host answers.
*   **The console** lists the founder's valid chains, as now, beside each
    peer any of the founder's views holds. A peer's last report is the
    latest signing time among its entries, and its tag comes from that
    entry's first address.

### The learned host retires

*   **What goes:** the learned host the rendezvous replies fed, its file in
    the state directory, and the selection's `Learn`. The directory reads
    attachments instead.
*   **WireGuard** keeps reading `SelfState.Host` for its entry's endpoint.
    That is now the host the founder's scope sees the node at, which is
    where the founder, the WireGuard directory's server, stands.
*   **The wildcard bind** asks the routing table for the source address
    toward `SelfState.Host`, or toward a live link's remote address while
    the host is unset. The conns that carry the first `Attach` need a host
    before any attachment exists. The first link, seeded from the
    bootstrap's rendezvous, gives them one.

### The site lab

*   **A third way of joining.** The lab keeps its two ways of joining, so
    their results stay comparable, and adds a third, `both`. In it, each
    site node after the first joins through an outside parent and an inside
    neighbor already in the site:
    *   3 through 1;
    *   4 through 2 and 3;
    *   5 through 0 and 3;
    *   6 through 2 and 4.

    The site's given neighbors form one island, and every site node also
    holds the outside directory.
*   **The two existing ways** run unchanged.
    *   Joined outside, no site node is given an inside neighbor, so no
        scope forms inside, as ADR-0032 accepts.
    *   Joined inside, 5 through 3 and 6 through 4, the site forms two
        islands, {3, 5} and {4, 6}, which no given neighbor connects. 5 and
        6 hold no outside directory, so the founder's view holds neither.

### The design overviews

The [architecture](/docs/design/architecture.md) follows: the topology
source draws candidates from the directory of every scope the node holds,
and the node bus carries each directory's view.

### Packages touched

| Package | Change |
| :-- | :-- |
| `proto/node/v1` | `Attach`; the entry's addresses; the link reply without its echo; the punch requests' directory |
| `pkg/libs/bus` | The directory's views by directory ID; the entries' addresses; `SelfState` without the reach |
| `pkg/modules/topology/impl/measured` | Attachments, the scoped directories, `Attach` and its echo, the entries, the selection's addresses, the scoped punch and re-punch; the learned host and `probeable` go |
| `internal/services` | The wildcard bind's routing toward a link |
| `pkg/apps` | The console's records over the views |
| `internal/testnetwork` | The scopes lab |
| `internal/testnetwork/behavior` | The site lab's third way of joining |
| `docs/design` | The architecture |

## Compatibility

*   **The wire.** The changes below mean nodes of the two versions share no
    directory and punch no link between them. Upgrade every node together.
    *   The directory service gains `Attach`, and the entry's form changes.
    *   The link reply drops its echo.
    *   The punch requests name a directory.
*   **State.** The learned host's file is no longer read or written, and
    nothing else persists.
*   **The console's API.** Unchanged.

## Test plan

The episodes follow ADR-0032's decision 5.

1.  **Attachments.**
    *   A node groups its links by the host each peer reports.
    *   A link moves when its report changes.
    *   An attachment outlives its links while its directory holds an
        entry.
2.  **Every directory has an ID.**
    *   A new attachment mints a fresh ID.
    *   Both ends of a link keep the lesser ID.
    *   Along a line of links, the IDs converge to the least, whatever the
        order of the calls.
    *   A node that restarts inside a scope adopts the scope's ID.
3.  **Merging IDs merges directories.**
    *   The greater ID's directory joins the lesser's, signer by signer.
    *   Merges and joins in any order end in the same directories under the
        same IDs, over generated links and entries.
4.  **Scopes are what the IDs join.** The lab places two nodes behind one
    translator and the founder outside:
    *   The two nodes share one ID, and the founder holds another.
    *   The founder's view never holds an inside address.
5.  **One entry per directory.**
    *   A node signs one entry per directory, naming the hosts of its
        attachments there.
    *   No entry is pushed or synced over a link of another directory.
    *   A withdrawal reaches every directory.
6.  **Bootstrap.** In the site lab's `both` way, the site's pairs link
    inside. Joined inside, each island's pairs do.
7.  **The node bus carries each directory's view.**
    *   The selection probes each address and dials the winner.
    *   The reflector stands in the target's scope.
    *   The re-punch reads the punched link's scope.
    *   The console lists the founder's views.

Beside the decisions:

*   **Reach per host.** The `Attach` reply reports the echo of the
    caller's host, and the link reply carries none.
*   **The learned host retires.** `SelfState.Host` follows the founder's
    scope, or the least directory ID on a node outside it, and the wildcard
    bind routes toward a link before the host is set.
*   **The benchmarks hold.** In the site's `both` way, 6 of 6 site pairs
    link inside. In every way, the founder's view never holds an inside
    address nor changes a site node's host.

## Implementation history
