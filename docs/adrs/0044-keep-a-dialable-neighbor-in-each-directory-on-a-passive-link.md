# Keep a Dialable Neighbor in Each Directory on a Passive Link

*   Status: proposed
*   Date: 2026-11-11

[TOC]

## Context and problem statement

Two needs tie a node to the dialable nodes of each directory a punch runs
in:

*   **A punch needs a reflector at both ends:** an established neighbor that
    reports itself dialable there
    ([ADR-0030](/docs/adrs/0030-punch-through-both-nats.md), decision 3). A
    node behind a NAT with no dialable neighbor can neither punch nor be
    punched.
*   **A node learns its directory over its links:** entries flood along
    links, and each link catches its two ends up
    ([ADR-0032](/docs/adrs/0032-replicate-the-node-directory-on-every-node.md),
    decision 4). A node with no link left in a directory stops signing
    there, and its view drops each entry a lifetime after its signing, 15
    minutes today. It then knows no dialable node to dial, and dials only
    what its table holds
    ([ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
    decision 8).

[Proposal 0133](/docs/proposals/0133-keep-the-last-link-to-a-reflector-in-each-directory.md)
keeps the last up link to a reflector in each directory a punch runs in,
and only a down verdict retires it. The kept link holds one of the cap's
eight slots (ADR-0017, decision 7) and carries beacons and paths, though the
link policy found the paths do not need it. A broken one is not replaced.
Each punch reflects off the first reflector in the directory's order, by
ISD-AS, which may lie across a continent while a nearby one is linked; a
binding request waits half a second for each of its three attempts.

The cap bounds beaconing fan-out (ADR-0017, decision 1;
[ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md), decision
6). A link that carries no beacons costs its liveness and the directory's
traffic, which every link carries: about one entry per node of the
directory every five minutes.

How should a node keep its reach to each directory's dialable nodes without
spending the slots that paths compete for?

## Decision drivers

*   **Reach outlives the link policy:** what reflection and the directory
    need holds whether or not paths need the link.
*   **The slots go to paths:** the cap's slots go to links that carry
    beacons.
*   **Recovery from what the node holds:** a node that loses its dialable
    neighbor regains one without help.
*   **Dialable nodes bear a known load:** they are few, and every link to
    them costs them.
*   **One way into the paths:** a link starts carrying paths only through
    the promotion's tests and coordination
    ([ADR-0037](/docs/adrs/0037-coordinate-link-changes-through-the-node-directory.md)).

## Considered options

*   **Keep the last reflector active,** as today.
*   **Reflect off any dialable node, unlinked:** the acceptor answers any
    binding request.
*   **One passive link per directory:** a link that carries no beacons.
*   **Two passive links per directory.**

## Decision outcome

Chosen option: **one passive link per directory**, realized as follows:

1.  **A link is active or passive.** An active link is a link as today. A
    passive link carries no beacons: neither end sends one over it, and a
    beacon arriving over it is dropped, so no path crosses it. Both ends
    hold the link in one mode, and a change of mode is asked over the link
    and answered.
2.  **A passive link serves all but paths.** Its liveness runs as any
    link's, keeping the NAT's mapping open; the directory floods and catches
    up over it (ADR-0032, decision 4); and its neighbor serves the node as a
    reflector (ADR-0030, decision 3).
3.  **Each node keeps a link to a dialable node in each directory a punch
    runs in,** a directory that holds an entry of an undialable node. One
    suffices: the link keeps the directory current, a punch needs one
    reflector, and a node that loses the link dials another dialable node,
    which needs no reflector. An active link meets the floor, and a passive
    one where no active link does.
4.  **The floor's last link is demoted, not retired.** Where the link
    policy would retire the node's last link to a dialable node of such a
    directory, as useless or displaced at the cap, it turns the link
    passive, announced and coordinated as a retirement is (ADR-0037). A
    passive link turns active only as a new link does: by the promotion's
    tests, announced and coordinated. It retires once an active link to a
    dialable node of its directory serves, or once its verdict stays down.
5.  **A broken floor is restored at once.** When a directory's last link to
    a dialable node goes down, or its peer retires it, the node dials, after
    a random delay, the dialable node there with the least round trip it
    measured, the next one on a failure, while its view shows any; the new
    link is passive. The node keeps it until it breaks, whatever faster node
    appears. Past its view, the node dials what its table holds (ADR-0017,
    decision 8).
6.  **A punch reflects off the fastest.** Of the node's up links, active or
    passive, to nodes dialable in the directory, the punch's binding request
    goes to the one with the least round trip the node measured.
7.  **Passive links count apart.** The cap counts active links, and so does
    ADR-0017's floor of two up links: a passive link carries no path, so it
    is neither a path's slot nor its redundancy. A dialable node admits
    passive links up to a bound of their own, above the cap, and refuses
    past it; the asker turns to the next dialable node.
8.  **The labs judge it:** the NAT labs, settled and with the founder down;
    a lab in which the dialable node that a node behind a NAT keeps leaves;
    and a lab of many nodes behind NATs per dialable node, for the bound.

This narrows ADR-0017's decisions 6 and 7, ADR-0036's decision 6, and
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)'s
principle 6 to active links, and ADR-0030's decision 3 to the fastest
reflector. It changes the beaconing loops that
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md),
decision 1, keeps in the core: they send over, and accept from, active
links alone. It replaces proposal 0133's rule. ADR-0032's decision 4
stands: entries travel along every link. Every other retirement could leave
the same way, passive first and closed once its paths age out, so that all
links leave alike; that is a decision of its own, once a lab weighs it.

### Positive consequences

*   A node behind a NAT keeps a reflector and a current directory whatever
    the link policy decides, and regains both within seconds of losing
    them, with no punch.
*   The kept link takes none of the cap's slots and carries no beacons.
*   A punch's binding request waits on the shortest round trip among the
    node's reflectors.
*   A dialable node holds one passive link per node behind a NAT that has
    no active link to a dialable node, not two.
*   A link can leave without dropping traffic: turned passive, it carries
    the paths that cross it until they age out, five minutes after its last
    beacon, and then closes.
    [ADR-0043](/docs/adrs/0043-grow-capacity-between-nodes-under-load.md)'s
    drains can take the same step, which moves every node's paths off the
    link, not the node's own leases alone.

### Negative consequences

*   The beaconing loops in the core read each link's mode: a core change
    that no draft asks for.
*   The link service carries the mode, and both ends must agree on it.
*   A passive link still carries its liveness and the directory's traffic,
    and a dialable node pays both for each one, up to its bound.
*   Between a floor link's break and its replacement, no punch runs in that
    directory, for seconds.
*   Nodes that keep their passive links on one dialable node redial
    together when it leaves; the random delay spreads them.
*   A passive link that paths come to need waits for the promotion's tests,
    where the active link it replaced served at once.

## Pros and cons of the options

### Keep the last reflector active, as today

*   Good, because it exists, and needs no mode.
*   Bad, because the kept link holds one of the cap's eight slots, and
    carries beacons and paths the link policy found the paths do not need.
*   Bad, because a broken one is not replaced: the node holds no reflector
    until its link policy buys a link to a dialable node for its paths.

### Reflect off any dialable node, unlinked

*   Good, because no link is needed: the acceptor answers any binding
    request.
*   Bad, because the directory travels over links: a node whose links all
    leave a directory drops its entries a lifetime after their signing, and
    with them every dialable node it could reflect off or dial. The labs,
    whose nodes never change, do not show it.

### One passive link per directory

*   Good, because reflection and the directory outlive the link policy
    without taking a slot.
*   Good, because one link keeps the directory current, and a dial that
    needs no reflector replaces a lost one.
*   Bad, because the core's loops read the mode, and the wire carries it.

### Two passive links per directory

*   Good, because punches go on through one link's break, and one link
    survives a replacement that keeps failing for a whole lifetime.
*   Bad, because dialable nodes hold twice the passive links.
*   Bad, because a failure of the node's own uplink takes both.
