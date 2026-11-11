# File the Beacon Policy as a Module

*   Status: accepted
*   Date: 2026-11-11

[TOC]

## Context and problem statement

The control-plane draft splits propagation in two: the control service must
select which beacons to propagate, and the AS's policy determines which
(Section 2.3.3). A node's policy is the rule
[ADR-0036](/docs/adrs/0036-select-beacons-per-origin-and-link.md) decided:
among the routes a receiver can take, each origin's cheapest, then backups,
then each link's cheapest, ranked by price.
[ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md)
added the cheapest route over each link into the node's cluster (principle
9), and
[ADR-0041](/docs/adrs/0041-describe-nodes-by-tags-their-sources-apply.md)
let the rule read the cluster as a group tag, which tells it nothing of how
the group formed.

The rule runs inside the beaconing loops
([beaconselect.go](/pkg/core/controlplane/beaconselect.go)), which
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md),
decision 1, places in the node core and freezes there, so that the core's
churn is the drafts'. The rule landed on 2026-11-05, covered the links into
a cluster from 2026-11-08, and read the group tag from 2026-11-10: three
changes to the core, none from a draft. The core reads the node tags for the
rule alone.

ADR-0009's tests split the loops' work. Which routes to send is policy,
since two implementations could choose differently, and do: scionproto's
control service keeps a best set of 20 by default (ADR-0036's context). The
rest is owed, since other nodes depend on it whatever the node's policy:

*   **No loops:** a receiver discards a route that crosses it (Section
    2.3.1).
*   **Nothing toward a core:** beacons never travel toward a core (Section
    2.3.5).
*   **The founder's routes to a peer not enrolled,** whose enrollment rides
    them
    ([proposal 0113](/docs/proposals/0113-send-unenrolled-peers-the-founders-beacons.md)).
*   **Live routes alone:** a route whose beacons stop leaves within seconds,
    and a route whose interface no longer leads to its sender is one the
    data plane cannot carry.

Where should the beacon policy live, so that the core stops changing with it
while other nodes keep what they depend on?

## Decision drivers

*   **A core that stabilizes:** the core's churn is the drafts' (ADR-0009);
    tuning the policy edits no core package.
*   **Owed stays core:** what other nodes depend on, whatever the node's
    policy, stays with the loops.
*   **No policy engine:** one rule, and no configuration (ADR-0004, decision
    1; ADR-0036).
*   **Readers learn what they use:** the policy reads node properties as
    tags, never from the component that computes them (ADR-0041).
*   **The rule stands:** the move changes no beacon.

## Considered options

*   **The core, as today.**
*   **The topology source:** the source that forms the groups picks the
    beacons too.
*   **A module the operator selects:** the policy kind of
    [ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md), one
    method the operator's arguments choose.
*   **A module the assembly binds:** one method, and no run argument.

## Decision outcome

Chosen option: **a module the assembly binds**, realized as follows:

1.  **The beacon policy is a module.** It decides which routes the node
    sends each receiver, and in what order: ADR-0036's decisions 3 and 4,
    with ADR-0039's principle 9 and ADR-0041's group, as they stand.
2.  **The loops keep what is owed, and ask.** Each pass, the loops gather
    each receiver's routes as they do today: those whose beacons still
    arrive over an interface that leads to their sender (ADR-0036,
    decisions 1 and 2); for a neighbor, less those that cross it, and the
    founder's alone for a peer not enrolled, while a core receives none;
    for the node's own set, every one (decision 5). They ask the policy
    once per receiver, keep the first 64 routes of its answer, the store's
    bound per interface (decision 6), and extend, sign, send, terminate,
    and register them as before.
3.  **The ask is synchronous, and the policy reads its own inputs.** The
    loops hand it what their filters already read: the receiver, the
    founder the TRC names, and the receiver's routes. Whatever else a rule
    reads, such as the node tags, the policy reads for itself, so a rule
    that reads more changes no core package. A policy may keep state
    between asks, as the draft allows (Section 2.3.3).
4.  **The contract keeps what is owed.** A policy answers with routes it
    was handed, each once, and with one at least whenever it was handed
    any. No rule can then send a route the loops withheld, or leave a
    receiver that can take a route without one.
5.  **One method, bound by the assembly.** No run argument selects it, and
    no operator configures it; a new rule replaces the method. ADR-0004's
    absence of a policy engine stays.

This narrows ADR-0009's decision 1: the beaconing loops of ADR-0004 stay in
the core, and the choice of which routes they carry leaves it. It narrows
ADR-0013's decision 2: a policy the network does not configure is bound by
the assembly, as storage is. ADR-0036's rule, ADR-0039's principle 9, and
ADR-0041's tags stand as written.

### Positive consequences

*   A new rule changes the module and its records; the core changes with
    the drafts and the loops.
*   The core reads no node tags: the loops read the TRC, the link table, and
    the store.
*   Each rule is tested apart from the loops, against the contract that
    keeps what is owed.

### Negative consequences

*   A rule that changes what a receiver can take, rather than what it gets,
    still changes the core.
*   ADR-0013's kinds no longer fix the selection alone: a policy module's
    document says whether the operator selects it.
*   The policy ranks each receiver's routes apart, where the loops ranked
    them once per pass, unless it keeps the ranking between asks.
*   One more module and contract suite to keep.

## Pros and cons of the options

### The core, as today

*   Good, because the loops and the rule read as one, with no seam between
    them.
*   Bad, because each change to the rule edits the frozen core: three in six
    days, none from a draft.
*   Bad, because the core reads the node tags for the rule alone.

### The topology source

*   Good, because the link policy and the beacon policy, which ADR-0039's
    clusters tie together, would sit in one module.
*   Bad, because beaconing would change with the source: each source would
    carry a rule, the file provider a copy of the measured provider's.
*   Bad, because the rule would read the clustering, where the group tag
    tells it nothing of how a group formed (ADR-0041).
*   Bad, because a source supplies the node's inputs (ADR-0013, decision 5),
    and which routes to send is none of them.

### A module the operator selects

*   Good, because it is ADR-0013's policy kind as written, and a deployment
    could try a rule without a new build.
*   Bad, because it brings back the policy engine ADR-0004 left out, for no
    reader that needs one: the labs compare rules against the commit
    before.

### A module the assembly binds

*   Good, because the core stops changing with the rule, and no run argument
    appears.
*   Bad, because it narrows ADR-0013's kinds, and the contract must keep
    what is owed.
