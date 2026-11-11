# Move the beacon selection into a module

This proposal implements
[ADR-0042](/docs/adrs/0042-file-the-beacon-policy-as-a-module.md): the beacon
selection moves from the control plane into a beacon policy module, which the
beaconer asks once per receiver among the routes the receiver can take. No
beacon changes.

[TOC]

## Summary

Today
([beacon.go](/pkg/core/controlplane/beacon.go),
[beaconselect.go](/pkg/core/controlplane/beaconselect.go)):

*   **The selection sits in the control plane:** the price, the rank, the
    group, and the picks. Each propagation pass ranks the qualifying
    candidates once, then picks each neighbor's set among those it can take;
    registration picks the node's own set among them all.
*   **The beaconer reads the node tags** for the group, which only the picks
    use.
*   **The picks stop at 64,** the store's bound per interface.

## Motivation

### Goals

*   A beacon policy module holds the contract; one method beneath it holds
    the selection as it stands and runs the module's contract suite
    (ADR-0042, decisions 1, 4, and 5).
*   The beaconer asks the policy once per receiver, handing it the receiver,
    the founder, and the candidates the receiver can take, and keeps the
    first 64 of the answer (decisions 2 and 3).
*   The beaconer reads no node tags.
*   ADR-0042 is accepted.

### Non-goals

*   A change to which routes a node sends or registers.
*   The path policy the SCION library holds.
*   A second method, or a run argument.

## Proposal

### The module

*   **`pkg/modules/beaconing`** holds the contract; its kind is policy,
    bound by the assembly, with no run argument selecting it. `Candidate`, a
    beacon and the interface it arrived on, moves here from the control
    plane, and the beacon store holds it. `Policy.Select` takes the
    receiver, the founder, and the candidates the receiver can take, and
    returns those to send, in the order to send them. The receiver is a
    neighbor, or the node itself for the set it terminates and registers.
*   **`impl/coverage`** is the method. The price, the rank, the group, and
    the picks move from the control plane unchanged, but for two points:
    *   The picks return whole; the beaconer keeps the first 64.
    *   `New` takes the node's ISD-AS and the node tags topic. The routes
        into the node's group count for a receiver in the group, the node
        itself included.
*   **`impl/beaconingtest`** is the contract suite: an answer holds only
    candidates handed, each once, and one at least whenever any was handed;
    the handed beacons stay as they were, since the store holds them; and
    the propagation and registration loops may ask at once.
*   **The route key.** `routeOf`, by which the store keys candidates and the
    rank breaks ties, moves to the segment library as `PCB.RouteKey`.

### The beaconer

*   **`BeaconerConfig.Policy`** replaces `NodeTags`.
*   **Propagation.** Each pass reads the qualifying candidates and, for each
    neighbor, those it can take, as today: the ones that do not cross it,
    the founder's alone for a peer not enrolled. It asks the policy with the
    neighbor and sends the first 64 of the answer, in order.
*   **Registration.** The node's own set is the first 64 of the policy's
    answer for the node itself, among every qualifying candidate.

### The assembly

`internal/services` builds the coverage method from the node's ISD-AS and the
node tags topic, and hands it to the beaconer.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/beaconing` | The contract, the coverage method, and the contract suite |
| `pkg/core/controlplane` | The beaconer asks the policy; the selection, its tests, and `Candidate` leave |
| `pkg/libs/segment` | `PCB.RouteKey`, the key the store and the method share |
| `internal/services` | The beaconer's policy |
| `docs` | The architecture's modules and path discovery; ADR-0042 accepted |

## Compatibility

Nothing on the wire changes, and a node sends and registers the same routes.

## Test plan

*   **The contract** (decision 4). The coverage method runs the suite over
    candidates from several origins, sharing links, and none.
*   **The method** (decisions 1 and 3). The selection's tests move with it,
    their cases unchanged but the bound's, which the beaconer's tests take:
    the price, the rank, each origin, the backups, each interface, and each
    link into the group, which a receiver in the group and the node itself
    take, and a receiver outside it does not.
*   **The asks** (decisions 2 and 3). With a policy that records its asks
    and answers in reverse: a neighbor is asked with the candidates that do
    not cross it, the founder's alone while it has not enrolled; a core
    neighbor is never asked; the node itself is asked with every qualifying
    candidate; the beaconer sends each answer in its order, and keeps 64 of
    a longer one.
*   **The roof** (decision 5). The walk test passes: the module declares
    its kind, the method runs the suite, and only the assembly and the tests
    import it.
*   **The labs.** The labs pass, and the regions, site, and stranded
    benchmarks run against the commit before.

## Implementation history

*   **The beaconer's tests bind a policy of their own,** which answers each
    ask with every candidate handed, in ingress and route order, and records
    the asks, so a new rule changes no test of the control plane. The test
    of the routes into the group moved to the coverage method.
*   ADR-0042 is accepted.
*   Mutations: 13 of 13 killed. The first run's replacement for a peer not
    enrolled offered every origin's routes left a variable unused and failed
    to build; rewritten, it was killed.
*   The pipeline passed.
*   Benchmarks against the commit before, one run each: every lab reached
    every pair. The regions lab settled on the same paths at 30 links after
    19 changes within 7.8 minutes, against 18 within 7.7; each site
    placement on the same paths with one change more, within 4.7 to 10.2
    minutes against 4.8 to 9.5; the stranded lab with every pair on its
    best path at 9 links within 10 seconds, against 8 links within 6.2
    minutes and a worst pair at 1.075 times its best. The regions and
    stranded cuts recovered within 10 seconds, as the commit before's.
