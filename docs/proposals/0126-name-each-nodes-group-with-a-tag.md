# Name each node's group with a tag

This proposal implements the node tags of
[ADR-0041](/docs/adrs/0041-describe-nodes-by-tags-their-sources-apply.md)
with their first key, `group`: the topology provider's selection applies
each node's group to the node tags each window, and the beaconer reads the
group tags where it read the cluster topic.

[TOC]

## Summary

Today:

*   **The cluster topic** ([bus.go](/pkg/libs/bus/bus.go)) carries the
    members of the node's cluster. The selection publishes it each window,
    and the beaconer reads it to carry the routes into the cluster to the
    neighbors in it
    ([proposal 0119](/docs/proposals/0119-form-clusters-and-link-them-through-their-nearest-members.md)).

## Motivation

### Goals

*   One node tags topic on the bus, on which each source replaces the values
    of its own key.
*   The selection applies every node's group: the members of a cluster share
    its name.
*   The beaconer carries the routes into the node's group to the neighbors
    that share it, as it carried the routes into the cluster.

### Non-goals

*   Other keys: the role stays with the TRC, and the reach with each
    address.
*   The entries: a node's group travels as its cluster does.

## Proposal

### The tags

*   **`bus.NodeTags`** holds each key's value on each node. `With` replaces
    one key's values whole, its empty values left out, and `Tag` reads one
    node's value of a key. `bus.TagGroup` names the group key.
*   **`Bus.NodeTags`** returns the topic; the cluster topic goes.

### The groups

Each window, the selection applies the group of each node its view holds by
the cluster that node's latest entry names, and the node's own by the
cluster the window names; a node naming none carries no group.

### The beacons

The beaconer's group is the nodes whose group tag is the node's own. A set
covers each link into the group at another member, and a neighbor in the
group takes those routes, as the cluster's members did.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | `NodeTags`, `TagGroup`, and the node tags topic, in place of the cluster topic |
| `pkg/modules/topology/impl/measured` | The selection applies the groups |
| `pkg/core/controlplane` | The beaconer reads the group tags |
| `internal/services` | The beaconer's node tags topic |

## Compatibility

Nothing on the wire changes, and the beaconer forwards the same routes to
the same neighbors.

## Test plan

*   **The tags.** A key's values replace its last ones whole, copied, their
    empty values left out, and leave the other keys' values; a node or a
    key the tags lack reads empty.
*   **The groups.** The members of the cluster the node joined carry its
    name, a node in no cluster none, and no node once the cluster
    dissolves; another key's values stay.
*   **The beacons.** A set covers each link into the group at another
    member, and the node's own set and a neighbor in the group take those
    routes, a neighbor in another group or in none does not.
*   **The labs.** The labs pass, and the metros benchmarks run against the
    commit before.

## Implementation history

*   **The role.** The first draft tagged each node's role as well, from the
    pinned TRC, for the portal to read. The portal's role decides which
    removal the console offers, and refuses the founder's, so it reads the
    TRC; a role tag waits for a reader that only describes.
*   Mutations: 10 of 10 killed. The first run let two live: a node in no
    group read every untagged node as its fellow beside another group's
    members, and the node's own entry, still naming a cluster the window no
    longer names, could stand for the node. The tests now cover both.
*   The pipeline passed. One run of the race detector failed
    `TestWireguardMeshExchange`, whose reply missed its wall-clock wait on a
    loaded runner; alone, it passed six runs of six, and the run after
    passed whole.
*   Benchmarks against the commit before, one run each: the metros lab
    settled on 25 links after 14 changes within 9.3 minutes, against 25
    after 10 within 8.3, its worst pair at 1.059 times the reference,
    against 1.068, each node probing the other metros 9.6 times a minute,
    against 9.5; after a cut between two metros, the better paths surfaced
    at once and the links settled within 10 seconds after one change, as
    before, and within 40 after the restore, against 70.
