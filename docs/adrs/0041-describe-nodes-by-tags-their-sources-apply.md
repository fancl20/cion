# Describe Nodes by Tags Their Sources Apply

*   Status: accepted
*   Date: 2026-11-08

[TOC]

## Context and problem statement

A node's components read properties of the nodes it knows, itself among
them, that other components own. The clusters added one
([proposal 0119](/docs/proposals/0119-form-clusters-and-link-them-through-their-nearest-members.md)):
the selection names the node's cluster each window, and each entry names its
signer's. The beaconer forwards the routes into the node's group to the
neighbors in it
([ADR-0039](/docs/adrs/0039-let-paths-react-links-settle-and-clusters-hold-still.md),
principle 9), so it needs each node's group beside its own. A topic of its
own carries the members of the node's cluster: the clustering reaches the
bus and the beaconer, though neither needs to know how a group forms, and
the next property of nodes would add a type and a topic of its own again.

Two properties stay where they are:

*   **Role.** The pinned TRC names the founder and the cores. The beaconer,
    the segment lookup, and the portal read it from the trust engine, and
    the portal's role decides which removal the console offers, and that it
    offers none for the founder.
*   **Reach.** It describes an address, not a node: each directory's entry
    reports it address by address
    ([ADR-0027](/docs/adrs/0027-tag-the-nodes-peers-cannot-dial.md),
    decisions 1 to 3).

How should a node describe the nodes it knows, so that a reader reads any
property the same way, learns nothing of how it is computed, and a new
property costs no new plumbing?

## Decision drivers

*   **One shape:** a reader reads every node property the same way, and a
    new property adds no type or topic.
*   **Readers learn what they use:** the beaconer needs which nodes share
    the routes into its group, not how the group formed.
*   **One owner per property:** a property's source alone applies and
    removes it.
*   **Authority stays at its source:** a decision that grants or refuses an
    action reads the property's source, never a copy that can lag it.
*   **Small:** plain strings, and no schema to keep.

## Considered options

*   **A typed event per property,** as the cluster topic is.
*   **A typed node record:** one event that holds each node's properties as
    fields.
*   **Key-value tags:** each node carries a string value per key, and each
    key has one source.

## Decision outcome

Chosen option: **key-value tags**.

1.  **A tag is a key and a value on one node.** Both are strings. A node
    carries at most one value per key, and an empty value is no tag.
2.  **Each key has one source, which owns it.** The first key is
    **`group`,** from the topology provider: the group the node belongs to,
    whose members share the routes into it. The topology provider names a
    cluster's members a group, each by the name its selection gives the
    node's own cluster and its entry gives every other's; a node in no
    cluster carries none.
3.  **Every node holds the tags of the nodes it knows, its own among them,
    as one topic on its bus**
    ([ADR-0031](/docs/adrs/0031-publish-node-state-as-events-on-a-node-bus.md)).
    Each source replaces what it applied, whole; readers subscribe or read
    the last event. A node's tags go once their source forgets the node.
4.  **Tags describe; authority reads its source.** A decision that grants
    or refuses an action reads the property where its source keeps it: the
    beaconer's acceptance of a core's beacon, an enrollment, an issuance,
    and the portal's removals read the TRC, as they do today. A property
    becomes a tag once a reader that only describes needs it.

### Positive consequences

*   The beaconer reads which nodes share its group, and the clustering
    stays inside the topology provider; a group that forms another way
    needs no change in the beaconer.
*   A new property is a key: its source applies it, and its readers read
    it.

### Negative consequences

*   Values are strings, and a misspelled key reads as absent.
*   One owner per key is a rule the sources keep, not a type.
*   A property that both describes and decides stays at its source, so
    readers find node properties in two places.

## Pros and cons of the options

### A typed event per property

*   Good, because each reader gets a typed value, and the bus names each
    property's publisher and readers.
*   Bad, because each property adds a type, a topic, and its plumbing, and
    its type carries the concept that computes it.

### A typed node record

*   Good, because the properties stay typed and sit in one event.
*   Bad, because each new property changes the record that every source
    shares.

### Key-value tags

*   Good, because one topic carries every property, and readers name the
    keys they read.
*   Bad, because values are strings that readers compare, and ownership is a
    rule the sources keep rather than a type.
