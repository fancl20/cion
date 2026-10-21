# Admit Every Host by a Key That Names Its Node

*   Status: proposed
*   Date: 2026-10-21

[TOC]

## Context and problem statement

[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
made the coordination service the allocator: a host's address comes from
one node's slice, and that node is the host's one peer — the netmap names
it, the host's WireGuard tunnel ends at its host-facing endpoint, and the
rest of the tailnet is the mesh beyond it. Its decision 6 left the choice
of node to the allocator: the slice with the most free addresses at the
first registration, the record never moving after.

Nobody chooses the node. The allocator counts free addresses; it does not
know where a host is or which node it should reach. A laptop in the same
building as one node can land on a node across an ocean because that slice
is emptier, and every packet it sends to its neighbors crosses the ocean
twice — once to its node, once back across the mesh. The operator who
mints the host's auth key knows where the host is, and nothing carries
that knowledge to the allocator.

A host also reaches the registry by more than one door. Under the
operator's chat and console a host joins by presenting a key the operator
minted, or by asking bare and waiting for the operator to approve it; under
the source-address posture it joins by where it dials from; with no policy
at all it joins openly. Only the key is a decision the operator made about
that host ahead of time — the one door that could also say where the host
goes.

The control plane stays where ADR-0011 put it: every client logs in at the
founding core, and the relay runs there. Only how a host is admitted and
where it attaches are in question.

This ADR decides how a host is admitted, who chooses its node, and what
happens when the chosen node cannot take it.

## Decision drivers

*   **The Key Is the Approval:** the operator approves a host by minting
    its key; a second door beside the key is a second policy to keep
    aligned with it.
*   **Operator Knowledge Over Load:** the person who mints a key knows the
    host's location; the attachment follows that choice, not a count of
    free addresses.
*   **Explicit Over Automatic:** every host's node is a decision someone
    made and can name before the host joins, never the outcome of load at
    the moment of login.
*   **Mechanism Over Policy:** ADR-0011's split holds — the policy names
    the node, and the coordination service does the slice's arithmetic.
*   **The Client Never Chooses:** a placement the client could pick would
    let one key's holder steer the network's data plane.
*   **Strictness:** a host placed elsewhere than named silently overrides
    the operator.

## Considered options

How a host is admitted:

*   **A Key or the Operator's Approval:** a minted key admits at once, and
    a bare registration waits for the operator, as today under the chat
    and the console.
*   **A Key Alone:** only a registration presenting a standing key the
    policy minted is admitted.
*   **The Source Address:** the registration's source admits it, as today
    under the source-address posture.

Who chooses a host's node:

*   **The Freest Slice:** the allocator, by free addresses, as today.
*   **The Key Names the Node:** the operator picks the node when minting,
    and a registration presenting the key lands there.
*   **The Operator Picks at Approval:** the node is chosen when a pending
    registration is approved.
*   **The Nearest Node, Measured:** the client's measured latency to each
    node decides, every node serving a relay the client probes.
*   **Where the Client Logs In:** every node relays the control plane, and
    a host lands on the node it logged in through.

## Decision outcome

Chosen options: **a key alone** and **the key names the node** — realized
as follows:

1.  **Every host presents a key.** A registration presenting no key, or a
    key that is spent, expired, revoked, or unknown, is denied, never
    pended: no prompt and no ask. Node enrollment and the founder's vote
    still go to the operator. This narrows ADR-0011's decision 3, under
    which a bare joiner prompts, and
    [ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md)'s
    decision 1, under which the console pends every boundary, to node
    enrollment and the vote.
2.  **A policy that mints no keys admits no hosts.** The source-address
    posture admits nodes alone and denies every registration, and a
    founding core running no policy enrolls nodes openly and refuses every
    registration. A deployment that serves hosts selects a policy that
    mints keys.
3.  **Every key names exactly one node.** The operator chooses it when
    minting; a console offers the founding core first, and a key minted
    without naming a node names the founding core. A registration
    presenting the key lands on that node: its address comes from that
    node's slice, and its one peer is that node. The key remains the whole
    approval.
4.  **The admission answer carries the node.** For a registration, the
    policy answers approve with the node its key names, and the
    coordination service allocates in that node's slice and nowhere else.
    This narrows ADR-0011's decision 3 — approve, deny, or pending, with a
    note — by a node, and its decision 6 to the arithmetic within the
    named slice.
5.  **Placement is strict.** A named node that holds no slice, publishes
    no host endpoint, or has no free address refuses the registration
    until it can take the host; the client's own retry carries the wait.
    The host never lands elsewhere.
6.  **Placement is permanent.** A host that registers again stays where it
    was admitted, as ADR-0011 decided. Moving a host is removing it and
    giving it a key that names the other node; its address changes with
    the slice.

### Positive consequences

*   One door admits hosts: the key the operator minted is the whole
    approval, and nothing pends or prompts for a host.
*   Hosts attach where the operator knows they belong, and a host's node is
    known — and shown beside its key — before it joins.
*   The allocator shrinks to arithmetic within one slice.
*   No client can steer its own admission or its placement.

### Negative consequences

*   A stale key fails outright: a spent, expired, or revoked key no longer
    falls back to the operator, and the client's login fails until a new
    key arrives.
*   A client that cannot be handed a key cannot join.
*   The source-address posture, and a founding core running no policy,
    serve no hosts.
*   A key naming a node that never serves hosts leaves its client retrying
    against a refusal; a key the Telegram bot mints cannot be checked at
    minting, for the bot holds no view of the nodes.
*   A node's outage strands its hosts, as before — now including the hosts
    the operator placed there on purpose, with no fallback to another node.
*   Moving a host changes its address.

## Pros and cons of the options

### A key or the operator's approval

*   Good, because a client without a key can still join, and a stale key
    fails toward the human.
*   Bad, because two doors admit one host, and the approval door carries
    no node.

### A key alone

*   Good, because the operator's decision is made once, ahead of the join,
    and carries the node with it.
*   Bad, because a stale key fails the login, and a client that cannot be
    handed a key has no way in.

### The source address

*   Good, because hosts on a trusted network join with nothing to hand
    out.
*   Bad, because it carries no node and no decision about the host itself.

### The freest slice

*   Good, because it needs nothing from anyone and spreads hosts over the
    nodes.
*   Bad, because free addresses are not location: a host can land far from
    where it is.
*   Bad, because the node is decided at login and cannot be named ahead.

### The key names the node

*   Good, because the operator who knows the host's location decides once,
    when minting.
*   Good, because the node is known before the host joins and is shown with
    the key.
*   Bad, because each placement needs its own key, and a mistyped node
    strands a client until a new key replaces it.

### The operator picks at approval

*   Good, because it serves joiners that present no key.
*   Bad, because a key is already the operator's approval, and a prompt
    that must choose among nodes grows with the network.

### The nearest node, measured

*   Good, because it needs no operator at all.
*   Bad, because every node must serve a relay and a probe target, and the
    placement trusts latencies the client reports.

### Where the client logs in

*   Good, because a host lands on a node it can reach.
*   Bad, because every node then serves an internet-facing control
    endpoint, with a WebPKI identity of its own to present.
