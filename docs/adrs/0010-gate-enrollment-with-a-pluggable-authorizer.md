# Gate Enrollment with a Pluggable Authorizer

*   Status: accepted
*   Date: 2026-09-17

[TOC]

## Context and problem statement

Enrollment is the one unauthenticated exchange that grants something.
The joiner presents no chain — the transport cannot name it — and the
CMS wrapper proves only possession of the key inside the CSR. What
issuance hands over is a name in the network's trust fabric, so
[ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)
makes enrollment "the gatekeeper that rejects collisions and strangers."
The collision half is solid: a name that already holds a chain under
another key rejects. The stranger half is `--allow-ia` — a static
ISD-AS set, literal in the process arguments, feeding two different
gates: chain issuance on the core and first-contact admission on every
node.

The set gates on the weakest signal the moment offers. At first
issuance the ISD-AS is a self-picked, unauthenticated claim — a
stranger simply picks an allowed name, and nothing distinguishes it
from the node that name was written for. What the exchange actually
verifies is possession of the subject key, and the completed handshake
binds the request to a return-routable source address. Meanwhile the
two postures a private network actually wants — admit joiners from
known addressing, admit joiners one by one from a phone — have no
expression at all.

This ADR decides where enrollment policy lives, what it may decide on,
and what becomes of the allowlist's second life on the admission side.

## Decision drivers

*   **Verified Facts Only:** No new trust anchors. Policy decides on
    what the exchange proves — key possession and a return-routable
    source address — not on what the requester claims about itself.
*   **Mechanism over Policy:** Per
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md),
    the core owns how a chain is issued and nothing about who receives
    one. Policy that can differ between deployments is policy that can
    be swapped, and swapped without touching the protocol surface.
*   **Almost-Zero Config:** Open enrollment stays the default; the
    founding claim survives restriction being available. A gate must be
    something a deployment opts into, not opts out of.
*   **Operator Sovereignty:** Which nodes join the network is the
    operator's decision, and it must be expressible both per deployment
    (by addressing) and per joiner (by a human's judgment).
*   **One Gate, Not Two:** The same static set feeding issuance and
    admission is two half-gates duplicating one decision. ADR-0008
    already arranges that admission builds on enrollment — a candidate
    link must clear the enrollment window, its evidence a chain the
    network issued — so the enrollment gate is the one place the
    decision belongs.
*   **Non-Scalable by Choice:** An approval that costs a human a button
    press per joiner is in bounds at CION's target scale.

## Considered options

How enrollment policy is expressed:

*   **Status Quo Allowlist:** Keep the static ISD-AS set as the
    gate.
*   **Pluggable Authorizer Seam:** The core defines the interface it
    calls at first issuance; implementations live beside it as policy
    and are chosen by run argument.

How an asynchronous approval meets a synchronous issuance request:

*   **Block Until Decided:** The request holds until an operator
    answers.
*   **Pending Verdict on the Retry Loop:** The request returns pending
    and the joiner's existing enrollment retry carries the wait.

What becomes of the admission-side allowlist:

*   **Keep, Narrowed:** `--allow-ia` stops gating issuance and keeps
    gating rendezvous and link admission.
*   **Retire Entirely:** The enrollment authorizer is the policy point;
    admission keeps its bounds and builds on enrollment as arranged.

## Decision outcome

Chosen options: the **pluggable authorizer seam**, a **pending verdict
on the retry loop**, and **retiring the allowlist entirely** — realized
as follows:

1.  **First issuance asks one question of policy; renewals ask none.**
    The trust service calls an authorizer exactly when the mechanical
    checks pass and no chain exists for the name: possession verified,
    the name free or held by the same key. A same-key renewal — the
    chain's own holder — passes without asking, so an operator is never
    prompted for a node already inside. The request carries the three
    facts the exchange established: the claimed ISD-AS, the subject key
    whose possession the CMS wrapper proved, and the SCION source
    address, which the completed handshake made return-routable and
    which remains the joiner's own claim otherwise — a node behind
    address translation presents its private address, so a private-range
    entry is what admits such joiners. The interface is defined with its
    consumer, per ADR-0009's one-way direction; implementations import
    the core, never the reverse. No authorizer selected keeps enrollment
    open — the zero-conf default.
2.  **The verdicts are allow, deny, and pending.** Pending is not an
    error state but a first-class verdict the joiner's machinery already
    consumes: the enrollment loop retries every few seconds, so a
    pending request returns as unavailable and the next retry asks
    again. Approval lands within one retry interval; no connection is
    held for a human's reaction time.
3.  **Two implementations ship beside the seam, one per process.** The
    CIDR authorizer admits joiners whose source address matches a
    listed prefix, failing closed when the request carries no address —
    a gate that opens when its signal is missing is no gate. The
    Telegram authorizer prompts a configured chat per new joiner — the
    claimed name, the key fingerprint, the source address, an approve
    and a deny button — keyed by name and key together, one prompt per
    identity, so a stranger's persistence re-prompts on a window, not on
    every retry. Only the configured chat's answers count; a prompt that
    cannot be sent denies. Decisions are in memory: a restart forgets
    pending and denied entries, and a join still in flight asks again,
    while enrolled nodes renew without prompting at all.
4.  **The selector is one run argument:** `--enroll-auth`, taking
    `method=spec` — `cidrs` with a prefix list, `telegram` with a chat
    and a token. Unset is open, exactly one method loads, and the
    argument is refused without `--core`, since the core is the only
    node that issues chains and a silently inert gate is the misleading
    configuration the role-aware checks exist to refuse. The shape
    leaves repetition — and with it combination — a later change that
    touches no interface. The token rides the argument and is visible
    in the process list: an accepted consequence of argument-driven
    configuration, the file indirection deliberately not built.
5.  **The allowlist retires on both sides of its double life.** This
    deliberately narrows ADR-0008's third point, whose admission policy
    is "restrictable to allowlisted ISD-ASes": admission's bounds stand
    as they are — rate caps, return-routability, the enrollment window
    every candidate must clear — and the restrictable policy is the
    enrollment authorizer. A joiner the authorizer never admits is a
    link no node establishes, which is ADR-0008's own arrangement
    turned into the whole of admission policy.

### Positive consequences

*   The stranger gate stands on verified facts — a possessed key and a
    return-routable address — instead of on the one field the requester
    fills in about itself.
*   Enrollment policy is swappable without touching the protocol
    surface: two implementations exist, a third needs no core change,
    and the CIDR and Telegram postures cover the realistic private
    network without configuration ceremony.
*   One gate replaces two half-gates: a single decision point at the
    trust boundary, with admission inheriting it through the enrollment
    evidence it already requires.
*   Per-joiner approval is human-scale and out of band — the operator's
    phone, not the node's logs.
*   The default node is unchanged: no argument, no authorizer, open
    enrollment.

### Negative consequences

*   The source address is self-claimed and weakened by translation; a
    CIDR list is an addressing policy, not an identity policy, and must
    be written knowing what joiners present.
*   The Telegram implementation places an external service in the trust
    path of a private network: with the API unreachable, enrollment
    fails closed — safe, but unavailable until it returns.
*   The bot token sits in the process arguments, visible in the process
    list; deployments that cannot accept this wait for the file
    indirection this ADR declines.
*   Decisions are in memory, so a core restart forgets pending approvals
    and re-prompts joins still in flight.
*   A node can no longer be more restrictive than its core's enrollment
    policy — per-node admission restriction has no mechanism. This
    rides ADR-0009's operating assumption that one operator runs an ISD,
    making the core's policy the operator's own.

## Pros and cons of the options

### Status quo allowlist

*   Good, because it is built, tested, and deterministic — a literal
    set an operator can read at a glance.
*   Bad, because it gates on the self-picked name at the exact moment
    the name is least trustworthy, and admits any stranger willing to
    pick an allowed one.
*   Bad, because it answers none of the postures that motivate gating:
    neither addressing-based nor per-joiner admission is an ISD-AS set.

### Pluggable authorizer seam

*   Good, because policy decides on the facts the exchange verified and
    only those.
*   Good, because it is ADR-0009's rule applied to trust: issuance is
    mechanism, admission is policy, and the seam is where the two meet
    without the core learning an implementation.
*   Bad, because it costs an interface and two implementations to keep
    coherent, and a human per joiner under manual approval — in bounds
    by choice, but a cost the allowlist did not carry.

### Block until decided

*   Good, because one round trip carries the whole exchange: approve,
    and the held request completes on the spot.
*   Bad, because a request must then outlast human reaction time, and
    the joiner's attempt timeout does not; every approval would arrive
    after the connection it was answering has died.
*   Bad, because each pending joiner holds transport state on the core
    for nothing the retry loop does not already provide.

### Pending verdict on the retry loop

*   Good, because it invents nothing: the enrollment loop already
    retries, and pending is a verdict it consumes without change.
*   Good, because the core holds no per-joiner transport state, and a
    restart costs at most one re-prompt.
*   Bad, because approval lands on the retry cadence rather than the
    button press, and the joiner logs its wait as warnings.

### Keep, narrowed

*   Good, because each acceptor keeps a defense of its own, independent
    of the core's policy.
*   Bad, because it keeps two places to configure one decision, and the
    two drift — an operator restricting enrollment and forgetting
    admission, or the reverse, gets a policy half-applied.

### Retire entirely

*   Good, because one gate at the trust boundary is the whole policy,
    and admission inherits it through the enrollment evidence
    ADR-0008 already requires of every candidate.
*   Good, because the admission side's signal — a verified ISD-AS — was
    only ever a proxy for "the core admitted this node," which the
    enrollment gate now decides directly.
*   Bad, because per-node restriction loses its mechanism; a node
    cannot refuse a peer its core admitted.
