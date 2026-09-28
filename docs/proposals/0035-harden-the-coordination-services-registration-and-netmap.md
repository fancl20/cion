# Harden the coordination service's registration and netmap

This proposal closes three distances between what
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
promises at the registration boundary and what the coordination
application checks: the machine key the noise channel authenticates is
heard by the admission seam and then forgotten — the record keeps no
trace of it, so any party holding a registered node key registers and
maps from any machine; registration's read, decision, and write run
with nothing holding them together, so concurrent admissions allocate
one address to many hosts; and the rate caps the [security
model](/docs/design/security.md) names as a control — "admission rate
caps bound strangers at the doors" — exist nowhere on the path. The
landing takes each gap at the boundary that owns it: the registry's
record binds the machine, one lock serializes the admission transaction,
and the doors take the limiter shape [proposal
0015](/docs/proposals/0015-trust-verification-and-issuance-hardening.md)
already landed at first issuance. Beside the three, the netmap's
experiment knob — an exported switch able to flip the shape of every
map the core serves — deletes with the experiment it carried.

[TOC]

## Summary

A registration presents two keys — the machine key the noise channel
authenticated and the node key the data plane will use — and the seam
hears both ([register.go](/pkg/apps/coordination/register.go)). The
record keeps one: a host entry carries the node key, the address, the
owning node, and the note
([directory.go](/pkg/apps/wireguard/directory.go)) — the machine key is
a verified fact for the length of one ask. The map's lookup matches the
node key alone
([netmap.go](/pkg/apps/coordination/netmap.go)), and the record's
idempotent answer does the same, so whatever machine presents a
registered node key receives the host's full netmap: its address, every
routed /32 in the network, the node's endpoint, the relay. Node keys
are public data the directory distributes to every node; a public value
is the control plane's capability, and the one check that could bind it
to the machine that earned it was never written.

Admission's allocation runs unserialized. `handleRegister` lists the
registry, asks the seam, allocates, and records, with nothing holding
the four together, and `PublishHost` is a per-key put with no address
uniqueness check of its own
([db.go](/pkg/apps/wireguard/impl/bbolt/db.go)). Two admissions that
overlap read one snapshot and allocate the same next free address —
confirmed on the running application, where eight concurrent
registrations with a seam that answered in a hundred milliseconds all
received the same address. ADR-0011's "unique by construction" holds
only under serialized admission; unserialized, the owning node programs
several peers owning one /32 and the record never moves, so the
collision is permanent.

Nothing on the path is capped. An unset authorizer admits by design,
the CIDR posture is stateless, and the Telegram plugin prompts a human
per bare joiner — each new node key a fresh prompt, so a flood of keys
is a flood of the operator's chat. Every admission is a permanent write
whose cost compounds — the allocation scans the registry, every open
map stream re-reads it each resend tick, every node re-fetches the
directory — and the streams and noise conversations that drive it are
themselves unbounded. The security model's bounds-not-revocation
control promises caps no code keeps.

The map's own shape is switchable at runtime. An exported experiment
knob — `SetDebugDiscoPeer`,
[netmap.go](/pkg/apps/coordination/netmap.go) — flips every served
netmap between the shipped wireguard-only peer and a disco peer with a
freshly generated key, through an unsynchronized package global that
nothing in the tree ever sets. The experiment concluded; the switch
outlived it, sitting on a served surface as a flag with no caller.

## Motivation

The three gaps are one boundary's own promises. ADR-0011's decision
drivers name the verified facts — "the keys the exchange presented" —
and one gate, one artifact: the decision that admits and the record
that keeps it are not two things to keep aligned. A seam that hears the
machine key and a record that drops it is exactly the misalignment the
driver declines; an allocator that is unique by construction only when
nothing overlaps is the driver's promise held by luck. The security
model states the caps as a control. None of the three is a
re-decision — the boundaries stand as ADR-0011 drew them — which is why
this grounds on the accepted records rather than proposing a new one,
the shape [proposal 0015](/docs/proposals/0015-trust-verification-and-issuance-hardening.md)
set when it closed the same distance at the trust plane's doors. The
knob's deletion is the cleanup beside them: a served surface's shape is
a fact of the code, not a flag's current value.

### Goals

*   The binding: the host entry records the machine key its noise
    channel authenticated; register's idempotent answer and the map both
    refuse a machine the record does not name, and a record older than
    this proposal binds the first machine that presents it.
*   The serialization: one lock holds the admission transaction — the
    read, the idempotency check, the seam's ask, the allocation, the
    record — so concurrent admissions allocate distinct addresses and a
    key racing itself converges on its record.
*   The caps: the seam's ask passes a per-source and an overall
    admission interval before it is asked; an open map stream holds one
    of a bounded set, past which the map answers once and closes; a
    noise conversation holds one of a bounded set, past which the
    upgrade refuses.
*   The map's fixed shape: the experiment knob and its global delete —
    the wireguard-only peer is the served form, stated where the peer is
    built, with no runtime switch anywhere.

### Non-goals

*   No new ADR: the boundaries stand as ADR-0011 drew them and the seam
    as [ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
    built it; this proposal checks the records' own promises.
*   No new run arguments: the bounds are mechanism, not policy —
    package constants beside the resend and keepalive ones, policy
    staying the seam's alone.
*   No store-side address check: the registry has one writer and the
    lock is where its transaction lives; a check inside `PublishHost`
    would re-check what the lock already guarantees.
*   No revocation, no key expiry, no re-asked admission: ADR-0011's
    durability stands — a mismatched machine is refused, a matched one
    answered, the seam never re-consulted for a record it already made.
*   No change to the seam's facts, the wire, or the client protocol:
    both keys already ride the facts, and a refused request is a path
    the clients already walk.
*   No conversation lifetime or shutdown work: an idle conversation's
    hold on the application's close is a separate finding with its own
    proposal; this proposal bounds how many conversations exist, not how
    long one lasts.
*   No change to the relay: the DERP server's openness is the posture
    ADR-0011 chose, a residual risk the security model carries, not a
    defect in this boundary.

## Proposal

### Bind the registration to its machine

The host entry grows the machine key — the public key of the pair the
noise channel authenticated when the registration arrived. The record's
claim widens by the fact its own driver already named: the key, the
address, the owning node, and now the machine that presented them. The
store's wire format grows the field with it; an older record decodes
with no machine key and binds the first machine that presents it, one
write on the answer path — the honest migration for a record that
never held the fact, its window the first presentation after the
upgrade, named here rather than hidden.

Register checks before it answers: a record that names a machine
answers a different machine with the refusal the denied registration
already carries, logged beside it. The map checks the same way, with
the unregistered key's own refusal — the node key alone maps nothing,
and the channel's authenticated machine is what the request owes. The
seam's facts change not at all: both keys ride them today, and the ask
stays keyed on the same identity it is keyed on now.

### Serialize the admission transaction

One mutex holds the whole transaction — the read, the idempotency
check, the seam's ask, the allocation, the record — the renewal
transaction's own shape
([trustservice.go](/pkg/controlplane/trustservice.go)). A Telegram
prompt's send holds a later registration behind it for as long as its
timeout; registration is rare enough that the queue is the honest price
of one key, one address. Overlapping admissions then read in order:
each allocation sees every record the last one wrote, the same key
racing itself meets the idempotent answer, and the freest slice is
chosen from what the registry holds, not from a snapshot luck timed.

### Bound the doors

The ask passes a limiter before the seam: the `sourceLimiter` shape
proposal 0015 landed at the renewal door — one admission per interval,
refilling over time, forgetting keys gone silent — keyed here by the
connection's source address, for an internet source's port is ephemeral
and a per-address-port cap would cap nothing. Beside it, an overall
interval of the same shape bounds the door against many slow sources:
a stranger's flood of fresh keys prompts no operator and writes no
record, and a fleet behind one NAT paces its logins at the interval —
the trust door's own price, paid where the sources share. The refusal
is the request's own retry path with the rate's status. The record's
idempotent answer passes uncapped: a re-registering member's read is
what the registry owes it, and the binding makes that answer a refusal
when the asker is not the member.

An open map stream holds one of a bounded set of streams: past the
bound, the map answers one full map and closes the stream — the
protocol's own degradation, no error, the client's polling carrying the
rest. The noise upgrade holds one of a bounded set of conversations:
past the bound, the handshake refuses before it begins. Both bounds are
constants of the application, beside the resend and keepalive ones.

### Fix the map's shape

The experiment knob and the global it flips delete, and the peer states
its shape where it is built: a wireguard-only peer carrying no disco
key, the model the client lines serve for third-party exits. The served
map's form becomes a fact of the code rather than a flag's current
value, and the shape the capability pin verifies loses the side door
that could flip it under the pin. Nothing changes on the wire: the
knob's unset value was the shipped form, and nothing in the tree ever
set it.

## Compatibility

The wire changes nowhere and the client lines need nothing: a refused
register or map is the protocol's own retry path, the same one a
pending registration already rides. The registry's record grows one
field; older records decode with no machine key and bind at first
presentation. The zero-conf default keeps its shape — open admission
stays open, now paced, a network that configured no seam still
admitting one host per source per interval. The map's served form
changes not at all: the deleted switch never moved it. Existing hosts
re-register at their next login from the same machine they have always
presented; the standing coordination and admission labs pass unchanged.

## Test plan

*   **The binding:** a host registered from one machine has its map and
    its register answer refused from a second machine — the probe's
    episode, held as a regression — while the first still maps; a
    record holding no machine key binds the first presenter and refuses
    the second; the seam's facts still carry both keys and the ask's
    identity is unchanged.
*   **The serialization:** registrations of many distinct keys fired
    concurrently, with a deliberately slow seam answer between the read
    and the write, allocate distinct addresses — the collision episode,
    held as a regression; the same key registered concurrently
    converges on one address and one record.
*   **The caps:** a second ask inside the source interval is refused
    without the seam being asked — the ask recorder proves the door —
    and asks past the overall interval wait; a map past the stream
    bound receives one full map and a closed stream; a conversation
    past its bound has the upgrade refused.
*   **The fixed shape:** the wireguard-only peer with no disco key is
    the served form, the episode
    ([netmap_test.go](/pkg/apps/coordination/netmap_test.go)) already
    holds, and no exported surface remains that could flip it.
*   **The standing labs:** the coordination and admission labs pass
    with the binding checked on every answer, the same machine
    presenting and the same record answering.

## Implementation history
