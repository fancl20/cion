# Gate enrollment with a pluggable authorizer

This proposal implements
[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md):
first issuance asks one question of policy through a seam in the trust
service, the verdicts are allow, deny, and pending — pending riding the
enrollment retry loop the joiner already runs — two implementations ship
beside the core (a prefix list and a Telegram prompt) chosen by the run
argument `--enroll-auth`, and the `--allow-ia` allowlist retires from
what remains of its double life. What proposal 0013 left as the
provider's gate becomes the enrollment authorizer's alone, and
ADR-0008's third point is amended to say so.

[TOC]

## Summary

Proposal 0013 emptied the issuance gate: `TrustService.AllowAS` left the
core as deployment policy inside the drafts' trust service, and the
stranger question moved wholly to the measured provider, where
`--allow-ia` still gates the rendezvous acceptor and the link service on
the one field the requester fills in about itself. That is the weakest
signal the moment offers — a self-picked, unauthenticated ISD-AS — and
the two postures a private network actually wants, admitting joiners by
addressing and admitting them one by one from a phone, have no
expression at all. This proposal builds what stands in the emptied
gate's place: an `EnrollmentAuthorizer` interface defined with its
consumer in `pkg/controlplane` and called exactly at first issuance —
possession verified, the name free — deciding on the three facts the
exchange established: the claimed ISD-AS, the subject key whose
possession the CMS wrapper proved, and the SCION source address the
completed handshake made return-routable. A pending verdict returns as
unavailable and the joiner's existing five-second retry cadence carries
the wait; no connection is held for a human's reaction time. Two
implementations live in a new policy package, `pkg/enrollauth`, and the
argument `--enroll-auth` loads exactly one; unset is open, the
zero-conf default. The allowlist's second life ends: the flag, the
provider's `AllowAS` plumbing, and their checks are removed, admission's
mechanical bounds — rate caps, link caps, return-routability, the
candidate window's enrollment evidence — standing as they are.

## Motivation

ADR-0010 decided the shape; the tree has moved since it was written, and
in the direction that makes the decision easier to land. The ADR's
context describes `--allow-ia` feeding two gates, chain issuance on the
core and first-contact admission on every node; proposal 0013 has since
removed the first — the trust service keeps the drafts' RPCs and the
name-taken check, nothing else — so the allowlist that remains is
admission-side only, a set every acceptor consults against a claim the
joiner wrote itself. One gate now, but the wrong one: it acts at first
contact, on the self-picked name, before anything about the requester is
verified, and its ISD-AS set answers neither private-network posture.
And the core, where ADR-0008 placed the gatekeeper that "rejects
collisions and strangers," holds only the collision half.

The machinery this proposal needs is already standing. The joiner's
enrollment loop retries any failure every `EnrollmentRetryInterval` and
logs its wait as warnings, so a pending verdict needs no client change.
The handler context already carries the requester's SCION address —
`http3.RemoteAddrContextKey` holds the `*scion.Addr` the QUIC transport
named the connection by, the pattern `arrivalInterface` reads for
beacon registration — and that address's underlay half is exactly the
ADR's fact: self-claimed in the SCION header (a node behind address
translation presents its private address), yet bound by the handshake,
for replies route to the claimed address within the joiner's own AS, so
a fabricated address the claimer cannot receive completes no handshake.
The role-aware argument checks `Validate` already applies — the core
takes no `--neighbor`, `--link-set` refuses it — are the natural home
for refusing `--enroll-auth` without `--core`. And the containment a
never-admitted stranger needs on the admission side is in place: a
candidate the sweep never sees enrollment evidence for retires with the
window, and the in-band link service refuses a channel that verified no
chain, so a joiner the authorizer never admits is a link no node
establishes — ADR-0008's own arrangement, now the whole of admission
policy.

### Goals

*   The seam: `TrustService` calls an `EnrollmentAuthorizer` exactly
    when the mechanical checks pass and no chain exists for the name —
    the CMS wrapper's possession proof verified, the name free. A
    same-key renewal, the chain's own holder, passes without asking, so
    an operator is never prompted for a node already inside. No
    authorizer selected keeps enrollment open — the zero-conf default.
*   The facts: the claimed ISD-AS from the CSR, the CSR's subject key,
    and the SCION source address from the request context — zero when
    the context carries none, which is itself a fact an implementation
    may fail closed on.
*   The verdicts: allow issues, deny refuses with `PermissionDenied`,
    and pending returns `Unavailable` — a first-class verdict the
    joiner's retry loop consumes without change, approval landing within
    one retry interval.
*   Two implementations in `pkg/enrollauth`, a policy package beside
    the core that imports it and is imported by the assembly alone: the
    CIDR authorizer admitting source addresses in a listed prefix,
    failing closed when the request carries no address, and the
    Telegram authorizer prompting a configured chat per new joiner —
    the claimed name, the key fingerprint, the source address, an
    approve and a deny button — keyed by name and key together, one
    prompt per identity, only the configured chat's answers counting, a
    prompt that cannot be sent denying, and every decision in memory.
*   The selector: one run argument, `--enroll-auth method=spec`, taking
    `cidrs` with a prefix list and `telegram` with a chat and a token.
    Unset is open, exactly one method loads, and the argument is refused
    without `--core` — a silently inert gate is the misleading
    configuration the role-aware checks exist to refuse.
*   The retirement: `--allow-ia`, `NodeConfig.AllowIA`, `parseAllowIA`,
    and the `AllowAS` fields of the measured provider's acceptor and
    link service are removed, with the run argument's help text and the
    tests that asserted the old posture.
*   The record: ADR-0010 marked accepted with its implementing proposal
    landed, and ADR-0008's third point — "restrictable to allowlisted
    ISD-ASes" — annotated with the narrowing ADR-0010 performs.

### Non-goals

*   No protocol change: the chain renewal request and response, the CMS
    wrapper, the issuance mechanics, and the enrollment lifecycle's
    constants are untouched. The Telegram traffic is an implementation's
    own out-of-band channel to an operator's phone, not a protocol the
    node speaks.
*   No client change: the joiner consumes a pending verdict as an
    unavailable retry, warnings and all — the noise is an accepted
    consequence, not a bug to fix here.
*   No combination of methods and no repetition of the argument: the
    single-value shape leaves both a later change that touches no
    interface. No file indirection for the bot token — it rides the
    process list, an accepted consequence of argument-driven
    configuration.
*   No persistence of decisions: a restart forgets pending and denied
    entries, a join still in flight asks again, and enrolled nodes renew
    without prompting at all — in memory by choice, per the ADR.
*   No per-node admission restriction: a node cannot be more
    restrictive than its core's enrollment policy, riding ADR-0009's
    operating assumption that one operator runs an ISD.
*   No change to the name-taken check, the rendezvous exchange, the
    link service's authenticated-channel requirement, or the candidate
    window's evidence rule — admission's bounds stand as they are.

## Proposal

### The seam at first issuance

The trust service gains the interface it calls, defined beside it per
ADR-0009's one-way direction — implementations import the core, never
the reverse:

*   `EnrollmentFacts`, the three facts the exchange established: the
    claimed `IA`, the CSR's subject `Key` whose possession the CMS
    wrapper proved, and `Addr`, the SCION source address — the
    underlay address of the `*scion.Addr` the request context's
    `http3.RemoteAddrContextKey` carries, read by a helper beside
    `arrivalInterface`'s pattern; the zero `netip.AddrPort` when the
    context carries none.
*   `EnrollmentVerdict` — deny, allow, and pending, with deny the zero
    value: an uninitialized verdict must not admit.
*   `EnrollmentAuthorizer`, the one-method seam
    `Authorize(context.Context, EnrollmentFacts) EnrollmentVerdict`.

`TrustService` grows an `Authorizer` field, nil meaning open. In
`ChainRenewal` the call sits exactly where ADR-0010 places it: after the
name-taken check and the wrapper's possession proof, only when no chain
exists for the name. `checkNameTaken` therefore learns to report what it
already computes — whether the name was free or a same-key renewal
passed — for the authorizer is asked on the free name alone. Deny
answers `PermissionDenied`, pending `Unavailable`, and both are logged
with the facts beside them, so the node's log mirrors the operator's
phone.

The address fact deserves its measure of trust stated plainly: the
underlay address in the SCION header is the joiner's own claim, but the
completed handshake binds it — a reply addressed to the claim travels
the reversed arrival path and is delivered within the joiner's AS to the
claimed host, so an address the claimer cannot receive completes no
enrollment at all. The claim is thus return-routable in the only sense
the CIDR authorizer needs: a joiner behind translation presents its
private address truthfully, and a private-range entry is what admits
such joiners; a fabricated address inside an allowed prefix completes
nothing.

### The CIDR authorizer

`pkg/enrollauth`'s first implementation is a prefix list: parse the
spec's comma-separated prefixes once at startup, and at enrollment
allow exactly a request whose address falls in a listed prefix. A
request carrying no address denies — a gate that opens when its signal
is missing is no gate. The check is stateless and instant, and its
denials are as quiet as its admissions: the trust service's log line is
the whole of the record.

### The Telegram authorizer

The second implementation prompts a human per new joiner, speaking the
Bot API over `net/http` directly — no SDK, for a vendored tree prices
every dependency, and the three calls this needs (`sendMessage`,
`getUpdates`, `answerCallbackQuery`) are plain HTTPS and JSON. Per new
identity — the claimed ISD-AS and the subject key's fingerprint keyed
together — the authorizer sends the configured chat one message: the
claimed name, the key fingerprint, the source address, and an inline
approve and deny button whose callback data carries the identity it
answers, inside Telegram's sixty-four-byte cap. A long-poll
`getUpdates` loop receives the buttons, run under the assembly's
`runBackground` supervision like every other loop, and only callbacks
from the configured chat count — an answer from any other chat is
logged and ignored.

The verdict rules are the ADR's, made concrete: the first ask sends the
prompt and returns pending; retries within the decision window return
pending without re-sending, one prompt per identity. An approved
identity returns allow for the window's remainder — the strong
no-prompt guarantee is the chain check's, not the map's, so a node
whose chain expired and rejoins asks again, a boundary worth knowing
rather than papering over. A denied identity denies for the window,
then may prompt again: a stranger's persistence re-prompts on a window,
not on every retry, and the operator keeps the button, not a config
file. A prompt that cannot be sent denies — with the API unreachable
enrollment fails closed, safe, but unavailable until it returns — and
the send carries its own short timeout so a slow API answers pending
promptly rather than holding the request toward the joiner's attempt
timeout. All of it lives in memory: a restart forgets pending and
denied entries, a join still in flight asks again, and a callback for
an identity the new process never prompted is answered with exactly
that and ignored.

One race the prompt itself resolves: two strangers claiming one name
present two fingerprints, and the operator approves at most one — the
name-taken check settles the loser on its next retry, exactly as it
does today.

### The selector argument

`--enroll-auth` is a single run argument, `method=spec`: `cidrs` takes
a comma-separated prefix list, `telegram` takes `<chat>:<token>` with
the split on the first colon — a group's negative chat id on the left,
the token's own colon kept intact on the right. `Validate` refuses the
argument without `--core`, refuses an unknown method, an empty prefix
list, and a chat that does not parse, and the spec is parsed once at
startup so a malformed one fails the boot, not the first joiner. Unset
is open. The assembly wires the chosen implementation into the trust
service and, for the Telegram authorizer, launches its poll loop under
the node's supervision — core only, for the core is the only node that
issues chains.

### The allowlist retires

`--allow-ia` and its plumbing go outright: the flag, `NodeConfig`'s
`AllowIA`, `parseAllowIA`, and the `AllowAS` fields and checks of
`RendezvousConfig` and `LinkService` — the zeroconf provider passing
them through included. Admission keeps its bounds as they stand: the
rendezvous exchange's nonce echo and rate and count caps, the link
service's authenticated-channel requirement, and the candidate window's
evidence rule, which is where the retirement spends its trust — a
joiner the authorizer never admits mints candidates and answers probes,
but no chain ever names it, no evidence ever establishes its link, and
the window retires it. The static lab's episode asserting enrollment
past a foreign allowlist is replaced by the authorizer's own episodes,
and a deployment upgrading from `--allow-ia` moves to `--enroll-auth`
in the same step — a coordinated upgrade, as the allowlist's retirement
is a behavior change an operator relying on it must make deliberately.

The record follows the code: ADR-0008's third point keeps its text and
gains the narrowing beside it — the restrictable admission policy is
the enrollment authorizer of ADR-0010, not an allowlisted ISD-AS set —
and ADR-0010 is marked accepted, its implementing proposal landed.

## Test plan

*   **Unit tests:** the seam — a nil authorizer issues as today; allow
    issues; deny answers `PermissionDenied` and pending
    `Unavailable`; the authorizer is asked exactly when no chain
    exists, never on a same-key renewal and never on a taken name; the
    facts it receives are the request's own — claimed ISD-AS, subject
    key, and the context's SCION address, zero when the context carries
    none. The CIDR authorizer — a match among several prefixes allows,
    a miss denies, a missing address denies, and an unparsable prefix
    fails the parse, not the enrollment. The Telegram authorizer
    against a local Bot API double — the first ask prompts and pends,
    retries do not re-prompt, the configured chat's approve allows and
    deny denies, another chat's callback is ignored, a send failure
    denies, the window's expiry re-prompts a denied identity, and a
    fresh instance — a restart — knows no decision. The argument —
    both specs parse, an unknown method, an empty prefix list, an
    unparsable chat, and `--enroll-auth` without `--core` are refused.
*   **Integration tests:** the join lab with a CIDR authorizer
    admitting the joiner's range — identity by rendezvous, TRC by the
    domain channel, enrollment allowed by prefix, the candidate
    established on its evidence; the same lab with the Telegram double
    — the joiner pends through retries, the operator presses approve,
    and enrollment completes within one retry interval; a core restart
    mid-join — the joiner's loop converges, a fresh prompt answers it,
    and an enrolled node renews with no prompt at all; the static lab
    with a CIDR authorizer — the file provider's vouch admits links,
    the authorizer bounds enrollment, and no allowlist exists anywhere.
*   **Negative tests:** a joiner outside the prefix list never enrolls
    — its candidate mints, its probes answer, the window retires it,
    and no chain ever names it; an unattended Telegram prompt never
    completes an enrollment and holds no transport state on the core;
    `--allow-ia` is gone — the flag, the config field, and the
    provider's gates; a denied identity's retry cadence is the loop's
    own, one denial per prompt window, not one per retry.

## Implementation history

*   (To be recorded as the change lands.)
