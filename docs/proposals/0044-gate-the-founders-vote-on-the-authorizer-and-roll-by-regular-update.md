# Gate the founder's vote on the authorizer and roll by regular update

This proposal implements the amended decisions 2 and 5 of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md):
the founder's sensitive vote on a submitted TRC rests on the authorizer's
allow alone, none is cast while no authorizer is configured, and an
authoritative core rolls its regular voting certificate by a regular update
its current key votes, which the founder pins without a vote. It reworks the
decision
[proposal 0037](/docs/proposals/0037-onboard-an-authoritative-core-by-sensitive-trc-update.md)
built and the authoritative's roll
[proposal 0038](/docs/proposals/0038-rotate-voting-and-root-certificates-by-sensitive-trc-update.md)
landed; the founder's own roll stays the sensitive update it casts itself.

[TOC]

## Summary

The founder's decision on a submission
([trccast.go](/pkg/controlplane/trccast.go)) classifies by the one
certificate the successor adds: a certificate naming an ISD-AS the
predecessor does not cover is an onboarding, and the authorizer is asked;
one naming a covered ISD-AS is a roll, and nothing is asked. Either way the
founder's sensitive key signs. The classification reads neither the added
certificate's class nor what the successor drops, so the roll's exemption
covers more than the replacement of the presenter's own regular certificate
it exists for: a presenter the operator approved once is not asked again
for a submission that adds one certificate naming itself. With no
authorizer configured, nothing is asked at all, and the founder votes on
every submission that passes the mechanical gates.

The routine roll needs no such exemption. Replacing one regular voting
certificate is a regular update (PKI draft, Section 3.5.4): the replaced
certificate's own key votes, and the founder's vote adds nothing the rules
require. The authoritative core submits it as a sensitive update all the
same ([rotation.go](/pkg/trust/rotation.go)), so every roll draws on the
founder's vote.

## Motivation

ADR-0015 now decides what the founder's vote rests on: the authorizer's
answer, asked of every submission the vote would complete. The decision
must therefore stop telling a roll from an onboarding, and the routine roll
must stop needing the vote. Both changes land together: gating every vote
without moving the routine roll to a regular update would put every
holder's roll behind an operator's answer.

### Goals

*   The founder's sensitive vote on a submission is cast only on the
    authorizer's allow, whatever the submission changes, and never while
    no authorizer is configured; enrollment and registration stay open
    when it is unset.
*   A submission that verifies against the founder's newest pinned TRC as
    submitted pins as submitted, with no vote and no question.
*   An authoritative core's routine roll is a regular update its current
    key votes beside the fresh key's proof of possession.
*   A core whose persisted key no longer covers its certificate in the
    newest TRC still rolls, by a sensitive update the authorizer gates.
*   The authorizer is told every key the successor adds.

### Non-goals

*   No check of the submission's shape: the founder votes on any
    sensitive update the authorizer allows. ADR-0015 records the shape
    check as the alternative the decision can grow into behind the same
    seam.
*   No change to the founder's own roll, still the sensitive update it
    casts through `CastLocal` under the decision's mutex.
*   No new run argument: `--trust.enroll-auth` keeps its syntax, and only
    its unset meaning changes, for the voting boundary alone.
*   No change to how the staged keys persist; the window this leaves is
    recorded below.

## Proposal

### The decision pins what verifies and votes on what is allowed

`DecideTRC` keeps its gates and its idempotent answer: a sensitive key to
vote with, a verified presenter, a submission whose landing the newest
pinned TRC already carries answered with that TRC, an update that
classifies against the newest pinned TRC, and a presenter holding an
enrolled chain. Past them it reads no shape and takes one of three
outcomes:

1.  A submission that verifies against the newest pinned TRC as submitted
    pins as submitted: a regular update its voters signed, or any update
    whose votes it carries already. Nothing is asked, and the founder
    signs nothing.
2.  A sensitive update that does not verify yet asks for the founder's
    vote: the authorizer is asked, and on its allow the sensitive key
    co-signs, the completed TRC verifies against the newest pinned TRC,
    and it pins.
3.  Anything else, a regular update missing a signature among them, is
    refused.

The roll and onboarding branches go, with the one-certificate rule, the
presenter's match to the added certificate, and the roll's quorum and AS
list checks: a regular update keeps those by cppki's own rules, and a
sensitive one rests on the answer. The decision's mutex still orders every
outcome against the founder's own cast.

### The authorizer sees every added key, and denies when unset

With no authorizer, `authorizeVoting` refuses and logs a warning: the
founder's vote is the one boundary an unset policy closes. The facts carry
the voting boundary, the presenter as the claim, the channel's underlay
source, and in `Keys` the fingerprint of every certificate the successor
adds, in the successor's order. `AdmissionFacts.VotingCert` is dropped: no
implementation reads it, and one certificate no longer describes what a
submission adds ([admission.go](/pkg/modules/enrollauth/admission.go)). The
Telegram prompt already prints every key, and it denies facts that carry no
key — a sensitive update that adds no certificate — while the CIDR
authorizer decides on the source alone. The run argument's help, the node
configuration, the admission module's package documentation, and the
security overview state the unset meaning.

### The authoritative rolls by regular update

`AssembleRotation` takes the voter: the predecessor's certificate whose
index the votes field carries. The founder's roll passes its sensitive
certificate, and the successor is the sensitive update it is today; the
authoritative's routine roll passes the certificate it replaces, and the
successor is a regular update — the quorum and both AS lists unchanged, the
changed certificate's predecessor voting. `RollVotingKey` signs it with the
fresh key and the current one, so the submission verifies as submitted and
the founder pins it unchanged.

When the persisted key no longer covers the certificate the newest TRC
names — a crash between pin and persist, an operator's replacement — the
current key cannot vote. The roll falls back to a sensitive update: the
founder's sensitive certificate is the voter, the fresh key signs alone,
and the founder's vote is asked of the authorizer like any other.

### A lost answer asks the operator

A roll whose answer is lost — the founder pinned the regular update, and
the holder's attempt timed out before the reply — leaves the founder's
newest naming a key the holder never persisted. The holder's next roll is
the sensitive fallback, so a routine roll becomes a question for the
operator. Staging the fresh key durably before the submission closes the
window; it arrives with the key persistence work of its own proposal.

## Test plan

*   **Unit, the decision:** an onboarding asks the authorizer once with
    the voting boundary, the presenter as the claim, the joiner's key as
    the one fingerprint, and the channel's source, and pins with the vote
    on allow; deny and pending refuse and pin nothing; a successor adding
    two certificates asks once with both fingerprints in the successor's
    order, and a deny refuses; with no authorizer configured, the
    onboarding is refused and nothing pins.
*   **Unit, the roll at the decision:** a regular-update roll pins exactly
    as submitted, the founder signing nothing, without asking an
    authorizer that would deny, and its re-presentation is answered with
    the pin; a lost-key roll — the founder's sensitive certificate the
    voter, the fresh key the only signature — is refused on deny and pins
    with the vote on allow; a regular update missing its vote is refused
    without asking.
*   **Unit, the gates:** an unenrolled presenter reaches no question; a
    stale predecessor, a missing possession proof, a node without the
    sensitive key, and a submission without a verified presenter refuse,
    as today.
*   **Unit, the assembly:** the founder's rotation, its sensitive
    certificate the voter, classifies as a sensitive update as before; a
    voter the predecessor does not carry is refused.
*   **Unit, the authoritative's roll:** the routine roll submits a regular
    update carrying the vote beside the possession proof, the caster
    casting nothing, both sides pinning and the fresh pair persisting; a
    persisted pair the newest TRC does not name re-rolls by sensitive
    update, the caster voting.
*   **Unit, the watch:** the authoritative's routine roll asks the
    authorizer nothing, and its mismatch roll asks it once.
*   **Integration:** the labs that onboard a core — the join, mesh, and
    two-core path labs — configure the founder's authorizer to admit the
    labs' loopback range, for with none the founder votes on nothing; the
    rotation lab does the same for its mismatch roll, which now asks the
    founder's vote. The rotation lab checks each rung's update type — the
    authoritative's routine roll a regular update, the founder's roll and
    the mismatch roll sensitive ones — and is renamed
    `TestCoresRotateByTRCUpdate`. The lab whose founder hosts no voting
    application is unchanged.

## Implementation history

*   The decision landed as proposed in `DecideTRC`, `authorizeVoting`
    asking the policy and `novelCerts` reading the certificates the
    successor adds ([trccast.go](/pkg/controlplane/trccast.go)); the roll
    landed in `AssembleRotation` and `RollVotingKey`
    ([rotation.go](/pkg/trust/rotation.go)).
*   The unset meaning reached documentation the plan leaves unnamed: the
    CIDR authorizer's, which decides every boundary on the source alone
    ([cidr.go](/pkg/modules/enrollauth/impl/cidr/cidr.go)), the voting
    application's ([voting.go](/pkg/apps/voting/voting.go)), and the
    voting service's comments
    ([voting.proto](/proto/voting/v1/voting.proto)). The generated Go
    files carry the same comment edits, made by hand: the raw descriptor
    holds no comments, so the edit is what regeneration produces.
*   The security overview gained a residual risk beside the unset
    meaning: the vote rests on the policy's answer alone, and an
    address-based policy lends it to every enrolled core inside its
    prefixes. Its line on losing the founding core now separates the
    core, whose loss halts enrollment and every TRC update, from its
    sensitive key, whose loss halts the updates that need its vote
    ([security.md](/docs/design/security.md)).
*   The tests landed as the plan spells them
    ([trccast_test.go](/pkg/controlplane/trccast_test.go),
    [rotation_test.go](/pkg/controlplane/rotation_test.go),
    [rotation_test.go](/pkg/trust/rotation_test.go)). The labs share the
    founder's policy as `votingAuth`
    ([corejoin_test.go](/internal/testnetwork/corejoin_test.go)), and the
    rotation lab classifies each rung against its predecessor
    ([rotation_test.go](/internal/testnetwork/rotation_test.go)).
