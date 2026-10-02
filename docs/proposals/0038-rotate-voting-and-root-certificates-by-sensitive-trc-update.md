# Rotate voting and root certificates by sensitive TRC update

This proposal implements the rotation seam of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md):
every voting certificate rolls inside a sensitive TRC update its holder
initiates — the founder's voting and root certificates, the CA key beside
them, inside the cast the founder signs itself; each authoritative core's
regular voting certificate in a successor the core assembles and submits
through the same channel its join used, the founder's sensitive vote
completing it; and every completed successor pinning the way the join's
successor pins. It lands on the update path
[proposal 0037](/docs/proposals/0037-onboard-an-authoritative-core-by-sensitive-trc-update.md)
builds and changes no path-layer behavior: the beaconing, lookup, and
registration decisions the same ADR records ride their own proposals.

[TOC]

## Summary

The rotation story today is a comment and a log line. The constants
give every trust material 365 days and disclaim the rest: "There is no
automated renewal yet: an expired node re-runs enrollment, and a new
base TRC means redeploying"
([certs.go](/pkg/trust/certs.go)). The enrollment loops watch the
pinned TRC's validity and only report — `logTRCValidity`'s verdict is
"log only, since a new base TRC means redeploying," escalating from
warning to error and doing nothing at either step
([lifecycle.go](/pkg/controlplane/lifecycle.go)). The issuer reissues
its CA certificate under the root "for the lifetime of the base TRC"
([issuer.go](/pkg/trust/issuer.go)) — the root itself, the voting
certificates, and the TRC they bound never roll; outliving any of them
means redeploying the ISD. Normal nodes hold none of this material:
their chains already rotate on the enrollment clock, so rotation is the
cores' concern — the founder's sensitive, regular, and root
certificates and each authoritative's regular one.

The update path 0037 builds carries additions and freezes the rest.
Its non-goal records the freeze: "the founder's voting and root
certificates are carried into the successor unchanged, so the
successor's validity is bounded by the earliest expiry among them — and
rolling any of them arrives in its own proposal, on the path this one
builds." This is that proposal. cppki's rules already read a rotation:
a certificate that reappears with the same distinguished name and a
fresh key is *changing*, its fresh successor must sign the update as
proof of possession, and the vote is an index into the predecessor's
certificates — the sensitive one, for the cast this proposal completes.
What is missing is everything around the artifact, on every core that
holds one: nobody stages its fresh key, nobody assembles its swap,
nobody watches its clock, and nothing keeps chains issued under a
replaced root verifying. The last gap is the grace machinery — the
predecessor staying active behind its successor for a bounded window
(Section 3.2.4) — which ADR-0015 schedules to arrive "with the first
removals." Rotation is the first removal, and the only material it
removes is a key's own predecessor.

Who rolls what is the ADR's own deciding question, and its answer is
the holder: the founder's watch answers the founder's clock and casts
alone, and each authoritative's watch answers its own and submits. The
founder-solicited alternative — one watch folding every core's answer
into a single successor — is the option the same record weighs and
rejects: a compromised key on another core has no self-initiated
answer, the watch fires only near expiry, and the solicitation is a
second wire surface beside the submission channel, with staging state
on every core.

## Motivation

ADR-0015 lands through proposals split along its seams, and rotation is
the first landing on the path 0037 builds: everything the join
assembled — predecessor-aware verification, newest-TRC discovery, the
submission channel — serves additions alone until something rolls. The
clock it answers is the whole tier's. Every certificate in the TRC
lives 365 days, cppki refuses a TRC whose certificates do not cover its
validity, and so the earliest expiry among them caps every successor
that carries them — an ISD that cannot rotate is an ISD with a
deployment date built in, and the moment a second member exists,
redeploying to outlive a certificate stops being acceptable.

The grace machinery belongs here because the first removals do: rolling
the root certificate removes the anchor of every chain issued beneath
it, and nodes hold chains for up to the three-day AS certificate
validity. The draft's grace period is what makes the replacement
invisible to the nodes, and it is the only part of the removal story
rotation needs — membership never changes here, only keys. Everything
harsher a removal could ask for, starting with retiring a core that
never answers, stays with the removal machinery its own proposal will
bring.

The holder governs the roll because the key is the holder's: generation,
clock, and the emergency answer included. A compromised key is rolled
the moment its holder decides, not at the next pass of a watch
elsewhere, and no key material ever leaves the node — what crosses the
wire is the certificate and the holder's proof of possession over the
artifact, so the founder verifies a key's holder without ever seeing
the key. The price is the one the ADR records and this proposal
inherits: a rotation epoch becomes a ladder of successors, one per
rolling holder; a member that never rolls caps the shared validity, and
nothing solicits it; and the founder's decision must learn to tell a
roll from an onboarding.

### Goals

*   Rotation is automatic on every core: a watch beside the chain
    lifecycle replaces the log-only posture, a named threshold decides
    when, and no operator action and no new run argument appear.
*   Every certificate rolls, each roll initiated by its holder: the
    founder's sensitive and regular voting certificates and its root
    certificate — the CA key beside them — inside the cast it signs
    itself, and each authoritative's regular certificate through the
    submission channel its join used, the founder's vote completing it.
*   The emergency answer exists: a holder may roll whenever it must —
    a mismatch between what it persists and what the newest TRC names
    fires the roll whatever the calendar says.
*   One submission path: joins and rolls ride the same channel and the
    same decision, casts stay serialized on the founder, and the
    decision asks the authorizer only where voting power is granted.
*   The CA rotates with the root: the root key and certificate roll
    inside the founder's successor, the CA key rolls beside them, the
    issuer rekeys on the pin, and chains issued under the replaced root
    keep verifying through the successor's grace period.
*   Fail-closed and crash-safe: staged material pins or discards,
    nothing partial pins, and a successor no pinned predecessor vouches
    for enters no database.

### Non-goals

*   No path-layer change: the authoritative originates no beacons,
    terminates no core segments, serves no core lookup, and registers
    its down segments no differently than a normal node — ADR-0015's
    path decisions land in their own proposal.
*   No solicitation: nothing asks a core to roll, and the founder folds
    no answers into its own cast. A member that never rolls keeps its
    certificate, its expiry capping every successor that carries it, and
    the expiry itself is the discovery: the cliff the ADR records.
*   No regular updates: rotation rides the sensitive path, ADR-0015's
    decision — a regular update cannot touch the sensitive voting
    certificates, and at quorum one it buys no second opinion either.
*   No second sensitive voter, no quorum change, no CA keys on the
    authoritative tier — ADR-0015's own non-goals; the founder stays
    the sole sensitive voter and the sole issuer.
*   No removals beyond replacement: retiring material nobody replaces is
    the removal machinery's, and arrives in its own proposal.
*   No offline sensitive key: the founder now signs periodically, not
    only at joins — the exposure ADR-0015 records deepens, it does not
    begin.
*   No trust reset and no base-number change: `noTrustReset` stays
    untouched and the serial keeps incrementing on the same base, so a
    lost ISD still recovers the way Section 3.6 describes.

## Proposal

### The watch replaces the log, on every core

Every core grows a rotation loop beside its enrollment loops, under the
same supervision ([node.go](/internal/services/node.go)) and with the
same pass shape — a calm inspection interval while nothing is due, the
retry cadence while a cast is failing. Each pass reads the newest
pinned TRC and the certificates in it the node itself holds — the
founder's three, an authoritative's one — and finds their earliest
expiry; `trust.RotationThreshold` — thirty days, the counterpart of the
chain renewal threshold's one day against the three-day chain validity
([engine.go](/pkg/trust/engine.go)): long enough to tolerate a month of
failed casts, short enough that the successor's validity stays
comfortable — decides the pass. Beyond the threshold the pass reports
what `logTRCValidity` reports today; within it the holder rolls. The
threshold is a constant with the zero-keeps-the-default override field
the enrollment intervals already model, for the lab to shrink; the run
command wires nothing new. A second trigger fires whatever the
calendar: a persisted key the newest TRC's certificate no longer covers
— the crash between a pin and its persist, or an operator who replaced
the node's voting material to evict a compromised key — rolls at the
next pass, the sensitive key alone excepted, for the vote it alone can
cast is the recovery, and its loss is the redeploy the quorum-one
coupling records. Normal nodes keep the log and discover successors
the way 0037 wires.

### A roll is staged, and pins or discards

Fresh keys are generated for the roll and live in memory alone. The
persisted set — the files the voting-key loaders read
([keys.go](/pkg/trust/keys.go)) — is untouched until the completed
successor is verified and pinned; then it is replaced as a set, the
fresh certificate persisting beside the fresh key exactly as the
joiner's certificate persists beside its key. A crash anywhere before
the pin leaves the predecessor's keys on disk and the next pass rolls
again — fresh keys are cheap, for nothing references them until the
TRC carrying their certificates is pinned. The rolling node pins the
completed artifact from its own cast — the submission's returned bytes,
the founder's local completion — and persists immediately after; the
window between the two is in-process, and the mismatch trigger stands
guard over it: a node whose persisted key no longer matches the
certificate the newest TRC names rolls again. The node's identity is
never at stake: the AS
key and the ISD-AS are untouched by a roll, and chains renew on the
enrollment clock they already keep.

### The founder rolls its own three

Locally, in one staging pass: a fresh sensitive voting key and
certificate, a fresh regular pair, a fresh root pair — the certificate
constructions unchanged
([certs.go](/pkg/trust/certs.go)) — and a fresh CA key beside the
root, the issuer's material rotating as a set even though only the root
is anchored in the TRC. The successor is `AssembleRotation`'s
([rotation.go](/pkg/trust/rotation.go)): each fresh certificate
replacing its same-named counterpart, everything else carried
unchanged. Each fresh certificate signs the successor: proof of
possession, cppki's own requirement for every certificate that
supersedes a same-named one, extended to the root the way ADR-0015
records it. The vote is cast by the old sensitive key — an index into
the predecessor's certificates — and the old key is present by
construction: it is the persisted one until the pin replaces it. The
completed artifact verifies against the pinned predecessor before
anything pins; the pin persists the staged set as a set and rekeys the
issuer under the fresh root.

### Each authoritative rolls its own

Every certificate another core holds is rolled by that core. When its
watch fires, the authoritative stages a fresh regular voting key with
its self-signed certificate — the construction its join used — and
resolves the founder's newest TRC: the numbers-less ask the drafts'
trust service answers, verified against the pinned chain and pinned,
the opening of its join's own cast. It assembles the successor with the
single staged certificate, signs the artifact with the fresh key — the
proof of possession, the same signature its join carried — and submits
the partially signed successor to the founder's voting application over
the verified peer channel, the caster its join used
([submitter.go](/pkg/apps/voting/submitter.go)). The founder's decision
classifies, votes, and pins; the completed artifact returns, verifies
against the predecessor the roller resolved, and pins; the staged pair
persists. A founder that does not answer — no application mounted, the
route refused — leaves the pass retrying on its cadence with nothing
pinned and the predecessor's pair on disk, the expiry escalating
`logTRCValidity`'s way; the roll completes when the founder does.

### The decision tells a roll from an onboarding

The submission the founder's decision examines
([trccast.go](/pkg/controlplane/trccast.go)) is the join's own, and the
question it asks of every submission — does this grant voting power —
is answered by reading what the submission changes. cppki's
classification calls a certificate *new* whether it names a fresh
ISD-AS or a fresh key under a distinguished name the predecessor
already carries, and the decision tells the two apart against the
predecessor: one new voter naming an ISD-AS the predecessor's
certificates do not cover is an onboarding, asked the authorizer's
question exactly as today; one changed certificate naming the
presenter's own ISD-AS is a roll, and it asks nothing, for a roll
grants no power the presenter lacked. The gates the join built stand
over both — the update classifies against the newest pinned TRC, the
presenter is the channel's verified peer holding an enrolled chain, the
possession signature verifies — and the roll's shape is narrower still:
exactly one certificate changed and the quorum, both AS lists, and
`noTrustReset` as they were, for a roll changes keys, never membership.
Everything else refuses and pins nothing. The idempotent answer the
join defined stands too: a submission whose landing the newest already
carries is answered with it, and casts nothing — read from what the
submission changes, never from the presenter's name alone, for a
rolling presenter is already named.

### A rotation epoch is a ladder of successors

Nothing folds two holders' rolls into one artifact. A rotation epoch is
a ladder: the founder's cast swaps its own three, each authoritative's
submission swaps its own one, and each completed successor stands on the
previous — the serials monotone by construction, for every path a
successor takes holds the decision's mutex: the submissions serialize
on it, and the founder's own cast holds it too, so a submission the
cast overlaps is refused on the older view and retried onto the new
newest. Each rung costs a discovery round — holders of the predecessor
pull the successor the reports name — and each rung carries the grace
period, though only the rung that replaces the root opens a window for
the replaced root; a later rung carries the fresh root and leaves the
earlier windows to expire on their own.

### Chains ride the grace

Chain verification resolves the anchor pool the draft's Section 3.2.4
defines for updates: the newest pinned TRC's roots, plus the
predecessor's while the newest is within its grace period.
`cppki.VerifyChain` already takes a TRC list and succeeds against any
of them, and the grace window is already readable — the anchoring read
in `GetChains` and `RenewChain` widens from one TRC to the pool
([network.go](/pkg/trust/network.go)). The arithmetic closes by
construction: a chain issued under the replaced root lives at most the
AS certificate validity, the grace window is exactly that, and the
renewal threshold sees a node renew inside a day — by the time the
grace ends, every chain issued before the cast has expired and every
chain after anchors in the fresh root. Renewal holds 0037's ordering
with one insistence: the node pulls the newest TRC before it verifies
the issued chain, so a chain under the fresh root verifies against the
successor and not the predecessor the node still holds. The issuer
follows the pin: the CA certificate reissues under the fresh root —
`ensureCACert`'s reissue path, forced by the root change rather than
the expiry proximity — and the chains issue under it from the pin on.

### Discovery rides what exists

Nothing here adds a distribution mechanism. The successor spreads the
way the join's does — signers cite the newest pinned TRC, verifiers
report it, holders pull what the report names — and the numbers-less
request returns it from the founder's endpoint. The trust database
keeps every TRC it has pinned: predecessors are what updates verify
against and what grace reads from, and the sweep that expires chains
has never touched TRCs
([db.go](/pkg/modules/trustdb/impl/bbolt/db.go)).

## Test plan

*   **Unit, the assembly:** the successor assembled from a predecessor
    and one staged certificate carries the incremented serial on the
    same base, the same distinguished name over a fresh key, every
    other certificate carried unchanged, the quorum and both AS lists
    untouched, the grace period set to the AS certificate validity, and
    a validity bounded by the earliest expiry the carried set holds;
    cppki classifies it a sensitive update and verifies it against the
    predecessor with the vote and the staged certificate's signature;
    removing either signature fails the verification.
*   **Unit, the watch:** a pass with the node's own certificates beyond
    the threshold casts nothing; a pass with one within it rolls exactly
    them; a persisted key the newest TRC's certificate does not cover
    fires the roll whatever the calendar says; the threshold field
    overrides the default.
*   **Unit, the decision:** a submission replacing exactly the
    presenter's own certificate asks no authorizer question and pins
    with the vote; a submission onboarding a new voter asks it as
    today; a submission replacing another core's certificate, touching
    the lists or the quorum, or presenting no verified chain refuses
    and pins nothing; the idempotent re-presentation still answers with
    the pinned newest.
*   **Unit, staging:** a failed submission leaves the persisted files
    untouched; the completed answer pins and the fresh pair persists
    beside it; a re-roll after a crash between pin and persist
    assembles a successor the rules accept; the founder's sensitive-key
    mismatch stays the terminal crash corner.
*   **Unit, the grace pool:** a chain under the replaced root verifies
    while the successor is in grace and fails after it, a later rung
    standing in between included; a chain under the fresh root verifies
    against the successor; the renewal verifies the issued chain
    against the pool it just pulled.
*   **Unit, the issuer:** chains issue under the fresh root once the
    successor is pinned, the CA certificate reissued under it.
*   **Integration, the rotation lab:** beside the join lab in
    [testnetwork](/internal/testnetwork), a founder and an
    authoritative core with their state pre-seeded so each holder's
    material approaches expiry — the founder's watch casts its own
    roll, the authoritative's submits its own, both pin, and the
    ladder's serials stay monotone; a third node discovers the
    successors from the founder's signed messages and verifies a chain
    renewed after the founder's pin under the fresh root, and a chain
    issued before the pin keeps verifying through the grace; replacing
    the authoritative's persisted voting pair fires the mismatch roll
    at the next pass.
*   **Negative and interruption:** a founder that does not answer
    leaves the rolling core retrying with nothing pinned and its old
    pair on disk; a straggler that never rolls keeps its certificate
    and caps every successor that carries it; a forged successor pins
    nowhere; a submission interrupted between possession and vote
    retries from the newest pinned TRC and leaves nothing partial
    pinned.
