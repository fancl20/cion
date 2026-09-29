# Rotate voting and root certificates by sensitive TRC update

This proposal implements the rotation seam of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md):
the founder's voting and root certificates and each authoritative
core's regular voting certificate roll inside a sensitive TRC update —
fresh keys staged for the cast, the founder's sensitive key casting the
vote, every rolled core co-signing with its fresh key, and the
completed successor pinning the way the join's successor pins. It lands
on the update path [proposal
0037](/docs/proposals/0037-onboard-an-authoritative-core-by-sensitive-trc-update.md)
builds and changes no path-layer behavior: the beaconing, lookup, and
registration decisions the same ADR records ride their own proposal.

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
certificates — the sensitive one, for the cast this proposal adds.
What is missing is everything around the artifact: nobody stages fresh
keys, nobody assembles the swap, nobody watches the clock, and nothing
keeps chains issued under a replaced root verifying. The last gap is
the grace machinery — the predecessor staying active behind its
successor for a bounded window (Section 3.2.4) — which ADR-0015
schedules to arrive "with the first removals." Rotation is the first
removal, and the only material it removes is a key's own predecessor.

## Motivation

ADR-0015 lands through proposals split along its seams, and rotation is
the first landing on the path 0037 builds: everything the join
assembled — predecessor-aware verification, newest-TRC discovery, the
serialized cast — serves additions alone until something rolls. The
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

### Goals

*   Rotation is automatic: a watch on the founder replaces the
    log-only posture, a named threshold decides when, and no operator
    action and no new run argument appear.
*   Every voting certificate rolls: the founder's sensitive and
    regular, each authoritative's regular — the founder solicits, the
    cores co-sign, and the exchange is the join's own, generalized from
    one joiner to every rolled core.
*   The CA rotates with the root: the root key and certificate roll
    inside the same successor, the CA key rolls beside them, the issuer
    rekeys on the pin, and chains issued under the replaced root keep
    verifying through the successor's grace period.
*   One cast path: a successor may onboard and roll at once, casts stay
    serialized on the founder, and the assembly is 0037's, grown —
    one mechanism, two needs, the ADR's own driver.
*   Fail-closed and crash-safe: staged material pins or discards,
    nothing partial pins, and a successor no pinned predecessor vouches
    for enters no database.

### Non-goals

*   No path-layer change: the authoritative originates no beacons,
    terminates no core segments, serves no core lookup, and registers
    its down segments no differently than a normal node — ADR-0015's
    path decisions land in their own proposal.
*   No regular updates: rotation rides the sensitive path, ADR-0015's
    decision — a regular update cannot touch the sensitive voting
    certificates, and at quorum one it buys no second opinion either.
*   No second sensitive voter, no quorum change, no CA keys on the
    authoritative tier — ADR-0015's own non-goals; the founder stays
    the sole sensitive voter and the sole issuer.
*   No removals beyond replacement: a core that never answers keeps its
    certificate, and the expiry of what is carried bounds every
    successor that carries it; retiring material nobody replaces is the
    removal machinery's, and arrives in its own proposal.
*   No offline sensitive key: the founder now signs periodically, not
    only at joins — the exposure ADR-0015 records deepens, it does not
    begin.
*   No trust reset and no base-number change: `noTrustReset` stays
    untouched and the serial keeps incrementing on the same base, so a
    lost ISD still recovers the way Section 3.6 describes.

## Proposal

### The watch replaces the log

The founder grows a rotation loop beside its enrollment loops, under
the same supervision ([node.go](/internal/services/node.go)) and with
the same pass shape — a calm inspection interval while nothing is due,
the retry cadence while a cast is failing. Each pass reads the newest
pinned TRC's certificates and finds the earliest expiry;
`trust.RotationThreshold` — thirty days, the counterpart of the chain
renewal threshold's one day against the three-day chain validity
([engine.go](/pkg/trust/engine.go)): long enough to tolerate a month of
failed casts, short enough that the successor's validity stays
comfortable — decides the pass. Beyond the threshold the pass reports
what `logTRCValidity` reports today; within it the founder casts. The
threshold is a constant with the zero-keeps-the-default override field
the enrollment intervals already model, for the lab to shrink; the run
command wires nothing new. No other node casts: every other node keeps
the log and discovers successors the way 0037 wires.

### A roll is staged, and pins or discards

Fresh keys are generated for the cast and live in memory alone. The
persisted set — the files `LoadOrCreateCoreKeys` reads
([keys.go](/pkg/trust/keys.go)) — is untouched until the completed
successor is verified and pinned; then it is replaced as a set, the
fresh certificates persisting beside the fresh keys exactly as the
joiner's certificate persists beside its key. A crash anywhere before
the pin leaves the predecessor's keys on disk and the next pass rolls
again — fresh keys are cheap, for nothing references them until the
TRC carrying their certificates is pinned. After the pin the retired
keys are gone and the next cast votes with the fresh sensitive key. The
node's identity is never at stake: the AS key and the ISD-AS are
untouched by a roll, and chains renew on the enrollment clock they
already keep.

### The founder rolls its own three

Locally, in one staging pass: a fresh sensitive voting key and
certificate, a fresh regular pair, a fresh root pair — the certificate
constructions unchanged
([certs.go](/pkg/trust/certs.go)) — and a fresh CA key beside the
root, the issuer's material rotating as a set even though only the root
is anchored in the TRC. Each fresh certificate signs the successor:
proof of possession, cppki's own requirement for every certificate
that supersedes a same-named one, extended to the root the way
ADR-0015 records it. The vote is cast by the old sensitive key — an
index into the predecessor's certificates — and the old key is present
by construction: it is the persisted one until the pin replaces it.

### The founder solicits the authoritative tier

Every in-horizon certificate held by another core is rolled by its
holder. The founder sends a roll request over the control endpoints the
cast already rides; the core stages a fresh regular key and self-signed
certificate — the construction its join used — and returns the
certificate; the successor carries it, and the co-signature round
collects the holder's signer info through the same exchange the join's
cast defines. Two request-response pairs per rolled core, on the
control endpoint every node already serves. A core that does not answer
in time keeps its certificate: the successor carries it unchanged and
the next pass solicits again, so the ISD's rotation never waits on one
node — at the price, recorded in the non-goals, that the straggler's
expiry bounds every successor that carries it. The solicited core does
not pin what it co-signs: it pins through the discovery every node
uses, and persists its staged key then. A core whose persisted key no
longer matches the certificate the newest TRC names — a crash between
its pin and its persist — rolls again on the next solicitation; a
re-rolled certificate supersedes a same-named one in either state, and
the rules never distinguish.

### The successor carries the swap

The assembly is 0037's, grown. The serial increments on the same base;
the staged certificates replace their in-horizon counterparts — same
distinguished name, fresh key and serial — while the out-of-horizon
certificates carry over unchanged; the quorum, `noTrustReset`, and
both AS lists are untouched, for a rotation changes keys, never
membership. A join ask in flight rides the same successor, the casts
staying serialized on the founder and the assembly folding in whatever
is pending. The votes field carries the predecessor's index of the
founder's sensitive voting certificate; the artifact carries that vote
and one signature per fresh certificate; cppki classifies the whole a
sensitive update. The validity runs from the backdated cast time to the
earliest expiry the carried set still holds — the fresh certificates
never rule it, so a completed rotation extends the successor's horizon
past the threshold, and only a carried straggler shortens it. The grace
period is the AS certificate validity, on every successor the founder
assembles: inert for the join's additions, and for rotation the window
in which the replaced root keeps anchoring.

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
    and a staged roll carries the incremented serial on the same base,
    the same distinguished names over fresh keys, the out-of-horizon
    certificates carried unchanged, the quorum and both AS lists
    untouched, the grace period set to the AS certificate validity, and
    a validity bounded by the earliest expiry the carried set holds;
    cppki classifies it a sensitive update and verifies it against the
    predecessor with the vote and every fresh certificate's signature;
    removing any one signature fails the verification.
*   **Unit, the watch:** a pass with every expiry beyond the threshold
    casts nothing; a pass with one within it rolls exactly the
    in-horizon certificates; the threshold field overrides the default.
*   **Unit, staging:** a failed cast leaves the persisted key files
    untouched; the pin replaces them as a set, the fresh certificates
    persisting beside the fresh keys; a re-roll after a crash between
    pin and persist assembles a successor the rules accept.
*   **Unit, the grace pool:** a chain under the replaced root verifies
    while the successor is in grace and fails after it; a chain under
    the fresh root verifies against the successor; the renewal verifies
    the issued chain against the pool it just pulled.
*   **Unit, the issuer:** chains issue under the fresh root once the
    successor is pinned, the CA certificate reissued under it.
*   **Integration, the rotation lab:** beside the join lab in
    [testnetwork](/internal/testnetwork), a founder and an
    authoritative core with the threshold shrunk — the watch casts, the
    solicitation and co-signature complete, both nodes pin the
    successor, a third node discovers it from the founder's signed
    messages and verifies a chain renewed after the pin under the fresh
    root, and a chain issued before the pin keeps verifying through the
    grace.
*   **Negative and interruption:** an unresponsive authoritative keeps
    its certificate while the cast completes for the reachable rolls; a
    forged successor pins nowhere; a cast interrupted between vote and
    co-signature retries from the newest pinned TRC and leaves nothing
    partial pinned.

## Implementation history
