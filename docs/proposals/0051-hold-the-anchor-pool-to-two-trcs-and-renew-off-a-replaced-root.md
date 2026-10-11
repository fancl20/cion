# Hold the anchor pool to two TRCs and renew off a replaced root

This proposal brings chain anchoring to the active-TRC rule of
[`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt) and
grounds on the grace that
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md)
records: "a roll's grace period (Section 3.2.4) covers the replaced material
for the AS certificate validity", and a rotation epoch is "a ladder of
successors — one per holder — each resetting the grace window". The anchor
pool holds the newest pinned TRC and, inside its grace period, its
predecessor, and every node renews its chain once the chain no longer
anchors in the newest TRC. This revises the pool of
[proposal 0038](/docs/proposals/0038-rotate-voting-and-root-certificates-by-sensitive-trc-update.md),
which compounds. No run argument, wire message, or store format changes.

[TOC]

## Summary

Chain verification resolves an anchor pool: `anchorPool` serves `GetChains`
and `RenewChain` ([network.go](/pkg/trust/network.go)), and
`Engine.AnchorPool` serves the SCION-native channel's peer check
([engine.go](/pkg/trust/engine.go), [mtls.go](/pkg/controlplane/mtls.go)).
Both walk back from the newest pinned TRC while each rung is within its own
grace period, so rungs that land inside one another's windows all stay
active. The draft allows two:

*   "No more than two TRCs can be active at the same time for any ISD"
    (Section 3.1).
*   A predecessor stops being active when "a subsequent TRC update (i.e.,
    the successor to the new TRC) is announced" (Section 3.2.4).
*   The trust anchor pool a relying party must build adds only "the
    preceding TRC's root certificates" to the newest's (Section 3.4).

The walk is 0038's design: its ladder "leaves the earlier windows to expire
on their own", and `TestAnchorPoolRidesGrace` checks a pool of three
([rotation_test.go](/pkg/trust/rotation_test.go)).

A chain leaves a replaced root only at its renewal threshold: the
enrollment pass renews once the chain's remaining validity drops below
`trust.ChainRenewalThreshold`, one day of the three-day validity
([lifecycle.go](/pkg/controlplane/lifecycle.go)). Under the draft's rule
alone, a rung that lands inside a root's window would strand every chain
still under the replaced root until then, for up to two days. CION's ladder
makes such rungs routine. Every holder rolls at the same thirty-day
threshold, so the founder's root roll and an authoritative core's roll land
close together whenever their certificates were issued close together, as
at an ISD's founding. In the rotation lab they land seconds apart
([rotation_test.go](/internal/testnetwork/rotation_test.go)).

## Motivation

The draft expects relying parties to leave the replaced material inside the
window: "If the grace period is too short, some control plane AS
certificates may expire before the corresponding ASes can fetch an updated
version from their CA" (Section 3.2.4). A node that renews as soon as its
chain stops anchoring in the newest TRC does that. A later rung then
strands only the chains of nodes that have not yet learned of the root
change, and only until they do. With the pool held to the draft, every
relying party agrees on which roots are active, whatever implementation it
runs.

### Goals

*   The anchor pool is the newest pinned TRC, plus its predecessor while the
    newest is within its grace period, in `anchorPool` and
    `Engine.AnchorPool` alike.
*   On every role, a chain that does not verify against the newest pinned
    TRC alone renews at its holder's next enrollment pass, whatever its
    remaining validity.
*   A chain under a replaced root keeps verifying through the successor's
    grace period, until the next rung lands.

### Non-goals

*   No change to the grace period, to the rolls, or to when holders roll:
    nothing defers a roll while a window runs, and a rung inside a window
    resets it.
*   No validity rule: an expired newest TRC keeps anchoring, and so does an
    expired predecessor inside its successor's window (Section 3.4, step 3;
    Section 3.2.4). Refusing them would turn a straggler's expiry into an
    outage, a change to the cliff ADR-0015 records.
*   No change to the renewal's channel or to the issuer. A stranded chain
    still renews: the renewal rides the WebPKI channel, and the trust
    service renews the holder of a name by its key
    ([trustservice.go](/pkg/controlplane/trustservice.go)).

## Proposal

### The pool holds two TRCs

`anchorPool` and `Engine.AnchorPool` return the newest pinned TRC, and its
predecessor beside it while the newest is within its grace period. The walk
goes. A rung that lands inside its predecessor's window resets the window,
as ADR-0015 records: the TRC before the predecessor anchors nothing from
then on. Both functions' documentation describes the pool as Section 3.4
does, as the documentation of `GetChains` and `verifyChainAgainstTRC`
already does.

### Chains leave a replaced root at the next pass

The enrollment pass reads the newest pinned TRC beside the chain
([lifecycle.go](/pkg/controlplane/lifecycle.go)). A chain far from its
threshold that does not verify against the newest TRC alone renews, with a
warning naming the TRC: the chain anchors in the predecessor's roots alone,
or in none. The renewal is the role's own. The founder self-issues under
the issuer it rekeyed at the pin, and the other roles renew through the
remote, which pulls the newest TRC before it verifies the chain. A pass
with no pinned TRC skips the check, and the TRC-validity report reads the
same TRC.

The founder's own chain leaves the replaced root at its first pass after
the pin. In production the pass with a valid chain runs every
`ChainInspectInterval`, a minute, so a chain stays stranded for about one
discovery round and one inspection. `NodePacing.Enrollment` paces the
enrollment pass's inspection as well as its retry, as it already paces both
for the rotation watch
([controlplane.go](/internal/services/controlplane.go),
[config.go](/internal/services/config.go)). The labs' inspections then run
at their enrollment pace, and production keeps the defaults.

## Test plan

*   **Unit, the pool:** while the successor is within its grace period, the
    pool holds it and its predecessor, and a chain under the replaced root
    verifies against it. A later rung inside the window holds itself and
    the rung before it: the chain under the replaced root no longer
    verifies, and a chain under the rung-1 root does. Past the later rung's
    grace period the pool holds the later rung alone. `Engine.AnchorPool`
    returns the same pools from the local database.
*   **Unit, the pass:** a normal node whose valid chain, far from its
    threshold, anchors only in the predecessor renews through the remote,
    and the chain it stores verifies against the newest TRC alone. The
    founder's pass self-issues on the same rule. A pass whose chain
    anchors in the newest renews nothing.
*   **Integration, the rotation lab:** once both holders have rolled, the
    founder's own chain verifies against its newest TRC alone, and so does
    the third node's once it has discovered the successors. The pre-pin
    chain verifies against the founder's rung beside its predecessor, and
    not against the founder's rung alone. The mismatch roll lands over the
    verified peer channel, whichever holder's rung came first.
