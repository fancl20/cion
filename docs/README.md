# Documentation

This directory holds CION's decision records (ADRs), its implementation
plans (proposals), the SCION drafts the code implements (specs), and the
style guides all of it is written under (styles). Work on CION moves
through three layers — design, plan, code — and the first two live here.

[TOC]

## Directory layout

*   `adrs/` — Architecture Decision Records in
    [MADR](https://adr.github.io/madr/) format: what was decided, and
    why.
*   `proposals/` — implementation plans: what lands, and how it is
    verified.
*   `specs/` — the IETF SCION drafts (control plane, data plane, PKI)
    the core implements. ADRs cite them by draft and section.
*   `styles/` — the style guides and the conventional commit convention.
    `AGENTS.md` at the repository root adds the project's own coding,
    documentation, and commit rules.

## The workflow

Every non-mechanical change moves through three layers, each answering
one question:

1.  **ADR — the design.** Records intention: the problem as it stood,
    the drivers that decided it, the options weighed, the outcome, and
    the consequences accepted. An ADR argues *why this boundary and not
    another*; it does not name flags, packages, or tests.
2.  **Proposal — the plan.** Grounds an objective in code: the seams it
    adds, the packages it touches, the arguments it exposes, and the
    test episodes that prove it. A proposal does not re-argue what its
    ADR decided.
3.  **Implementation — the code.** The landing, cited back: the commit
    names its proposal, and the code carries the deciding record's
    number where the decision shows.

## When a record is required

**An ADR is required** when a future reader's question is *why this
way* and the honest answer needs the rejected options: a boundary
between core and apps, what the wire carries, what a peer must answer,
where keys live, how the tree is cut into packages.

**A proposal is required** when the change implements an ADR, adds or
changes a run argument, crosses package boundaries, or needs a test
plan a reviewer should check before reading the diff. Every proposal
names in its opening the ADR it implements or grounds on; a hardening
proposal may ground on an accepted ADR's promises rather than implement
a new decision.

**Neither record** when the change is mechanical — a rename, a
dependency bump, a lint fix, a de-flaked test — and the commit message
carries the whole rationale. The test is whether it can: if the commit
summary has to argue rather than describe, the argument belongs in a
record.

## Sequencing

1.  The ADR lands as `proposed` before implementation of its decision
    begins.
2.  The proposal may be drafted against a `proposed` ADR; the code it
    plans does not land until the ADR's fate is settled.
3.  The implementing commit lands the code, the proposal's
    implementation-history entry, and the ADR's flip to `accepted`
    together. An ADR is never accepted ahead of existing code, and
    never left `proposed` once its code exists.
4.  One ADR may land through several proposals, split along the
    machinery's seams. Two proposals deciding one seam is a collision
    waiting for a re-decision — and the loser's in-flight work reverts.
5.  A proposal implementing an ADR maps the ADR's promises to test
    episodes in its test plan, so that `accepted` means decided *and*
    implemented. A promised invariant with no episode is a gap the
    record shows as green.

## Statuses

**ADRs** carry MADR status lines:

*   `proposed` — landed, not yet implemented.
*   `accepted` — flipped by the implementing commit.
*   `superseded by [ADR-NNNN]` — re-decided; the superseded text stays.

**Proposals** carry no status line — the implementation history is the
status:

*   No history entry — the plan is in flight.
*   A history entry — the plan has landed; the entry records where. A
    plan re-decided before it lands records that instead: what stands
    as designed, and which ADR superseded it.

## Maintaining the record

*   A re-decision lands as a new ADR superseding the old. Superseded
    records are never deleted or rewritten.
*   A narrowing lands as an annotation beside the narrowed point,
    naming the record that narrows it.
*   A factual or citation error is corrected in place.
*   Otherwise a landed record's body is immutable; its status line is
    the one routine edit.

## Writing conventions

*   File names are `NNNN-kebab-case-title.md`. Numbers are monotonic
    per directory and never reused.
*   ADRs and proposals number in separate spaces. Always carry the
    prefix: *ADR-NNNN* and *proposal NNNN* are different documents even
    when their numbers coincide.
*   Links are absolute from the repository root.
*   ADRs follow MADR — context and problem statement, decision drivers,
    considered options, decision outcome, consequences. Proposals carry
    Summary, Motivation with Goals and Non-goals, Proposal, Test plan,
    and Implementation history.
*   Every record opens with a `[TOC]` marker under its first paragraph.

## Implementation history

The implementing commit appends the entry. It records the landing's
coordinates — the commit, and where the code lives — and every
divergence from the plan. It does not restate what the Proposal section
already specifies: a history that agrees with the plan adds cost, not
information, and its length is earned only where the landing differed
or the plan left the location unnamed.

## Code and commit conventions

*   Code cites the deciding record where the decision shows, one line:
    `// (ADR-NNNN)`, `// (proposal NNNN)`.
*   Commit messages follow
    [conventional commits](/docs/styles/conventionalcommits.md), one
    one-line summary, with `(proposal NNNN)` naming the implemented
    proposal.
*   The implementing commit carries the code, the history entry, the
    ADR's status flip, and any annotations the landing narrows into
    earlier records — one commit, so the record never trails the code.
