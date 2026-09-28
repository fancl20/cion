# File the Node's Seams as Modules

*   Status: accepted
*   Date: 2026-09-27

[TOC]

## Context and problem statement

[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
cut the tree three ways — a frozen core, shared libraries, applications — on
the complaint that the packages had stopped naming their contents. Half of
what that record filed under shared libraries already carries a discipline
the other half lacks. The trust, path, and link databases each define their
contract at the package root and file implementations beneath it: a bbolt
store each, a memory store beside the link database's, and a shared contract
suite every backend runs — the shape of a seam. Two seams break the shape.
The enrollment authorizer's contract lives with its consumer in the control
plane while its implementations live in a package of their own — the shape
inverted, defined by who calls it rather than by what it is. And the
topology provider sits inside the applications namespace with both its
implementations as flat files, under a roof this record's companion
([ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md))
fixes to resident services, which the provider is not.

Nothing enforces the discipline the three databases follow. Only review
keeps a control-plane service from importing a backend directly, and
nothing in the tree answers the question a reader most needs asked: which
parts of this node vary, and who decides their implementation? The
databases are bound by the assembly and selected by no one. The authorizer
is selected by an operator's argument
([ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)).
The provider is selected by arguments of its own. Three species of seam —
and behind them, ADR-0009's shared-library bucket quietly holds two
different things: vocabulary both sides of the node's boundary speak,
which cannot vary without a protocol change, and seams where an
implementation could differ, which exist to. Filing them together hides
the difference the tree most needs to show.

This ADR decides how the node's seams are filed and what the filing
asserts. The application side is [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)'s;
the topology machinery's place is decided here, as this record's largest
narrowing.

## Decision drivers

*   **The Tree Names Its Contents:** ADR-0009's founding complaint, applied
    to the seams — the tree should say what varies and what cannot, without
    prose beside it.
*   **Boundaries That Check Cheaply:** a violation should be a mechanical
    find — a shape walk, an import rule — not a judgment call review might
    miss.
*   **One Composition Root:** concrete implementations bind in one place;
    no service reaches around a contract to the code behind it.
*   **Mechanism over Policy:** engines stay with the core; what varies is
    the seam beneath them, and the seam alone.
*   **Selection Belongs to the Kind:** storage is the assembly's to bind,
    policy and sources the operator's to select; the structure must not
    force one selector on all three.
*   **Single Binary:** modules are in-process packages behind Go
    interfaces; [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)'s
    rejection of the external plugin stands.

## Considered options

How the seams are filed:

*   **Convention at the Root:** the databases' discipline extended to the
    two stragglers, no new roof.
*   **One Roof of Modules:** the seams move under a single parent — the
    contract at each module's root, implementations beneath it, the species
    declared.
*   **A Generic Module Abstraction:** one registration grammar — name,
    constructor, perhaps lifecycle — every seam speaks.

Where the topology machinery sits:

*   **First Application:** the provider enters the applications list as its
    richest resident.
*   **The Source Module:** the provider is the node's configuration source
    — a species of seam, not a service.

## Decision outcome

Chosen options: **one roof of modules** and **the source module** —
realized as follows:

1.  **Every seam is a module.** The contract lives at the module's root;
    implementations live beneath it, one package each; a shared contract
    suite runs against every implementation, the databases' existing
    pattern. The roof is the node's pluggable surface — countable at a
    glance, so that the answer to "what can vary" is a directory listing.
    A second implementation has an obvious home and a suite to pass before
    it exists.
2.  **Each module declares its kind, and the kind fixes selection.**
    *Storage* is bound by the composition root — the assembly alone
    imports implementations, and a run argument names a backend the day a
    second one exists. *Policy* is the operator's — exactly one
    implementation, selected by a spec grammar, the enrollment authorizer
    the resident example. *Source* is the configuration plane, selected by
    its own arguments. The kind lives in the module's own documentation; a
    module changing kind is exactly the conversation review should have.
3.  **The discipline checks mechanically.** A walk of the roof asserts the
    shape; an import rule asserts that concrete implementations are
    imported by the assembly and the tests alone — what today holds by
    review alone. The compiler still enforces only what it ever did,
    cycles and the one-way direction; the roof's contribution is that what
    review cannot hold, a lint can.
4.  **The taxonomy narrows.** Shared libraries split into libraries — pure
    vocabulary that cannot vary — and modules, the seams that can. This
    narrows
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)'s
    packaging; the boundary that record drew — the frozen core
    enumeration, mechanism versus policy, apps through the assembly —
    stands as written. The engines stay where they are: verification and
    issuance are the drafts' mechanism, core whatever store sits beneath
    them, and a storage contract moving to its module leaves the engine
    whole in its own package.
5.  **Topology is the source module.** This narrows ADR-0009's "the
    topology machinery of ADR-0008 is an application — the measured
    provider — loaded by default." What the provider provides is not a
    service the node offers but the node's own inputs: configuration,
    granted from outside. A node cannot author its own name in the
    namespace or its own edges in the graph — a joiner's ISD-AS is
    provisional until the network completes it, and a link exists when
    something outside the node vouches for or measures it. The store, the
    change signal, and the generation supervisor are the reload machinery:
    sources write, the node rebuilds — one mechanism every source feeds
    and no source owns. The measured provider and the file provider differ
    only in the controller's pace, the network's measurements against an
    operator's edits, and a third controller needs no core change —
    ADR-0009's promise about providers, read as a promise about modules.
6.  **No fetch contract beside the store.** A configuration source that
    only served snapshots would fit the vouched end of the spectrum and
    fail the measured one: the measured source's next configuration
    includes a link that has not happened yet — a stranger who will dial
    the rendezvous socket an hour from now — so the source must run loops
    and serve admission, and its memory is the store itself, its loops
    reading back the facts they recorded. A snapshot seam would stand up a
    second source of truth beside the one ADR-0009 froze. The seam stays
    as it is: sources land decisions, the node reloads.
7.  **The source's interface is the node's phase list.** Identity
    completion before the phases — a joiner has no name until the source
    grants one; wiring after the phases build what the loops consume;
    seeding before the first data plane generation; mounts into the
    assembly's endpoint; loops only after every bind has succeeded. Binds
    are synchronous at assembly so a failure refuses the boot — the
    discipline
    [proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)
    bought back from racing goroutines. A source that started its own
    loops at construction would hide one interface word and pay the node's
    invariants for it — a partially assembled node already serving, and
    failures logged where they must refuse. Declined.

### Positive consequences

*   The pluggable surface is countable: the roof is the inventory, and a
    reader learns what varies from the tree rather than from prose.
*   Second implementations get a home and a contract suite; the link
    store's memory backend stops being a private convenience and becomes
    the pattern.
*   Composition-root exclusivity becomes a lint, not a hope.
*   The three seam species stop blurring: engines are core, vocabulary is
    libraries, seams are modules, services are applications — each roof
    asserting one true thing.
*   Topology's rich lifecycle is explained by its kind — configuration
    precedes the thing configured — instead of carried as the applications
    namespace's exception.

### Negative consequences

*   The trust engine and its storage contract sit under different roofs,
    and every seam change becomes a visible cross-package edit. Also the
    point — a seam change reviewable as such — but the cost is real.
*   A roof, a shape walk, and an import rule to maintain; the compiler
    enforces none of the shape.
*   Operators meet selection vocabularies beside the applications list —
    the source's arguments and the policy's grammar — the cost of
    selection semantics that travel with kind rather than one knob for
    everything.
*   The moves touch more than the assembly: the authorizer's contract
    leaves the control plane, and the databases' importers follow their
    contracts — mechanical, but wide.

## Pros and cons of the options

### Convention at the root

*   Good, because the discipline already exists where it matters most, and
    the two stragglers are small moves.
*   Good, because no new roof means no new claim to maintain.
*   Bad, because the inventory stays implicit: nothing in the tree
    distinguishes a package that could vary from one that cannot.
*   Bad, because composition-root exclusivity stays a review hope; the
    rules worth enforcing have no place to be checked against.

### One roof of modules

*   Good, because the roof asserts one true thing — a seam with
    implementations, kind declared — and every tenant satisfies it.
*   Good, because enforcement gets cheap: shape walks and import rules
    against a known root.
*   Good, because it gives the seam species their names — storage, policy,
    source — where readers meet them.
*   Bad, because it costs moves pure convention would not ask for: the
    authorizer's contract, the databases, the provider's promotion.
*   Bad, because a roof is a claim: kept honest, it constrains where new
    code may land, and every addition asks which roof first.

### A generic module abstraction

*   Good, because one registration grammar is uniform in the strong
    sense.
*   Bad, because the species differ in what they need — storage a
    transactional contract, policy a synchronous ask, the source a
    lifecycle — and one grammar either grows every module's needs into
    every other's interface or forbids them.
*   Bad, because a framework absorbs the boundary review should see.

### First application

*   Good, because one list would answer every what-runs question.
*   Good, because the provider already satisfies an application's shape —
    mounts, loops, close.
*   Bad, because the list would select not a service but a way of being
    configured — the confusion the kinds exist to prevent — and its
    default entry is one no deliberate combination omits anyway.
*   Bad, because the provider's assembly moments — before the name,
    before the first generation — would become every application's
    interface, or an exception inside the table.

### The source module

*   Good, because it files the machinery by what it provides —
    configuration — and the kinds carry its selection.
*   Good, because the applications list stays a list of services, none of
    them a mode of the node's own formation.
*   Bad, because topology keeps a lifecycle richer than a storage
    module's, and the kinds differ in weight even under one roof.
