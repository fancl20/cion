# File the node's seams as modules

This proposal implements
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md): the
node's seams move under one roof, `pkg/modules`, each filed as a module
— the contract at the module's root, the implementations one package
each beneath it, a shared contract suite every implementation runs, and
the kind declared in the module's own document. Three storage modules:
the trust, path, and link databases, whose discipline the record
extends rather than invents. One policy module: the enrollment
authorizer, its contract leaving the control plane to join the
implementations it selects among. One source module: the topology
machinery, promoted out of the applications namespace to the place the
record files it — the node's configuration source. The discipline
becomes mechanical, a walk of the roof and an import rule, where today
it holds by review alone. No wire, flag, store, or behavior changes:
the moves are the filing, and the tree learns to name what varies.

[TOC]

## Summary

What exists is a discipline without a roof. The three databases hold
their contracts at their package roots — [`trust.DB`](/pkg/trust/db.go),
[`pathdb.DB`](/pkg/pathdb/pathdb.go), and [`links.DB`](/pkg/links/links.go)
— and file their implementations beneath, a bbolt backend each, a
memory backend beside the link database's, and a
[contract suite](/pkg/links/impl/dbtest/dbtest.go) every backend runs.
Two seams break the shape. The enrollment authorizer's contract lives
with its consumer — `AdmissionAuthorizer` in
[admission.go](/pkg/controlplane/admission.go) — while its
implementations and its selection grammar live in `pkg/enrollauth`, a
package of their own: the shape inverted, defined by who calls it
rather than by what it is. And the topology provider sits inside the
applications namespace as flat files, one package holding the seam, the
measured provider, and the file provider together, under a roof
[ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)
fixes to resident services — which the provider is not.

Nothing enforces any of it. The databases' backends are imported by the
assembly and the test harness alone, but only because no contributor
has imported them elsewhere yet; a control-plane service could reach a
bbolt store tomorrow and nothing would object. And ADR-0009's
shared-library bucket holds two different things — vocabulary both
sides of the node's boundary speak, and seams where an implementation
could differ — filed together, the difference invisible in the tree.

This proposal lands the roof. Five modules: `trustdb`, `pathdb`, and
`links` of the storage kind, bound by the assembly; `enrollauth` of the
policy kind, selected by its spec grammar; `topology` of the source
kind, selected by its own arguments. The trust engine keeps `pkg/trust`
whole, the generation supervisor and the change signal stay the
assembly's, and the stores they sit beneath gain their visible home. A
walk asserts the roof's shape; an import rule asserts that
implementations are bound by the assemblies and the tests alone. The
architecture overview follows the code, its libraries split from its
modules.

## Motivation

ADR-0013 decided the filing; this proposal draws it in packages. The
ground is already prepared, seam by seam:

*   The databases have the shape. Contract at the root, one package per
    backend beneath, a suite every backend runs — the move is a change
    of roof, not of discipline, and the link database's memory backend
    is the second implementation the pattern already holds.
*   The authorizer's grammar already travels with its implementations.
    `enrollauth.Load` parses the `--enroll-auth` spec beside the
    constructors it selects among; the contract is the one piece filed
    on the wrong side of the tree, and it moves alone.
*   The source's interface is already the phase list. The `Provider`
    seam [proposal 0011](/docs/proposals/0011-minimal-node-core-and-topology-providers.md)
    landed — `CompleteIdentity` before the phases, `Wire` between them,
    `Seed` before the first data plane generation, `Mounts` into the
    endpoint, `Run` only after the binds, `Close` — is the interface
    ADR-0013 asserts, already synchronous at assembly per
    [proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)'s
    rule. Nothing new is asked of it; it moves and is restated.
*   The selection regimes already differ by kind, as the record's
    driver demands. Storage is bound in one place — `openState` in the
    assembly opens the three bbolt stores; policy is selected by a spec
    grammar the node validates at boot; the source is selected by
    arguments of its own. The filing follows selection that already
    exists; it forces nothing.

What remains is the roof itself, the two stragglers' moves, and the
checks — the pieces the tree cannot grow by accretion, because a roof
is a claim every tenant must satisfy at once.

### Goals

*   The roof: `pkg/modules`, one parent for every seam. Each module's
    contract at its root, its implementations one package each beneath,
    a shared contract suite every implementation runs, and the kind —
    storage, policy, or source — declared in the module's package
    document, where the walk can read it.
*   The storage modules: `trustdb`, `pathdb`, and `links` beneath the
    roof, their backends and suites moving with them. The trust engine
    stays whole in `pkg/trust`; the link database's memory backend
    becomes a peer implementation, the pattern rather than a private
    convenience.
*   The policy module: `enrollauth`, its contract moved from the
    control plane to the module's root, its implementations one package
    each beneath, and the spec grammar staying at the root beside them.
*   The source module: `topology`, promoted out of `pkg/apps` — the
    contract at its root, the measured and file providers one package
    each beneath, the package document restating what it is: the node's
    configuration source, not an application.
*   The walk: a test at the roof's root asserting the shape — every
    child of the roof a module, every module's kind declared, nothing
    beneath a root but implementations and the suite.
*   The import rule: the same test asserting that implementation
    packages are imported by the assemblies and the tests alone —
    composition-root exclusivity as a mechanical fact.
*   The documents: ADR-0013 accepted at landing; the architecture
    overview splitting its libraries from its modules; the security
    model unchanged, the filing moving no boundary.

### Non-goals

*   No behavior change to the moved machinery: constants, RPC shapes,
    admission rules, pacing, and reconciliation move verbatim, and the
    standing integration proofs must pass unmodified.
*   No new backends: no second production store is built, and no
    storage-selection argument grows — the run argument that names a
    backend arrives the day a second backend does, in the change that
    lands it.
*   No selection-semantics change: `--enroll-auth`, `--link-set`, and
    `--neighbor` stand exactly as they are — unset meaning open
    enrollment, the measured provider by default, the two sources
    refused together, the authorizer refused without `--core`.
*   No fetch contract beside the store: ADR-0013's sixth point is a
    refusal carried forward — no snapshot or watch API joins the source
    seam, which stays what it is: sources land decisions, the node
    reloads.
*   No generic module grammar: no registry, constructor table, or
    lifecycle type shared across kinds — ADR-0013's declined option
    stays declined.
*   No application-side work: the applications table is
    [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)'s
    to land through its own proposal; `pkg/apps` keeps the ping,
    WireGuard, coordination, and SOCKS applications; and the WireGuard
    directory store keeps the databases' discipline where it is — an
    application's own state is not a node seam, and the roof does not
    claim it.
*   No engine moves: verification and issuance stay `pkg/trust`;
    beaconing, the health monitor, and the generation supervisor stay
    with the node.
*   No wire, proto, or store-format change of any kind.
*   No lint configuration: the checks land as the tree's own tests; a
    golangci-lint rules file is ceremony this proposal does not add.

## Proposal

### The roof

`pkg/modules` is the node's pluggable surface, a namespace as `pkg/apps`
is — the one package it holds is the check that asserts it. Five
modules, each asserting one true thing:

| Module | Kind | What varies | Selection |
| :--- | :--- | :--- | :--- |
| `modules/trustdb` | storage | where trust material persists | bound by the assembly |
| `modules/pathdb` | storage | where segments persist | bound by the assembly |
| `modules/links` | storage | where the neighbor table persists | bound by the assembly |
| `modules/enrollauth` | policy | who is admitted, joiner or host | `--enroll-auth`, exactly one method |
| `modules/topology` | source | where topology decisions come from | `--neighbor` or `--link-set`, exclusive |

Each module's package document states its kind in its opening lines and
the selection the kind fixes beside it. The kind is prose the walk can
parse, not a type: a module changing kind is exactly the conversation
review should have, and the walk makes sure the conversation has
somewhere to read the current answer.

The kinds differ in weight — a storage module is one transactional
interface, the source module a lifecycle — and the roof files them
together anyway, because what they share is the claim: an
implementation could differ, and the tree says where it would land. A
second backend, a third authorizer method, a third controller: each has
an obvious home and a suite to pass before it exists.

### The storage modules

`pathdb` and `links` move whole: contract, types, backends, and suite
change roof and nothing else. `trustdb` is the one surgery. `pkg/trust`
today holds the engine beside the store — verification and issuance,
the signer, the renewal, the genesis — with the database contract in
[db.go](/pkg/trust/db.go) and the backend beneath `impl/`. The contract
and its implementations move to `modules/trustdb`; the engine stays
whole in `pkg/trust` and imports the module's root, taking
`trustdb.DB` where it took `trust.DB`. Engine and storage contract sit
under different roofs from the landing on — ADR-0013's accepted cost,
paid for the seam change that is visible as a seam change.

The link database's memory backend moves as a peer implementation, not
a test convenience: it runs the module's suite beside the bbolt
backend's run, and an embedding that prefers no state directory imports
it knowingly. It is not an operator choice — no argument grows, because
the assembly binds one production backend and the memory one is not it.

`openState` in the assembly stands as the place the three bind, unchanged
but for import paths: the composition root opens the bbolt stores under
the state directory, and after the move it imports them from the roof.
The integration harness (`internal/testnetwork`) binds the same
implementations for its in-process nodes and follows the same paths.

### The policy module

The contract moves to the module's root: `AdmissionAuthorizer`, with
the facts, verdicts, and boundaries it speaks, leaves
[admission.go](/pkg/controlplane/admission.go) and lands beside the
implementations in `modules/enrollauth`. The control plane keeps what
is the control plane's — the trust service that asks the question — and
imports the module's root to pose it; the coordination application
imports the same root for the registration boundary, and its import of
the control plane thins to what it truly consumes. The inverted
direction ends: today the implementations import the consumer for
their own contract; after the move the consumer and the implementations
meet at the module, and neither imports the other.

Beneath the root, one package per implementation — the CIDR authorizer
and the Telegram one — with `Load` and its `method=spec` grammar
staying at the root, where the selection vocabulary of the policy kind
lives. The authorizer's own loop — the Telegram poll — runs under the
node's supervision as it does today, selected and started by the
assembly.

The module gains the contract suite the databases' pattern demands: a
suite both implementations run, asserting the verdict vocabulary and
the fail-closed rule — a gate that cannot reach its signal denies. The
implementations' own suites keep their specifics; the shared suite
carries what the contract promises.

### The source module

The topology machinery is promoted out of the applications namespace.
The contract — `Provider` and `Pieces` — stays at the module's root,
already the phase list ADR-0013 asserts: identity completion before the
phases, wiring between them, seeding before the first data plane
generation, mounts into the endpoint, loops only after every bind has
succeeded, and close at the end. Beneath the root, one package per
implementation: the measured provider — taking the rendezvous acceptor,
the joiner's dials, the node directory, the in-band link service, and
the selection loop with it, machinery only it runs — and the file
provider beside it. The package document restates what the package is:
the source module of ADR-0013, the node's configuration source — what
it provides is not a service the node offers but the node's own inputs,
granted from outside — no longer the topology application of ADR-0009,
whose applications roof now holds services alone.

The reload machinery stays the node's, because no source owns it: the
store is the links module's, and the change signal and the generation
supervisor stay in the assembly,
[dataplane.go](/internal/services/dataplane.go) rebuilding the data
plane whatever wrote. The measured provider and the
file provider still differ only in the controller's pace, and a third
controller needs no core change — the promise read as a promise about
modules, now with a home for the third to land in.

Selection stands as it is: the measured provider by default, the file
provider when `--link-set` names a link-set, the two refused together,
the first-start neighbor requirement satisfied by either. The
applications list ADR-0014 will draw never names the source: it is
selected here, by arguments of its own.

### The walk and the import rule

Both checks land as one test package at the roof's root, and the roof's
root holds nothing else. The walk reads the tree: every child of
`pkg/modules` is a module; every module's root package declares its
kind in its document — one of storage, policy, source; nothing sits
beneath a root but implementation packages and the module's contract
suite; and every implementation runs the suite. The import rule reads
`go list`'s import graph: an implementation package is imported by the
assemblies — `internal/services` and `internal/testnetwork` — and by
tests, by no one else. What holds today by review alone becomes the
tree's own assertion, run with the tests.

The checkers prove themselves the way the machinery does, against
fixtures built to fail: a tree with a module whose kind line is missing,
a stray package beneath a root, an implementation outside `impl/`, and
a fabricated import from outside the allowlist each fail their
assertion, so the checks cannot silently pass on nothing. The compiler
keeps what it ever enforced — cycles and the one-way direction; what
review could not hold, the walk and the rule now do.

### Records, documents, and the boundaries

ADR-0013 flips to accepted in the implementing commit, its promises
mapped below. ADR-0009 and ADR-0010 stand as written — the packaging
split and the contract's new home are narrowings the new record carries
alone; a decision at its date, not a description of the tree as it
stands. The architecture overview follows the code: its shared-library
section slims to the vocabulary it names — the SCION library, segment
types, the bootstrap channel, peer identity — a modules section rises
beside it carrying the five with their kinds, and the neighbor table
and the path database, today named as core components, are named as
modules the core consumes, bound by the assembly. The topology bullet
leaves the applications list, and the overview's topology section
speaks the source. The security model changes nowhere: the filing moves
contracts and import paths, no boundary, assumption, or control — the
admission seam asks the same question at the same moments, from a root
of its own.

## Test plan

*   **Move fidelity:** the databases' contract suites pass at their
    new paths against every backend — bbolt each, the link module's
    memory beside its bbolt; the trust engine's suites pass against the
    module's contract; the rendezvous, link service, directory,
    selection, and file-provider suites pass in the source module; the
    integration proofs pass unmodified — `TestJoinByRendezvous`'s
    three-node network and `TestStaticLabByLinkSet`'s static one — the
    behavior-neutral claim made testable.
*   **The walk:** each assertion holds on the roof as landed — five
    modules, five kind declarations, nothing beneath a root but
    implementations and suites; the fixture tree fails each assertion
    in turn — a missing kind line, a stray package beneath a root, an
    implementation outside the implementations' place.
*   **The import rule:** the graph as landed passes — the assemblies
    and the tests the only importers of implementation packages; the
    fabricated import from outside the allowlist fails the check.
*   **The policy suite:** both authorizers run the module's contract
    suite — the verdict vocabulary, and the fail-closed rule: the CIDR
    authorizer denies a request carrying no address, the Telegram one a
    prompt it cannot send.
*   **The source's standing episodes:** first-start identity completion
    under either provider — the founding core's draw returning
    unchanged; seeding idempotent, before the first generation; the
    mounts behind the peer-identity middleware under the measured
    provider and none under the file provider — moved with the module,
    not rewritten.
*   **The run arguments:** the flag surface is unchanged — `--enroll-auth`
    parses and refuses without `--core`, `--link-set` refuses
    `--neighbor`, and no new argument exists for the parser to take;
    the standing argument tests pass with moved imports alone.

## Implementation history

*   The roof: `pkg/modules`, holding one test package alone —
    [walk_test.go](/pkg/modules/walk_test.go), the walk and the import
    rule. The walk reads the tree (kind line, `impl/` alone beneath a
    root, one package per implementation, suites exempt by name); the
    import rule reads `go list` (production importers of an
    implementation: `internal/services` and `internal/testnetwork`
    alone). Both prove themselves against fixtures built to fail beside
    the run on the roof as landed; the checks read the tree at run time,
    so a change elsewhere in the roof can be served from `go test`'s
    cache — the repo's `-count` discipline defeats it.
*   The storage modules: `links` and `pathdb` moved whole to
    [pkg/modules/links](/pkg/modules/links/links.go) and
    [pkg/modules/pathdb](/pkg/modules/pathdb/pathdb.go); the trust
    surgery split `pkg/trust` — the contract to
    [pkg/modules/trustdb](/pkg/modules/trustdb/trustdb.go) with the
    bbolt store and the suite beneath it, the engine whole in `pkg/trust`
    taking `trustdb.DB` where it took `trust.DB`. `openState` binds the
    three unchanged but for import paths.
*   The policy module's selector: **a divergence.** The plan kept `Load`
    and its grammar at the module's root, beside implementations filed
    one package each beneath — a shape Go forbids, for a root-level
    `Load` must import the implementations to construct them while they
    must import the root for `AdmissionFacts` and `AdmissionAnswer`: an
    import cycle. Per review, the grammar moved to the assembly —
    `loadEnrollAuth` in
    [internal/services/enrollauth.go](/internal/services/enrollauth.go),
    called by `Validate` and `setupEnrollAuth` — and the caller imports
    the implementation the spec names directly, `impl/cidr` and
    `impl/telegram`: the databases' own pattern, and the import rule's
    letter. The implementations are
    [cidr.Authorizer](/pkg/modules/enrollauth/impl/cidr/cidr.go) and
    [telegram.Authorizer](/pkg/modules/enrollauth/impl/telegram/telegram.go);
    the contract is
    [pkg/modules/enrollauth](/pkg/modules/enrollauth/admission.go), and
    the coordination application's import of the control plane is gone.
*   The suites: the policy module's contract suite is
    [impl/authtest](/pkg/modules/enrollauth/impl/authtest/authtest.go) —
    the zero verdict denying, the fail-closed rule under facts each
    implementation cannot decide. The source module gained its own,
    [impl/providertest](/pkg/modules/topology/impl/providertest/providertest.go),
    the walk's "every implementation runs the suite" made real: the
    founding core's draw returning unchanged, seeding idempotent before
    the first generation.
*   The source module: the contract at
    [pkg/modules/topology](/pkg/modules/topology/topology.go); the
    measured provider and its machinery in
    [impl/measured](/pkg/modules/topology/impl/measured/provider.go)
    (`measured.Provider`, `measured.Config`); the file provider in
    [impl/file](/pkg/modules/topology/impl/file/provider.go)
    (`file.Provider`, `file.Config`, `file.WatchInterval`).
    `selectProvider` in the assembly selects as before, importing both
    implementations directly.
*   The records: ADR-0013 accepted; the architecture overview split — a
    modules section carrying the five with their kinds, the neighbor
    table and the path database named as modules the core consumes, the
    topology and enrollment-policy bullets leaving the applications
    list, the topology section speaking the source. The security model
    unchanged.
