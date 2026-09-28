# Select the resident applications by name

This proposal implements
[ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md):
the resident applications become entries in one closed table at the
applications roof's root — each entry carrying its name, its own run
arguments, its role bounds, the applications it requires, and a
constructor that adapts the node's environment into its configuration —
and one run argument selects them: `--applications`, unset to keep the
inference the run arguments already practice, empty to run the
deliberate core, given to load exactly the names it lists, every
miscombination refusing the boot with the fix named. The assembly's
four per-application touches — the setup phase, the HTTPS mount, the
starts, the reverse closes — become walks over the table's order, and a
fourth resident costs the assembly nothing. The WireGuard port argument
leaves the node configuration for its entry, the SOCKS application's
wait for its assigned slice moves from the assembly into the
application's own serving, and the roof gains the walk and the import
rule its sibling already holds. No resident changes behavior; no wire,
store, or socket moves.

[TOC]

## Summary

What exists is selection by inference, one key per application, and an
assembly that touches each resident four times. The WireGuard
application loads when the shared host port is nonzero — zero the
explicit refusal
([wireguard.go](/internal/services/wireguard.go)); the coordination
application loads when the core's WireGuard application did, the
directory store whose shape implies the service
([coordination.go](/internal/services/coordination.go)); the SOCKS
application assembles beside the WireGuard application whose router it
borrows, one publication later, when the directory's assignment arrives
([socks.go](/internal/services/socks.go)). Each key costs the assembly
the same four touches: a setup function of its own called from
setupNode's phase list, a branch in the HTTPS mount
([https.go](/internal/services/https.go)), a block in the starts, and a
slot in the reverse closes whose borrow orderings the comments carry by
hand ([node.go](/internal/services/node.go)). The loading argument
itself — `--wireguard.host-port` — registers in a command helper and
writes a field of the node configuration
([run.go](/cmd/cion/run.go), [config.go](/internal/services/config.go)):
an application's story told in three places, none of them the
application's.

This proposal lands the table and the argument. The root of
[pkg/apps](/pkg/apps) — the roof [proposal
0026](/docs/proposals/0026-file-the-nodes-seams-as-modules.md) left a
namespace beside `pkg/modules` — gains its root package: the entry, the
environment, the seam, and the closed list of the three residents.
`--applications` selects: unset, every application whose role bounds
hold, requirements load, and required arguments are present — the
zero-conf default unchanged; given, exactly the listed, in table order
whatever order the list spells; given empty, none — the deliberate core
at last a stated shape rather than an accident of unset arguments. The
assembly walks the loaded: setup after the node's phases, the HTTPS
handler from whichever residents contribute one, the starts under the
node's supervision, release in reverse — the borrow orderings structural
in the table's order rather than hand-maintained in the closes. Adding
an application adds a package and an entry, and touches the assembly
not at all.

## Motivation

ADR-0014 decided the selection and the seam; this proposal draws them
in packages. The ground is prepared, fact by fact:

*   Each resident is already a selectable unit — its own package under
    the roof, its own keys and state directory, `New`, `Run`, and
    `Close` its own lifecycle — and its borrows already ride narrow
    seams the owner exports: the coordination application takes the
    directory registry, the SOCKS application the router and the
    assigned slice
    ([app.go](/pkg/apps/wireguard/app.go),
    [directory.go](/pkg/apps/wireguard/directory.go)).
*   The assembly's walk points already exist: setupNode ends in the
    applications' phases, assembleHTTPS mounts a mux
    ([https.go](/internal/services/https.go)), start launches loops
    under runBackground's absorbed panics, and Close releases in
    reverse ([node.go](/internal/services/node.go)) — four walks in
    search of a list to walk.
*   The refusals have house precedent: Validate's role-aware checks
    refuse the misleading configuration naming the fix — the provider
    mixture, the authorizer off the core
    ([config.go](/internal/services/config.go)) — loud misconfiguration
    refused in the assembly's own idiom already.
*   The roof's check has precedent: [pkg/modules](/pkg/modules)
    asserts its shape and import rule from one test package at its root
    ([walk_test.go](/pkg/modules/walk_test.go)); the closed table wants
    the same two assertions, and the application packages already
    satisfy them — nothing under the roof imports the assembly or the
    harness in production sources today.

What remains is what the tree cannot grow by accretion: the table
itself, the list argument, the walks over the entries, and the check
that keeps the table closed — the pieces that must land at once for any
of them to hold.

### Goals

*   The table: [pkg/apps](/pkg/apps)'s root package holds the entry —
    name, run arguments' registration, role bounds, requirements,
    constructor — the environment, the seam interface, and the closed
    list in the order the borrows need: wireguard first, its borrowers
    after.
*   The argument: `--applications`, repeatable, comma-separated,
    registered beside the placement three on both run commands and
    ping, its help carrying the three regimes — unset infers, empty
    runs none, given loads exactly.
*   The refusals: an unknown name naming the residents, a role
    violation naming the role, a broken requirement naming the missing
    application, a named application whose required argument is refused
    naming the argument to give — all where Validate checks today,
    before any assembly runs.
*   The walks: setup, mount, start, and release over the loaded in
    table order; setupWireguard, setupCoordination, serveSocks, the
    coordination branch of the HTTPS mount, the starts block, and the
    hand-ordered closes delete, and the node struct's per-application
    fields retire for the loaded list.
*   The arguments' homes: the WireGuard entry registers
    `--wireguard.host-port` — spelling, default, help, and part-block
    order unchanged — and the field leaves the node configuration; each
    constructor adapts the environment into its application's own
    configuration, the core's store opening and the relay derivations
    moving with it.
*   The check: the walk and the import rule at the applications roof's
    root, on the pattern [pkg/modules](/pkg/modules/walk_test.go)
    set — the closed table and the one-way direction made mechanical.
*   The records: ADR-0014 accepted at landing; the architecture
    overview's applications section gains the selection.

### Non-goals

*   No new application, no new arguments beyond the list, and no
    behavior change to any resident: the same constructors, stores,
    sockets, and supervision — a panicked loop absorbed and logged,
    nothing restarted, ADR-0009's consequence carried unchanged.
*   No dynamic loading: the table is closed at build; an operator's own
    application needs a build and a release — the single-binary
    decision's cost, restated where it becomes visible.
*   No selection for the source module: the topology machinery never
    enters the list — ADR-0014's fifth point — and `--topology.link-set`
    and `--topology.neighbor` stand exactly as they are.
*   No enable or disable flags, no aliases, no grouping mechanism: the
    list is the whole surface; two flags answering one question is the
    semantics ADR-0014 declined.
*   No netmap change: a withheld exit's address rides the map
    unanswered — the map lists addresses, not offers, and the offering
    narrows where the offering lives.
*   No store, wire, or proto change of any kind.

## Proposal

### The table

[pkg/apps](/pkg/apps) gains its root package, holding the entry, the
environment, the seam, and the table itself — nothing else. The entry
carries the five facts ADR-0014 names: the application's name; the
registration of its own run arguments, a function over a flag set run
when the command builds its surface — the flags exist when the command
is built, the application when the node assembles, and the registration
belongs to the entry, not to the interface; its role bounds; the
applications it requires beside it; and its constructor, which takes
the environment and the loaded entries and returns the application. The
table is one slice literal in table order — wireguard, coordination,
socks — the order the borrows need, the owner first and its borrowers
after, which is the reverse of the release. The application packages
import the core and the libraries and nothing above them — not the
assembly, not the harness, not the roof's own root; the seam is
satisfied structurally, an interface no implementation needs to import,
and the cycle the ownership forbids is a cycle Go itself would refuse.

The environment is the node's facts the constructors adapt: the
identity and role, the state root, the control host, the domain, the
trust engine and path provider, the sending conn and the interface-down
cache, the service-socket registration, the admission authorizer, the
core route the joiner's directory fetch rides, the relay derivation's
inputs with the harness's placement among them, and the directory
pacing — everything wireguardConfig, relayPresence, and
setupCoordination read today
([wireguard.go](/internal/services/wireguard.go),
[coordination.go](/internal/services/coordination.go)). The loaded
entries come beside it: that is where the borrows resolve.

The seam is the assembly's three surfaces at the interface the entries
return: `Run` under the node's supervision, `Close` in the release
walk, and the handler the node's HTTPS server mounts — nil where an
application mounts nothing, coordination the one contributor today. The
service sockets stay the applications' own registrations through the
environment's callback, the mesh socket and the core's directory
service exactly as today
([app.go](/pkg/apps/wireguard/app.go)); the control endpoint's mux
remains the assembly's, held open for the day a resident needs it.

### The list argument

`--applications` — repeatable, comma-separated — registers beside the
placement three, so each command's help reads the frame, the
composition, then the part blocks. It stays bare under [proposal
0031](/docs/proposals/0031-namespace-the-run-arguments-by-the-part-they-affect.md)'s
rule because the rule's axes say it must: a prefix names a part, and
the list names no part — it selects among them, the composition beside
the role that [proposal
0027](/docs/proposals/0027-split-the-run-command-by-the-nodes-role.md)
made a command. Three regimes:

*   **Unset, the inference stands.** An application loads when its role
    bounds hold, every application it requires loads, and its required
    arguments are present. The WireGuard application's required
    argument is the shared port's nonzero value — the 51820 default
    loads it, zero the explicit refusal — coordination loads on the
    core beside it, SOCKS beside it wherever it loads. A restart needs
    no argument it did not need before, and the zero-conf default
    serves hosts unasked.
*   **Given, exactly the listed load**, in table order whatever order
    the list spells. Four refusals, each naming the fix, each checkable
    where Validate checks the provider mixture today
    ([config.go](/internal/services/config.go)): an unknown name
    answers with the residents' names; a role violation names the role
    the application requires; a broken requirement names the missing
    application — SOCKS without the router it borrows, coordination
    without the registry; the WireGuard application named with the port
    refused names the argument to give. Requirements never imply:
    nothing silently loads beside the list, and nothing silently skips.
*   **Given empty, none load**: on the core, the deliberate node that
    serves the drafts' services and nothing else; on any node, the pure
    forwarder — a shape the inference regime could only approximate by
    arguments left unset. Under ACME the challenge-only server stands
    as assembleHTTPS already builds it; under static files with nothing
    mounted, the port stays unbound
    ([https.go](/internal/services/https.go)).

The unset-versus-empty distinction is load-bearing at the argument, and
the flag's help carries it: nil is the inference, the empty value the
deliberate none — the one subtlety ADR-0014's negative consequences
charge this surface with, paid where it is incurred.

### The residents

| Entry | Own arguments | Requires | Role bounds |
| :--- | :--- | :--- | :--- |
| `wireguard` | `--wireguard.host-port` (nonzero to load) | — | any node |
| `coordination` | — | `wireguard` | the core alone |
| `socks` | — | `wireguard` | any node |

**wireguard** registers `--wireguard.host-port` — the spelling,
default, and help the command's helper carries today
([run.go](/cmd/cion/run.go)); the flag's destination becomes the
entry's own arguments, and the field leaves the node configuration. The
constructor adapts the environment as wireguardConfig does today: the
control host, the relay presence from the domain, the application's
state directory, the core's directory store opened in the constructor
or the joiner's core route, the pacing riders
([wireguard.go](/internal/services/wireguard.go)). No requirements, no
role bound: any node serves hosts.

**coordination** is core-only — the role bound the entry carries and
the refusal names on any other node — and requires wireguard, whose
registry it borrows through the owner's exported interface: the borrow
resolves at assembly from the loaded entries, and the requirement's
check has already made the missing case a refused boot rather than a
failed assertion. The constructor adapts the environment as
setupCoordination does today: the domain, the registry, the admission
authorizer, the relay advertisement, the state directory, the harness's
relay-only posture
([coordination.go](/internal/services/coordination.go)).

**socks** requires wireguard, whose router and assigned slice it
borrows — the one resident whose construction is a publication's
answer, not a boot's fact. The borrow resolves at assembly with the
rest; the wait moves home. The application's own serving waits for the
assignment and claims the slice's first address when it arrives, the
wait serveSocks holds today
([socks.go](/internal/services/socks.go)) deleting with the function —
assembled one publication later than the WireGuard application's own,
exactly as it is today, the application's package gaining what the
assembly held. [Proposal
0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)'s
application lands as an entry and never knows the assembly.

### The assembly over the table

setupNode ends in the walk: resolve the selection, then construct in
table order, the environment built once from the node's phases and the
loaded entries growing as the constructors return. assembleHTTPS asks
the loaded for handlers instead of the coordination field; start walks
the loaded under runBackground; Close releases the loaded in reverse
table order, the two borrow comments deleted with the fields they
annotated — the order they hand-maintained is the table's now. The
node struct's wireguard, coordination, and socks fields retire for the
loaded list ([node.go](/internal/services/node.go)), and the booted
application's typed accessor retires with them: the loaded set is
reachable by name through the table's type
([app.go](/internal/services/app.go)), the harness asserting the
concrete application where the labs watch host peers — the same
assertion the borrowing entries make. The commands register the
entries' arguments by walking the table, the command's wireguard helper
deletes ([run.go](/cmd/cion/run.go)), and ping keeps the same node
surface as the run commands, its own application never an entry — the
client that boots a node, not a resident a node runs.

### The roof's check

One test package at the applications roof's root, asserting what
[pkg/modules](/pkg/modules/walk_test.go) asserts for its own roof: the
walk reads the tree — every child of pkg/apps is a resident with an
entry in the table, or the ping application, the command's own client;
the import rule reads the import graph — no application package's
production sources import anything above the roof, the one-way
direction ADR-0009 drew made mechanical. The checks prove themselves
against fixtures built to fail, as the modules' walk does; review keeps
the table closed, and the walk counts it.

### Records, documents, and the boundaries

ADR-0014 flips to accepted in the implementing commit, its five points
mapped to the episodes below. ADR-0009 stands as written — its sixth
point's assembly-owned sockets are the seam these walks carry, and its
loadable components gain their loading regime; the
topology-as-default-application narrowing already lives in ADR-0013.
ADR-0012 stands: proposal 0024 landed its service as a unit that record
can select, and the selecting record now exists without touching the
map's form. The architecture overview follows the code: its
applications section names the closed table and the list's three
regimes, and its endhost section's every-node-an-exit gains the two
words the default earns — by default. The security model
changes nowhere: the list is an operator surface over offers, not a
trust boundary — the asymmetric-failure control already carries what a
resident's death does, and the deliberate core is that same shape taken
at the boot instead of the crash.

### Compatibility

No spelling retires: the list is a new argument, and the entries'
arguments keep theirs — `--wireguard.host-port` among them, the
registrar moving home while the surface stands still. Unset, every boot
loads what it loads today: the zero-conf default, the zero refusal, the
ping command's node alike. The harness builds the node configuration
directly and keeps building it — the host port moves to the entry's
arguments, one field's new home; the list stays unset; the inference
loads what the labs load today. [Proposal
0031](/docs/proposals/0031-namespace-the-run-arguments-by-the-part-they-affect.md)
landed first, so the entry registers on the spelling it fixed, and
nothing beyond the one flag composes the two.

## Test plan

*   **The table's shape:** the walk holds on the roof as landed — three
    residents, three entries, ping exempt by name — and the fixture
    tree fails it: a package without an entry, an entry without its
    package. The import rule holds — no application's production
    sources import above the roof — and the fabricated import fails it.
*   **The surfaces:** `--applications` parses on both run commands and
    ping into the node configuration's list, nil against the empty
    value; the entries' flags register from the table —
    `--wireguard.host-port` in its part block, spelling and default
    unchanged — and each command's help reads the placement three, the
    list, then the part blocks.
*   **The regimes:** unset infers — the 51820 default assembles
    wireguard and socks, the refused port assembles neither, the core's
    default adds coordination; given loads exactly — `wireguard` alone
    serves hosts with no SOCKS offer; given empty assembles none.
*   **The refusals:** an unknown name answers with the residents'
    names; `coordination` on the local command names the core role;
    `socks` alone and `coordination` alone name `wireguard`;
    `wireguard` beside the refused port names the argument to give —
    each before any assembly runs, at Validate.
*   **The seam:** the HTTPS mount walks the loaded — the bind, no-bind,
    and wildcard-refusal episodes keep their shapes
    ([https_test.go](/internal/services/https_test.go)) — and the
    service sockets register through the environment, the WireGuard
    configuration episodes moving home with the constructor
    ([wireguard_test.go](/internal/services/wireguard_test.go)).
*   **The lifecycle:** the table orders whatever order the list spells
    — `socks,wireguard` assembles wireguard first — and the labs'
    teardowns pass with the release in reverse, the borrow orderings
    structural.
*   **The proofs:** the standing labs pass — the rendezvous join, the
    static link-set, the coordination and admission labs, the SOCKS
    near and far exits — the harness renamed by one field and asserting
    the concrete applications where it watches host peers. Two shapes
    gain their first episodes: the deliberate core, an empty list
    enrolling a joiner over the control endpoint and binding no
    application surface; and the withheld offer, a host's flow to a
    withheld exit dying unroutable at the node that withholds it.

## Implementation history
