# Select Resident Applications by Name

*   Status: accepted
*   Date: 2026-09-27

[TOC]

## Context and problem statement

[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
made applications loadable components of one process, serving through the
assembly's mechanisms. What loads today is decided by inference from other
arguments: the WireGuard application when its configuration file is named,
coordination when the core's WireGuard application loaded, the provider by
arguments of its own. Each application costs the assembly four times over
— a setup phase, the HTTPS mount, the starts, the reverse closes — and
the pattern has already bred one fork that
[proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)
retired at cost: the core's TLS path, keyed on an application's presence.
[Proposal 0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)
lands SOCKS beside the WireGuard application — borrowing its router as
coordination borrows its store — and retires the application's
configuration file into run arguments, which would key presence on a third
field and hand-wire the fourth resident.

[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md)
twice pointed past itself rather than decide this: "the offer's surface,
which applications a node runs," belongs to "the applications architecture
record to come," and
[proposal 0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)
lands its service as "a unit that record can select," deciding "nothing
about selection itself." This is that record.

What an application is has sharpened since ADR-0009 drew the boundary:
a resident service a formed node runs for its hosts — assembled after the
node exists, offering surfaces through the assembly.
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md) names the
other half of the boundary: the node's inputs arrive through modules, the
configuration source foremost. Applications are the node's outputs. This
record decides how the combination of applications is selected, and
through what seam they assemble.

## Decision drivers

*   **Almost-Zero Config:** the default boot loads what its arguments
    already imply; an operator who wants a deliberate combination names
    the whole list once.
*   **Loud Misconfiguration:** a named application that cannot load
    refuses the boot, naming what it needs — the same role-aware refusal
    the run arguments already practice. Nothing silently skips, and
    nothing implicitly loads.
*   **The Assembly Owns the Sockets:** applications contribute handlers
    and register service sockets; no internet-facing listener of their
    own, per
    [proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)'s
    rule. Identity, ports, and the bind decision stay the node's.
*   **One Place Answers "What Can a Node Be":** the residents and their
    combinations are enumerable by reading one table.
*   **Single Binary:** residents are in-process; no dynamic loading, now
    or later — ADR-0009's rejection of the external plugin stands.
*   **Stable Seam:** a new application follows the resident ones from day
    one, mounting through the surfaces the assembly already owns.

## Considered options

How the combination is selected:

*   **Presence-Keyed Inference:** an application loads when its own
    arguments are given — the status quo's direction.
*   **Name-Keyed Selection:** one run argument carries the list — unset,
    empty, or explicit.
*   **Defaults with Overrides:** additive enable and disable flags over
    the inferred default.

What assembles an application:

*   **Assembly Glue:** the node assembly builds each application's
    configuration itself — today's shape.
*   **The Closed Table:** one aggregate holds the seam and the residents'
    entries; each application keeps its own configuration, and its entry
    adapts the node's environment into it.
*   **Self-Registration:** applications register themselves at init; the
    binary imports them blank.

## Decision outcome

Chosen options: **name-keyed selection** and **the closed table** —
realized as follows:

1.  **Applications are entries in one closed table.** Each entry carries
    the application's name; its own run arguments, registered by the entry
    — flags exist when the command is built, the application when the node
    assembles, and the registration belongs to the entry, not to the
    interface; a constructor that adapts the node's environment into the
    application's own configuration; the applications it requires beside
    it; and its role bounds, a core-only application refused on any other
    node. The application packages import nothing above them; the table
    imports them; the assembly imports the table. Adding an application
    adds a package and an entry, and touches the assembly not at all.
2.  **Selection is the list argument.** Unset, every application whose
    required arguments are present loads — the zero-conf default keeps
    inference as its regime, and a restart needs no argument it did not
    need before. Given, exactly the listed applications load: an unknown
    name, an application whose required arguments are missing, a role
    violation, or a broken requirement refuses the boot naming the fix.
    Given empty, none load — the deliberate core that serves the drafts'
    services and nothing else, a shape the inference regime could only
    approximate by arguments left unset. Requirements never imply:
    naming coordination without the WireGuard application whose registry
    it borrows is an error, not a silent load. Explicit combinations,
    loudly validated.
3.  **The seam is the assembly's three surfaces**, carried from ADR-0009
    and proposal 0023: handlers on the control endpoint, behind the
    peer-identity middleware; handlers on the node's HTTPS server, which
    presents the identity and answers the challenge beside them; and
    service sockets registered with the data plane's generations.
    Applications hold their own keys and their own state directory, and
    send through assembly-provided connections. One application may
    borrow another's machinery through the narrow interface the owner
    exports — coordination the directory store, SOCKS the router —
    resolved at assembly, where a missing capability refuses the boot.
    Proposal 0024's application lands as an entry and never knows the
    assembly.
4.  **Lifecycle is table order.** Setup in table order, after the node's
    phases; loops under the node's supervision at start — a panic
    absorbed and logged, nothing restarted, ADR-0009's consequence carried
    unchanged; release in reverse order, so the borrow orderings the
    hand-maintained closes carry as comments become structural.
5.  **The topology machinery is not an application** and never enters the
    list: it is [ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)'s
    source module, selected by its own arguments. The default node is the
    core, the measured source, and every service whose arguments are
    present — and the applications list governs the last clause alone.

### Positive consequences

*   The presence-keyed forks stop multiplying: enabling is one mechanism,
    not one per application, and the fourth resident costs the assembly
    nothing.
*   The bare core becomes a stated shape rather than an accident of unset
    arguments — labs and minimal forwarders get it deliberately.
*   Deliberate combinations are validated: broken requirements and role
    violations answer at boot with the fix named, not at runtime with a
    missing surface.
*   Proposal 0024 lands into the shape it presumed — a unit this record
    selects.
*   The seam is small and named: a new application follows the WireGuard
    application's path from day one.

### Negative consequences

*   Two regimes to document — inference when unset, exact when given —
    and the unset-versus-empty distinction is load-bearing at the
    argument; the flag's documentation carries it, or operators will trip
    on it.
*   The table is closed: an operator's own application needs a build and
    a release, not an argument — the single-binary decision's cost,
    restated where it becomes visible.
*   Supervision is unchanged: a panicked application loop is absorbed and
    logged, nothing restarts it, and a resident that exits takes its
    surface silently from the node's offer.
*   The default regime keeps inference: an operator must still know that
    setting an application's argument loads the application — the very
    implicitness the list exists to remove, preserved for the zero-conf
    claim.

## Pros and cons of the options

### Presence-keyed inference

*   Good, because zero config survives with no new surface at all, and
    each application's arguments are its own story.
*   Bad, because every application adds an inference, and inferences fork
    the assembly — the TLS fork proposal 0023 retired is the pattern's
    cost, already paid once.
*   Bad, because combinations have no expression: the bare core, the
    core without a tailnet, the forwarder that serves nothing — none can
    be asked for.

### Name-keyed selection

*   Good, because one argument answers every combination question, and
    its errors are checkable at parse: unknown names, missing
    requirements, role violations.
*   Good, because the default rides free — unset is the inference regime,
    kept deliberately rather than replaced.
*   Bad, because two regimes now exist, and the empty-versus-unset edge
    is subtle at a list-valued argument.

### Defaults with overrides

*   Good, because each change is local — enable this, disable that — and
    no one writes whole lists.
*   Bad, because two flags answer one question, and their composition is
    a semantics to define, document, and defend.
*   Bad, because the result is not readable from the command line alone
    without replaying the inference it claims to override.

### Assembly glue

*   Good, because it is today's shape and needs no new concept.
*   Bad, because every application touches the assembly four times, and
    the touches are where the forks breed.
*   Bad, because the assembly learns every application's configuration
    grammar — the dependency that keeps a resident from moving.

### The closed table

*   Good, because one place enumerates the residents, and the assembly
    shrinks to phases over a list.
*   Good, because the entries own their arguments, so an application's
    configuration lives with the application.
*   Bad, because it is a structure to hold: the entries must not reach
    up, the table must import them all, and review keeps the table
    closed.

### Self-registration

*   Good, because adding a resident is one package and one import, and no
    table to edit.
*   Bad, because the residents become implicit — the binary's behavior
    depends on its import list, and "what can a node be" is answered by
    grep rather than by reading.
*   Bad, because init-time registration hides ordering, and ordering is
    load-bearing in both directions the lifecycle cares about.
