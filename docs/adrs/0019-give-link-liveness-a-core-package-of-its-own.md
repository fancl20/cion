# Give Link Liveness a Core Package of Its Own

*   Status: accepted
*   Date: 2026-10-14

[TOC]

## Context and problem statement

[ADR-0018](/docs/adrs/0018-file-every-package-under-the-roof-of-its-kind.md)
filed the core as four packages: the data plane, the border router of the
data-plane draft; the control plane, the control service of the
control-plane draft; trust, the control-plane PKI of the PKI draft; and the
bootstrap channel.
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
enumerates one more core item beside the data plane and the control
endpoint: "the BFD sessions on every serving link and the health monitor
that reduces their arrivals to ADR-0008's verdicts — liveness owed by every
node however its topology is decided". The sessions implement the
data-plane draft's liveness (Section 6.1), not the control-plane draft's
mechanism, and upstream keeps its sessions in a package of their own beside
the border router (`router/bfd`). Yet they live in the control plane's
package.

They touch nothing else there, and nothing there touches them: the
beaconer reads their verdicts through a function. They are the control
plane's only reason to import the data plane, the neighbor table, gopacket,
and SCION's header layers. [Proposal 0055](/docs/proposals/0055-file-the-pki-procedures-with-the-trust-engine.md)
moved the PKI procedures out of the package and deferred the next split.

This ADR decides where link liveness lives.

## Decision drivers

*   **The Tree Names Its Contents:** each core item the records enumerate is
    a package a reader can find.
*   **The Core Reviews Against the Drafts:** the control plane's package
    reads against the control-plane draft alone, and liveness against the
    data-plane draft's Section 6.1.
*   **Upstream Ports Stay Close to Upstream:** every production file of the
    data plane is a port of the upstream router.
*   **Mechanical Moves:** identifiers keep their names, and no behavior
    changes.

## Considered options

*   **A Fifth Core Member, `liveness`:** the sessions and the monitor in
    `pkg/core/liveness`.
*   **A Fifth Core Member, `bfd`:** the same package under the draft
    section's and upstream's name.
*   **Into the Data Plane:** the sessions and the monitor beside the router.
*   **Stay Put:** liveness remains in the control plane's package.

## Decision outcome

Chosen option: **a fifth core member, `liveness`** — realized as follows:

1.  **The BFD sessions and the health monitor move to `pkg/core/liveness`,
    together.** The monitor keeps one session per serving link across data
    plane generations and runs the sessions' lifecycle itself. The
    identifiers keep their names.
2.  **The core has five members:** the data plane, the control plane,
    liveness, trust, and the bootstrap channel. This narrows ADR-0018's
    first decision; the core walk's enumeration follows it.
3.  **The seam with the data plane stays as it is.** A session implements
    the data plane's `Session`, the flag its egress check reads, and sends
    its frames through the link's `RawWriter`; liveness imports the data
    plane, never the reverse.
4.  **The data plane's production importers become liveness and the
    assembly.** This narrows ADR-0018's fourth decision, which named the
    control plane and the assembly.
5.  **The landed records stand as written.** The map below translates
    their links at HEAD.

| Before | After |
|---|---|
| `pkg/core/controlplane/bfd.go` | `pkg/core/liveness/bfd.go` |
| `pkg/core/controlplane/monitor.go` | `pkg/core/liveness/monitor.go` |

### Positive consequences

*   Each core item ADR-0009 enumerates has a package, and the control
    plane's reviews against its draft alone.
*   The control plane's package stops importing the data plane, the neighbor
    table, gopacket, and SCION's header layers.
*   Liveness's tests stand alone: they share no fixture with the control
    plane's.

### Negative consequences

*   A fifth member: the core walk's list, the architecture overview, and a
    reader's map of the core change.
*   The assembly's and the labs' references change their package
    qualifier.

## Pros and cons of the options

### A fifth core member, `liveness`

*   Good, because it maps ADR-0009's enumeration item one to one, under the
    word the records use, as upstream gives its sessions a package.
*   Good, because no identifier changes.
*   Bad, because it adds a member to name, check, and review.

### A fifth core member, `bfd`

*   Good, because it carries the draft section's and upstream's name.
*   Bad, because the identifiers would stutter — `bfd.BFDSession` — or
    change.

### Into the data plane

*   Good, because the core keeps four members.
*   Bad, because it adds CION's own code and the neighbor table to a
    package of upstream ports, where upstream keeps the sessions apart.
*   Bad, because the monitor outlives every data plane generation the
    package builds.

### Stay put

*   Good, because nothing moves.
*   Bad, because the control plane's package keeps a mechanism of the
    data-plane draft and the imports only it needs.
