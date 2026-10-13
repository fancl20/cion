# File Every Package Under the Roof of Its Kind

*   Status: accepted
*   Date: 2026-10-13

[TOC]

## Context and problem statement

[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
cut the tree into a frozen core, shared libraries, and applications, and
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md) split the
shared libraries into libraries, pure vocabulary that cannot vary, and
modules, the seams that can. The records name four kinds — engines are core,
vocabulary is libraries, seams are modules, services are applications — each
roof asserting one true thing. Two of the kinds have a roof: `pkg/apps` and
`pkg/modules` each hold one kind and check it with a walk of the roof and an
import rule. The core and the libraries sit flat beside them, eleven
packages: three engines (`controlplane`, `dataplane`, `trust`), the
bootstrap channel (`webpki`), three pieces of SCION vocabulary (`scion`,
`segment`, `peeria`), and four generic building blocks (`expiring`, `loops`,
`ratelimit`, `statefile`). A reader learns which is which from prose — the
complaint ADR-0009 began with.

The flat list also hides two edges the records' rules cannot see. Four
packages outside the core — the SCION library, the applications' table,
ping, and the measured provider — import the router for three underlay
facts: the end-host port, the buffer size, and the address resolver. And
the bootstrap channel calls itself a library, yet it runs a
certificate-maintenance loop and an HTTP-01 server, which ADR-0009 says a
library never does. No rule names what a core package or a library may
import, so nothing reports either.

This ADR decides where the core and the libraries live and what their roofs
assert.

## Decision drivers

*   **The Tree Names Its Contents:** ADR-0009's founding complaint, applied
    once more — each kind the records name is a directory listing.
*   **Boundaries That Check Cheaply:** ADR-0013's driver — what a package may
    import is a mechanical find, not a judgment call.
*   **The Core Reviews Against the Drafts:** the core reads as the SCION
    subset CION implements — the data-plane, control-plane, and PKI drafts.
*   **Package Names Carry the Meaning:** the style guide's rule — the package
    name matters more for readability than the path, and a package is named
    for what it provides, not `util` or `common`.
*   **Mechanical Moves:** no wire, flag, store, or behavior change; the code
    moves, and only its import paths and qualifiers change.

## Considered options

*   **Four Roofs:** `pkg/core` and `pkg/libs` beside `pkg/modules` and
    `pkg/apps`, one roof for each kind the records name.
*   **Five Roofs:** four roofs, the libraries split into SCION vocabulary and
    a roof of generic helpers.
*   **Upstream Component Names:** scionproto's top-level split — `router`,
    `control`, a PKI package, an end-host package.
*   **A Helpers Roof Alone:** the four generic building blocks under one roof,
    everything else flat.
*   **One Helpers Package:** the four generic building blocks merged into a
    single package.

## Decision outcome

Chosen option: **four roofs** — realized as follows:

1.  **Every package under `pkg/` sits beneath the roof of its kind.**
    *   `pkg/core`, the engines — what every node runs: the data plane, the
        border router of the data-plane draft; the control plane, the
        control service of the control-plane draft; trust, the control-plane
        PKI of the PKI draft; and webpki, the bootstrap channel.
    *   `pkg/libs`, the libraries — shared by core and applications, no
        loops of their own, no policy: the SCION library, segment, peeria,
        the underlay leaf, expiring, loops, ratelimit, and statefile.
    *   `pkg/modules`, the seams, as ADR-0013 filed them.
    *   `pkg/apps`, the applications, as
        [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)
        filed them.

    A test-support package moves with the package it supports. This narrows
    the packaging of ADR-0009, whose core lists its packages by path, and of
    ADR-0013, whose engines stayed where they were; the boundaries both
    records drew stand as written.
2.  **The core's roof keeps the records' name.** `core` is ADR-0009's node
    core, which every AS runs, not SCION's core AS: the founding and
    authoritative cores run the same core as every other node, and
    `cion run core` selects a role, not a roof.
3.  **The generic building blocks are libraries, each its own package.** They
    pass ADR-0009's test — shared, no loops of their own, no policy — and
    stay small packages named for what they provide: the roof is a
    namespace, the package name the meaning. A merged helpers package would
    rename every call site and hand every importer every dependency, bbolt
    included.
4.  **The underlay vocabulary leaves the data plane.** `EndhostPort`,
    `BufferSize`, and `ResolveAddrPort` move to `pkg/libs/underlay`, with the
    port of upstream's `private/topology/underlay` definitions that holds the
    first — upstream keeps them as a package of their own. The data plane
    imports the leaf, and its production importers are the control plane and
    the assembly alone.
5.  **The bootstrap channel is core.** webpki realizes
    [ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md)'s
    WebPKI-anchored core endpoint: the certificate the founding core's
    control endpoint presents, kept current by a maintenance loop, and the
    client a fresh node verifies it with. Enrollment cannot begin without
    it. It is the one core package the drafts do not specify.
6.  **The roofs check mechanically.** Each new roof's root holds its check
    alone, as `pkg/modules`'s does, and the checks read production sources:
    *   a core package imports libraries, module contracts, and core
        packages — never an application, a module implementation,
        `internal/`, or `cmd/`;
    *   a library imports libraries and module contracts only. The SCION
        library reads `pathdb.Segment` from the path database's contract, so
        a library may import a module contract.
7.  **The landed records stand as written.** Their links into moved
    directories resolve at the records' own commits; the map below
    translates them at HEAD.

| Before | After |
|---|---|
| `pkg/controlplane` | `pkg/core/controlplane` |
| `pkg/dataplane` | `pkg/core/dataplane` |
| `pkg/trust`, `pkg/trust/trusttest` | `pkg/core/trust`, `pkg/core/trust/trusttest` |
| `pkg/webpki`, `pkg/webpki/webpkitest` | `pkg/core/webpki`, `pkg/core/webpki/webpkitest` |
| `pkg/scion` | `pkg/libs/scion` |
| `pkg/segment` | `pkg/libs/segment` |
| `pkg/peeria` | `pkg/libs/peeria` |
| `pkg/expiring` | `pkg/libs/expiring` |
| `pkg/loops` | `pkg/libs/loops` |
| `pkg/ratelimit` | `pkg/libs/ratelimit` |
| `pkg/statefile` | `pkg/libs/statefile` |
| `EndhostPort`, `BufferSize`, `ResolveAddrPort`, and the underlay definitions in `pkg/dataplane` | `pkg/libs/underlay` |

### Positive consequences

*   `pkg/` lists the kinds, and `pkg/core` lists the review surface the
    drafts describe.
*   Every package's imports are checked against its kind: four roofs, four
    rules, where two held before.
*   The applications' walk test says an application imports "the core and
    the libraries"; both now name directories.
*   The SCION library, the applications, and the measured provider stop
    depending on the router.
*   New shared code has an obvious home and a rule to pass before it lands.

### Negative consequences

*   A wide mechanical change: 102 Go files move, about 230 import lines
    change in about 120 files, and every branch in flight rebases across it.
*   148 links in 20 landed records name paths that no longer exist at HEAD;
    a reader translates them with the map.
*   "Core" keeps two meanings in one tree: the node core this roof holds,
    and SCION's core AS that `cion run core` makes a node.
*   Every import path into the core and the libraries grows a segment.
*   The roofs are not a strict stack: a library may import a module
    contract while `pathdb.Segment` lives in the path database's contract,
    and that contract imports a library.

## Pros and cons of the options

### Four roofs

*   Good, because each roof asserts one thing the records already name, and
    the tree and the records share one vocabulary.
*   Good, because the checks are cheap walks of known roots, the shape
    `pkg/modules` already runs.
*   Bad, because it moves every core and library package at once.

### Five roofs

*   Good, because SCION vocabulary and generic helpers separate at a glance.
*   Bad, because the records name no fifth kind: both pass the library test,
    and their import rules would read the same.

### Upstream component names

*   Good, because a reader of scionproto finds `router` and `control` where
    upstream keeps them.
*   Bad, because it renames packages, not only paths: every call site
    changes, and the records' vocabulary goes with them.
*   Bad, because upstream splits by binary, and CION runs the border router
    and the control service in one node.

### A helpers roof alone

*   Good, because it is small: 34 import lines.
*   Bad, because the core and the SCION libraries stay flat and unchecked,
    and the hidden edges stay hidden.

### One helpers package

*   Bad, because the style guide rules out names like `util`: call sites
    lose the package name that said what they use.
*   Bad, because it ties unrelated dependencies together: a loop's pause
    would link bbolt.
*   Bad, because it removes no concept; the four ideas stay four.
