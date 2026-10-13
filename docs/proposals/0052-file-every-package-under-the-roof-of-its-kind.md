# File every package under the roof of its kind

This proposal implements
[ADR-0018](/docs/adrs/0018-file-every-package-under-the-roof-of-its-kind.md):
the core and the libraries move beneath roofs of their own, `pkg/core` and
`pkg/libs`, beside `pkg/modules` and `pkg/apps`. The underlay vocabulary
leaves the data plane for a library, the bootstrap channel joins the core,
and both new roofs check their imports the way `pkg/modules` checks its
own. The walk helpers the roofs' checks copy become one test-support
package. No run argument, wire message, store format, or behavior changes:
code moves, and only import paths and three qualifiers change.

[TOC]

## Summary

`pkg/` holds two roofs and eleven flat packages. The engines
(`controlplane`, `dataplane`, `trust`) and the bootstrap channel (`webpki`)
sit beside the SCION vocabulary (`scion`, `segment`, `peeria`) and four
generic building blocks (`expiring`, `loops`, `ratelimit`, `statefile`).

Two edges cross the line ADR-0018 draws:

*   The SCION library imports the data plane for `BufferSize` and
    `ResolveAddrPort`, the applications' table
    ([wireguard.go](/pkg/apps/wireguard.go)) for `EndhostPort` and
    `ResolveAddrPort`, and ping ([pinger.go](/pkg/apps/ping/pinger.go)) and
    the measured provider
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)) for
    `EndhostPort`. `EndhostPort` lives in the port of
    upstream's underlay definitions ([defs.go](/pkg/dataplane/defs.go));
    the resolver and its private sibling `resolveLocalAddr` are CION's
    additions to the ported [udpip.go](/pkg/dataplane/udpip.go).
*   The bootstrap channel imports the trust engine and runs loops:
    `CertManager.Manage` and the HTTP-01 server
    ([tls.go](/pkg/webpki/tls.go)). The architecture overview lists it
    among the shared libraries ([architecture.md](/docs/design/architecture.md)).

The two roofs that exist check themselves with walk tests
([apps](/pkg/apps/walk_test.go), [modules](/pkg/modules/walk_test.go)),
and each test carries its own copy of the same helpers: the `go list`
reader, the directory walkers, and the import-path derivation, about a
hundred lines each.

## Motivation

ADR-0018 files every package by its kind and makes each roof's imports a
mechanical check. The moves are wide but mechanical; the edges, the checks,
and the overview are what make the roofs assert something.

### Goals

*   Every package under `pkg/` sits beneath the roof of its kind, at the
    paths ADR-0018's map lists.
*   No library imports a core package. The data plane's production
    importers are the control plane and the assembly.
*   `pkg/core` and `pkg/libs` each check their imports, and the core's walk
    asserts its enumeration. Each check proves it can fail.
*   The four roofs' checks share one copy of the walk helpers.
*   The architecture overview files the bootstrap channel with the core.

### Non-goals

*   No package is renamed, split, or merged, and no identifier changes but
    the three underlay symbols' qualifier.
*   No check of the libraries' no-loops rule: a goroutine scan would exempt
    `loops` and still miss a loop a dependency starts, as certmagic does
    for the bootstrap channel. Review keeps the rule.
*   `pathdb.Segment` stays in the path database's contract, so a library
    may import a module contract.
*   No landed record's body changes (ADR-0018, decision 7); ADR-0018's
    status line is the one edit.

## Proposal

### The underlay leaf

`pkg/libs/underlay` holds the facts of the UDP/IP network beneath SCION
that the data plane shares with its users:

*   [defs.go](/pkg/dataplane/defs.go), moved whole: the underlay types and
    `EndhostPort`, its package clause back to upstream's `underlay`.
*   `BufferSize`, from [packet.go](/pkg/dataplane/packet.go), whose
    `bufSize` alias reads it from the leaf.
*   `ResolveAddrPort`, and `ResolveLocalAddr`, the exported
    `resolveLocalAddr`: the data plane's links resolve a local address,
    whose host may be empty, through it.

The data plane, the SCION library, the applications' table, ping, the
measured provider, and the assembly import the leaf for the three symbols.

### The libraries' roof

`scion`, `segment`, `peeria`, `expiring`, `loops`, `ratelimit`, and
`statefile` move beneath `pkg/libs`. Their package names stay, so call
sites change nowhere; import paths change in every importer.

### The core's roof

`controlplane`, `dataplane`, `trust`, and `webpki` move beneath
`pkg/core`, with the test-support packages `trust/trusttest` and
`webpki/webpkitest`.

### The roofs' checks

Each new roof's root holds one test package and nothing else, as
`pkg/modules`'s does. Both read production imports from `go list`; test
imports are free.

*   **`pkg/core`:** the walk asserts that the roof's children are the four
    packages ADR-0018 names — ADR-0009's frozen enumeration as the tree's
    assertion. The import rule asserts that no core package imports an
    application, a module implementation, `internal/`, or `cmd/`.
*   **`pkg/libs`:** the import rule asserts that every import a library
    makes inside the module is a library or a module's contract root.

Fixtures prove each assertion can fail, as the modules roof's do.

`internal/walktest` holds the helpers the four roofs share: the module's
root, its package graph from `go list`, a directory's children and whether
it holds a package, the packages beneath a roof, and a directory's import
path. The applications' and modules' walk tests drop their copies for it.
Each roof keeps its own rules.

### Records and documents

ADR-0018 flips to accepted in the last commit, with this proposal's
history. The architecture overview's bootstrap channel moves from the
shared libraries to the node core, and the libraries gain the underlay.
The security model changes nowhere: no boundary, assumption, or control
moves with the code.

The change lands in four commits, each passing every check: the underlay
leaf; the libraries' moves; the core's moves; and the checks, the shared
helpers, the overview, the history, and the flip.

## Test plan

*   **Move fidelity:** every package's tests pass at its new path with
    import paths and the underlay qualifier as their only changes, and the
    integration labs pass unmodified — the behavior-neutral claim made
    testable.
*   **The underlay leaf:** `ResolveAddrPort` normalizes a v4-mapped address
    to IPv4 and refuses an empty host; `ResolveLocalAddr` resolves an
    empty host to any address.
*   **The core's walk:** the roof as landed passes with its four children;
    a fixture roof with a fifth child fails, and so does one whose root
    holds a production source file.
*   **The core's import rule:** the graph as landed passes; fabricated
    production imports of an application, a module implementation,
    `internal/services`, and `cmd/cion` each fail; a fabricated test
    import passes.
*   **The libraries' import rule:** the graph as landed passes; fabricated
    production imports of a core package, an application, a module
    implementation, and `internal/services` each fail; a module contract
    passes.
*   **The shared helpers:** the applications' and modules' walks pass on
    the tree and fail their fixtures as before.

## Implementation history
