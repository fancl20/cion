# Narrow the topology provider's environment

This proposal narrows the topology seam's contract, the source module
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md) files: what
`Wire` hands a provider stops naming three of the core's types. The peer
client, the path provider, and the link latencies arrive as interfaces of
the methods a provider calls, and the carrier takes the applications' name
for the same role, `Environment`. The measured provider's components
declare the narrower subsets they call. No run argument, wire message,
store format, or behavior changes.

[TOC]

## Summary

`Wire` delivers `topology.Pieces`
([topology.go](/pkg/modules/topology/topology.go)): the node's completed
ISD-AS, its link store, its peer client, its path provider, its trust
engine, its health monitor's verdicts, and its link latencies. Four of the
seven are core types: `*controlplane.PeerClient`, `*scion.PathProvider`,
`*trust.Engine`, and `*controlplane.LinkLatency`.

A provider calls few of their methods. The measured provider's link client
calls the peer client's `VerifiedClient`
([provider.go](/pkg/modules/topology/impl/measured/provider.go)); its
selection loop calls the path provider's `Path` and `Enumerate` and the
latencies' `Record`
([selection.go](/pkg/modules/topology/impl/measured/selection.go)); its
directory client calls the path provider's `LocalPath` and hands the engine
to the control endpoint's client machinery
([directory.go](/pkg/modules/topology/impl/measured/directory.go)). The file
provider reads the ISD-AS and the store alone.

The concrete types let a provider reach every method of the core's
components, make a component's test build the real ones, and leave a third
provider to meet the core's types where the contract could name the few
methods it needs. The applications' table hands its residents the same
kind of carrier under another name, `apps.Environment`.

## Motivation

The contract should state what a provider may use, in the methods it calls,
and read as its sibling contract does.

### Goals

*   The contract names what a provider may use of the node's peer client,
    path provider, and link latencies: the methods the measured provider
    calls.
*   Each of the measured provider's components declares the subset it
    calls.
*   The carrier reads as the applications' does: `topology.Environment`.

### Non-goals

*   The trust engine stays `*trust.Engine`: the directory's channel hands it
    to `controlplane.NewSCIONClient`, whose TLS reads the engine's chain,
    key, and anchor pool, so an interface would reach into the core's client
    machinery and give the provider nothing.
*   No change to `apps.Environment`, which carries the engine and the path
    provider the same way.
*   No change to `Wire`'s moment among the phases, or to the ISD-AS, the
    store, or the verdicts, which are already a value, an interface, and a
    function.
*   The contract keeps importing the core, for `controlplane.Mount` and the
    engine.

## Proposal

### The environment

`topology.Environment` replaces `Pieces`, and the provider's method becomes
`Wire(Environment)`. Its fields:

*   `IA`, `Store`, `Engine`, and `Verdicts`, as they are.
*   `Peer`, a `PeerChannel`: the node's channel to its peers, whose
    `VerifiedClient` is the client of its mutually verified side.
*   `Paths`, a `Paths`: the node's path resolution, `Path`, `Enumerate`, and
    `LocalPath`. The field is renamed from `Provider`, which the package's
    own provider interface already names.
*   `Latencies`, a `LatencyRecorder`: `Record` receives a link's one-way
    delay estimate.

The contract declares the three interfaces beside the environment. The
node's peer client, path provider, and link latencies satisfy them as they
are, and the assembly builds the environment from them unchanged
([controlplane.go](/internal/services/controlplane.go)).

### The measured provider

*   The link client holds a `topology.PeerChannel`.
*   The selection loop's configuration takes its paths as an interface of
    `Path` and `Enumerate`, declared beside it, and its latencies as a
    `topology.LatencyRecorder`.
*   The node directory's configuration takes its paths as an interface of
    `LocalPath`, declared beside it.

The provider's own fields and the file provider's follow the rename.

### Records and documents

The landed records that name `Pieces` stand as written. The change lands in
one commit.

## Test plan

*   **Fidelity:** the provider contract suite, the measured and file
    providers' tests, and the integration labs pass with the rename as their
    only change: the narrowing removes no method a provider calls.
*   **The narrowing:** the assembly's construction of the environment is the
    check that the node's components satisfy the contract; the measured
    configurations' fields accept the same components, so the selection and
    directory tests run on them unchanged.

## Implementation history

*   Landed in one commit, as planned: the environment and its three
    interfaces in the contract ([topology.go](/pkg/modules/topology/topology.go)),
    and the measured configurations' `Paths` fields taking `SelectionPaths`
    ([selection.go](/pkg/modules/topology/impl/measured/selection.go)) and
    `DirectoryPaths`
    ([directory.go](/pkg/modules/topology/impl/measured/directory.go)),
    each declared beside its configuration.
