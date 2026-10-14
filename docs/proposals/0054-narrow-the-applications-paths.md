# Narrow the applications' paths

This proposal carries
[proposal 0053](/docs/proposals/0053-narrow-the-topology-providers-environment.md)'s
narrowing to the applications roof. The path provider the table's
environment hands its residents, the one the WireGuard application's
configuration takes, and the one the ping application's configuration takes
arrive as interfaces of the methods each consumer calls, each declared by
its own contract. The fields take the name 0053 gave the topology
provider's, `Paths`. No run argument, wire message, store format, or
behavior changes.

[TOC]

## Summary

The table's environment carries the node's path provider as
`*scion.PathProvider` ([apps.go](/pkg/apps/apps.go)). The WireGuard entry
hands it to the application's configuration
([wireguard.go](/pkg/apps/wireguard.go)), and the ping command hands the
node's to the ping application's
([ping.go](/cmd/cion/ping.go)).

The consumers call few of its methods. The WireGuard application calls
`Enumerate` when it warms its mesh routes
([directory.go](/pkg/apps/wireguard/directory.go)) and `LocalPath` in its
mesh socket ([bind.go](/pkg/apps/wireguard/bind.go)) and its directory
client ([directoryclient.go](/pkg/apps/wireguard/directoryclient.go)). The
ping application calls `Path`
([pinger.go](/pkg/apps/ping/pinger.go)).

The concrete type lets a resident reach every method of the node's path
provider, and leaves a test or another caller to build the provider where a
contract could name the method it needs: proposal 0053's reasons, on the
roof beside the topology provider's.

## Motivation

The applications' contracts should state what their consumers call of the
node's paths, as the topology provider's now does.

### Goals

*   Each contract names what its consumers call of the node's path
    provider: the table's environment and the WireGuard configuration
    `Enumerate` and `LocalPath`, the ping configuration `Path`.
*   The WireGuard application's mesh socket and directory client declare
    the `LocalPath` they call.
*   The fields read as the topology provider's: `Paths`.

### Non-goals

*   The engine stays `*trust.Engine`, and the WireGuard application's
    `Engine` alias with it, for proposal 0053's reason: the directory's
    channel hands it to `controlplane.NewSCIONClient`.
*   The interface-down cache stays `*scion.InterfaceDownCache`.
*   No shared interface: each contract declares its own, as proposal 0053's
    did.

## Proposal

### The environment

`apps.Environment.Paths` is an `apps.Paths`, declared beside the
environment: `Enumerate` and `LocalPath`. The assembly hands it the node's
path provider ([applications.go](/internal/services/applications.go)).

### The WireGuard application

`wireguard.Config.Paths` is a `wireguard.Paths`: `Enumerate` and
`LocalPath`. The route warm-up calls the first. The mesh socket and the
directory client take an interface of `LocalPath` alone, declared beside
them.

### The ping application

`ping.Config.Paths` is a `ping.Paths`: `Path`. The command and the labs hand
it the node's path provider, or one over a crafted database, as they do
today.

The change lands in one commit.

## Test plan

*   **Fidelity:** the applications' tests, the ping labs, and the WireGuard
    labs pass with the rename as their only change: the narrowing removes no
    method a consumer calls.
*   **The narrowing:** the assembly's environment, the table's WireGuard
    entry, and the command's ping configuration are the checks that the
    node's path provider satisfies each contract; the labs that hand ping a
    provider over a crafted database compile against `ping.Paths`
    unchanged.

## Implementation history

*   Landed in one commit, as planned: `apps.Paths` beside the environment
    ([apps.go](/pkg/apps/apps.go)), `wireguard.Paths` beside the
    configuration ([app.go](/pkg/apps/wireguard/app.go)), `localPaths` once
    for the mesh socket and the directory client
    ([bind.go](/pkg/apps/wireguard/bind.go)), and `ping.Paths`
    ([pinger.go](/pkg/apps/ping/pinger.go)).
*   The mesh socket and the directory client hold the interface as
    `resolver`: the socket already names its path cache `paths`.
*   The route tests set the lookup of the provider their fixtures built, so
    they reach it through two helpers that assert the concrete type,
    `providerOf` and `appProvider`
    ([route_test.go](/pkg/apps/wireguard/route_test.go)).
