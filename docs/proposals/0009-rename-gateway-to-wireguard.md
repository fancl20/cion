# Rename the gateway to WireGuard

This proposal renames what [proposal
0006](/docs/proposals/0006-wireguard-gateway-application.md) landed and
[proposal 0007](/docs/proposals/0007-gateway-service-addressing.md) kept
calling "the gateway" to what it is: the WireGuard application. WireGuard
does not need to be the only gateway in the system, so its name stays at the
application level — every system-level seam that today references the
application by the role it happens to hold alone says `wireguard` instead,
and "gateway" returns to being a common noun. The rename changes no
behavior, and nothing deployed carries the old names: the same freedom
proposal 0007's renumbering already banked.

[TOC]

## Summary

The SCION service value `SvcGateway` becomes `SvcWireguard` and the mesh
endpoint string becomes "isd-as,wireguard"; the numeric value stays `0x7ff1`
and `SvcDirectory` keeps name and value, both already scoped by the
application's package. The protobuf moves from `proto/gateway/v1` to
`proto/wireguard/v1` with package `wireguard.v1`, regenerated with the pinned
plugins. The node assembly's `setupGateway`, its `gateway` field, and the
configuration's `gateway:` section become `wireguard` forms — a stale
`gateway:` section stops parsing, the rename made visible to operators. The
application type `wireguard.Gateway` becomes `wireguard.App`, the pure
app-level name, and the log strings, doc comments, and the test harness's
identifiers follow.

## Motivation

Proposal 0006 named the application after the role it held alone: the node
configuration's `gateway:` section, `ConfigGateway` and the node assembly's
`setupGateway` and `gateway` field, the SCION service value `SvcGateway`
with its "isd-as,gateway" endpoint string, and the protobuf package
`gateway.v1` naming the application's own directory API. Every seam
references the application by a role, not a name — and nothing about the
system requires WireGuard to be the only thing filling that role. A second
gateway application, another overlay or tunnel serving hosts the same way,
would find the role word claimed: its operators would write a `gateway:`
section that is not theirs, address a `gateway` service that is not its
socket, and read "the gateway" in logs and comments that mean WireGuard.

The fix is naming, not architecture: the application's own name belongs to
the application level, and the seams that reference it carry that name. The
rename is mechanical because the codebase already agrees on the destination —
the application lives in `pkg/apps/wireguard` — and cheap because the old
names exist nowhere outside the repository.

### Goals

*   Rename the SCION service: `SvcGateway` becomes `SvcWireguard`, the name
    table's "gateway" becomes "wireguard", and the mesh endpoint string is
    "isd-as,wireguard"; the value `0x7ff1` stays, and `SvcDirectory` keeps
    its name and value — the constants' package already names the
    application.
*   Move the protobuf: `proto/gateway/v1` becomes `proto/wireguard/v1`, the
    package `gateway.v1` becomes `wireguard.v1`, the Go packages
    `gatewayv1`/`gatewayv1connect` become `wireguardv1`/`wireguardv1connect`,
    regenerated with the pinned plugins; `buf.gen.yaml`'s comment follows.
*   Rename the node assembly's wiring: `internal/services/gateway.go` becomes
    `wireguard.go`, `setupGateway` and `parseGatewayConfig` take `Wireguard`
    forms, the node's `gateway` field and its background-service name follow.
*   Rename the node configuration's section: `gateway:` becomes `wireguard:`,
    `ConfigGateway`/`ConfigGatewayPeer` become
    `ConfigWireguard`/`ConfigWireguardPeer` — a stale `gateway:` section is
    refused at configuration, not silently ignored.
*   Rename the application type: `wireguard.Gateway` becomes
    `wireguard.App`, the name of the thing itself rather than its role, the
    way the node assembly's `App` names a node booted for an application; log
    strings and doc comments follow, and the test harness's identifiers —
    `GatewayOptions`, `NodeConfig.Gateway`, `startGateway`, the
    `GatewayPublish`/`GatewayRefresh`/`GatewayRetry` cadence, and the
    integration proofs' `TestGateway*` names — take `Wireguard` forms.

### Non-goals

*   A generic gateway abstraction: no interface, plugin registry, or
    applications framework. This is naming only; a second gateway
    application proposes its own seams when it exists.
*   Rewriting the historical proposals and ADRs — they are records of the
    words their moment used, and their links and quotes keep working.
*   The application-internal vocabulary that names the application's parts
    rather than the application: the mesh, the shared host-facing port, the
    overlay subnet, the exits, the egress.
*   The SCION service values on the wire, the store's JSON shape, and the
    socket lifecycle — renamed names, not numbers or behavior.

## Proposal

### The service value and its names

`SvcGateway` (`0x7ff1`) becomes `SvcWireguard`; the name table the IPC
endpoint string reads maps "wireguard" to it, so a peer's configured mesh
endpoint is "isd-as,wireguard" and `ParseEndpoint` refuses "gateway" as an
unknown name — an operator's stale endpoint fails at configuration, the same
place an unparseable one always did. `SvcDirectory` (`0x7ff2`) keeps its
name and value: the directory is the application's own service, and the
constant's package, `pkg/apps/wireguard`, already carries the application's
name. The registration callbacks (`RegisterSvc`/`UnregisterSvc`) name no
application and stay.

### The protobuf

The directory API is the application's own surface; its home becomes
`proto/wireguard/v1` with package `wireguard.v1`, the Go packages
`wireguardv1` and `wireguardv1connect`, regenerated with the pinned plugins
the module's `buf.gen.yaml` names. The ConnectRPC procedure paths move with
the package — `wireguard.v1.DirectoryService/...` — and the message full
names likewise; nothing is deployed, so no compatibility shape remains. The
store's bbolt bucket and JSON keys never carried the package name and do not
move.

### The node assembly and its configuration

`internal/services/gateway.go` becomes `wireguard.go`;
`setupGateway`/`parseGatewayConfig` become `setupWireguard`/
`parseWireguardConfig`; the node's `gateway` field becomes `wireguard` of
type `*wireguard.App`, and the background service's name follows. The node
configuration's section becomes `wireguard:` with
`ConfigWireguard`/`ConfigWireguardPeer`; a configuration still naming
`gateway:` stops parsing — the rename's one operator-visible edge, honest
rather than silently accepted. The testnetwork harness follows:
`GatewayOptions` becomes `WireguardOptions`, `NodeConfig.Gateway` becomes
`NodeConfig.Wireguard`, `startGateway` becomes `startWireguard`, and the
integration proofs run as `TestWireguardMeshExchange` and
`TestWireguardEgressProxiesInternet`.

### The application type and its vocabulary

`wireguard.Gateway` becomes `wireguard.App`: inside the package named
wireguard, the type names the thing itself, and every qualified reference —
the node's field, the harness's `Node.Gateway`, the tests' locals — reads as
the application rather than leaning on the role word. The log strings
follow ("Serving the WireGuard application", "WireGuard mesh tunnel up"),
as do the doc comments that say "the gateway" where they mean the
application — `pkg/apps/wireguard`'s package doc, the counters, the keys,
the directory's entries, and the control plane's pointer to "the gateway's
directory client" among them. The test helpers' names
(`newTestGateway`, `parseGatewayOf`, `gatewayNodeConfig`) and the import
alias `gatewaybbolt` take `Wireguard`/`wireguard` forms.

## Test plan

*   **Unit tests:** the endpoint string's round trip over
    "isd-as,wireguard", with "gateway" among the malformed names refused at
    configuration; the service-registration and directory assertions under
    the renamed constants; the configuration decoding of the `wireguard:`
    section beside the refusal of a stale `gateway:` one.
*   **Integration tests:** proposal 0006's proofs re-run unchanged in
    behavior under their new names — the nodes publish and fetch through the
    core's directory service, mesh handshakes ride it, and the host-to-host
    echo and internet egress carry as before.
*   **Negative tests:** a stale `gateway:` section and a stale "gateway"
    endpoint name are both refused at configuration.
*   **The acceptance gate:** `git grep -i gateway` over the module returns
    only the historical records — `docs/proposals` and `docs/adrs` — beside
    the one place the word must remain by necessity: the store's
    legacy-shape test, whose proposal-0006 JSON keys are the history it
    tests.

## Implementation history
