# File link liveness under its own core package

This proposal implements
[ADR-0019](/docs/adrs/0019-give-link-liveness-a-core-package-of-its-own.md):
the BFD sessions and the health monitor move from `pkg/core/controlplane`
to `pkg/core/liveness`, the core's fifth member. Identifiers keep their
names, the seam with the data plane stands, and no run argument, wire
message, store format, or behavior changes.

[TOC]

## Summary

The control plane's package holds the link liveness ADR-0009 enumerates as
a core item of its own: the BFD sessions
([bfd.go](/pkg/core/controlplane/bfd.go)) and the health monitor that keeps
one per serving link across data plane generations
([monitor.go](/pkg/core/controlplane/monitor.go)), 537 lines with 648 of
tests. Nothing else in the package uses them, they use nothing else in it,
and their tests share no fixture with the package's other tests. The
assembly builds the monitor and reads its verdicts
([controlplane.go](/internal/services/controlplane.go),
[node.go](/internal/services/node.go),
[app.go](/internal/services/app.go)), and one lab reads the transmission
interval ([join_test.go](/internal/testnetwork/join_test.go)).

## Motivation

ADR-0019 gives liveness a package, so the control plane's reviews against
the control-plane draft alone and liveness against the data-plane draft's
link failure detection.

### Goals

*   The sessions and the monitor live in `pkg/core/liveness`, with their
    tests.
*   The core walk enumerates five members.
*   The control plane's package no longer imports the data plane, the
    neighbor table, gopacket, or SCION's header layers.

### Non-goals

*   No identifier changes, and no change to the data plane's `Session` and
    `RawWriter`, which the sessions implement and send through.
*   The transport and beaconing splits stay undecided.

## Proposal

`bfd.go`, `monitor.go`, and their tests move to `pkg/core/liveness` as they
are, the tests internal to the package, for they read its unexported
state. The package's document states what it runs: a BFD session per
serving link, and the monitor that keeps the sessions across generations
and reduces their arrivals to a verdict per interface. The assembly and
the lab change their references' package qualifier.

The core walk's members gain `liveness`, its document lists five members,
and its fixture's extra child stays a non-member. The architecture
overview gives liveness its own bullet in the node core, out of the control
endpoint's. ADR-0019 flips to accepted.

The change lands in one commit.

## Test plan

*   **Fidelity:** the sessions' and the monitor's tests pass in
    `pkg/core/liveness` unchanged but for the package clause, and the
    assembly's tests and the integration labs pass with the new qualifier —
    the BFD lab's detection and recovery among them.
*   **The core walk:** the roof as landed passes with five members, and the
    fixtures fail on an extra child, a production source at the root, and a
    missing member, as before.
*   **The boundary:** the control plane's imports lose the data plane and the
    neighbor table, and liveness imports the data plane and the neighbor
    table alone of the core and the modules.

## Implementation history
