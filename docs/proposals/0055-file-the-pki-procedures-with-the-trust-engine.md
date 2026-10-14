# File the PKI procedures with the trust engine

This proposal carries
[ADR-0018](/docs/adrs/0018-file-every-package-under-the-roof-of-its-kind.md)'s
first decision into the control plane's package. The enrollment lifecycle,
the rotation watch, and the founder's TRC decision are the PKI draft's
procedures, and they move from `pkg/core/controlplane` to `pkg/core/trust`,
beside the engine and the update steps they drive. The trust material and
chain renewal services stay with the control endpoint, which serves them.
The decision takes the submission's source address from its caller, so the
trust package stays free of the transport. No run argument, wire message,
store format, or behavior changes, and the core keeps its four members.

[TOC]

## Summary

ADR-0018 files the control plane as "the control service of the
control-plane draft" and trust as "the control-plane PKI of the PKI draft".
`pkg/core/controlplane` still holds three of the PKI draft's procedures,
about 890 lines beside beaconing, lookup, the health checks, and the
transport:

*   [lifecycle.go](/pkg/core/controlplane/lifecycle.go): the chain's
    lifecycle — renewal below the threshold, re-anchoring onto the newest
    TRC, the authoritative core's onboarding, and the expired-chain sweep.
*   [rotation.go](/pkg/core/controlplane/rotation.go): the rotation watch,
    which rolls the voting and root certificates a core holds.
*   [trccast.go](/pkg/core/controlplane/trccast.go): the founder's decision
    on a submitted TRC update, and the casts the founder runs under the same
    lock.

They use nothing of the control plane but one interface assertion, and the
steps they drive already live in trust: the renewal, the update, and the
rolls ([update.go](/pkg/core/trust/update.go),
[rotation.go](/pkg/core/trust/rotation.go)). Trust imports no control-plane
package. The one tie to the transport is the decision's admission check,
which reads the submission's source address from the HTTP/3 request
context ([trustservice.go](/pkg/core/controlplane/trustservice.go)'s
`remoteUnderlay`).

## Motivation

The tree should file each draft's mechanism in its own package, as
ADR-0018 says it does.

### Goals

*   `pkg/core/controlplane` holds the control-plane draft's mechanism, and
    `pkg/core/trust` the PKI draft's: the engine, the update steps, and the
    procedures that drive them.
*   The decision takes the submission's source address from its caller.
*   Trust stays free of the transport: it imports neither quic-go nor
    connect.
*   The moved tests run on `trusttest`, duplicating no fixture.

### Non-goals

*   The trust material and chain renewal services stay in the control plane:
    the control-plane draft's services, mounted on its endpoint.
*   No identifier changes name, and the core walk's member list stands.
*   The beaconing, health, and transport splits are not decided here.
*   The assembly's `selfEnroll`, which repeats the founder's renewal, stays
    for a later step.

## Proposal

### What moves

`lifecycle.go` and `trccast.go` move as they are. `rotation.go` moves as
`rotationwatch.go`, for trust holds a `rotation.go` of its own, the roll's
update steps. The exported identifiers keep their names: `TRCDecider`,
`DecideTRC`, `CastLocal`, `EnrollmentConfig`, `Renewal` and its
constructors, `RunEnrollment` and the enrollment intervals,
`RotationConfig`, `Roll` and its constructors, and `RunRotation`. The trust
service keeps its assertion that it implements the control plane's
services.

### The decision's source

`DecideTRC` takes the source address beside the presenter:
`DecideTRC(ctx, presenter, source, trc)`. Both are read where a submission
enters. The control plane exports `RemoteUnderlay`, the reader its trust
service's rate cap and the decision used, and the voting application calls
it beside the verified presenter. The voting application's `Decider`
interface gains the argument.

### The tests

*   `trccast_test.go`, `lifecycle_test.go`, and `rotation_test.go`, as
    `rotationwatch_test.go`, move as external tests of package `trust_test`
    on `trusttest`. A test-only `export_test.go` hands them the four passes
    they drive: `enrollPass`, `sweepOnce`, `sweepChains`, and
    `rotationPass`.
*   The decision's episodes pass the source as an argument where they built
    a request context for it.
*   The recording authorizer the trust service's tests and the moved tests
    both use joins `authtest` as `Recorder`. The other helpers follow the
    tests that use them.
*   `TestBeaconingRunReturnsOnCancel` moves to `beacon_test.go`, the
    beaconer's own file.

### The assembly and the documents

The assembly builds the decider, the renewals, and the rolls from trust
([controlplane.go](/internal/services/controlplane.go)) and hands the voting
application the decider as it does today. The architecture overview's
trust engine gains the procedures it now holds.

The change lands in one commit.

## Test plan

*   **Fidelity:** the moved tests pass in `trust_test` as they passed in
    the control plane; the trust service's, the endpoint's, and the voting
    application's tests pass where they stand; and the integration labs
    pass unmodified.
*   **The source:** the decision's admission episodes see the source they
    pass in the facts the policy is asked with, and the voting
    application's episode hands the decision the source its request
    carried.
*   **The boundary:** trust's imports gain the loops library and the
    enrollment authorizer's contract alone; the transport stays out of its
    package graph.

## Implementation history
