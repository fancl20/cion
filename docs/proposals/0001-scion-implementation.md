# Implement SCION dataplane and interfaces

This proposal outlines the implementation of the SCION dataplane and the
definition of pure interfaces for the controlplane and PKI within the CION
project.

[TOC]

## Summary

This proposal aims to integrate SCION networking capabilities into CION. It
involves implementing the SCION dataplane by reusing specific, spec-compliant
libraries from the reference implementation (`github.com/scionproto/scion`),
such as `slayers`. Additionally, it defines pure interfaces for the controlplane
and PKI components to establish clear boundaries and contracts for future
implementation.

## Motivation

To support SCION networking, CION requires a functional dataplane and defined
structures for its control and security components. Reusing existing, compliant
libraries for the dataplane accelerates development and ensures protocol
adherence, while defining interfaces for the controlplane and PKI allows for
modular development and prevents tight coupling with specific implementations.

### Goals

*   Implement the SCION dataplane in CION.
*   Reuse `github.com/scionproto/scion` libraries that directly reflect the
    SCION specification, specifically `slayers`.
*   Avoid using `github.com/scionproto/scion` libraries that are specific to the
    reference implementation's internal details.
*   Define pure interfaces for the SCION controlplane.
*   Define pure interfaces for the SCION PKI.

### Non-goals

*   Full implementation of the controlplane logic (interfaces only).
*   Full implementation of the PKI logic (interfaces only).
*   Replicating the entire `scionproto/scion` codebase.

## Proposal

### Dataplane implementation

The dataplane implementation will focus on packet handling and forwarding
according to the SCION protocol specifications. We will leverage the
`github.com/scionproto/scion` repository, specifically targeting packages like
`slayers` that implement the wire format and protocol logic defined in the
specs. Care will be taken to strictly avoid importing packages that tie the
implementation to the reference implementation's specific infrastructure or
internal tooling.

### Controlplane interfaces

We will define a set of pure interfaces to represent the SCION controlplane.
These interfaces will abstract the operations required for path discovery,
beaconing, and other control plane functions, allowing for flexible future
implementations.

### PKI interfaces

Similarly, we will define pure interfaces for the Public Key Infrastructure
(PKI). These interfaces will handle certificate management, trust root
operations, and key verification, ensuring a clear separation of concerns
between the definition of security operations and their concrete realization.

## Test plan

*   **Unit Tests**: Comprehensive unit tests will be written for the dataplane
    implementation to verify correct packet processing and adherence to the
    spec.
*   **Interface Validation**: The defined interfaces for controlplane and PKI
    will be reviewed to ensure they cover the necessary functionality without
    leaking implementation details.
*   **Integration Tests**: Basic integration tests will be set up to verify that
    the dataplane can correctly utilize the `slayers` library.

## Implementation history