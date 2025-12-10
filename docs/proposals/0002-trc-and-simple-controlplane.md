# Implement TRC and a Simple Control Plane for Direct Links

This proposal outlines the implementation of Trust Root Configuration (TRC) and
a simplified control plane for the CION project. The control plane will
initially focus on path discovery and establishment over direct links.

[TOC]

## Summary

This proposal drives the next phase of CION's development by establishing its
security foundation and basic connectivity. It involves implementing the Trust
Root Configuration (TRC) mechanism to enable cryptographic trust. Concurrently,
it proposes a minimal control plane capable of discovering and using direct
links, serving as a functional testing ground and proof-of-concept before fuller
SCION pathing is implemented.

## Motivation

To operate securely and effectively, CION requires a root of trust and a
mechanism to exchange routing information. TRCs provide the necessary security
anchor. A simplified control plane focusing on direct links allows for
incremental development, enabling early testing of the data plane and basic node
interactions without the complexity of full multi-hop routing and beaconing
immediately.

### Goals

*   Implement Trust Root Configuration (TRC) generation, distribution, and
    validation mechanisms.
*   Develop a minimal control plane that supports neighbor discovery and path
    usage over direct links.
*   Define messages and APIs for direct link management.
*   Validate the cryptographic foundations of the network.

### Non-goals

*   Implementation of full multi-hop SCION path construction or beaconing.
*   Advanced path selection metrics (latency, bandwidth, etc.) beyond direct
    connectivity.
*   Inter-domain path discovery beyond immediate neighbors.

## Proposal

### Trust Root Configuration (TRC) Implementation

We will implement the logic required to handle TRCs, which act as the root of
trust for the CION network. This includes:

*   **Generation**: Tools or internal logic to generate valid TRC artifacts,
    managing the cryptographic keys for trust anchors.
*   **Validation**: Logic within CION nodes to parse and cryptographically
    verify received TRCs.
*   **Storage & Access**: A mechanism to securely store and retrieve active TRCs
    for use by other components (like the Control Plane and PKI).

### Simple Control Plane (Direct Links)

The control plane implementation will be scoped to "direct links" only. This
involves:

*   **Discovery**: A mechanism for CION nodes to detect directly connected
    peers.
*   **Path Representation**: Representing a direct connection as a valid SCION
    path segment.
*   **Signaling**: Defining a minimal set of control messages to exchange link
    capabilities and status.
*   **Integration**: Exposing these direct paths to the data plane so traffic
    can be forwarded to neighbors.

## Test plan

*   **TRC Validation Tests**: Unit tests ensuring that correctly signed TRCs are
    accepted and invalid/tampered ones are rejected.
*   **Direct Link Setup**: Integration tests where two CION nodes are connected;
    verifying they can discover each other and exchange control messages.
*   **Packet Forwarding**: Functional tests sending data packets over the
    discovered direct links to verify the end-to-end flow.

## Implementation history

*   983e7f7: Partial implementation of TRC and simple Control Plane PoC (TRC generation bypasses full validation, simple direct link discovery).