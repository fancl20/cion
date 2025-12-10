# Adopt SCION Architecture for Inter-Operator Routing

*   Status: accepted
*   Date: 2025-12-10

[TOC]

## Context and problem statement

CION is designed to support a network of nodes managed by multiple independent
operators spread across different geographic regions. The system needs to allow
traffic routing between these operators while maintaining strict sovereignty; an
operator must have absolute control over traffic entering their node and decide
explicitly which paths are shared with the network.

Furthermore, the system requires a "SCION-aware" client capability, where the
client—not the network—dynamically selects the path (e.g., for latency,
bandwidth, or geofencing reasons) without nodes needing to pre-configure all
possible global routes.

The implementation constraints for CION are strict: it must be a single binary
with "almost zero config." It does not target scalability *within* an Autonomous
System (AS); instead, the topology assumes a 1:1 relationship between a Node and
an AS.

We need a network architecture that supports path-aware networking, strict
operator control, and decentralized routing without the heavy configuration
burden of traditional BGP or the complexity of standard multi-component
deployments.

## Decision drivers

*   **Path Awareness:** Clients must be able to choose specific routes through
    the network (e.g., avoiding specific regions or optimizing for specific
    metrics) without network-side state manipulation.
*   **Operator Sovereignty:** Operators require absolute control over which
    paths are advertised and allowed, preventing unauthorized transit traffic.
*   **Decentralized Control:** No central authority should dictate routing
    tables; path discovery should be dynamic via beaconing.
*   **Deployment Simplicity:** The architecture must allow for collapsing the
    control and data planes into a single binary to meet the "zero config" and
    "one node per AS" goals.
*   **Scalability of State:** We cannot maintain global routing tables on
    individual nodes. Forwarding state should be carried in packets.

## Considered options

*   **BGP / MPLS (Traditional):** Standard inter-domain routing.
*   **Overlay Networks (e.g., WireGuard Mesh + OSPF):** Flat IP overlays.
*   **SCION (Scalability, Control, and Isolation On Next-Generation Networks):**
    As defined in IETF drafts
    [`draft-dekater-scion-controlplane`](/docs/specs/draft-dekater-scion-controlplane.txt),
    [`draft-dekater-scion-dataplane`](/docs/specs/draft-dekater-scion-dataplane.txt),
    and [`draft-dekater-scion-pki`](/docs/specs/draft-dekater-scion-pki.txt).

## Decision outcome

Chosen option: **SCION**, because it is the only architecture that natively
decouples path control from data forwarding, allowing clients to select paths
while enforcing operator sovereignty via cryptographically secured path
segments.

SCION's design aligns perfectly with the CION use case:

1.  **Path-Awareness:** The SCION Data Plane allows the client to embed the
    forwarding path in the packet header, enabling dynamic route selection
    without node reconfiguration.
2.  **Beaconing:** The SCION Control Plane uses PCB (Path Segment Construction
    Beacons) to disseminate routing information. This allows operators to define
    exactly how their node connects to neighbors without pre-configuring global
    routes.
3.  **Simplified Topology:** Since CION targets "one node per AS", we can
    drastically simplify the standard SCION implementation. We will collapse the
    Border Router, Control Service, and Dispatcher into a single CION binary.
4.  **Security:** The SCION PKI and data plane provide cryptographic
    verification of paths, ensuring traffic only flows through authorized
    segments.

### Positive consequences

*   **Client Autonomy:** Clients can intelligently route around failures or
    bottlenecks without waiting for global protocol convergence.
*   **Zero-Config Routing:** Nodes only need to know their immediate neighbors;
    path discovery happens automatically via beacons.
*   **Stateless Forwarding:** Intermediate nodes do not need to store routing
    tables for the whole network; forwarding decisions are made based on the
    packet header.
*   **Traffic Policing:** Operators can cryptographically restrict who uses
    their transit capability.

### Negative consequences

*   **Protocol Complexity:** Implementing the full SCION stack (even simplified)
    is complex compared to a simple TCP/UDP tunnel.
*   **Non-Standard Headers:** Traffic is not native IP; it requires
    SCION-specific headers, meaning applications must be adapted or proxies used
    (though CION acts as this proxy).
*   **MTU Overhead:** The SCION header adds bytes to the packet, slightly
    reducing payload capacity (MSS).

## Pros and cons of the options

### BGP / MPLS

*   Good, because it is the industry standard for inter-AS routing.
*   Bad, because BGP convergence is slow.
*   Bad, because it does not support source-selected routing natively (traffic
    engineering is complex and operator-driven, not client-driven).
*   Bad, because configuration is heavy and error-prone.

### Overlay Networks (WireGuard Mesh)

*   Good, because it is simple to set up point-to-point encryption.
*   Bad, because routing protocols (OSPF/BGP) on top of the mesh still suffer
    from convergence issues.
*   Bad, because it does not offer inherent path control to the client; the
    routing protocol decides the "best" path.

### SCION

*   Good, because it inherently supports multipath communication and client path
    selection.
*   Good, because path segments are cryptographically signed, enforcing operator
    control.
*   Good, because forwarding is stateless (routers don't hold global table
    state).
*   Bad, because it requires a specific PKI infrastructure (TRC, certificates),
    though this will be managed within the CION binary context.