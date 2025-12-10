# CION

**Non-scalable SCION**

CION is a lightweight, single-binary implementation of the SCION Internet
architecture, designed specifically for multi-operator environments with a "one
node per Autonomous System (AS)" topology.

## Goal

The primary goal of CION is to provide a simplified, "almost zero config"
network solution that enables:

*   **Operator Sovereignty:** Operators retain absolute control over traffic
    transit rules and path sharing.
*   **Path Awareness:** Clients can dynamically select routing paths based on
    latency, geography, or other metrics without network-side configuration
    changes.
*   **Operational Simplicity:** A collapsed architecture that combines standard
    SCION components (Border Router, Control Service, Dispatcher) into a single,
    easy-to-deploy binary.

> **Note:** CION does not target internal AS scalability. It is optimized for
> scenarios where a single node handles the routing for an entire AS.