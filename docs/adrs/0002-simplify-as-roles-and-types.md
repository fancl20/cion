# Simplify AS Roles and Types

*   Status: accepted
*   Date: 2025-12-12

[TOC]

## Context and problem statement

The SCION architecture defines a flexible and granular set of roles and
attributes for Autonomous Systems (ASes) within an Isolation Domain (ISD). An AS
can be a **Core AS** or a **Non-Core AS**. Among Core ASes, distinctions are
made based on:

1.  **Voting Rights**: An AS can be a "Voting AS" capable of signing Trust Root
    Configurations (TRCs). Voting rights are further split into **Root**,
    **Sensitive**, and **Regular** types.
2.  **Authoritative Status**: An "Authoritative AS" is responsible for
    distributing TRCs and knowing the latest version.

Implementing this full matrix of capabilities requires complex configuration
structures and logic in the PKI and Control Plane subsystems. For CION's goal of
a simplified, easy-to-deploy node, this level of granularity adds unnecessary
overhead.

## Decision drivers

*   **Simplicity**: We want to minimize configuration complexity for the
    end-user.
*   **Code Maintainability**: We want to avoid combinatorial logic in
    certificate generation and validation.
*   **"One Node per AS"**: CION's topology implies a flatter, simpler hierarchy
    than global internet-scale deployments.

## Decision outcome

We will simplify the AS roles into a single `ASType` enumeration, effectively
creating a tiered model rather than a capability-matrix model.

The defined types are:

1.  **`ASTypeCore`**: Represents a "Super" Core AS.
2.  **`ASTypeAuthoritative`**: Represents a "Standard" Core AS.
3.  **`ASTypeNormal`**: Represents a Non-Core AS.

### Detailed definitions

| CION Role | Standard SCION Equivalent | Capabilities / Certificates |
| :--- | :--- | :--- |
| `ASTypeCore` | Core AS, Voting (Root, Sensitive, Regular), Authoritative | Generates **Root**, **Sensitive**, and **Regular** voting certificates. Can sign all TRC updates. |
| `ASTypeAuthoritative` | Core AS, Voting (Regular only), Authoritative | Generates **Regular** voting certificate only. Participates in regular TRC updates but not sensitive/root updates. |
| `ASTypeNormal` | Non-Core AS (Leaf or Transit) | No voting certificates. Standard AS certificate only. |

### Comparison with spec

*   **Spec**: The SCION specification treats "Core", "Voting", and
    "Authoritative" as orthogonal or semi-orthogonal properties. A Core AS might
    be non-voting. A Voting AS might hold only "Sensitive" rights but not
    "Regular".
*   **CION**: We couple these properties. If you are `ASTypeCore`, you are
    automatically Authoritative and hold *all* voting rights. If you are
    `ASTypeAuthoritative`, you are automatically Core and hold *Regular* voting
    rights. We do not support "Non-voting Core ASes" or other permutations.

## Positive consequences

*   **Simplified Logic**: Certificate generation can simply switch on `ASType`
    to decide which keys and certificates to create (see
    `pkg/pki/certificates.go`).
*   **Easier Configuration**: Users select a single "Role" for their node rather
    than configuring multiple boolean flags.
*   **Clear Hierarchy**: The tiers (Core > Authoritative > Normal) are intuitive
    for smaller private networks.

## Negative consequences

*   **Reduced Flexibility**: It is impossible to configure an AS that, for
    example, is Core but Non-Voting (often used for backup cores).
*   **Terminology Overload**: We repurpose "Authoritative" to mean "Core AS with
    Regular Voting Rights", which might slightly confuse experts of the strict
    SCION spec where "Authoritative" specifically refers to TRC distribution.
