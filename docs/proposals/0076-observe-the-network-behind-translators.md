# Observe the network behind translators

This proposal lets the labs draw translators of the three behaviors RFC 4787
sets apart: full cone, port-restricted, and symmetric. A packet between two
translated hosts crosses both translators. A translated network joins the
behavior labs: a lab asserts what it serves today, and benchmarks measure
what it does not. No production code changes.

[TOC]

## Summary

The fabric's boundary maps each inside socket to one gateway port and admits
any outside source to it: a full-cone translator
([boundary.go](/internal/testnetwork/fabric/boundary.go)). Only the first
boundary that claims a packet applies
([fabric.go](/internal/testnetwork/fabric/fabric.go)), so a packet between
two translated hosts crosses one of them. The translate labs run a two-node
line ([translate_test.go](/internal/testnetwork/translate_test.go)); no
behavior lab draws a boundary.
[ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md)
brought translation into scope wherever one side holds a stable address.
What lies beyond the full cone is unobserved: translators that filter or map
per destination, translated nodes beside each other, a mapping that changes
under a standing link.

Measured on a scratch copy of the change below: three public nodes — the
founder, an authoritative core, and one more, 10ms apart — and four
translated nodes, each behind its own translator, 2ms apart and 20ms from
every public node.

*   **Settled:** every translated node linked to all three public nodes and
    to no translated node. All 42 pairs reached, by chosen path and by ping.
    The worst pair stood 22.5 times the reference: two translated nodes 2ms
    apart crossed a public node, 45ms under the 5ms penalty.
*   **Symmetric:** a node behind a symmetric translator never enrolled. Its
    parent recorded the mapping the joiner's rendezvous dial drew, while the
    link's own traffic left through another mapping. The parent's replies
    went to the first one, which the translator filters, and the parent
    retired the entry when the candidate window ended.
*   **Rebinding:** once a translator dropped a node's mappings, no ping
    reached the node or left it for the 43 virtual minutes left in the run.
    Its three links stayed established.
*   **Founder down:** every surviving pair kept reaching through the other
    public nodes. A translated node restarted during the outage, after its
    peers had retired its links, re-dialed the public peers its link store
    held. Every survivor reached it again within three minutes.

## Motivation

### Goals

*   The labs draw the translators deployments meet: full cone,
    port-restricted, and symmetric.
*   A packet between two translated hosts crosses both translators, so an
    exchange that punches through them can be proven on the fabric.
*   A behavior lab asserts what a translated network serves today, and
    benchmarks measure what it does not.

### Non-goals

*   No production change. Each gap the lab shows gets its own proposal.
*   No hairpinning, nested translation, translated TCP, or mapping timeout
    beyond today's idle window.

## Proposal

### Translator behaviors

`Behavior` names RFC 4787's two choices:

*   **Mapping:** endpoint-independent keeps one gateway port per inside
    socket; endpoint-dependent draws one per socket and destination.
*   **Filtering:** endpoint-independent admits any outside source to a
    mapping; address-and-port-dependent admits only the endpoints its
    socket sent to.

`FullCone`, `PortRestricted`, and `Symmetric` name the three combinations
deployments meet. `TranslateAs` draws a boundary of a behavior with no
first-contact forward: an inside node dials its peers' published addresses.
`Translate` keeps drawing the full-cone boundary the translate labs use.

### Chained crossings

The fabric passes a packet out of the boundary holding its source, then
into the boundary owning its destination. A packet between two translated
hosts crosses both, as through two translators.

### The translated network

The behavior labs' network learns each node's address on the wire: its host,
or its translator's gateway. The fabric shapes a packet before it
translates it, so delays and cuts draw one tap per direction, from each
node's host to the other's wire address.

The translated network is the scratch network above. The authoritative
core lets a scenario take the founder down.

*   **The lab:** with full-cone and port-restricted translators, the network
    settles, and every pair reaches over its chosen path and answers a ping.
*   **The benchmarks**, on demand like the others:
    *   *settled:* the standard assessment;
    *   *rebind:* a translator drops a node's mappings, and the pings to and
        from the node are read for ten minutes, beside its links;
    *   *symmetric:* whether a node behind a symmetric translator enrolls
        within a budget;
    *   *founder down:* the survivors' pings, and the time a translated node
        restarted during the outage takes to return.

### Packages touched

| Package                         | Change                                              |
| :------------------------------ | :-------------------------------------------------- |
| `internal/testnetwork/fabric`   | Translator behaviors, chained crossings             |
| `internal/testnetwork`          | A node a lab stops and restarts on its state        |
| `internal/testnetwork/behavior` | The translated network, its lab, and its benchmarks |

## Compatibility

Only the labs change. The translate labs keep their full-cone boundary and
first-contact forward.

## Test plan

*   **The fabric:** each behavior maps and filters as RFC 4787 defines it; a
    mapping retires past its idle window and the next crossing draws a fresh
    one; two port-restricted translators carry an exchange once both sides
    have sent toward each other.
*   **The translate labs:** they pass unchanged.
*   **The translated lab:** it passes in the behavior labs' runs.
*   **The benchmarks:** each runs and reports, five runs each.

## Implementation history

*   Landed as proposed: the translator behaviors and chained crossings
    ([boundary.go](/internal/testnetwork/fabric/boundary.go),
    [fabric.go](/internal/testnetwork/fabric/fabric.go)), a node a lab stops
    and restarts on its state ([node.go](/internal/testnetwork/node.go)),
    and the translated network with its lab and benchmarks
    ([translated_test.go](/internal/testnetwork/behavior/translated_test.go),
    [lab_test.go](/internal/testnetwork/behavior/lab_test.go)). The fabric's
    test of a mapping's expiry, documented without a body, landed beside the
    behaviors' tests ([boundary_test.go](/internal/testnetwork/fabric/boundary_test.go)).
    Across five runs: the settled network reached all 42 pairs, its worst
    pair 22.5 times the reference under the 5ms penalty and 20 times
    without; the rebound node reached no peer and no peer reached it for the
    ten minutes read, its three links established; the node behind a
    symmetric translator never pinned the TRC or linked; every survivor of
    the founder's loss reached every other within 17 to 115 seconds, and the
    restarted node returned within 222 to 296 seconds.
