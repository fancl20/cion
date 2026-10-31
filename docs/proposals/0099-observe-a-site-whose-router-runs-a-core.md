# Observe a site whose router runs a core

This proposal adds a third shape of site to the labs of
[proposal 0078](/docs/proposals/0078-observe-a-site-behind-one-translator.md):
the site's NAT runs on a router that also runs the authoritative core, bound
to the wildcard as the daemon binds by default, and every site node joins
through that core alone, at its inside address. The site network of proposal
0078 stays as it is, so its results remain comparable. Beside the labs, the
socket source gains the routing table, which the wildcard bind's source
resolution reads through it.

[TOC]

## Summary

The labs place a site's nodes behind a NAT, never on it:

*   **No node runs on a NAT.** The fabric's NAT owns its gateway, a host no
    node may hold, and each stack holds one host
    ([nat.go](/internal/testnetwork/fabric/nat.go),
    [fabric.go](/internal/testnetwork/fabric/fabric.go)).
*   **No lab binds the wildcard.** The fabric binds concrete addresses
    alone, and the wildcard bind's source resolution asks the kernel's
    routing table directly
    ([wildcardhost.go](/internal/services/wildcardhost.go)), which holds
    none of the fabric's hosts.
*   **Every site joins partly outside.** In each of the site network's ways
    of joining, a site node joins through a public parent, or through a
    site node that does
    ([site_test.go](/internal/testnetwork/behavior/site_test.go)).

Measured on the change below, five runs of each benchmark; the site
network's figures are those
[proposal 0098](/docs/proposals/0098-form-directory-scopes-from-links.md)
recorded:

| Site                                  | Settles (min) | Pairs linked inside | Worst pair |
| :------------------------------------ | :------------ | :------------------ | :--------- |
| Joined through outside neighbors      | 1.8–2.2       | 0 of 6              | 22.5       |
| Joined through inside neighbors       | 1.3–2.0       | 2 of 6              | 29.5       |
| Joined both ways                      | 5.0–8.5       | 6 of 6              | 1.35–1.75  |
| Joined through the core on its router | 1.2–1.8       | 6 of 6              | 1.35–1.7   |

The worst pair is its path's cost over the reference under the 5ms penalty.
Through the core on its router, the formed links' worst pair is a site node
and a public node: 20ms apart through the NAT, against 27ms through core 1
with its transit's penalty.

Two observations beside the figures:

*   **The founder's views hold no site node.** The site's nodes stand in no
    scope the founder holds, so its views hold no entry of theirs, and the
    console lists them as silent.
*   **The first fetch tries core 1.** A site node's first fetch of the TRC
    goes to its neighbor core 1, which holds no WebPKI certificate of the
    network's domain, and fails until the locator turns to the founder.
    The site's nodes hold chains 15–35 s after the boot. The site network
    shows the same failures.

## Motivation

### Goals

*   A lab runs a node on a NAT's router: holding the gateway beside an
    inside host and bound to the wildcard, as a router running CION is.
*   A lab asserts what a site served through such a node serves, and a
    benchmark measures it beside the site network's ways of joining.

### Non-goals

*   No change to what a node does.
*   Port forwarding, hairpinning, and nested NATs.
*   Sites whose nodes also join outside: the site network covers them.

## Proposal

### A router on the fabric

*   **The router.** `NAT.Router` boots the stack on the NAT's own box: the
    gateway beside an inside host, one of the NAT's inside hosts. A socket
    bound to the wildcard sends to the NAT's inside hosts from the inside
    host, crossing nothing, and to every other host from the gateway,
    untranslated; the routes' source hints choose. The stack's ephemeral
    ports lie above the mapping band.
*   **The gateway's own packets.** The NAT keeps the gateway's mapping band
    for its crossings. Every other packet to the gateway — from inside, or
    from outside beyond the band — is the router's, and falls where no
    router runs, as before. A packet from the gateway crosses nothing.
    `Fabric.Node` refuses a NAT's gateway, which its router alone holds.
*   **The wildcard.** A stack binds the IPv4 wildcard, which receives at
    every host the stack holds; the bound address reads 0.0.0.0, as the
    kernel's does.

### The routing table in the socket source

The socket source gains the routing table: the local address a
wildcard-bound socket's packets toward a destination leave from. The kernel
source answers from the kernel's table, which the wildcard host resolution
asks today; a fabric stack answers from its routes. The resolution reads it
from the node's socket source.

### The gateway site network

*   **The network.** The founder 0 and the public node 2, 10ms apart. Core
    1 runs on the router of the site's port-restricted NAT, bound to the
    wildcard: its gateway 20ms from both, its inside host 2ms from the
    site's nodes 3 to 6, which stand 2ms apart. Core 1 joins through the
    founder, and each site node through core 1 alone, at its inside host.
    A node bound to the wildcard is named by its host on the fabric.
*   **The taps.** A router's pair with a node behind its NAT is shaped at
    the router's inside host. A pair across the NAT is shaped from the node
    behind it alone: the other node's packets go to the gateway, which the
    router's own pair with that node shapes, at the same 20ms.
*   **The lab:** the network settles, and every ordered pair reaches over
    its chosen path and answers a ping. Core 1 measures each of its links
    at the delay the network drew. Its entry names the gateway in the
    founder's directory, neither behind a NAT nor unanswered, and its
    inside host in a directory the founder does not hold, where every site
    node's entry names its inside address. The founder's views hold no site
    node's inside address.
*   **The benchmark,** on demand like the others: once the network
    settles, the standard assessment, beside the site's pairs linked
    inside.

### Packages touched

| Package                         | Change                                               |
| :------------------------------ | :--------------------------------------------------- |
| `internal/testnetwork/fabric`   | The router, the wildcard bind, and the stacks' routes |
| `pkg/libs/underlay`             | The routing table in the socket source               |
| `internal/services`             | The wildcard host reads the socket source's routes   |
| `internal/testnetwork`          | A wildcard-bound node: its address and its name      |
| `internal/testnetwork/behavior` | The gateway site network, its lab, and its benchmark |

## Compatibility

No change to what a node does: the kernel source's routing table is the
kernel's. Where no router runs, the NAT changes nothing: a packet to the
gateway outside its crossings finds no stack and falls, as the NAT dropped
it before. The site and NAT networks keep their nodes and taps.

## Test plan

*   **The fabric:** a router's routes, its wildcard socket's sends and
    receipts on both sides, and the NAT's band beside it.
*   **The socket source:** its routes, the kernel's where it names none.
*   **The gateway site lab** passes in the behavior labs' runs.
*   **The other labs** pass unchanged, and the site network's benchmark
    holds its figures.
*   **The benchmark** runs and reports, five runs.

## Implementation history
