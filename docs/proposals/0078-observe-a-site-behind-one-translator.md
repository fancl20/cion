# Observe a site behind one translator

This proposal grounds
[ADR-0028](/docs/adrs/0028-serve-each-site-a-directory-of-its-own.md)'s
context in a lab: four nodes behind one translator, joining through outside
neighbors or through inside ones. A lab asserts what such a site serves
today, and benchmarks measure its inside links, its detours, and the hosts
and tags the founder's directory holds of its nodes. Beside the labs, only
an accessor of the assembly changes: the labs read a node's directory copy.

[TOC]

## Summary

The fabric's boundary admits several inside hosts, and a packet between two
of them crosses nothing
([boundary.go](/internal/testnetwork/fabric/boundary.go)); no lab places two
nodes behind one translator. The behavior labs draw a translated pair's
delays from each host to the other's gateway
([lab_test.go](/internal/testnetwork/behavior/lab_test.go)), an address two
hosts behind one translator never send to.

Measured on the change below, five runs of each benchmark: three public
nodes — the founder, an authoritative core, and one more, 10ms apart — and
four nodes of one site behind a port-restricted translator, 2ms apart and
20ms from every public node.

*   **Joined through outside neighbors:** no site pair linked, in ten runs
    of ten. Every site pair reached through a public node, the worst pair 22.5
    times the reference under the 5ms penalty, the translated lab's figure.
    No inside address was ever published, and the network settled after
    two minutes.
*   **Two joined through inside neighbors:** inside addresses spread. A node
    joined at an inside address publishes it until an outside peer's reply
    replaces it; site peers probe that address, link, and learn their own
    inside addresses from the replies, which they publish in turn. Every site
    pair linked inside in nine runs of ten, and four of six pairs in the
    tenth. In the five settled runs, the worst pair stood 1.35 to 2.1 times
    the reference, and the network settled after 7.7 to 12.3 minutes.
*   **The hosts:** in those runs, the founder's directory held a site node's
    inside address for up to four minutes, and a node's host changed up to
    four times, every change before the network settled. Every node ended
    on the gateway.
*   **The tags:** a node's tag changed up to five times before the network
    settled. One node of twenty ended untagged behind the translator: only
    an acceptor inside the site could have answered its last echo, at the
    inside address it published then.

## Motivation

### Goals

*   The behavior labs place several nodes behind one translator, each pair
    of them shaped host to host.
*   A lab asserts what a site serves today, in both ways of joining, and
    benchmarks measure what ADR-0028 claims of it: inside links, detours,
    and the hosts and tags the founder's directory holds.

### Non-goals

*   No change to what a node does. ADR-0028's site directory gets its own
    proposal.
*   No hairpinning, and no nested translators.

## Proposal

### A site on the fabric

`site` places nodes behind one boundary: their packets to each other cross
nothing, and every other node's go to the gateway. `drawPair` draws one tap
for a pair whose packets go host to host: two untranslated nodes, or two
behind one boundary.

### The site network

The network above. Its site joins in two ways: every node through a public
parent, or 5 and 6 through 3 and 4 at their inside addresses.

*   **The lab:** in both ways, the network settles, and every pair reaches
    over its chosen path and answers a ping.
*   **The benchmarks**, on demand like the others, in both ways:
    *   *settled:* the standard assessment, beside the site's pairs linked
        inside;
    *   *hosts:* the founder's directory copy, read every ten seconds from
        the boot until the network settles and ten minutes beyond — each
        site node's changes of host and of tag, those after the settling,
        the reads that found its inside address, and its final host and
        tag — beside the site's pairs linked inside.

### The directory's read

The assembly's `App` returns its measured provider's directory copy; the
hosts benchmark reads the founder's. `awaitSettledEach` runs a read at each
of the settling wait's own, so the benchmark reads from the boot on.

### Packages touched

| Package                         | Change                                       |
| :------------------------------ | :------------------------------------------- |
| `internal/testnetwork/behavior` | The site, its network, lab, and benchmarks   |
| `internal/services`             | The directory copy for the labs              |

## Compatibility

Only the labs and an accessor of the assembly change. The translated labs
keep their taps: a pair behind two boundaries draws them as before.

## Test plan

*   **The site lab:** it passes in the behavior labs' runs, in both ways of
    joining.
*   **The translated labs:** they pass unchanged.
*   **The benchmarks:** each runs and reports, five runs each.

## Implementation history
