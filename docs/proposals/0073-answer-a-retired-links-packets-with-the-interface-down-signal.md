# Answer a retired link's packets with the interface-down signal

This proposal gives a retired link the answer a down link already gets: the
data plane drops a packet whose verified hop field names an interface its
generation no longer serves, and answers the packet's source with SCMP
External Interface Down under the same per-interface cap, as the data plane
draft asks of a router whose link cannot forward. A source then sets the
path aside at its first send, as it does for a down link, rather than
sending into the retired link until the segments through it read stale. No
message type, stored field, run argument, or constant changes.

[TOC]

## Summary

A retired link leaves the data plane with the generation swap its store
write signals: each generation is built from the store's serving links
([dataplane.go](/internal/services/dataplane.go)). A packet whose path still
names the link's interface reaches `validateEgressID`
([processor.go](/pkg/core/dataplane/processor.go)), which answers with an
SCMP Parameter Problem for an unknown hop-field interface. No source acts on
it: the interface-down cache recognizes External Interface Down alone
([ifdown.go](/pkg/libs/scion/ifdown.go)). The segments through the link keep
their rank until they read stale, five minutes after their last refresh
([proposal 0072](/docs/proposals/0072-serve-every-pair-a-live-path-ranked-by-declared-latency.md)),
and a source whose chosen path crosses the link sends into it meanwhile.

A link that is down, not retired, is answered with External Interface Down,
and its sources set the path aside within a round trip. The measured
selection retires a link whose verdict stayed down for three windows, 90
seconds at the daemon's pacing, and a dialer retires a link it finds useless
while the link still carries traffic. From either retirement until the
segments read stale, the link's sources hear nothing they act on.
[Proposal 0046](/docs/proposals/0046-harden-neighbor-selection-and-link-liveness.md)
noted the answer and kept the node's own retired interfaces out of
composition; a link retired elsewhere stayed dark.

Measured on a scratch copy, on a static lab of five nodes where the core A
reaches D over B, or over C and E, and A's chosen path crosses B's link to
D: once B retired the link, A reached D again 32 to 33 milliseconds later in
five runs of five, losing one ping each time. Without the change it took 5
minutes and 0.6 seconds, and 148 pings, until the segments through B read
stale.

## Motivation

### Goals

*   A source whose chosen path crosses a link retired elsewhere sets the
    path aside at its first send, as it does for a down link.
*   The draft's message, the existing cap, and the existing source handling
    carry the answer: no new message, cache, or constant.

### Non-goals

*   No source-side reading of the Parameter Problem: the drafts define no
    such message, and the router knows what failed.
*   No longer retention. A signal holds ten seconds, the draft's current
    practice; a source whose best candidate still crosses the link sends
    once more per lapse, until the segments read stale.
*   No revocation. The segments through the link stay stored and
    composable, and count as routes until an echo over them lands the
    signal (ADR-0017, decision 4).

## Proposal

### A retired interface is answered as a down one

The data plane draft asks a router to drop a packet destined to a link that
is down and to notify the packet's source (Sections 6.1 and 6.2). The
control plane draft's message for it is External Interface Down, for a
packet that cannot be forwarded because the link to an external AS is
broken (Section 6.5.2); its other error messages are Packet Too Big and
Internal Connectivity Down.

`validateEgressID` runs after the current hop field's MAC verified, so an
egress the generation lacks names a link this AS held: the hop field is the
AS's own. Such a packet is dropped, and its source answered with External
Interface Down naming the local ISD-AS and the interface: the answer
`validateEgressUp` gives a down link, under the same cap of ten
notifications per interface per second. The sibling check keeps its
Parameter Problem.

Sources need no change. The conn records the signal, composition demotes a
path crossing the interface to the last resort for ten seconds, the
WireGuard bind drops the quoted destination's cached path, and the measured
selection's echo ends at the signal, a candidate crossing a signaled
interface counting as no route.

### Packages touched

| Package                | Change                                                    |
| :--------------------- | :-------------------------------------------------------- |
| `pkg/core/dataplane`   | An egress the generation lacks answered as a down one     |
| `internal/testnetwork` | The retired link's lab                                    |

## Compatibility

The message is the drafts' own, and a source on the previous release
already acts on it. A router on the previous release keeps answering with a
Parameter Problem, and its sources keep waiting for the segments to read
stale.

## Test plan

*   **The data plane:** a packet whose verified hop field names an
    interface the generation does not serve is dropped and answered with
    External Interface Down carrying the local ISD-AS, the interface, and
    the quoted packet; a burst earns no more notifications than the cap.
*   **The lab:** on the static lab, A's chosen path to D crosses B's link to
    D. Once B retires the link, an echo over the path lands the signal in
    A's cache, and A reaches D over C and E while the path through B is
    still fresh.
*   **The behavior labs and benchmarks:** the labs pass, and the settled
    and cut benchmarks of both networks are compared before and after.

## Implementation history

*   Landed as proposed: `validateEgressID` answers an egress the generation
    lacks as a down one ([processor.go](/pkg/core/dataplane/processor.go)),
    and the static lab proves the retired link's signal end to end
    ([static_test.go](/internal/testnetwork/static_test.go)). Across five
    runs, the settled and cut benchmarks of both networks, which send no
    traffic, held their ranges from before the change, save one regions cut
    run: its links settled seven seconds after the cut, and its scenario
    ended five minutes later, before three pairs' segments through the cut
    link read stale — a race the scenario's end runs against the staleness
    window with or without the change.
