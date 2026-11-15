# Keep a loaded link up in demand mode

This proposal implements decision 6 of
[ADR-0043](/docs/adrs/0043-grow-capacity-between-nodes-under-load.md): load
never takes a link down. A link's BFD session runs RFC 5880's asynchronous
mode, and switches to demand mode when load loses its control messages while
the congestion module's echoes still cross the link: the echoes keep the
session up, and once they stop, a Poll sequence brings the peer's control
messages back. It replaces
[proposal 0137](/docs/proposals/0137-brake-each-link-mark-what-returns-and-move-off-hot-paths.md)'s
rule that every arrival keeps a session up, and the data plane stops
reporting arrivals to the sessions. No wire message, stored field, or run
argument is added.

[TOC]

## Summary

Today:

*   **A session runs RFC 5880's asynchronous mode**
    ([bfd.go](/pkg/core/liveness/bfd.go)), the data-plane draft's subset, as
    upstream's sessions do: it goes down after a detection time without a
    control message, which a loaded link loses with the rest
    ([scionproto/scion#4019](https://github.com/scionproto/scion/issues/4019)).
    In the hub lab, ten minutes of load past the hub's uplink take down
    between 1 and 14 links.
*   **Every arrival keeps a session up,** since proposal 0137: the data plane
    reports each arrival from the peer to the session
    ([udpip.go](/pkg/core/dataplane/udpip.go)), which RFC 5880's asynchronous
    mode does not count. With the rule, the hub lab lost no link under load;
    without it, up to 6 in ten minutes of steady load and up to 4 after its
    uplink's rate fell.

This proposal adds:

*   **Demand mode under load.** When the detection time passes without a
    control message, a session whose link carried an echo within the last
    second sets the Demand bit instead of going down; its peer stops its
    periodic control messages, and the echoes keep the session up. A session
    whose link carries no echo for a second clears the bit.
*   **Poll sequences.** A change of the Demand bit runs RFC 5880's Poll
    sequence, and a session answers a Poll at once with the Final bit, so the
    peer's control messages are back within a round trip of the switch.
*   **Each link's last echo, from the congestion module.** The module keeps
    when an echo last crossed each link, either way: the replies to its own
    echoes, and the requests of the neighbor's, which the responder hands it.
    The sessions read it at each interval.
*   **No arrival hook.** The data plane hands the sessions their control
    messages alone.

## Motivation

ADR-0043 grows the capacity between two nodes under load, and decision 6
keeps load from shrinking it by taking links down. Proposal 0137 kept the
hub lab's links up by counting every arrival as a sign of life, which RFC
5880 does not allow and which hooks the data plane into the sessions. Demand
mode is RFC 5880's own answer: it leaves the proof of connectivity to the
system, and names the peer's traffic and echoes as that proof. The brake
already echoes every link that carries traffic, about ten times a second at
128 kbit/s or more, so a loaded link holds the proof demand mode needs, and
an idle link, which load does not cross, keeps asynchronous mode.

### Goals

*   The sessions keep RFC 5880's rules.
*   In the hub lab, load takes down far fewer links than asynchronous mode
    lets it, each only until the brakes engage, and the flows deliver as
    under proposal 0137.
*   A link that stops carrying packets goes down within a detection time and
    a second, in either mode.
*   An idle link costs what it costs today.

### Non-goals

*   Authentication, and BFD's own Echo function, which upstream's sessions
    leave out too.
*   Idle links behind a congested line: no echo crosses them, so they keep
    asynchronous mode and lose their control messages as today.
*   The first seconds of a sudden overload, before the brakes engage: a link
    that no packet crosses for the detection time goes down, as in
    asynchronous mode, and comes back once they do.
*   Nodes without this proposal.

## Proposal

### The sessions

*   **Asynchronous mode** is where a session starts, and where it stays while
    its peer's control messages arrive.
*   **Into demand mode.** When the detection time passes without a control
    message, a session that is Up, whose peer last reported Up, and whose
    link carried an echo within the last interval sets the Demand bit and
    stays Up; any other goes down, as today. Its peer stops its periodic
    control messages (RFC 5880, Section 6.8.7).
*   **In demand mode,** a session goes down once the detection time passes
    with neither an echo nor a control message, as soon as asynchronous mode
    would.
*   **Back to asynchronous mode.** A session in demand mode whose link
    carried no echo for an interval clears the bit. Until its Poll sequence
    ends, the echoes still count toward the detection time.
*   **Poll sequences** (Section 6.5): a change of the bit sets the Poll bit on
    the session's packets at each interval until the peer's Final arrives,
    and a session answers a Poll at once with the Final bit.
*   **Each end on its own.** The bit only stops the peer's periodic messages:
    the peer keeps its own mode and still receives the session's. Under a
    flow in one direction, the receiving end, whose echoes are the sender's
    requests, may switch alone.

### The echoes

*   **The congestion module** keeps when an echo last crossed each link,
    either way: the arrival of a reply to one of its echoes, and of a request
    the neighbor sent, which the responder hands it. The sessions read it at
    each interval; it needs no loop of its own and no bus topic.
*   **The responder** hands the module each echo request it answers that
    crossed one link to the node, over a one-hop path.

### The data plane

`Session.Heard` goes, and the external link reports no arrivals to its
session.

### The labs

*   **The hub benchmarks** count the links lost, beside proposal 0137's
    numbers.
*   **An idle link** stays in asynchronous mode, and goes down within a
    detection time and a second once its line is cut.

### Packages touched

| Package                  | Change                                         |
| :----------------------- | :--------------------------------------------- |
| `pkg/core/liveness`      | Demand mode under load, and Poll sequences     |
| `pkg/core/dataplane`     | No arrival hook                                |
| `pkg/core/responder`     | Hands on the requests it answers over a link   |
| `pkg/modules/congestion` | Each link's last echo                          |
| `internal/services`      | The responder and the monitor read the module  |

## Compatibility

Not kept. A node without this proposal ignores the Demand and Poll bits and
keeps sending periodic control messages, which keep the session up as today.

## Test plan

*   **The sessions:** no Demand bit while control messages arrive; the switch
    at the detection time only for a session Up, its peer Up, and an echo
    within the interval; Poll sequences and their answers; demand mode up on
    the echoes, and down a detection time after the last; asynchronous mode
    again on the peer's Final; under a flow in one direction, the receiving
    end alone switches.
*   **The congestion module:** a link's last echo is the latest reply or
    request across it.
*   **The responder** hands on the requests that crossed one link to it.
*   **The labs:** the idle link, and the hub benchmarks.
