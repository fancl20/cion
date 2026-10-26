# Follow Each Link's Own Flow

*   Status: accepted
*   Date: 2026-10-26

[TOC]

## Context and problem statement

[ADR-0021](/docs/adrs/0021-certify-the-neighbor-observe-its-locator.md)
separated a link's certified identity from its observed locator. Every
arrival records the source the link observes, and the link's own
conversation — its BFD stream and one-hop answers — follows that
observation. Transit follows the locator, which moves only on the peer's
authenticated link request (decision 3), re-sent by a returning node's own
pass over its entries at start (decision 4). Bare arrival never moves it
(decision 5).

The translated lab of
[proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md),
and a restart beside it, show three ways a translated peer's locator comes
from the wrong source:

*   **A dropped mapping cuts a node off while its links stay up.** Its peers
    observe the new mappings, and BFD stays up, but transit keeps the
    locator the last link request installed. Link requests run only at
    establishment and at start: no ping reached the node or left it for ten
    minutes.
*   **A joiner behind a symmetric translator never enrolls.** Its parent's
    candidate locator is the mapping the rendezvous dial drew, while the
    link's own flow leaves through another. The link request that would move
    the locator needs the chain the enrollment never delivers.
*   **A restarted node cuts off its translated neighbors.** Its pass over
    its entries records each reply's claimed address, which for a translated
    peer is the socket it bound inside its translator. Nothing moves the
    locator again until the peer sends its own request: when the public node
    2 restarted on its state, at most two of its six peers reached it, and it
    reached two, for ten minutes, in three runs of three.

## Decision drivers

*   **Transit follows the peer:** a link's locator tracks where the peer's
    packets come from, within seconds of a change.
*   **Possession guards established links:** an established link's locator
    moves only on an exchange the peer's chain authenticates, as ADR-0021
    holds.
*   **Candidates at the rendezvous bar:** an unproven candidate's locator
    moves on return-routability, the bar its rendezvous claim already meets.
*   **No new message:** the link request and the BFD session carry it.

## Considered options

*   **Periodic link requests:** every node re-sends its link requests on a
    cadence, and the acceptor's existing rule moves the locator.
*   **Locators BFD proves:** transit follows the observed source once the
    link's BFD session answers there, for every link.
*   **The flow, confirmed in either direction:** a node's own answered link
    request records the link's observation, a link that observes its
    established peer elsewhere sends one, and a candidate follows the source
    its BFD session answers.

## Decision outcome

Chosen option: **the flow, confirmed in either direction**, amending
ADR-0021's decisions 3 to 5:

1.  **An answered request records the observation, in either direction.** A
    node's own link request rides the link's one-hop path, and its answer
    arrives over that link from the peer the handshake proved. The node
    records the source its link observes the peer at, as the acceptor records
    the request's arrival. A claimed address stays the record only while the
    link has observed nothing.
2.  **An established link observed elsewhere sends a request.** When a link
    observes its established peer at an address other than its locator, the
    node sends the peer its link request, at most once every few seconds, and
    the answer moves the locator by point 1. The node watches its own link's
    observation and polls nothing of the peer.
3.  **A candidate follows the source its BFD session answers.** An unproven
    candidate, which no chain confirms yet, takes its link's observed source
    as its locator once its BFD session answers there. An established link's
    locator never moves on BFD alone.

### Positive consequences

*   Measured on the change, five runs each: every pair answered its ping
    again by the benchmark's second read, 13 seconds after a translator
    dropped a node's mappings or a public node restarted; a joiner behind a
    symmetric translator enrolled within 55 to 109 seconds. The settled
    network and the founder's loss measure as before.
*   No message or field changes: the link request and the BFD session carry
    the moves.

### Negative consequences

*   A mismatch costs an authenticated request, and the acceptor's echo, at
    most once every few seconds per link. A spoofed arrival can trigger one.
*   A candidate's locator moves on return-routability, not possession: a
    party that answers the BFD session from a spoofed source can steer a
    candidate's transit until its link request lands or its window ends, as
    its rendezvous claim already could.
*   The follow loop reads the link store and each link's observation every
    second.

## Pros and cons of the options

### Periodic link requests

*   Good, because the acceptor's existing rule does the moving.
*   Bad, because recovery waits for the cadence, and each link pays a request
    per cadence whether or not anything moved.
*   Bad, because it fixes neither the symmetric joiner, which holds no chain
    to send a request with, nor the restarted node's own record.

### Locators BFD proves

*   Good, because it needs no exchange beyond the BFD stream the link
    already runs.
*   Bad, because an established link's transit would move on
    return-routability: an off-path party able to spoof the link's port could
    steer it, where ADR-0021 asks for possession.

### The flow, confirmed in either direction

*   Good, because established links move only on possession, in whichever
    direction the request runs.
*   Good, because it fixes all three: the dropped mapping, the symmetric
    joiner, and the restarted node.
*   Bad, because candidates move on return-routability.
