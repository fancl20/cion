# Tag the nodes peers cannot dial

This proposal implements
[ADR-0027](/docs/adrs/0027-tag-the-nodes-peers-cannot-dial.md). The node
that accepts a link request echoes the requester's published rendezvous
address and answers the outcome in its reply. Each node checks at
publication whether its published host is its own. The directory entry
carries both facts, and the portal tags each node with its role and at most
one observed tag: NAT or Degraded.

[TOC]

## Summary

The portal lists each node beneath its ISD-AS with one badge, its role,
read from the founder's issued chains and the TRC
([portal.go](/pkg/apps/portal.go), [portal.js](/pkg/apps/portal/portal.js)).
Nothing in the records says whether peers can dial a node.

The facts ADR-0027 names lie within the measured provider:

*   The link service answers each link request with its own side of the
    link ([linkservice.go](/pkg/modules/topology/impl/measured/linkservice.go)).
    The provider beside it holds the directory copy whose entry names the
    requester's published rendezvous address
    ([directory.go](/pkg/modules/topology/impl/measured/directory.go)), and
    the selection loop's probe already echoes such addresses
    ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)).
*   A node's entry publishes its learned external host, or the founding
    core's domain's address
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)). Under
    the wildcard bind, the control address's default
    ([config.go](/internal/services/config.go)), a request's claimed link
    address names a port alone.
*   In the translated lab of
    [proposal 0076](/docs/proposals/0076-observe-the-network-behind-translators.md),
    nodes 3 to 6 publish their translators' gateways, which forward no port,
    and nodes 0 to 2 publish their own hosts.

## Motivation

### Goals

*   The portal shows each node's role as its first tag, then NAT or Degraded
    when peers cannot dial it.
*   The facts come from the link request, the rendezvous echo, and the
    directory publication.
*   The translated lab asserts what the founder's directory reports of each
    node.

### Non-goals

*   No loop decides on the facts: the selection loop keeps probing every
    candidate.
*   No detection of symmetric translators.
*   No re-check between establishments: a node's answer follows its latest
    establishment and each start's confirm pass.
*   No firewall on the fabric. Degraded combines the two facts the
    translated lab observes apart, and unit tests cover the combination.
*   No count of tagged nodes on the Nodes tab.

## Proposal

### The acceptor's echo

`LinkReply` gains `optional bool rendezvous_answered = 3`. The link service
records the requester's entry as it does today, releases its lock, and
echoes the requester's published rendezvous address from the provider's
directory copy before it replies. The echo is the selection loop's probe:
an ephemeral port on the control host, the zero ISD-AS, and the control
address claimed. `rendezvous_answered` carries whether the echo was
answered, and stays unset when the directory copy holds no entry for the
requester.

An answered echo costs a round trip. An unanswered one costs the exchange's
three attempts, 1.5 seconds, inside the requester's 5-second establishment
bound. The requester's acceptor answers the echo as it answers a probe,
minting the unnamed candidate a probe mints.

### The requester's answer

The provider's link client keeps the latest `rendezvous_answered` a reply
carries; a reply without one keeps the last. The selection loop's
establishments and the confirm pass both send through the link client.

### The published facts

`Entry` gains `bool translated = 4` and `bool rendezvous_unanswered = 5`,
and `DirectoryEntry` gains the two fields beside its addresses. At each
publication the node binds an ephemeral UDP port on its published host
through its socket source:

*   a bind refused with `EADDRNOTAVAIL` names a host the node does not hold,
    and the entry publishes `translated`;
*   a bind that succeeds publishes the entry untranslated;
*   any other refusal fails the publication, which retries.

`rendezvous_unanswered` is the negation of the latest answer, false before
any. The directory service stores and lists both facts as it does the
addresses.

The fabric's stacks refuse a bind on a host they do not hold with
`EADDRNOTAVAIL`, the kernel's errno.

### The portal

*   `apps.Environment` gains `NodeReach`: the facts of each entry in the
    node's directory copy, by ISD-AS. The assembly adapts it from the
    measured provider; under the file provider it is nil.
*   `portal.Node` gains `Reach`: `nat` when the node's entry is translated
    and unanswered, `degraded` when it is unanswered alone, and empty
    otherwise or without an entry. The nodes API answers it as `reach`,
    omitted when empty.
*   The page draws a tags row beneath the ISD-AS, on one line: the role tag,
    then NAT in violet or Degraded in amber. The search matches tag names.
*   The labs read the founder's facts through the assembly's `App`.

### Packages touched

| Package                              | Change                                         |
| :----------------------------------- | :--------------------------------------------- |
| `proto/node/v1`                      | The reply's echo outcome, the entry's facts    |
| `pkg/modules/topology/impl/measured` | The echo, the answer, the published facts      |
| `internal/testnetwork/fabric`        | The kernel's errno for a host no stack holds   |
| `pkg/apps`                           | The environment's facts, the records' tag      |
| `pkg/apps/portal`                    | The tag in the API and on the page             |
| `internal/services`                  | The facts from the measured provider           |
| `internal/testnetwork`               | The wildcard lab's assertion of the report     |
| `internal/testnetwork/behavior`      | The translated lab's assertion of the facts    |

## Compatibility

*   An acceptor of an earlier release leaves `rendezvous_answered` unset,
    and the requester keeps its last answer.
*   An earlier publisher's entry carries zero facts and tags nothing. An
    earlier reader ignores the new fields.

## Test plan

*   **The acceptor:** a requester whose published rendezvous address answers
    is answered `true`; one whose address is silent, `false`; one the
    directory copy lacks, unset.
*   **The requester:** a reply's answer is kept; a reply without one keeps
    the last.
*   **The publication:** a host the socket source binds publishes
    untranslated; one it refuses with `EADDRNOTAVAIL` publishes translated;
    another refusal fails the publication. The directory service
    round-trips both facts.
*   **The wildcard bind:** a node bound to the wildcard checks the learned
    host its entry publishes, never the wildcard. In the wildcard lab, the
    founder publishes its domain's address, the loopback its namespace
    holds, and reports it untranslated.
*   **The fabric:** a bind on a host no stack holds is refused with
    `EADDRNOTAVAIL`.
*   **The portal:** the records derive NAT, Degraded, and no tag from the
    facts; the nodes API answers `reach`.
*   **The translated lab:** once settled, the founder's directory copy
    reports nodes 3 to 6 translated and unanswered, and nodes 0 to 2
    neither.

## Implementation history
