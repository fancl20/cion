# Send unenrolled peers the founder's beacons

This proposal has a node send a peer that has not enrolled the founder's
beacons alone. A joiner's bootstrap beacons then name one origin, the
founder, so its first fetch reaches the founder without taking turns among
the cores, and the joiner stops when that origin fails the WebPKI check
instead of retrying.

[TOC]

## Summary

Today:

*   **A joiner takes turns among the cores.** Before it pins a TRC, a node
    cannot tell which core founded the network: the founder is the holder
    of the pinned TRC's sensitive voting certificate. `BootstrapCore`
    alternates the enrollment fetch across the origins of the bootstrap
    beacons, freshest first
    ([beacon.go](/pkg/core/controlplane/beacon.go)). A turn at a core other
    than the founder fails its WebPKI handshake and costs an enrollment
    retry, five seconds ([lifecycle.go](/pkg/core/trust/lifecycle.go)).
*   **The first turn often misses.** Every node sends every neighbor its
    five freshest beacons, whatever their origin, and a core originates its
    own on every link. A joiner under another core hears that core's
    beacons fresher than the founder's, the reason the alternation exists
    ([0039](/docs/proposals/0039-make-the-path-layer-multi-core.md)), and
    takes its first turn there.
*   **A joiner never learns it was misled.** A turn at a core that is not
    the founder fails as any wrong turn does, so a neighbor that sends only
    such cores' beacons keeps the joiner retrying for good.

## Motivation

### Goals

*   A joiner's first fetch reaches the founder: one bootstrap path, with no
    turns among the cores.
*   A joiner stops, naming the neighbor, when the beacon it rides leads to
    a core that does not hold the founder's certificate.
*   A joiner whose neighbor has not pinned a TRC waits for it, with no
    fallback.
*   Both topology providers, and a restart before the pin, behave the same,
    and nothing on the wire changes.

### Non-goals

*   Authenticating a joiner's bootstrap beacons: before its pin it verifies
    nothing, and the WebPKI handshake stays the check
    ([ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md),
    decision 4).
*   The beacons an enrolled peer receives, which beacon selection decides.
*   A neighbor that drops the joiner's traffic, or sends it no beacon,
    stalls it as today.

## Proposal

### The sender

*   **A peer that has not enrolled receives the founder's beacons alone.**
    A node propagates to it only the beacons the founder originated, the
    founder its pinned TRC names. A core other than the founder originates
    nothing toward it, and the founder originates as today. A node that
    has not pinned a TRC stores no beacons and sends none, as today. This
    narrows the fixed bounded set of
    [ADR-0004](/docs/adrs/0004-discover-paths-with-spec-aligned-beaconing.md),
    decision 1, for the peers that have not enrolled.
*   **A peer has enrolled once its handshake presents a chain.** The
    beacon channel verifies no receiver, because a receiver may not have
    enrolled yet ([mtls.go](/pkg/libs/scionrpc/mtls.go)). It records, per
    peer, whether the receiver's certificate at the last handshake was a
    chain the pinned TRC anchors, naming the peer, or the ephemeral
    certificate of a node without a chain. A peer without a record has not
    enrolled, so a new link's first pass carries the founder's beacons
    alone.
*   **A node that obtains a chain reopens the connections it answered
    without one.** Its endpoint closes a connection whose handshake
    presented the ephemeral certificate at the connection's first request
    after the node holds a chain, refusing that request. The peer's next
    beacon handshakes anew and finds the chain. The client side already
    retires the connections it dialed before it held a chain
    ([client.go](/pkg/libs/scionrpc/client.go)).

### The joiner

*   **The joiner aims at the origin of its bootstrap beacons.** Before its
    pin, its founder route takes the origin of its freshest bootstrap
    beacon, the founder's when its neighbors follow the rule.
    `BootstrapCore` takes no turns. After the pin, the route takes the
    founder the TRC names, as today.
*   **The joiner stops when that origin is not the founder.** A first
    enrollment whose WebPKI handshake meets a certificate that does not
    name the founder's identity stops the node. The error names the
    origin, the neighbor whose beacon the route rode, and the identity:
    the neighbor sent a beacon the founder did not originate, or the
    identity is not the founder's. A missing route, a timeout, or any other
    failure retries as today.
*   **The joiner waits for a neighbor that has not pinned.** Such a
    neighbor sends nothing, and the enrollment retries every five seconds
    until a beacon arrives, as it does today before any beacon.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/scionrpc` | The beacon channel records each receiver's enrollment from its handshake; the endpoint closes the connections it answered without a chain once it holds one |
| `pkg/core/controlplane` | An unenrolled peer receives the founder's beacons alone; `BootstrapCore` names the freshest origin |
| `pkg/core/webpki` | A certificate that does not name the founder's identity fails the dial with a mark |
| `pkg/core/trust` | That mark stops a first enrollment before the pin |
| `internal/services` | The founder route before the pin, and the stop naming the origin and the neighbor |

## Compatibility

Nothing on the wire changes. A neighbor of an earlier release sends every
core's beacons, so a joiner behind it may aim at a core that is not the
founder and stop. Networks start afresh, as none is in production.

## Test plan

*   **The sender.** A peer without a record, or whose handshake presented
    the ephemeral certificate, receives the founder's beacons alone and no
    beacon a core other than the founder originates. A peer whose
    handshake presented a chain receives the best set.
*   **The record.** A handshake presenting the ephemeral certificate
    records the peer as not enrolled, and one presenting a chain the TRC
    anchors as enrolled. A receiver that obtains a chain is recorded
    enrolled after the sender's next send.
*   **The endpoint.** A connection answered with the ephemeral certificate
    is closed at its first request once the node holds a chain, the
    request refused; one answered with the chain stays open.
*   **The joiner.** Before the pin, the founder route takes the freshest
    bootstrap origin. A first enrollment that meets a certificate not
    naming the identity stops the node, naming the origin, the neighbor,
    and the identity; a timeout retries.
*   **The labs.** A core joining through an authoritative holds the
    founder's beacons alone before its pin and enrolls at its first
    attempt. The labs and benchmarks pass, and the site and NAT labs
    report their joins' first attempts against the commit before.

## Implementation history

*   The record: the beacon channel's dial records each receiver's
    enrollment in a `scionrpc.Receivers` from the certificate the
    receiver's handshake presented — a chain the pinned TRC anchors,
    naming the peer — and `PeerClient.Enrolled` reads it
    ([client.go](/pkg/libs/scionrpc/client.go),
    [peerclient.go](/pkg/core/controlplane/peerclient.go)). A core the TRC
    names counts as enrolled whatever the record.
*   A probe beside the rule: the record forms only on a dial, so a node
    holding no founder beacon would never record its enrolled peers and
    send them nothing — a node restarted while the founder is down, say.
    Each propagation pass probes every peer the record holds as not
    enrolled with a request no service answers
    ([beacon.go](/pkg/core/controlplane/beacon.go)).
*   The endpoint closes a connection it answered with the ephemeral
    certificate at its first request once the node holds a chain, with
    H3_REQUEST_REJECTED: the client's transport retries a request without
    a body, the probe, on a new connection, whose handshake updates the
    record within the same call ([serve.go](/pkg/libs/scionrpc/serve.go),
    [mtls.go](/pkg/libs/scionrpc/mtls.go)).
*   The joiner: `BootstrapCore` names the freshest origin, and
    `BootstrapNeighbor` the neighbor that sent its beacon for the stop's
    error. Before the pin the founder route takes `BootstrapCore`'s
    origin as the founder, the one-hop shortcut included; after it, the
    path provider's route to the founder covers both former branches
    ([controlplane.go](/internal/services/controlplane.go)).
*   The stop: the core client marks a handshake that meets a certificate
    not naming the identity (`x509.HostnameError`) with a
    `trust.NotFounderError` naming the core reached
    ([remote.go](/pkg/core/webpki/remote.go)); the enrollment pass returns
    it as terminal before the pin
    ([lifecycle.go](/pkg/core/trust/lifecycle.go)), and the role loop names
    the neighbor and the identity.
*   The tests landed as planned, with the lab's subject moved: a core
    opens a bootstrap slot for every core it hears after its pin, so the
    path lab's node under the authoritative, a non-core, carries the
    assertion that it holds the founder's slot alone
    ([corepath_test.go](/internal/testnetwork/corepath_test.go)); a new join
    lab stops a joiner that names an identity the founder does not hold
    ([join_test.go](/internal/testnetwork/join_test.go)). Mutations 16 of
    16 killed.
*   Benchmarks against the commit before, in the site and NAT labs, which
    join through a second core: no enrollment took a turn at a core other
    than the founder, against 8 such turns in nine site runs and 11 in six
    NAT runs before, and the NAT lab's founder-down joins took 15 seconds at
    most, against up to 35. In the site lab joined from inside, one node
    joined after 26 seconds instead of 21, waiting a pass longer for a
    beacon of the founder. The site lab joined both ways settled after a
    median of 13 changes in 10.7 minutes over nine runs, against 11 in 8.5
    before, with overlapping ranges (8.5 to 20.7 minutes, against 7.3 to
    19.2), and reached every pair in all nine runs, against seven of nine
    before. The other site and NAT benchmarks held.
