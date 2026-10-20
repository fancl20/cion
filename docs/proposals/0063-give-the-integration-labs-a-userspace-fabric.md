# Give the integration labs a userspace fabric

The labs' network is the kernel's. Every node the harness boots binds
kernel sockets on the loopback the whole process shares — the forwarding
plane's link sockets ([udpip.go](/pkg/core/dataplane/udpip.go)), every
SCION socket the control plane and the applications send over
([conn.go](/pkg/libs/scion/conn.go)), the measured provider's rendezvous
acceptor, dials, and band probes
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)) —
and the labs that need the network to behave lean on kernel facilities:
they re-execute into user and network namespaces and program tc
([netem_test.go](/internal/testnetwork/netem_test.go)). No lab can put a
middlebox on the path — a userspace relay cannot stand where a NAT would
stand, the lesson the translation lab's header records — so the two
link-level proofs [proposal
0061](/docs/proposals/0061-treat-the-neighbors-locator-as-an-observation.md)
names remain undone. This proposal gives the labs a second network to
boot on: a userspace fabric, one netstack per node, its channel endpoints
and everything between them harness code, where delay, loss, and
translation are taps a lab draws. Nodes boot through the same assembly on
either network; the proofs whose subject is the kernel's own socket
semantics stay where they are.

[TOC]

## Summary

Three walls hold today. First, the middlebox wall: the kernel's wildcard
binds are dual-stack, monopolizing a port in both families for the whole
process, and its source selection for a wildcard socket varies per
destination, so a relay the peers dial directly can neither attribute nor
faithfully translate their traffic — the translation lab
([translate_test.go](/internal/testnetwork/translate_test.go)) proves the
exchange at the relay it can address and defers the link-level proofs.
Second, the runner wall: the namespace labs need a host that grants
unprivileged user namespaces and interface administration, and skip where
it declines either — the refusal path is the harness's own
([netem_test.go](/internal/testnetwork/netem_test.go)). Third, the
determinism wall: tc's ticks and the kernel's scheduling shape what the
shaped labs observe, prices no lab controls.

The fabric removes all three by owning the network outright. One gVisor
netstack per node — `gvisor.dev/gvisor` is already a direct dependency,
and the SOCKS application already pumps packets between a netstack and
the node through a channel endpoint
([app.go](/pkg/apps/socks/app.go)) — connected by a forwarder the
harness owns: packets a stack writes to its channel are routed by
destination address to the target stack's inbound side, through the taps
the lab has drawn. A delay tap replaces a netem band, a blackhole or cut
replaces a u32 filter group, and a translation boundary — a NAT the
packets traverse without ever being addressed to it — replaces the relay.
One socket seam carries the nodes onto it: the three packages that bind
kernel sockets today construct through a single source, whose default
implementation is exactly the kernel sockets they open now.

What moves: the translation lab's deferred proofs land as the boundary's
labs, and the stranded lab draws its bands as taps, leaving the
namespace. What stays: the wildcard lab and every proof whose subject is
the kernel's socket surface. What retires: the userspace translator and
the tc machinery; the namespace itself remains for the wildcard lab
alone.

## Motivation

The middlebox wall is a kernel fact, not a harness choice. A node's
rendezvous dials and its link sockets are wildcard-bound in the
configurations the labs boot, so their ports belong to the whole process
in both address families, and the source address the kernel stamps on a
wildcard socket's packet depends on the destination — a relay sees
sources it cannot map back to a socket, and a second node cannot bind the
ports the first one's wildcard holds. The translation lab recorded the
lesson and re-scoped its assertion to the exchange
([translate_test.go](/internal/testnetwork/translate_test.go)): only the
dial-a-relay path can be translated honestly on a shared kernel loopback.
What the deferred proofs need is a translation the packets traverse
transparently — mapping-carried data, reverse-translated returns, inbound
silence for unmapped destinations — which is a middlebox on the wire,
which the kernel loopback cannot give the harness and the namespace labs
can only get from nftables-grade facilities the runners decline.

The runner wall is the same wall at a different height. The stranded lab
and the translation and wildcard labs each re-execute the test binary
into a fresh user and network namespace because a shaped or exclusively
bound loopback cannot be shared with the process's other labs — and the
mechanism skips on any host that blocks unprivileged user namespaces or
declines administering the namespace's interfaces. A lab whose
prerequisites the runner can silently refuse is a lab that proves nothing
where it is most wanted.

The fabric is within reach because the repository already holds its
parts. `gvisor.dev/gvisor` is a direct dependency; the SOCKS application
runs a full netstack beside the node and feeds it from the node's own
router through a `channel.Endpoint`
([app.go](/pkg/apps/socks/app.go)), the same pump a fabric runs in
reverse; and the kernel socket calls the node makes concentrate in three
packages, behind constructors a single seam can replace.

### Goals

*   One socket seam, filed in `pkg/libs/underlay`: the three packages
    that bind kernel sockets construct through it, the default
    implementation is the kernel sockets they open today, and no wire
    byte or production behavior changes.
*   A fabric the labs boot nodes on: per-node netstacks routed by
    destination, drawing the labs' loopback host pool as plain names,
    holding no kernel port at all.
*   Taps a lab draws and lifts for any pair of hosts: one-way delay,
    loss, blackhole, cut — the stranded lab's bands expressed directly,
    with no namespace, no privileges, and no tc.
*   A translation boundary between inside hosts and the outside: mappings
    with an explicit policy, idle expiry, and rebind on demand — the
    transparent middlebox — carrying the two link-level proofs proposal
    0061 deferred: the mapping-carried data path holding a link up past
    the mapping's idle timeout, and a restart's fresh mapping re-aiming
    the former neighbor.
*   One clock under the fabric: every stack and every tap's scheduler
    take the same `tcpip.Clock`, the seam a deterministic network later
    builds on.

### Non-goals

*   No move of the kernel family: the wildcard lab keeps the kernel and
    its namespace — its subject is the default wildcard's binds across
    every interface of the family, proved by a dial from outside the node
    ([wildcard_test.go](/internal/testnetwork/wildcard_test.go)) — and
    every lab asserting the socket surface stays kernel-bound.
*   No production change: no run argument, no flag; `Run` and `BootApp`
    pass the kernel default, and the seam adds no behavior beside the
    constructor swap.
*   No synctest conversion: the labs keep real time; the shared clock is
    laid down, not exploited.
*   No IPv6 fabric, no bandwidth or MTU modeling, no reorder — the taps
    are the behaviors the labs already shape (delay, loss, blackhole,
    cut) plus translation; more can be drawn when a lab asks.
*   No ADR: no boundary moves — the seam files one interface where three
    sites called the kernel directly, and the fabric lives under the
    labs' roof.

## Proposal

### The socket seam

`pkg/libs/underlay` — the facts of the UDP/IP network the data plane
shares with the node's sockets — gains the socket source: a UDP listener
returning a conn with the operations the sites use (`ReadFromUDP`,
`WriteToUDP`, the batch pair, deadlines, `LocalAddr`, buffer sizing,
`Close`), beside a TCP listener for the founder's HTTPS bind. The kernel
implementation is what the sites open today: the provider's
`udpBatchConn` becomes the seam's kernel conn wholesale, and the family
selection its `newUDPConn` performs under wildcard binds stays with it,
answering the kernel's semantics. The fabric implementation binds the
concrete address it is given on the node's stack — endpoint, `Bind`,
`gonet.NewUDPConn` — where per-family ports and immediate release are the
stack's own facts.

The three sites construct through the source: the provider's
`newUDPConn`, `scion.NewConn`'s bind, and the measured provider's
rendezvous acceptor, `RendezvousEcho` dials, and band probes. The
founder's HTTPS listener ([https.go](/internal/services/https.go))
constructs through the TCP side, so a fabric founder's coordination
surface rides the fabric and its port 443 is its stack's alone — no
namespace needed to keep two founders' ports apart. Everything above the
constructors is untouched: the provider's receive and forward loops, the
BFD session's raw writes, the SCION conn's reads and deadlines, and the
QUIC transports that ride it. The fabric's `ReadBatch` returns the first
datagram then whatever is immediately ready — the shape
`MSG_WAITFORONE` gives — and `WriteBatch` writes through; batching
remains a fast path the kernel owns.

The source enters at the boot, beside the run arguments — a parameter
`Run` and `BootApp` fill with the kernel default and the labs' boot fills
with the fabric's. It is not a parsed argument and not a `NodeConfig`
field; the node hands it to the provider, its conns, and the measured
provider's config, which today already carries a conn factory
([node.go](/internal/services/node.go)).

### The fabric

A new package under the labs' roof, `internal/testnetwork/fabric`, boots
the network a lab draws. Each node gets one gVisor stack — IPv4 with UDP
and TCP transports, the SOCKS application's own recipe
([app.go](/pkg/apps/socks/app.go)) — with one NIC on a `channel.Endpoint`
sized to the underlay's jumbo datagram (`underlay.BufferSize`), holding
the host the lab drew from the pool [proposal
0036](/docs/proposals/0036-allocate-the-labs-loopback-hosts.md) keeps
handing out. The draws become plain names: no kernel interface carries
them, and two labs may draw overlapping nothing or identical hosts
without meeting, for each stack routes its own.

A forwarder drains every stack's channel and routes by destination
address to the target stack's inbound side — `ReadContext` out,
`InjectInbound` in, the pump the SOCKS application already runs. Between
drain and inject stand the taps the lab has drawn for the packet's
source and destination pair. The fabric's clock is one
`tcpip.Clock` — every stack takes it at `stack.New`, every tap's
scheduler runs on it — so a delayed packet, a mapping's idle expiry, and
the stacks' own retransmission timers all read one time.

### The taps

The lab draws a tap for a pair of hosts and lifts it, the stride
[netem_test.go](/internal/testnetwork/netem_test.go) already gives with
`steer` and `lift`, minus the kernel beneath:

*   **Delay** holds a packet on the clock for the drawn one-way time, per
    direction — the netem bands the stranded lab steers by pair.
*   **Loss** drops the packet, wholly or by fraction.
*   **Blackhole** drops both directions of a pair while it stands.
*   **Cut** drops a pair's packets and lifts to restore them.

### The translation boundary

The lab draws a boundary between inside hosts and the outside: an address
the boundary owns — the gateway the translated node dials through — and
the upstream hosts beyond. Packets from inside to outside cross it and
are rewritten: the source becomes the gateway under a port the boundary
draws from the translator's own band
([translate_test.go](/internal/testnetwork/translate_test.go)), one
mapping per inside socket under the endpoint-independent policy the
translator held — other policies drawable when a lab asks. Packets from
outside to the gateway's drawn ports are reverse-translated to the inside
socket the mapping records; every other inbound packet to a drawn port is
dropped, the silence a real translation gives. A mapping retires after
its idle window on the fabric's clock, and the lab can force a fresh one
— the changed mapping the restart proof needs. The rewrite renews the IP
and UDP checksums; the reverse-translated delivery back to the inside
socket is the proof it renewed them right.

### The labs

*   **The boundary's proofs.** The translation lab's deferred pair lands:
    a translated joiner's link carrying its BFD stream and data through
    the mapping, holding Established past idle timeouts the mapping
    outlives only because the stream refreshes it, its mapping expiring
    under silence and the link falling with it; and a translated node's
    restart drawing a fresh mapping that the founder's entry re-aims —
    the confirm's agreement rule reading the observation the mapping
    spells — the link re-establishing over the new mapping. The
    exchange-level assertion the current lab holds keeps its shape, the
    boundary answering for the relay.
*   **The stranded lab** draws its bands as taps — the one-way delays,
    the blackholes, the cut — and leaves the namespace. Its topology,
    pacing, and assertions are unchanged.
*   **The kernel family** stays as it is. The wildcard lab keeps its
    namespace; the labs whose evidence is the kernel's socket behavior
    keep the kernel.

### Packages touched

| Package                              | Change                                            |
| :----------------------------------- | :------------------------------------------------ |
| `pkg/libs/underlay`                  | The socket seam and its kernel implementation     |
| `pkg/libs/scion`                     | `NewConn` constructs through the seam             |
| `pkg/core/dataplane`                 | `udpBatchConn` becomes the kernel conn; the provider takes the source |
| `pkg/core/webpki`                    | The HTTPS listener constructs through the seam    |
| `pkg/modules/topology/impl/measured` | The acceptor, dials, and band probes construct through the seam |
| `internal/services`                  | The boot's socket-source input, flowing to the three sites |
| `internal/testnetwork`               | The fabric, taps, and boundary; the labs; the tc machinery retires |

### Migration

Each commit keeps the tree green:

1.  **The seam.** The source in `underlay`, the kernel implementation
    from `udpBatchConn`, the three sites constructing through it, the
    boot input. The kernel family's suite passes unchanged — the default
    opens the same sockets.
2.  **The fabric.** The package, the forwarder, the taps, the clock, and
    the fabric's own proofs; a first lab boots two nodes on it.
3.  **The boundary.** The translation taps and the two deferred proofs;
    the userspace translator retires.
4.  **The stranded lab.** Its bands become taps; `openTrafficControl`,
    `shapeLoopback`, `steer`, and `lift` retire with the go-tc import;
    `ownNetns` and `raiseLoopback` stay for the wildcard lab.

## Compatibility

Production behavior is identical: the seam's default opens the same
kernel sockets, no wire bytes change, and the fabric exists only in the
labs' process. The moved labs' evidence is re-scoped by the move, and the
scoping is stated where the labs live: a fabric lab proves protocol
behavior on a modeled network — netstack's, not Linux's, with per-stack
port spaces, per-family wildcard binds, and always-computed checksums —
while the kernel family keeps proving the socket surface. That trade is
the point of having both: a lab picks its network by what its assertion
names.

Parallelism widens. Fabric labs hold no kernel ports, so they overlap any
lab freely — the collision [proposal
0036](/docs/proposals/0036-allocate-the-labs-loopback-hosts.md) fenced
with the host pool cannot occur between a fabric lab and anything — and
the namespace labs that remain shrink to the wildcard one. `go.mod`
gains nothing: `gvisor.dev/gvisor` is already direct.

## Test plan

*   **The seam:** the kernel family's full suite passes unchanged,
    `go test -race -count=2` — the default construct is the same sockets
    the sites opened before.
*   **The fabric:** routing delivers by destination between stacks; a
    delay tap spaces arrivals by the drawn one-way time on the fabric's
    clock; loss, blackhole, and cut drop their pairs and lift restores.
*   **The boundary:** both directions translate; an idle mapping expires
    on the clock; unmatched inbound to a drawn port is dropped; a forced
    rebind changes the mapping; the reverse-translated delivery returning
    to the inside socket proves the checksum renewal.
*   **The deferred proofs:** the mapping-carried data path holds the
    link Established past idle timeouts and falls when the mapping
    expires under silence; the restart's fresh mapping re-aims the
    founder's entry and the link re-establishes over it.
*   **The stranded lab:** its assertions hold on the drawn taps, in no
    namespace, on a host that grants the process nothing.
*   **The suite:** the full gate passes with both families beside each
    other.

## Implementation history

*   The seam landed first: the socket source in `underlay` — the kernel
    conn the provider's `udpBatchConn` was, beside the TCP listener the
    founder's HTTPS bind takes — with the three sites constructing
    through it and the boot carrying the source beside the run arguments
    ([sockets.go](/pkg/libs/underlay/sockets.go),
    [conn.go](/pkg/libs/scion/conn.go),
    [udpip.go](/pkg/core/dataplane/udpip.go),
    [app.go](/internal/services/app.go)). The kernel family's suite
    passes unchanged; the family selection stays with the kernel conn,
    naming the family under a hint where the provider's link sockets
    always pinned it.
*   The fabric, its taps, and the boundary landed under the labs' roof:
    one gVisor netstack per node — IPv4 admitting the loopback pool's
    hosts inbound — drained by a forwarder that routes by destination
    through the drawn taps and the drawn boundary, on one clock
    ([fabric.go](/internal/testnetwork/fabric/fabric.go),
    [taps.go](/internal/testnetwork/fabric/taps.go),
    [boundary.go](/internal/testnetwork/fabric/boundary.go)). The
    translation's checksums renew over zeroed checksum fields, both the
    IP header's and the UDP's — the boundary's one real trap.
*   The boundary's fidelity closes the reach a userspace relay cannot: the
    inside is unreachable from the outside, every crossing named for the
    gateway — which is what makes the neighbors' traffic ride the links,
    whose locators the observations spell. Without it the founder reaches
    the translated node's real address directly, mints entries aimed at
    it, and their sessions' BFD tears at the translated session.
*   The translation lab rides the fabric: the exchange-level proof keeps
    its shape, the mapping-carried data path holds Established across
    idle windows and falls with the mapping under silence, and the
    restart proof lands as the fresh mapping the founder's fresh entry
    records — a drawn port the stopped node's socket never spelled. The
    re-establishment over the changed mapping stays deferred: the
    returning node's confirm rides its link's verdict, and the verdict
    waits on the very locator the confirm would re-aim — a cycle that
    stands between a plain relocated node and its confirm too, the
    relocation gap [proposal
    0061](/docs/proposals/0061-treat-the-neighbors-locator-as-an-observation.md)
    left unproven at the kernel, now named by the fabric.
*   The stranded lab draws its bands as taps and leaves the namespace; the
    tc machinery retired with the go-tc import, `ownNetns` and
    `raiseLoopback` staying for the wildcard lab alone
    ([stranded_test.go](/internal/testnetwork/stranded_test.go),
    [netns_test.go](/internal/testnetwork/netns_test.go)).
*   The labs that boot whole tiers run in processes of their own
    ([solo_test.go](/internal/testnetwork/solo_test.go)) — the isolation
    the namespace re-exec once gave them by accident, kept now that the
    fabric needs neither namespace nor privileges. Under the race
    detector a full tier crawls late in a suite process that has hosted
    every other lab's nodes — the same lab that joins in half a minute
    alone takes thirty inside it — and a fresh process runs it at its own
    pace. Each inner run draws its loopback hosts from a band of its own
    above every draw the outer and the earlier inner runs can reach, for
    a fabric node's resident applications still bind their fixed ports on
    the kernel loopback the processes share.
