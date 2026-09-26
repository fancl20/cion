# Serve egress as a SOCKS service

This proposal implements
[ADR-0012](/docs/adrs/0012-serve-egress-as-an-overlay-socks-service.md):
internet egress becomes a service an advertised address names — SOCKS5,
RFC 1928 CONNECT and UDP ASSOCIATE, served on a node's own tailnet
address through a netstack the node already knows how to run, every node
offering by default. The service is an application of its own —
`pkg/apps/socks`, assembling beside the WireGuard application and
borrowing its router the way the coordination application borrows its
store — carrying no selection semantics of its own: which applications a
node runs is the applications architecture record's to decide, and this
service lands as a unit that record can select. The netmap grows every
node's own address as one more single-IP route beside the allocated host
/32s; the node delivers its own address to the service — the routing fact
the record presumed without naming; the echo-ICMP relay retires with the
default it served; and the WireGuard configuration file retires into run
arguments — the file is the section that escaped
[ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)'s
retirement of the node file, and this landing returns it.

[TOC]

## Summary

What exists is the exit without a path to it, and the exit is a mode of
an application rather than a thing of its own. The egress machinery of
[proposal 0006](/docs/proposals/0006-wireguard-gateway-application.md)
still builds in `pkg/apps/wireguard/egress.go`: a gVisor netstack on a
channel link, a promiscuous, spoofing NIC claiming the slice's first
address, TCP and UDP forwarders, the flow bound `maxEgressFlows`, the
idle sweep `egressIdle`, the dial timeout `egressDialTimeout`, and the
splice and per-flow socket mapping beneath them. Nothing feeds it:
`Inbound`, the machinery's entry, has had no production caller since
proposal [0022](/docs/proposals/0022-tailscale-coordination-service.md)
deleted the router's egress plumbing with the host default it served.
The address the record's service answers on is unroutable on the node
that holds it, `applyDirectory` skipping the node's own entry and the
router holding no route to it. The netmap carries the allocated host
/32s alone. And the machinery is switched by a field of the WireGuard
application's configuration file — one more concern folded into an
application that already carries the mesh and the hosts.

This proposal makes the service an application and lights it: the SOCKS
application rides beside the WireGuard application, owning the netstack,
the listener, and the flow machinery the egress already built, its
forwarders left behind with the default they served. Every node offers:
the netmap grows each node's own address — the slice's first, which the
allocator never issues — as one more single-IP route, nothing new rides
the directory entry, and the router delivers the node's own address
exactly when the application runs. The echo-ICMP relay retires. The
WireGuard configuration file retires in the same landing — the slice and
the shared host port promote to `--slice` and `--host-port`, the egress
field dies without ever being promoted, and `--wireguard-config` with
its loader goes. No kernel state, no store change, no client-side
software: any SOCKS-aware application becomes a client, and one login
serves every node.

## Motivation

ADR-0012 decided the shape; the code is one seam away from it on each of
three fronts, and each seam is a fact in the tree:

*   The unfed exit. `egress.Inbound` is the machinery's entry — TCP and
    UDP into the netstack — and nothing in production calls it. The
    forwarders' input was the default-routed packets the host model no
    longer produces: with no default anywhere, a flow addressed to an
    internet destination cannot reach the node that would terminate it.
    The machinery beneath stands idle beside them — the flow tables, the
    bound, the sweep, `spliceConns`, the one-socket-per-flow UDP mapping.
*   The unroutable own address. `applyDirectory` skips the node's own
    entry when it builds the router's table — mesh slices for the peers,
    host /32s for the owned — so the slice's first address counts
    unroutable on the node that holds it no less than on any other, and
    the record's "delivered in-process" has no delivery to ride.
*   The stranded file. The WireGuard configuration file is the section
    that moved out of the node file when ADR-0008 retired it into run
    arguments — three fields left (`subnet`, `listenPort`, `egress`) of
    the surface that record closed, still parsed by its own loader behind
    `--wireguard-config` while every other argument of the node stands on
    the command line.

Everything the service needs already stands:

*   The reply path. Packets the netstack produces — replies and relays —
    already flow to the router (`drain`, `sink`, `routeFromEgress`) and on
    to whatever device the destination claims; the service's answers ride
    it unchanged, and it moves with the machinery.
*   The reserved address. The coordination allocator starts after the
    slice's first address and reserves the node's own in its budget, so no
    host can hold the serving address and no route can collide with an
    allocated /32.
*   The map's propagation. The map comparison is a whole-map equality and
    the stream's ticker re-reads the registry, so a node's arrival or
    departure reaches a connected host with no new change machinery.
*   The mesh's carriage. Every node's mesh device already carries every
    other node's slice; a far host's packets to a serving address ride
    routing that exists, and the delivery is the serving node's alone to
    add.
*   The borrowing precedent. The coordination application already
    assembles beside the WireGuard application and borrows its store
    through a narrow interface; a service application borrowing the router
    the same way is the assembly's own pattern, not a new one.
*   The client. Any SOCKS-aware application names a destination, and the
    destination is the one selector every client can already express.

### Goals

*   The application: the SOCKS service is an application of its own,
    assembling beside the WireGuard application and borrowing its router,
    owning the netstack, the listener, and the flow machinery — RFC 1928
    CONNECT and UDP ASSOCIATE, no authentication beyond method none, the
    listener in-process and binding the tailnet alone.
*   The shape: the application is a unit the applications architecture
    record to come can select — a thing of its own beside the WireGuard
    application — and it decides nothing about selection itself: no
    surface, no flag, no semantics of choosing among applications.
*   The map: every node's own address joins the routed addresses as one
    more single-IP route — the same form the allocated host /32s take,
    never a covering prefix — with nothing new on the directory entry;
    one login serves every node, and switching exits changes no state
    anywhere.
*   The delivery: the node's own address becomes a routed destination
    exactly when the application runs, the machinery's inbound gains its
    first production caller, and the reply direction stands as it is.
*   The accounting: the service runs on the flow machinery with its values
    unchanged — the bound, the idle sweep, the dial timeout — the outbound
    legs the node's own sockets as today.
*   The dialect, pinned end to end: method none only; a UDP ASSOCIATE
    reply naming the exit's true tailnet address and the relay port; the
    relay answering the association peer's arrival address; an
    association's lifetime its TCP connection; fragmented datagrams
    refused; BIND refused; nothing relaying UDP inside TCP; the payload
    budget stated.
*   The retirements: the echo-ICMP relay goes whole, with
    `golang.org/x/net/icmp` out of the module's direct dependencies, and
    the WireGuard configuration file goes with its loader — ADR-0008's
    closed surface closed. ADR-0012 is accepted at landing and the design
    documents follow the code.

### Non-goals

*   No application selection: which applications a node runs — the
    surface an operator would use to withhold this offer — is the
    applications architecture record's decision; this proposal adds one
    application, shapes it as a selectable unit, and adds no surface,
    flag, or semantics for choosing among applications.
*   No per-host egress policy: a serving node serves every host the
    registry admits alike — no allowlist, no quota, no per-host
    accounting; with one operator per ISD it would be ceremony without a
    threat model.
*   No authentication beyond method none: no RFC 1929
    username/password, no GSS-API, no credential surface of any kind —
    tailnet reachability is the admission, membership the one policy.
*   No default route and no covering prefix anywhere in the map:
    single-IP routes alone, and no route-all preference asked of any
    host.
*   No UDP inside TCP and no ICMP successor: UDP keeps flow semantics or
    it is not served, and internet ICMP is gone with nothing drafted to
    inherit it.
*   No file-borne configuration: the run arguments are the surface,
    nothing reads a file, and no field retires into another file later.
*   No change to how an application's services ride the node's assembly —
    the seam [proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)
    is deciding; this proposal adds an application, it does not move the
    assembly.
*   No change to the directory store or its entries: the address the map
    adds is the first address of the slice the node entry already
    carries, and the store, its proto, and its contract tests stand as
    they are.
*   No client-side work: nothing in this repository must change for a
    client to use the service — standard SOCKS clients are the
    compatibility surface, exercised out-of-repo against the documented
    endpoint the way 0022's capability pin already treats the tailnet
    client lines; the only SOCKS client written in-tree is the minimal
    test double.
*   No SOCKS5 features beyond the dialect: no BIND, no fragmentation, no
    association lifetime past its TCP connection, no idle bound distinct
    from the flow bound.
*   No change to the mesh, the trust fabric, or the coordination
    service's registration and admission; no IPv6 service — the netstack
    is IPv4 and so is the tailnet.

## Proposal

### The SOCKS application

The service is an application of its own, `pkg/apps/socks`, and the
machinery moves to it: the netstack of `pkg/apps/wireguard/egress.go`,
the flow tables, the bound, the idle sweep, the dial timeout, the splice,
and the one-socket-per-flow UDP mapping all become the application's own,
and the WireGuard application's egress wiring — the configuration field,
the construction, the router alias — deletes with them. The forwarders do
not come along: their role, terminating flows addressed to internet
destinations, died with the default, and the only input they could catch
is a flow to the node's own address at a port nothing listens on, which
they would terminate and then dial back at the node itself — a connection
answered then reset, plus a wasted flow against the bound. The
application's netstack installs no forwarders at all; the listener is its
serving surface, and an unlistened port is refused by the stack's
no-listener path, the honest answer for a port with nothing behind it.

The application assembles beside the WireGuard application and borrows
its router, the way the coordination application borrows its store: the
node's own address is delivered to the application's inbound path, and
the packets the netstack produces — replies and relays — flow back to the
router and on to whatever device the destination claims. Without the
WireGuard application there is nothing to borrow, and the SOCKS
application does not assemble — a node that serves no hosts serves no
one. The listener binds the node's own address — the slice's first, the
address the allocator never issues — at the registered SOCKS port, 1080,
a code constant beside the flow bounds, so no argument grows and every
client knows it by convention. It is the repository's first in-process
listener, and the stack's own demux is the separation it needs:
transport delivery tries registered endpoints before any fallback, so a
flow addressed to the node's own address at the service's port reaches
the listener and nothing else changes hands.

The application carries no selection semantics: it assembles whenever the
WireGuard application does, every node offering by default. When the
applications architecture record draws the node's application surface,
this application is already a unit that record can select — and its
offering, the first address in the map, narrows with it.

The dialect is the record's, pinned: RFC 1928; method negotiation offers
none and refuses the rest — tailnet reachability is the admission, hosts
existing only through registration at the one seam; CONNECT and UDP
ASSOCIATE are served; BIND is refused; a datagram with `FRAG` set is
refused; nothing relays UDP inside TCP; and the payload budget an
application should assume is stated beside the overlay MTU — 1242 bytes,
the tunnel's 1280 less the IPv4 and UDP headers and the ten-byte SOCKS
UDP header, advisory on the inbound wire where the router's MTU
enforcement already bounds the reply.

CONNECT is the old `handleTCP` told from the other end: one accepted leg
spliced to one `net.Dialer` leg under the standing dial timeout,
`spliceConns` carrying both directions with half-close propagation, the
flow entering the TCP table, counting against the bound, and swept by
the idle sweep. UDP ASSOCIATE answers with the exit's true tailnet
address and the relay endpoint's port; the endpoint is a bound UDP socket
on the netstack at the node's own address, an ephemeral port the bind
allocates. Inside one association, each destination the client names
gets one outbound socket of the node's own — the socket itself the reply
mapping, the shape the UDP mapping already is — one flow against the
bound, swept by idle and by the association's teardown alike. Replies
answer the association peer's arrival address: a datagram returns to the
source the client's datagrams arrived from, not the address its TCP
request named. An association's lifetime is its TCP connection — the
leg's close sweeps the association's sockets at once — and refusal is
told, not implied: at the bound, a CONNECT or an association is answered
with a SOCKS error on its own TCP leg, the client learning the refusal's
cause rather than watching a silent drop.

### The netmap carries every node's address

The netmap's routed addresses are the registry's whole occupied space,
and the registry's occupied space grows one address per node: beside
every allocated host /32, each node entry contributes the first address
of its slice as one more /32 — the same single-IP form, the same sort,
riding `AllowedIPs` and `Addresses` together as the landed shape already
does. Nothing new rides the entry, and the store, its proto, and its
contract tests stand untouched: the address was always derivable; it
simply had no service behind it. The form is the invariant, not a
convenience: a single-IP Tailscale address is a route the client lines
hold unconditionally, where a covering prefix — the range itself, or the
slice — is an advertised subnet route that sits behind the client's own
route-all preference, a preference no host of this network is asked to
hold. The addition cannot collide with an allocation: the allocator
starts after the slice's first address and reserves the node's own, so
the serving address is never a host's and the host /32s are never the
node's. Propagation is free — the map comparison is a whole-map
equality, so a node's arrival or departure changes the answer and the
standing resend ticker carries the new map to every connected host, a
full map still the smallest correct answer. One login serves every node,
and the exit a flow uses is which tailnet address it is sent to:
switching exits writes nothing anywhere, because there is nothing to
write. When the applications architecture record draws selection, this
rule narrows from every node's address to the offering nodes' — a
narrowing that lands in that record alone.

### The node delivers its own address

The service's address is unroutable today, and not only on hosts: the
node's own table skips its own entry — mesh slices from the peers, host
/32s from the owned — so a packet addressed to the slice's first address
counts unroutable exactly where the record says it is delivered
in-process. This landing is the routing change the record presumed: when
the SOCKS application assembles, the router's table gains one more
delivered destination — the node's own overlay address, exact, handed to
the application's inbound path — installed with the application and
absent without it. The delivery is address-exact, never the slice: the
node's hosts keep their /32s to the host device, the peers' slices keep
their routes to the mesh devices, and an address in the node's own slice
that is neither a host's nor the node's own stays unroutable as it is
today. The inbound path gains its first production caller here — packets
from the host device and the mesh devices alike, delivered by destination
rather than by arrival — and the reply direction already stands. The
mesh carries a far host's packets to the serving node's own mesh device
on routing it already holds; the carriage is every node's slice routing,
and the delivery is the serving node's alone to add.

### The echo relay and the file retire

Internet ICMP is gone — SOCKS carries TCP and UDP — and the relay that
served it goes whole: `echo.go` deletes from the WireGuard application,
the relay and its socket adapter, the `EchoSocket` knob, and the echo
count in the flow accounting going with it (the machinery's inbound, ICMP
case and all, has moved to the SOCKS application, which installs none).
The header helpers the package's tests lean on — `netipToAddress`,
`internetChecksum` — move with the machinery, their consumers unchanged.
`golang.org/x/net/icmp` leaves the module's direct dependencies, the
relay its only importer. The echo suites retire with the relay, and the
retirement's own negative checks replace them: an ICMP packet addressed
to the node's own address is dropped and counted, never relayed.

The WireGuard application's configuration file retires whole:
`--wireguard-config`, `LoadWireguardConfig`, and `ConfigWireguard` go —
the two fields the file still carried promote as `--slice` and
`--host-port`, the slice's grammar the one 0022 narrowed (a prefix the
tailnet range contains) moved from the loader's check to the argument's
validation, and no slice running no WireGuard application, the empty
path's behavior carried over. The egress field dies without ever being
promoted: the application it switched is gone, and the offering it would
have named is every node's default. The retirement's bookkeeping is the
flag parser's own: a deployment still passing `--wireguard-config` fails
at the parse, the coordinated upgrade the file's `RejectUnknownMembers`
performed now performed on the command line — the same step moves a
deployment from a file to arguments, and no intermediate state exists.

### Records, documents, and the boundaries

ADR-0012 is amended as the draft it still is — its sovereignty driver and
its third decision restated: every node offers by default, nothing new
rides the entry, and the offer's surface is the applications architecture
record's to draw — and it flips to accepted in the implementing commit.
ADR-0005, ADR-0008, and ADR-0011 stand as written, their narrowings
carried by the records that performed them — this one finishes what
ADR-0008 started. Two boundaries are drawn once here. The applications
architecture record to come decides which applications a node runs; this
proposal adds one application, shaped as a unit that record can select,
and decides nothing about selection. And
[proposal 0023](/docs/proposals/0023-serve-the-coordination-endpoint-from-the-node.md)
decides how an application's services ride the node's assembly — the
coordination endpoint onto the one server holding the identity;
different questions on adjacent ground, whichever lands later carrying
the wiring between them. The design documents follow the code: the
architecture's endhost section names the service — every node an offered
exit, SOCKS at the serving address, no default, internet ICMP gone; its
applications section gains the SOCKS application beside the WireGuard and
coordination ones; and its one-view sentence still serving hosts through
an embedded gateway is rewritten for tailnet clients at last. The
security model's host-to-node boundary gains the service's shape — every
node offering by default, the offer's withholding left to the record that
draws the application surface — and its residual risk carries what the
record owns: every node is an internet exit for every admitted host,
no per-host egress restriction has a mechanism, and the service's
reachability is the tunnel's reachability, the host-side relay limit 0022
recorded among the coordination record's consequences.

## Test plan

*   **Unit, the SOCKS application:** against the egress suite's
    in-process lab, with a minimal hand-rolled RFC 1928 client — the
    vendored `golang.org/x/net/proxy` speaks CONNECT only, and no UDP
    ASSOCIATE client exists in the tree, so the double is written, not
    found. CONNECT splices both directions through a loopback echo
    standing for the internet; a destination that refuses answers a SOCKS
    error; method negotiation offering anything but none is refused; BIND
    is refused. UDP ASSOCIATE: the reply carries the exit's true tailnet
    address and the relay's port; a datagram relays to its destination
    and the reply returns with the header rewritten; a datagram with
    `FRAG` set is refused; the relay answers the arrival address — send
    from a second source, receive the reply there.
*   **Unit, bounds and lifetime, under `testing/synctest`:** at the flow
    bound a CONNECT and an association are refused on their own legs, TCP
    and UDP counted together; a silent flow sweeps at the idle bound; an
    association whose TCP leg closes sweeps its outbound sockets and
    releases its relay port at once; an association with traffic
    survives.
*   **Unit, the netmap builder:** every node entry contributes its
    slice's first address as one more /32 among the host /32s, sorted; a
    node's arrival or departure flips the map comparison's verdict so the
    resend fires; no covering prefix appears anywhere in the map.
*   **Unit, the router:** with the application assembled, a packet
    addressed to the node's own address reaches the application's inbound
    path; an address in the node's own slice that is neither a host's
    nor the node's own stays unroutable; without the application the
    node's own address stays unroutable. `go-cmp` for the structural
    assertions, as `impl/dbtest` already uses it.
*   **Unit, the run arguments:** `--slice` and `--host-port` parse and
    validate — a slice the tailnet range contains, a usable port;
    `--wireguard-config` is refused as unknown, the flag parse performing
    the retirement's bookkeeping; the loader's deletion is the build's
    own assertion.
*   **Unit, the retirement's negatives:** an ICMP packet addressed to the
    node's own address is dropped and counted, never relayed; the moved
    header helpers still serve the suites that use them; no
    `golang.org/x/net/icmp` import remains in either application.
*   **Integration, the coordination lab pattern** — the assembly harness
    with the tsnet host double, `Poll` loops for convergence: the near
    case, a host SOCKS-dialing its own node's serving address to a
    loopback internet echo, TCP by CONNECT and UDP by association; the
    far case, the serving node the other node, the mesh carrying the
    serving address; the choice, one host's two flows naming each node's
    address — exit selection as the destination decision, switching exits
    writing nothing anywhere; the unroutable negative, a host's direct
    dial to an internet destination never entering the tunnel. The labs
    set the run arguments directly; the file-writing helper retires with
    the file.
*   **Negative, across the suites:** no default route and no covering
    prefix anywhere; a destination no slice claims counts unroutable at
    the node; no file-borne configuration remains anywhere in the tree;
    and the mihomo and vendor client lines remain out-of-repo exercises
    of the documented endpoint, per the capability-pin precedent.

## Implementation history
