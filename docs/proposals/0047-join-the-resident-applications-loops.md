# Join the resident applications' loops

This proposal makes each resident application's `Run` return only once
every goroutine it started has returned, and leaves the release of what
the application bound to its `Close`.
[Proposal 0043](/docs/proposals/0043-supervise-the-nodes-loops-and-resolve-its-role-once.md)
put the node's loops on a supervisor that waits for each loop before it
runs the releases in reverse order, and left the applications' own
goroutines for a series of their own. The lifecycle stays
[ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)'s
decision 4 — loops under the node's supervision, a panic absorbed and
logged, release in reverse table order — and the posture stays
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)'s:
a failed application is logged, and the node serves on.

[TOC]

## Summary

The supervisor ([supervise.go](/internal/supervise/supervise.go)) waits
for each application's `Run`, then runs each application's `Close` in
reverse table order ([applications.go](/internal/services/applications.go)).
Two of the four residents return from `Run` while goroutines they started
still run. The WireGuard application's `Run`
([app.go](/pkg/apps/wireguard/app.go)) starts its socket readers, its pipe
drains, the relay bridge, and the directory's server, publisher, and sync,
and returns at cancellation through a deferred `Close` that releases the
devices, the sockets, and the directory store — the store the coordination
application, its borrower, still serves from. The SOCKS application
([app.go](/pkg/apps/socks/app.go)) starts an accept loop, a drain, and
goroutines per connection and per association, joins none of them, and
never closes its netstack.

Here an application's `Run` starts its loops through a wait group, each
with a panic absorbed and logged, and the goroutines they start per peer,
connection, or association join the same group. `Run` ends them at
cancellation and returns once they have returned; `Close` releases what
the constructor bound, after `Run` or alone. The WireGuard application
stops releasing at `Run`'s end, the SOCKS application closes its netstack
and refuses flows once stopped, and the coordination application closes
its relay clients' connections beside its conversations'.

## Motivation

At cancellation today:

*   The WireGuard application's `Run` returns as soon as its context ends,
    and its deferred `Close` releases the application while the sync loop
    and the publisher ([directory.go](/pkg/apps/wireguard/directory.go))
    may be mid-pass. A sync pass that reaches `applyDirectory` after
    `Close` set `meshPeers` to nil writes the nil map, and the goroutine,
    which recovers nothing, crashes the process.
*   The same `Close` closes the directory store before the coordination
    application's release runs, and the open map streams read a closed
    store until their conversations end.
*   The relay bridge ([derpbridge.go](/pkg/apps/wireguard/derpbridge.go))
    reads the context only between frames, so it outlives `Run` and
    `Close` by up to the relay's keepalive, and each connect attempt
    leaves a network monitor and its event bus that nothing closes.
*   The directory client of every node but the founder
    ([directoryclient.go](/pkg/apps/wireguard/directoryclient.go)) closes
    its QUIC transport and never the SCION conn beneath it, the leak
    proposal 0043 closed for the node's own clients.
*   The SOCKS application never closes its netstack, whose dispatcher
    goroutines and endpoints outlive it; a connection still in its
    handshake has no deadline and no owner
    ([serve.go](/pkg/apps/socks/serve.go)); and a CONNECT or ASSOCIATE
    that completes after `Close` registers into tables nothing sweeps.
*   The DERP server's `Accept` registers a connection without checking
    whether the server has closed, so a relay client whose upgrade
    completes during the stop is served by a closed server until it
    leaves.

The coordination application's conversations, which only their clients
used to end, are closed by its `Close` since 3565a4b.

### Goals

*   Every resident's `Run` returns once every goroutine it started has
    returned: its loops, and the goroutines it starts beneath them per
    peer, per connection, or per association.
*   `Run` releases nothing a borrower uses; `Close` releases what the
    constructor bound, once `Run` has returned or when `Run` never ran,
    and a second call releases nothing again.
*   No goroutine an application started outlives its `Close`, and every
    socket it bound is closed by then.
*   An application's loops absorb a panic and log it, as the supervisor
    does for `Run` itself.

### Non-goals

*   No joins inside third-party machinery: wireguard-go's device routines,
    quic-go's and HTTP/3's connection goroutines, and `net/http`'s handler
    goroutines end through their owner's `Close`, and nothing waits for
    them.
*   No recover in the callbacks wireguard-go's routines run — the binds and
    the pipes' reads and writes: absorbing a panic there would leave the
    third party's locks and state as the panic found them.
*   No recover in the goroutines the loops start per peer, per connection,
    or per association: a panic in one crashes the process, as one in the
    coordination application's conversations does.
*   No change to the applications' policy: Degrade, as ADR-0014's
    decision 4 and proposal 0043 give it.
*   No change to how the coordination application ends its conversations.
*   No new run argument, default, or wire change.
*   No new record.

## Proposal

### The contract

The application seam ([apps.go](/pkg/apps/apps.go)) says `Run` "serves
the application until the context is canceled" and `Close` "releases the
application". They become:

*   `Run` runs the application's loops until the context is canceled,
    each in its own goroutine with a panic absorbed and logged, and
    returns once every goroutine it started has returned. It may close
    what nothing borrows to end a loop; what a borrower uses stays for
    `Close`.
*   `Close` releases what the constructor bound, once `Run` has returned,
    or alone when `Run` never ran — a failed boot releases applications
    whose `Run` never started. A second call releases nothing again.

The wording follows the topology contract
([topology.go](/pkg/modules/topology/topology.go)) as proposal 0043 left
it.

### The loops package

No `pkg/` package imports `internal/supervise`, so the measured provider
starts its loops through a `runLoop` of its own
([provider.go](/pkg/modules/topology/impl/measured/provider.go)). That
shape moves into a library package, `pkg/loops` (introduced), which the
measured provider and the applications share: `loops.Go(ctx, wg, name,
fn)` runs `fn`, a `func(context.Context)`, in its own goroutine under the
`sync.WaitGroup` `wg`; a panic is absorbed and logged with the loop's name
and `runtime/debug.Stack`, and a return before the context ends is logged
with the name. A loop runs for `Run`'s span, so its early return marks a
fault. A goroutine a loop starts per peer, connection, or association ends
with what it serves, so it joins the same wait group through `wg.Go`
alone, as the coordination application's conversations do.

### The WireGuard application

`Run` stops deferring `Close`. It starts, through `loops.Go`:

*   The mesh and host socket readers ([bind.go](/pkg/apps/wireguard/bind.go),
    [hostbind.go](/pkg/apps/wireguard/hostbind.go)). A `context.AfterFunc`
    sets each socket's read deadline to now, the shape the measured
    provider's probes take, and a reader returns on the deadline once the
    context has ended. The sockets stay open for `Close`, so `Run` releases
    nothing `New` bound, and `Close`, which the group runs before its
    `Stop` returns, frees the fixed host port in time for an in-process
    restart.
*   The host pipe's drain ([pipe.go](/pkg/apps/wireguard/pipe.go)), which
    returns at cancellation as well as at its pipe's close.
*   The relay bridge, whose client a `context.AfterFunc` closes at
    cancellation, ending a blocked `Recv`. Each attempt closes its network
    monitor and event bus as it returns.
*   On the founder, the directory server, whose socket a
    `context.AfterFunc` closes at cancellation through one
    `sync.OnceValue` close, as proposal 0043 closes the control endpoint's:
    QUIC answers a read deadline by reading again, so only the close ends
    the serve. `Close` closes the socket again, harmlessly.
*   The publisher and the sync loop, which already return at cancellation.

`applyDirectory`, on the sync loop, starts each mesh peer's drain through
`wg.Go`, so the application holds the wait group and the context for
`Run`'s span. A peer's drain returns at cancellation, or when its peer
leaves the directory and its pipe closes.

`Run` returns once all have returned. `Close` keeps its order — the
devices, the registrations, the sockets, the directory client, the
directory socket, the store — and also resets the interface-down receiver
`New` installed. The directory client's `Close` closes its SCION conn after
its transport, which covers `New`'s failure path too. The harness's
WireGuard application ([network.go](/internal/testnetwork/network.go))
calls `Close` once its `Run` returns.

### The SOCKS application

`Server.Run` assembles the application once the slice is assigned and
runs it. Nothing borrows the application, so `Run` releases it before it
returns. `App.Run` starts the accept loop and the drain through
`loops.Go`. The accept loop starts each connection's conversation, and a
conversation its splice or its association's relay and legs, through
`wg.Go`. A conversation's handshake runs under a deadline of
`egressDialTimeout`, so a client that connects and sends nothing gives its
goroutine and its endpoint back while the node serves. At cancellation
`App.Run`:

1.  marks the application stopped, so a CONNECT or ASSOCIATE that
    completes afterward closes its legs instead of registering them;
2.  closes the netstack with `stack.Close`, which aborts every endpoint —
    the listener's accept, a handshake's read, and every leg — and closes
    the tracked internet legs;
3.  cancels the dials and resolutions in flight, which take a context
    derived from `Run`'s in place of `context.Background`;
4.  waits for the wait group, then for the netstack's own goroutines with
    `stack.Wait`.

`Close` keeps releasing what `New` bound when `Run` never ran — the
delivery, the listener, the link, and now the netstack — and releases
nothing twice. `New`'s failure paths close the netstack they created.

### The coordination application

`Run` starts nothing: the application's surfaces run on the node's HTTPS
server, whose connections hijacked for a conversation or a relay client
outlive the server's close. Its `Close` ends the conversations, and the
relay's connections join the same set: the relay handler hands the DERP
server a response writer whose `Hijack` registers the connection under the
conversations' mutex, refused once `Close` has run. A relay client
accepted during the stop closes at once, and `Close` closes the registered
ones before the DERP server's own close waits for them.

### Packages touched

| Package                              | Change                                |
| :----------------------------------- | :------------------------------------ |
| `pkg/loops`                          | New: `Go`, the libraries' loop start  |
| `pkg/modules/topology/impl/measured` | Its loops through `pkg/loops`         |
| `pkg/apps`                           | The `Run` and `Close` docs            |
| `pkg/apps/wireguard`                 | Joined loops, no release in `Run`     |
| `pkg/apps/socks`                     | Joined loops, the netstack closed     |
| `pkg/apps/coordination`              | Relay conns closed like conversations |
| `internal/testnetwork`               | The harness's `Close`, the labs       |

No record is needed: the posture stands as ADR-0009 states it, and the
lifecycle as ADR-0014's decision 4 orders it; this proposal makes the
applications keep both. `pkg/loops` is a library like the others, which
the applications import as they import the core's.

### Migration

Each commit keeps the tree green:

1.  **Add the loops package.** `pkg/loops` and its tests; the measured
    provider's `runLoop` gives way to it.
2.  **Join the WireGuard application.** The loops, the readers' deadlines,
    the drains, the relay bridge's ends, the directory server's close,
    `Run` releasing nothing, the directory client's conn, the
    interface-down reset, and the harness's `Close`.
3.  **Join the SOCKS application.** The loops, the handshake deadline, the
    stopped flag, the netstack's close and wait, the derived contexts, and
    `New`'s failure paths.
4.  **Close the relay's connections.** The coordination application's
    relay handler, and the contract's docs, true of every resident from
    this commit on.

## Test plan

*   **Unit, the loops:** in a `testing/synctest` bubble, a loop's panic is
    logged with its name and stack and absorbed while its sibling runs on,
    a return before the context ends is logged, and the wait group's
    `Wait` returns once every loop has returned after cancellation.
*   **Unit, WireGuard:** an application built over the package's fixture
    runs; once its context is canceled, `Run` returns — the test waits on a
    channel `Run`'s return closes, bounded by the test's deadline — with a
    mesh peer's device up and the bridge blocked in `Recv` against a relay
    that sends nothing. After `Close`, the host port binds again at once,
    and a read on the directory client's conn reports `net.ErrClosed`.
*   **Unit, SOCKS:** in the package's lab, `Run` returns after
    cancellation with a client held mid-handshake, a CONNECT whose dial
    blocks until its context ends, and a spliced flow, whose internet leg
    sees its connection close. A CONNECT whose dial returns only after the
    stop closes both legs at once. A client that connects and sends
    nothing sees its connection close after the handshake bound, which
    the lab's configuration shortens as it shortens the idle bound.
*   **Unit, coordination:** with a relay client connected, `Close` returns,
    and the client sees its connection end; a relay upgrade that completes
    after `Close` ends at once.
*   **Integration, the restart:** `TestCoreRestartsInPlace` loads the
    WireGuard application, so each boot rebinds its fixed host port at
    once.
*   **Integration, the stop:** a tailnet lab closes the node before its
    clients leave, and the node's `Close` returns.
