# Supervise the node's loops and resolve its role once

This proposal gives the node one supervisor and one reading of its role.
The node runs the loops
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
enumerates as its core, and the modules' and applications' loops beside
them, as detached goroutines under one absorb-and-log posture, and releases
their stores without waiting for them. Here each loop runs named, under a
failure policy, and is waited for before the resources it uses release in
reverse order of acquisition. The applications keep the posture ADR-0009
and [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)'s
decision 4 give them; the core takes
[proposal 0019](/docs/proposals/0019-dataplane-processor-fail-fast.md)'s,
where a failure stops the node and the operator's process supervisor
restarts it; and the loops still start only after every bind has
succeeded, as
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)'s decision 7
orders them. The role is
[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md)'s single `ASType`
enumeration, derived from the run arguments as
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md)'s
decision 1 decides; it is derived once, where the rest of the run arguments
are now resolved.

[TOC]

## Summary

`runBackground` ([node.go](/internal/services/node.go)) starts each of the
node's loops in a goroutine with a recover, logs what the loop returns, and
never joins it; `node.Close` releases the stores right after the
cancellation, beneath loops still running; and the role is read from the
run flags, from `identity.asType`, and from whichever role-specific values
are set. The change:

*   A supervisor, `internal/supervise` (introduced): named loops, each under
    a policy — Fatal for the core and the node's HTTPS server, Degrade for
    the modules, the applications, and certificate management — and a stack
    of owned resources, released in reverse order of acquisition once every
    loop has returned.
*   The failures that should stop the node are returned: the authoritative
    core's onboarding returns `trust.ErrNoVotingApp` where it called a
    callback, the echo responder its failed read where it logged it, and
    the Fatal policy makes either the node's stop and `Run`'s error.
*   `context.AfterFunc` replaces the four goroutines that close a loop's
    socket when the loops' context ends, and each of those loops returns
    with its socket released, so an in-process restart rebinds the fixed
    ports at once.
*   Every resource registers where the boot acquires it — the sockets and
    clients nothing releases today among them — and a failed boot unwinds
    through the same stack. `Run` and `BootApp` share one boot, and
    `App.Wait` (introduced) reports how the node stopped.
*   The role is derived once, as a `trust.ASType`, and every branch reads
    it; one switch builds each role's parts and loops, and pkg/controlplane
    takes per-role values where it inferred the role from nil fields.
*   `NodeConfig.Validate` becomes a resolution: the addresses, the
    enrollment authorizer, and the application selection, each produced
    once and handed to setup.

## Motivation

Nothing waits for the node's loops. `runBackground` never joins what it
starts, and both exits release beneath them: `Run`
([app.go](/internal/services/app.go)) defers `n.Close()` before it derives
the loops' context, so the cancellation and the release run back to back,
and `App.Close` cancels and closes in one step. The beaconer names the
hazard: `Beaconer.Run` ([beacon.go](/pkg/controlplane/beacon.go)) joins its
loops "so a caller that waits for Run closes no store beneath an in-flight
pass", and recovers in each loop because "a pass that meets a closing
store" would otherwise take the process down — and no caller waits. The
measured provider's `Run`
([provider.go](/pkg/modules/topology/impl/measured/provider.go)) returns at
once with its loops detached, and `NodeDirectory.Run`
([directory.go](/pkg/modules/topology/impl/measured/directory.go)) leaves
its publish loop behind.

Every loop has the applications' failure policy. `runBackground` absorbs a
panic and logs a returned error alike for the data plane, beaconing, the
control endpoint, and enrollment — the posture ADR-0009 grants
applications, applied to the enumeration it froze as the core. An echo
responder whose read fails logs "Echo responder exited" and returns
([responder.go](/internal/services/responder.go)), and the node answers no
echo while it looks healthy — the effect `assembleResponder`'s doc gives as
the reason the responder is core: a node without one "silently disables the
comparator on every neighbor". Under `BootApp`, a replacement generation
that cannot build is logged and the node serves on without a data plane;
under `Run`, the same failure ends the process. `Run`'s doc says "A loop's
terminal failure stops the node from inside", and one loop is wired to it:
the authoritative core's onboarding, through `EnrollmentConfig.Fatal`
([lifecycle.go](/pkg/controlplane/lifecycle.go)) and the node's `fatal`.

Resources leak. `node.Close` leaves "the loops' own sockets (endpoint,
responder, clients)" to "close with their owners when the process exits".
The endpoint and responder sockets close from goroutines on the loops'
context, racing an in-process restart that rebinds their fixed ports, and
a boot that fails after binding them leaks both: setup's unwinding calls
`node.Close`, which never names them. Nothing calls `CoreClient.Close`
([remote.go](/pkg/webpki/remote.go)), and nothing closes the core client's
resolution conn or the selection probe conn. `CoreClient.Close`,
`PeerClient.Close`, and `NodeDirectory.Close` each close a QUIC transport
built over a caller's conn, and `quic.Transport.Close` closes only a conn
it created, so the conn beneath each transport stays open even where its
client is closed. `PrepareTLSCert` ([tls.go](/pkg/webpki/tls.go))
never stops the certmagic cache it creates, and its HTTP-01 server shuts
down on the context setup received — the caller's, which `App.Close` does
not cancel.

The role is re-derived wherever a branch needs it. `Validate`
([config.go](/internal/services/config.go)) spells the founding predicate
from the flag pair; `loadIdentity` derives `identity.asType` from the
same pair; `selectProvider`, `setupTrustRole`, `buildBeaconing`,
`assembleEndpoint`, and `start` read it; and `buildMessenger` (`coreClt`),
`start` (`votingKey`, `certMgr`), `assembleHTTPS` (`certMgr`), and
`appEnvironment` (`decider`) infer it from which values are set.
pkg/controlplane infers it again — `EnrollmentConfig.VotingKey`,
`RotationConfig.Decider`, `TRCDecider.Sensitive` — and the voting
application refuses a missing decision per submission. Each nil check is a
role check the compiler cannot see, and a place a new branch can miss.

The run arguments resolve more than once. `Validate` builds the enrollment
authorizer and discards it, and `setupEnrollAuth`
([node.go](/internal/services/node.go)) builds it again under a comment
saying the spec "parses here once"; the Telegram method reads its
invitations file each time. `apps.Select` runs in `Validate` and again in
`setupApplications`. The control address resolves per conn
(`controlBind`), per generation (`registerControlService`,
`registerBackends`), per registration (`registerSvc`, `unregisterSvc`), and
in `selectProvider` and `httpsBindAddr`; the internal address resolves per
generation and per conn. Each resolution is `net.ResolveUDPAddr`, most of
them through `dataplane.ResolveAddrPort`, and a DNS lookup for a host name.

### Goals

*   Every loop the node starts is named, runs under a failure policy, and is
    waited for before anything it uses is released.
*   The core's failures stop the node with the cause, `Run` returning it;
    the modules' and applications' degrade the node, as ADR-0009 and
    ADR-0014 hold.
*   Resources release in reverse order of acquisition, on a failed boot as
    on a stop, and an in-process restart rebinds every fixed port without a
    retry.
*   One boot for `Run` and `BootApp`.
*   The role derived once, as ADR-0002's enumeration, and read by every
    branch; each role's parts and loops built in one switch; no role
    inferred from a nil.
*   The run arguments resolved once: the addresses, the authorizer, and the
    application selection.

### Non-goals

*   No change to the modules' and applications' posture: a panicking or
    exited loop is absorbed and logged, and nothing restarts it —
    ADR-0009's consequence, ADR-0014's decision 4, and the topology
    contract. A module or resident whose failure should stop the node needs
    a record narrowing that decision and the contract.
*   No restart machinery: a stopped node is the process supervisor's to
    restart, proposal 0019's posture, with no budget and no backoff.
*   No change to the data plane's own recovers — the underlay's receiver
    and forwarder and the internal link's dispatch keep `handlePanic`, as
    proposal 0019 left them — nor to the generation swap.
*   No joins inside the applications: the goroutines the WireGuard and
    SOCKS applications start beneath their `Run` stay theirs, for a series
    of their own.
*   No new flag, default, or wire change.
*   No change to how the role derives: from the run arguments alone,
    ADR-0015's decision 1.
*   No change to `testnetwork.StartNode` beyond its call sites: retiring it
    in favor of `services.BootApp` is a later proposal's.
*   No new record.

## Proposal

### The supervisor and its policies

`internal/supervise` holds a group of loops and the resources they use. Its
API is introduced by this proposal:

*   `supervise.New(ctx)` returns a `*supervise.Group` and the group's
    context, derived from `ctx` through `context.WithCancelCause`.
*   `Group.Go(name, policy, fn)` runs `fn`, a
    `func(context.Context) error`, under the group's context in its own
    goroutine.
*   `Group.Own(name, release)` pushes `release`, a `func() error`, onto the
    group's stack; the boot calls it where the resource is acquired.
*   `Group.Wait()` blocks until the group's context ends, waits for every
    loop, runs the releases in reverse order of registration, and returns
    the first Fatal failure wrapped with its loop's name, so `errors.Is`
    still finds the cause. Release errors join it, `net.ErrClosed`
    excepted: a socket its loop closed on cancellation is closed again by
    its release, harmlessly. Every call returns the same result.
*   `Group.Stop()` cancels the group and returns what `Wait` returns. It is
    idempotent, and it releases what a boot acquired before failing.

A loop's policy, a `supervise.Policy`, is one of two:

*   `supervise.Fatal`: an error returned before the group's context ends
    cancels the group, the error its cause. A nil return is completion,
    logged, and the group runs on. A panic is not recovered: it unwinds to
    the runtime, which prints the value and the stack and exits, and the
    process supervisor restarts the node.
*   `supervise.Degrade`: a panic is recovered and logged with the loop's
    name and `runtime/debug.Stack`, and a return before the group's context
    ends is logged; the siblings serve on, and nothing restarts the loop.

Under either policy, an error returned after the group's context ended is
the shutdown's own echo — a socket closed beneath a read — logged at debug
level and never a cause.

The Fatal panic stays unrecovered for proposal 0019's reasons and one of
the supervisor's own. A recovered panic must unwind into an ordered stop,
and the stop waits for loops that may block on state the panicking
goroutine left behind — one held mutex keeps `Wait` from returning. The
crash cannot hang, keeps the runtime's own report, and leaves a core loop's
death "either impossible or loud".

| Loop                                 | Policy  |
| :----------------------------------- | :------ |
| Data plane: generations and swaps    | Fatal   |
| Health monitor                       | Fatal   |
| Beaconer                             | Fatal   |
| Control endpoint                     | Fatal   |
| Echo responder                       | Fatal   |
| Enrollment, every role               | Fatal   |
| Rotation watch, cores                | Fatal   |
| HTTPS server, when bound             | Fatal   |
| Certificate management, founder      | Degrade |
| Topology provider                    | Degrade |
| Enrollment authorizer, when selected | Degrade |
| Each resident application            | Degrade |

The Fatal rows are the core ADR-0009 enumerates, the trust lifecycle's
loops among them, and the node's HTTPS server, whose failure leaves every
mounted surface and the TLS-ALPN challenge unanswered. The Degrade rows are
the modules, the residents, and certificate management. The topology
provider absorbs its own loops' panics under its contract, and a dead
authorizer poll answers no prompt, so the gate it serves stays closed.
Certificate management retries a failed issuance at the CA's pace: a
founder whose WebPKI identity is not yet obtained still serves the rest of
the ISD, and a crash would restart into a fresh request each time, against
the CA's rate limits.

### What loops return

A loop returns an error when the node should stop, and retries what the
network may still answer, as it does today:

*   The authoritative core's onboarding returns `trust.ErrNoVotingApp`, the
    condition the node already stops on, and `EnrollmentConfig.Fatal` and
    the node's `fatal`, `fatalOnce`, `fatalErr`, and `stop` go.
    `RunEnrollment` gains an error result and cancels its chain sweep
    before waiting on it: its deferred `sweep.Wait()` would otherwise hold
    the returned error until the node's cancellation, which only that error
    can bring.
*   The echo responder's failed read is returned: `responder.Run` gains an
    error result.
*   `ServeHTTP3`, `ServeHTTPS`, and the data plane loop return their
    failures already; under `BootApp`, the data plane's now stops the node,
    as it ends `Run`.
*   A failed read of the node's own state — its chain, its pinned TRC, its
    voting material — stays a logged retry: with the stores released only
    after the loops, it marks a store fault, not a shutdown, and a lasting
    one shows in the log.
*   Certificate management keeps a failed issuance retrying: `Manage` hands
    the domain to certmagic's `ManageAsync`, whose obtain retries at
    certmagic's backoff until it succeeds or the group's context ends, and
    holds until that context ends. A static-file founder starts no
    certificate management.
*   The rotation watch's lost-sensitive-key verdict stays a logged
    condition: the founder serves everything else, and stopping it would
    take the ISD's issuer down over a loss whose recovery is a redeploy.

### Close on cancel

Four goroutines close a socket when the loops' context ends: the control
endpoint's in `start` ([node.go](/internal/services/node.go)), the echo
responder's ([responder.go](/internal/services/responder.go)), the
rendezvous acceptor's
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)), and
the HTTPS server's ([tls.go](/pkg/webpki/tls.go)). Each becomes a
`context.AfterFunc` registration. As each loop returns, it calls the
registration's stop function; false means the close has started, and the
loop waits for it to finish. A read fails as soon as the close begins, and
only the first `Close` waits for the descriptor's release — a second
returns at once — so a loop that returned without waiting could let `Wait`
return, its release's second `Close` returning at once, while the
descriptor is still bound. The HTTPS server's registration closes the
server rather than the listener alone, so the connections it tracks end
with it; a hijacked connection stays its handler's.

`serveHTTP01` ([tls.go](/pkg/webpki/tls.go)) drops its context.
`CertManager.Close` (introduced) stops the certmagic cache and shuts the
HTTP-01 server down, returning once its `Serve` has returned; a
static-file manager's `Close` releases nothing.

### Owned resources and one boot

The boot registers each resource as it acquires it, so the stack follows
the acquisition order:

1.  the trust, path, and link databases, in `openState`;
2.  the role's: the founder's certificate manager, or the core client with
    its two conns;
3.  the peer conn and the peer client;
4.  the endpoint conn, then the topology provider where `Mounts` binds its
    sockets;
5.  the responder conn;
6.  each application, in table order;
7.  the HTTPS listener.

Once every loop has returned, the releases run in reverse: the applications
in reverse table order, as ADR-0014's decision 4 keeps them, and the
databases last. The data plane loop stops its generation before it returns,
as it does on cancellation today, so the stack holds no generation. A
failed boot calls `Stop`, which releases what the boot acquired — the
endpoint and responder sockets among them. `node.Close` and its nil checks
go: a resource the boot never reached was never registered.

Ownership follows the call: whoever asks for a conn closes it. The node
closes the conns it binds for itself — the endpoint's, the responder's, the
peer client's, and the core client's two — and a client's `Close` closes
its QUIC transport alone, so each client releases before its conns. The
measured provider closes the conns it draws through `NewConn`, and an
application or an `App.Conn` caller closes its own.

`Run` boots exactly as `BootApp` does — the first generation built
synchronously, the loops started after it — and returns what `Wait`
returns. `superviseDataplanes` goes, and `BootApp`'s order, the one every
lab already exercises, is the only one. `App.Wait` (introduced) blocks
until the node stops — its context canceled or a Fatal loop failed — and
returns the group's result. `App.Close` becomes `Close() error`, canceling
and returning the same.

The beaconer's per-loop recover ([beacon.go](/pkg/controlplane/beacon.go))
goes. It stands on two reasons: a caller's recover cannot reach the
goroutines `Run` spawns, and a pass can meet a closing store. No caller
recovers a core loop any longer, and the stores release only after every
loop has returned, so a beaconing panic is the core's and crashes the
process. `TestBeaconingLoopAbsorbsPanics` goes with the recover; its
cancellation half, `Run` returning once every loop has exited, stays.

### The measured provider's loops

The topology contract ([topology.go](/pkg/modules/topology/topology.go))
says `Run` "runs the provider's loops until the context is canceled, each
in its own goroutine with a panic absorbed and logged". It gains that `Run`
returns once every loop it started has returned, and that `Close` releases
what assembly bound once `Run` has returned. The measured provider's `Run`
starts its loops through `sync.WaitGroup.Go` and waits, keeping
`runLoop`'s recover; `NodeDirectory.Run` joins its publish loop the same
way. `Run`'s own `assemble` call and the panic on its failure go: `Mounts`
assembled the provider before any loop runs, and binds belong to assembly.
`Provider.Close` closes the directory conn and the probe conn it drew
through `NewConn`, after the directory's transport. The file provider's
`Run` already returns with its one loop.

### The role, typed once

`NodeConfig.resolve` (introduced), below, derives the role from the run
arguments as `loadIdentity` does today: `trust.ASTypeCore` for the core
flag without a neighbor, `trust.ASTypeAuthoritative` with one,
`trust.ASTypeNormal` without the flag. It is ADR-0002's enumeration, the
one "certificate generation can simply switch on", and no second type
appears.
`identity.asType` goes, and every branch reads the resolved role:
`resolve`'s own founding checks, `selectProvider`'s founding flag,
`buildBeaconing`'s core tier (any role but `trust.ASTypeNormal`), the role
switch below, `assembleHTTPS` in place of its `certMgr == nil`, and the
application selection and environment in place of the founding predicate
they read today.

### The resolved configuration

`NodeConfig.Validate`, which only `setupNode` and the package's tests call,
becomes `NodeConfig.resolve` (introduced), returning a `resolvedConfig`
(introduced): the `NodeConfig` it resolved and, beside it,

*   the role;
*   the control and internal addresses as `netip.AddrPort`, resolved once
    through `dataplane.ResolveAddrPort`;
*   the enrollment authorizer and its run function, built once, so the
    trust service, the decision, and the applications hold one instance;
*   the selected `[]apps.Entry`, selected once.

Setup consumes it; `setupEnrollAuth`, `controlBind`, `parseControlHost`,
and `parseInternalHost` go. `scionConn` binds the resolved control host,
and the provider, the service registrations, and `httpsBindAddr` read it —
`httpsBindAddr` keeping the harness's placement and the wildcard refusal.
The libraries keep their string parameters and receive the resolved
literal: `NewInternalLink`'s address, `scion.ConnConfig.InternalAddr`, and
`apps.Environment.ControlHost`, which the WireGuard entry
([wireguard.go](/pkg/apps/wireguard.go)) then resolves without DNS. A host
name in either address resolves once at boot rather than at every bind, and
every conn and generation sees the one answer. The HTTPS assembly's tests
([https_test.go](/internal/services/https_test.go)) build their node from a
resolved configuration.

### Per-role strategies

One three-case switch over the role, in `setupTrustRole`, builds each
role's parts and returns them with the role's loops as closures; `start`
hands the closures to the group once every bind has succeeded.

*   **The founder** (`trust.ASTypeCore`) builds its core keys, its TRC —
    genesis, or the newest pinned — the issuer, the decision, its first
    chain by self-enrollment, and its WebPKI identity, `PrepareTLSCert`
    moving in from `assembleEndpoint`. Its loops: enrollment by self-issue,
    rotation by local cast, certificate management, and the authorizer's
    poll when the selected method has one, for `resolve` refuses
    `--trust.enroll-auth` on every other role.
*   **The authoritative core** (`trust.ASTypeAuthoritative`) builds its
    voting key and certificate and the core client over its two conns. Its
    loops: enrollment by remote renewal and onboarding cast, and rotation
    by submission.
*   **The normal node** (`trust.ASTypeNormal`) builds the core client over
    its two conns. Its loop: enrollment by remote renewal, with the pinned
    TRC's validity report.

The HTTPS server's loop stays conditional on a bound listener: a
static-file founder whose applications mount nothing binds none.

The switch hands four products to the later phases: the engine's remote,
the trust service's issuer, the WebPKI identity, and the TRC decision. Each
is held as the type its consumer takes, so a role that offers none leaves a
true nil, and `buildMessenger`'s branch on `coreClt` and `appEnvironment`'s
typed-nil guard go.

pkg/controlplane takes per-role values in place of nil-encoded fields:

*   `RunEnrollment` and `RunCoreEnrollment` merge into one `RunEnrollment`
    returning `error`. `EnrollmentConfig` keeps `IA`, `DB`, `Key`, the
    intervals, and `Timeout`; its `Remote`, `Issuer`, `VotingKey`,
    `VotingCert`, and `Caster` give way to one field, `Renewal`
    (introduced), of the interface type `controlplane.Renewal`
    (introduced), with a constructor per role: the founder's self-issue,
    the normal node's remote renewal with its TRC validity report, and the
    authoritative core's remote renewal followed by its onboarding cast.
*   `RotationConfig`'s `Decider`, `Issuer`, `Remote`, and `Caster` give way
    to one field, `Roll` (introduced), of the interface type
    `controlplane.Roll` (introduced), with a constructor per holder: the
    founder's local cast and the authoritative core's submission. The value
    answers both of the watch's questions — whether the persisted material
    agrees with the pin, and how to roll — so `materialDue` and `roll` stop
    branching on `Decider != nil`.
*   The `Sensitive == nil` refusals in `TRCDecider.DecideTRC` and
    `TRCDecider.CastLocal` go: the decision exists on the founder alone,
    built with its sensitive key.

`voting.New` refuses a nil `Config.Decide`, as it refuses a nil
`MountControlEndpoint`, and the service's per-submission refusal goes: the
voting application loads on the founder alone, where the decision exists.

The node struct sheds `votingKey`, `votingCert`, and `coreClt` to the
switch's locals and closures, `enrollAuth` and `enrollRun` to the resolved
configuration, and `stop`, `fatalErr`, and `fatalOnce` to the group.

### Packages touched

| Package                              | Change                                             |
| :----------------------------------- | :------------------------------------------------- |
| `internal/supervise`                 | New: the group, its policies, the stack            |
| `internal/services`                  | The group, one boot, the role, `resolve`           |
| `pkg/controlplane`                   | Returned failures, per-role values                 |
| `pkg/webpki`                         | `context.AfterFunc`, `CertManager.Close`, `Manage` |
| `pkg/modules/topology`               | The contract's `Run` and `Close` docs              |
| `pkg/modules/topology/impl/measured` | Joined loops, closed conns                         |
| `pkg/apps`                           | `Environment.TRCDecision`'s doc                    |
| `pkg/apps/voting`                    | `New` refuses a nil decision                       |
| `internal/testnetwork`               | Call sites, the restart labs                       |
| `cmd/cion`                           | `App.Close`'s error                                |

`internal/supervise` belongs to none of the kinds ADR-0009 and ADR-0013
file — core, libraries, modules, applications. It is the assembly's own
machinery, under `internal/` beside `services`, `testnetwork`, `dbtest`,
and `socksclient`, and only the assembly imports it. No `pkg/` package
outside its tests imports `internal/`, so `pkg/controlplane` and the
measured provider join their own loops with `sync.WaitGroup`.

No record is needed: the new package sits outside the roofs those records
file; the modules' and applications' posture stands as ADR-0009, ADR-0014's
decision 4, and the topology contract state it; the core's posture is
proposal 0019's; and the role is ADR-0002's enumeration, derived as
ADR-0015's decision 1 decides.

### What this leaves for the assembly proposal

A later proposal retires `testnetwork.StartNode` in favor of
`services.BootApp`. This one leaves it one boot whose terminal failure
`App.Wait` reports; each role's parts built in one switch, from
pkg/controlplane values a harness can build with the same constructors;
and loops that return their failures and join their own goroutines.
`StartNode` changes only at its call sites: the merged `RunEnrollment`,
given a per-role value, under its own `handlePanic`.

### Migration

Each commit keeps the tree green:

1.  **Add the supervisor.** `internal/supervise` and its tests; nothing uses
    it yet.
2.  **Return the loops' failures.** `RunEnrollment` and `RunCoreEnrollment`
    return `error`, the onboarding returning `trust.ErrNoVotingApp` with
    the sweep canceled before it is waited on; `EnrollmentConfig.Fatal`
    goes, the node's closure handing the returned error to `fatal` until
    the group arrives; `responder.Run` returns its failed read;
    testnetwork's call sites follow.
3.  **Join the measured provider's loops.** `Run` and `NodeDirectory.Run`
    join, `Provider.Close` closes its conns, and the topology contract's
    docs say so.
4.  **Run the node on the group.** One boot for `Run` and `BootApp`,
    `App.Wait`, `App.Close() error`, and the table's policies; what
    `node.Close` releases today registers at acquisition; `node.Close`,
    `runBackground`, `superviseDataplanes`, and the fatal plumbing go, as
    do the beaconer's per-loop recover and its test.
5.  **Close on cancel with `context.AfterFunc`.** The four sites, each loop
    returning with its socket released.
6.  **Release what nothing releases.** The endpoint and responder conns,
    the core client and its two conns, and the peer conn join the stack;
    `CertManager.Close` takes the HTTP-01 server off the setup context; and
    `Manage` retries through `ManageAsync`, started for an ACME-managed
    identity alone.
7.  **Resolve the run arguments once.** `NodeConfig.resolve` and
    `resolvedConfig`, the role among its fields; `Validate`,
    `setupEnrollAuth`, `controlBind`, `parseControlHost`,
    `parseInternalHost`, and `identity.asType` go, and every branch reads
    the resolved role.
8.  **Hand pkg/controlplane per-role values.** `controlplane.Renewal`,
    `controlplane.Roll`, and the merged `RunEnrollment`; the decision's
    refusals; `voting.New`'s refusal; testnetwork's call sites follow.
9.  **Build the role's parts in one switch.** `setupTrustRole`'s switch,
    the WebPKI identity moved into the founder's branch, the products held
    as their consumers' types, and the node struct's role fields gone.

## Test plan

*   **Unit, the supervisor:** each episode in a `testing/synctest` bubble,
    `synctest.Wait` marking the moment every goroutine has blocked. A Fatal
    error cancels the group: the sibling's context ends, and `Wait` returns
    the error wrapped with the loop's name, `errors.Is` finding the cause.
    A Degrade panic and a Degrade error are logged with the loop's name, the
    panic with its stack, and the sibling runs until `Stop`. A Fatal loop's
    nil return leaves the group running. An error returned after
    cancellation is not the cause. Three releases registered A, B, C run C,
    B, A, and only after the loop's own return is recorded. `Stop` with no
    loop started releases at once; a second `Stop` returns the same result
    and releases nothing again. A release's `net.ErrClosed` is dropped, and
    any other release error joins the result.
*   **Unit, the Fatal panic:** the test re-executes its own binary for the
    panicking case alone and asserts a non-zero exit whose output carries
    the panic's value — the crash observed, not simulated. Until its exec,
    the fork holds every descriptor the test process has open, and the
    package holds no test that rebinds an address, so the fork keeps no
    sibling's socket bound.
*   **Unit, close on cancel:** the responder, the rendezvous acceptor, and
    `ServeHTTPS` each serve, see their context canceled, and return, and
    the address each held binds again at once, without a retry.
*   **Unit, the certificate manager:** a manager `PrepareTLSCert` builds
    for a domain over a throwaway storage serves HTTP-01 on port 80, the
    port `TestHTTP01ChallengeSolves` already binds; once `Close` returns,
    port 80 binds again at once. Against a CA that answers nothing,
    `Manage` keeps running until its context ends and then returns nil. A
    static-file manager's `Close` returns nil.
*   **Unit, the measured provider:** a provider assembled through `Mounts`
    on a loopback host of the package's own, as `TestZeroconfMounts` takes
    one, with `NewConn` drawing real conns. `Run` returns after
    cancellation — the test waits on a channel `Run`'s return closes,
    bounded by the test's deadline — and after `Close` a read on each drawn
    conn reports `net.ErrClosed` and the rendezvous port binds again.
*   **Unit, enrollment and rotation:** in a synctest bubble, an onboarding
    renewal whose caster answers `trust.ErrNoVotingApp` makes
    `RunEnrollment` return it at that pass, and the bubble's exit proves
    the sweep returned too. `TestEnrollmentPasses` and
    `TestCoreEnrollmentPass` run on the per-role renewals,
    `TestFounderRotationPasses` and `TestAuthoritativeRotationPasses` on
    the per-holder rolls.
*   **Unit, the role and the resolution:** a table over `resolve` — the core
    flag without a neighbor resolves `trust.ASTypeCore`, with one
    `trust.ASTypeAuthoritative`, and without the flag `trust.ASTypeNormal`
    — replaces `TestLoadIdentityDerivesTier`'s tier checks and keeps its
    restart case. `TestNodeConfigValidate` and
    `TestNodeConfigValidateApplications` refuse through `resolve` as they
    refuse today. The trust service, the decision, and the applications'
    environment hold the authorizer instance `resolve` built, and the
    applications that load are its entries.
*   **Unit, voting:** `voting.New` refuses a nil decision.
*   **Integration, the stop:** `TestJoinerStopsWithoutVotingApp` passes
    through the group, and a `BootApp` variant asserts the same error from
    `App.Wait`.
*   **Integration, the restart:** `TestJoinByEnrollAuthTelegramRestart`
    boots the successor right after `Close` returns, now by construction;
    a new lab restarts a core three times on the same state and addresses,
    each boot succeeding at once and a joiner enrolled against the last.
*   **Negative, the failed boot:** `TestHeldHostPortRefusesBoot` continues
    past the refusal: the held socket closes, and a second boot on the same
    host succeeds, the endpoint and responder ports released by the first
    boot's unwinding.
