# Namespace the run arguments by the part they affect

This proposal namespaces the daemon's arguments by the part of the node they
configure: the topology source's two under `--topology.`, the trust plane's
five under `--trust.`, the host-serving port under `--wireguard.`, and the
forwarding plane's three tuning arguments under `--dataplane.`. The three
that place the node itself — `--state`, `--internal`, `--control` — stay
bare, and the rule they leave behind reads in every help line: a bare
argument places the daemon, a namespaced one configures the part its prefix
names. Nothing beneath the parse moves — the same fields assemble into the
same node configuration, the validator checks the same facts with restated
flag names, and the unprefixed spellings retire outright, as `--core` did.

[TOC]

## Summary

The command surface partitions by role and by nothing else.
[Proposal 0027](/docs/proposals/0027-split-the-run-command-by-the-nodes-role.md)
made the role the command; within each command the arguments sit in one
alphabetical list that mixes parts. `--host-port`, the WireGuard
application's loading argument, sits beside `--state`, the directory the
identity, the keys, and every store live under, in the same registration
([run.go](/cmd/cion/run.go)). `--link-set`, the static topology provider's
selection, sits in that registration too. The local role's registration
mixes the other axis: `--neighbor`, the measured provider's bootstrap, beside
`--domain`, the trust plane's identity
([run_local.go](/cmd/cion/run_local.go)). The partition by part lives only
in the source — in which helper registers which flag — and the operator
reads one undifferentiated list.

This proposal makes the partition the argument's name, the way 0027 made the
role the command:

| Part | Arguments | Carried by |
| :--- | :--- | :--- |
| placement (bare) | `--state`, `--internal`, `--control` | both run commands, ping |
| topology | `--topology.link-set` | both run commands, ping |
| topology, joining | `--topology.neighbor` | `run local`, ping |
| trust, core | `--trust.domain` (the core's own), `--trust.acme-email`, `--trust.cert-file`, `--trust.key-file`, `--trust.enroll-auth` | `run core` |
| trust, local | `--trust.domain` (the network's) | `run local`, ping |
| wireguard | `--wireguard.host-port` | both run commands, ping |
| dataplane | `--dataplane.processors`, `--dataplane.batch-size`, `--dataplane.queue-size` | both run commands |

## Motivation

*   The shared registration mixes three parts.
    [addSharedNodeFlags](/cmd/cion/run.go) registers "the node arguments
    every assembling command takes": `--state`, under which the identity,
    the keys, and every store live
    ([node.go](/internal/services/node.go)); `--internal` and `--control`,
    the two addresses the daemon's own sockets bind
    ([dataplane.go](/internal/services/dataplane.go),
    [https.go](/internal/services/https.go)); `--link-set`, which selects
    the file provider over the measured one
    ([node.go](/internal/services/node.go)); and `--host-port`, the WireGuard
    application's port and loading argument
    ([wireguard.go](/internal/services/wireguard.go)). Three of the five
    place the node; two configure a part.
*   The role registrations mix the other axis. The local command's
    `--neighbor` feeds the measured provider's rendezvous bootstrap — the
    topology machinery — while its `--domain` feeds the enrollment and TRC
    fetch: two parts in one registration, on both commands' surfaces.
*   The architecture already drew the line the surface misses.
    [ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)
    tests the boundary: "If removing a capability still leaves a forwarding,
    beaconing, enrolling SCION AS, it is policy — and policy lives under an
    app." Host serving fails that test, and the topology machinery is "the
    default-loaded application, with a file-backed provider as the static
    alternative" — yet their arguments print beside the node core's with no
    mark of the boundary the record drew.
*   [ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)
    made the arguments the applications' loading regime: "setting an
    application's argument loads the application", and "each application's
    arguments are its own story". The story prints without a byline today —
    `--host-port` reads as the node's own until its help text says
    otherwise.
*   The exclusivity the grammar could teach. `--link-set` and `--neighbor`
    name one selection — [Validate](/internal/services/config.go) refuses
    their mixture, "one topology provider per process" — but they register
    in two helpers and print in one list, their disagreement the only clue
    they are two arguments of the same choice. Under one prefix the
    namespace itself says so.
*   The naming has working precedent: Prometheus's server namespaces its
    subsystem arguments the same way (`--storage.tsdb.path`), and the
    dotted spelling is what shell completion and `--help` grep find first.

### Goals

*   The namespaces: every argument renames per the table, keeping its
    meaning, type, default, and role coverage; the bare three keep their
    spellings.
*   The help that reads in parts: each command's `--help` lists the
    placement flags first, then each part's block, by registration order.
*   The restated messages: the validator's and the tuning checks' error
    texts name the namespaced spellings, so no message names an argument no
    command registers.
*   The refused spellings: every unprefixed form of a renamed argument
    fails as an unknown flag naming it, beside the standing retirements.
*   The unchanged assembly: `services.NodeConfig`, `Validate`, `Run`, and
    `BootApp` keep their shapes; the integration harness builds the same
    struct it builds today.

### Non-goals

*   No new arguments and no new defaults:
    [proposal 0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)'s
    51820 default stays that proposal's landing, on whichever spelling lands
    second.
*   No assembly, store, wire, or selection change of any kind.
*   No ping redesign: its three request flags stay bare on the
    application's own command — one command, one purpose — and only the
    inherited node arguments rename.
*   No grouping mechanism beyond the name: no custom usage templates, no
    flag annotations, no `--set` grammar — the last being the
    configuration file the run arguments replaced, in disguise.
*   No aliases, hidden successors, or transitional parsing for the
    unprefixed spellings.

## Proposal

### The rule

A bare argument places the daemon; a prefix names the part. `--state` roots
the node's files; `--internal` and `--control` bind its own addresses —
placement, the frame every part consumes: the applications' mesh sockets
derive from the control address's host
([wireguard.go](/internal/services/wireguard.go)), and the measured
provider's sockets from the same
([node.go](/internal/services/node.go)). A part's arguments say what it
does once placed, and the line between the frame and the forwarding plane's
part is placement against tuning: `--internal` places the internal link's
socket, `--dataplane.queue-size` tunes the plane that serves it.

The prefixes enumerate the owners the tree already files — the planes,
engines, seams, and applications of the roof
([pkg/](/pkg), [pkg/modules](/pkg/modules)) — and only an owner with an
argument appears. The control plane reads none today: its sockets are the
placement argument `--control`, and its periods are constants, so no
`--controlplane.` stands beside `--dataplane.`; the roof already names the
home for the day one is promoted from the test pacing, and reserving it
keeps that block mechanism knobs rather than reopening it for identity
arguments. The filing follows the concern, not the consumer:
`--trust.enroll-auth` names the posture the argument gates — first
issuance — where `--controlplane.enroll-auth` would file it by who calls
it, the inversion
[ADR-0013](/docs/adrs/0013-file-the-nodes-seams-as-modules.md)
corrected when it filed the authorizer as a module of its own.

### The parts

**topology.** The source module's two arguments, the file provider's
link-set and the measured provider's neighbor, take the one prefix — two
spellings of the one selection
[Validate](/internal/services/config.go) already guards, whose refusal
message names both namespaced forms. The prefix carries what the two
registrations could not: that choosing one is refusing the other.

**trust.** `--trust.domain` keeps its role-split registration — the core's
own domain, the WebPKI identity of its certificate, on the core; the
network's core domain, the WebPKI identity of the enrollment and TRC fetch,
on everyone else. The domain is the trust plane's identity, not placement:
the HTTPS hostname and the relay URL the applications dial derive from the
identity it names ([coordination.go](/internal/services/coordination.go),
[wireguard.go](/internal/services/wireguard.go)) — the frame consuming what
the trust plane establishes. The core's four issuance arguments join it:
the certificate's acquisition trio and the first-issuance gate. One
umbrella covers the three readers — the engine that verifies, the client
that acquires, the module that gates — because the arguments configure one
posture: the node's standing in the network's trust fabric.

**wireguard.** `--wireguard.host-port` names the application that binds the
port and whose nonzero value loads it — the gate
[proposal 0029](/docs/proposals/0029-assign-the-node-slice-from-the-directory.md)
leaves in the argument. The riders follow the application: the SOCKS
service borrows its router, and the directory assigns the slice at its
first publication. A prefix naming the serving surface instead —
`--hosts.port` — would under-attribute: one application owns the port, the
loading, and the gate.

**dataplane.** The three tuning arguments take the forwarding plane's name,
catching the surface up to the seam the code already has:
`services.DataplaneOptions` carries them as a struct separate from the node
configuration, handed to `Run` beside it
([run.go](/cmd/cion/run.go)).

### The surface it reads

pflag prints a flag set alphabetically by default; the namespaced arguments
would cluster but the bare three would interleave (`control`, `internal`,
and `state` sort between the blocks). Turning sorting off and registering in
the table's order — placement, topology, trust, wireguard, dataplane —
makes each command's `--help` read as the table does: the frame, then each
part's block.

### Compatibility

The unprefixed spellings fail as unknown flags naming the argument — the
outright retirement
[proposal 0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)
and [proposal 0027](/docs/proposals/0027-split-the-run-command-by-the-nodes-role.md)
practice, with no in-repo caller outside the command tests: the integration
harness builds `NodeConfig` directly and passes unmodified. The proposal
drafts against
[proposal 0029](/docs/proposals/0029-assign-the-node-slice-from-the-directory.md)'s
surface — the slice the directory's assignment, `--host-port` the gate —
and composes with
[proposal 0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)'s
default whichever lands first: a default is a value, the namespace a
spelling.

## Test plan

*   **The surfaces:** each command's flag set parses its parts' namespaced
    arguments into the same node configuration fields — the role preset
    included — and each command's help lists the placement flags before the
    part blocks.
*   **The refusals:** each unprefixed spelling of a renamed argument
    refuses as an unknown flag naming it, beside `--core`,
    `--wireguard-config`, and `--behind-nat`; the role refusals keep 0027's
    shape over the new names.
*   **The messages:** the validator's and the tuning checks' error texts
    name the namespaced spellings; no error text names an unprefixed one.
*   **The proofs:** the integration labs pass unmodified — the harness
    builds the node configuration directly.

## Implementation history

*   The registrations: [run.go](/cmd/cion/run.go) carries the placement
    three and the static selection under `addSharedNodeFlags`, the
    `dataplane.` three under `addTuningFlags`, and the one new helper
    `addWireguardFlags` — the host port leaving the shared registration so
    the wireguard block prints after the role's trust block — while the
    role registrations carry their `trust.` blocks and the local one's
    `topology.neighbor`
    ([run_core.go](/cmd/cion/run_core.go),
    [run_local.go](/cmd/cion/run_local.go)). The three commands turn
    their flag sets' sorting off, so each `--help` prints the frame, then
    the part blocks, in registration order — ping's bare request flags
    last.
*   The messages: the validator's refusals name the namespaced spellings
    ([config.go](/internal/services/config.go)), and so do the tuning
    checks' and the two providers' first-start errors
    ([run.go](/cmd/cion/run.go),
    [measured/provider.go](/pkg/modules/topology/impl/measured/provider.go),
    [file/provider.go](/pkg/modules/topology/impl/file/provider.go)); the
    unprefixed spellings refuse as unknown flags beside the standing
    retirements, and the commands' long descriptions and the comments
    naming an argument follow the rename.
*   The proofs: proposal 0030 landed first, so its 51820 default rides
    under the new spelling with no accommodation; the command tests check
    the surfaces parse into the same fields, the help's part order, the
    unknown-flag refusals of the role arguments and of every unprefixed
    spelling, and the restated refusal texts
    ([run_test.go](/cmd/cion/run_test.go),
    [ping_test.go](/cmd/cion/ping_test.go)); the integration labs pass
    unmodified, the harness building the node configuration directly. The
    architecture's two module mentions follow the rename
    ([architecture.md](/docs/design/architecture.md)).
