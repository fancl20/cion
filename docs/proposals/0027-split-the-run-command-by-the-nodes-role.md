# Split the run command by the node's role

This proposal splits `cion run` into two subcommands, `cion run core` and
`cion run local`: the role an operator names as the command itself rather
than a boolean beside it. Each subcommand registers only its role's
arguments — the core's issuance and certificate arguments on the one, the
joining arguments on the other — over one shared flag helper and one shared
daemon body, so the underlying command, the node assembly, and the state
directory are exactly what they are today. `--core` retires with the mix it
switched: the role-aware refusals the validator performs at boot become
unknown-flag errors at the parse, the `--domain` argument states one meaning
per role instead of both in one sentence, and `cion ping` assembles a local
node, taking the local command's arguments alone. No assembly, store, wire,
or selection change; the tree's command surface learns the partition the
arguments already had.

[TOC]

## Summary

The run command's surface is one flag set for two roles. `--core` switches
the node's role — trust genesis and issuance on the core, enrollment and
the measured join on everyone else — and the rest of the surface serves
both roles at once: beside the switch itself, four of the sixteen other
arguments are the core's alone ([`--acme-email`](/cmd/cion/run.go),
`--cert-file`, `--key-file`, `--enroll-auth`, each saying so in a
parenthetical), one is refused on the core (`--neighbor`), one writes a
reachability class only a joiner's advertisement carries (`--behind-nat`),
and `--domain` means the core's own domain under `--core` and the
network's core domain otherwise — both meanings explained in one help
sentence and one validation message. The partition is real but negative:
the operator learns it from refusal messages and from help text that
names the other role in parentheses.

This proposal makes the partition the command tree. `cion run` becomes a
parent with no run function — a bare invocation prints the roles, as a
bare `cion` prints the commands — and its two subcommands, `core` and
`local`, each preset the role and register their own arguments over the
shared ones. The role-aware checks the parse can perform become unknown
flags: the core's command has no `--neighbor` to refuse, the local
command no `--enroll-auth`. The node configuration, its validator, and the
daemon body stand unchanged behind them — the in-process assemblers
([`BootApp`](/internal/services/app.go), the integration harness) build
the same `NodeConfig` they build today, and the validator's role checks
keep guarding that path.

## Motivation

The arguments are already partitioned; the surface just does not say so.
Each fact is in the tree:

*   Four arguments beside the role's own switch are the core's alone.
    `--acme-email`, `--cert-file`, and `--key-file` feed the core's
    WebPKI certificate preparation; `--enroll-auth` is refused without
    `--core` by [Validate](/internal/services/config.go) — only the core
    issues chains, so only the core's gate means anything. Their help
    text carries the partition as parentheticals: "(core only,
    optional)", "(core only)".
*   Two are the joining side's alone. `--neighbor` names an existing
    node's rendezvous address — refused on the core, which nodes join
    rather than dial. `--behind-nat` writes the `Private` bit of the
    node's directory entry, which the [selection
    loop](/pkg/modules/topology/impl/measured/selection.go) reads to skip
    the node as anyone's candidate: an advertisement to the network one
    is joinable to, which the founding core — the node every early joiner
    dials — has no use for beyond refusing them.
*   `--domain` is two arguments in one. The core's own name under
    `--core`, the network's core domain otherwise, explained twice over:
    once in the flag's help, once in the missing-domain error. Every
    operator of either role reads both halves to find theirs.
*   The validator's role checks are the surface's rear guard.
    [Validate](/internal/services/config.go) refuses the core a neighbor,
    the local node an enrollment policy, and the two topology sources
    their mixture — checks the command tree could make unanswerable, the
    way [proposal 0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)
    made `--wireguard-config`'s retirement a fact of the parse.
*   `cion ping` registers the core's flags it cannot use. The command
    boots the node to send over its own assembly, and the core's issuance
    arguments have no meaning under it — but they parse, and the role
    arrives by the same boolean.

The naming follows the drafts' vocabulary turned operator-side. The SCION
specifications call these ASes
[*non-core*](/docs/specs/draft-dekater-scion-controlplane.txt); CION takes
the word a private network's operator says — a *local* node, joining an
existing network and serving its hosts — as it repurposed *authoritative*
in
[ADR-0002](/docs/adrs/0002-simplify-as-roles-and-types.md) for the same
reason: the operator-facing word beats the spec's structural one at the
operator's hands. [ADR-0005](/docs/adrs/0005-serve-endhosts-with-a-wireguard-gateway.md)
already speaks of a host's *local node*, and the roles agree in practice:
the node a host dials is a local one, the core's own hosts the exception a
slice on the core covers.

### Goals

*   The command tree: `cion run core` and `cion run local` as subcommands
    of a non-runnable `cion run`; each presets the role in the node
    configuration it assembles and shares one daemon body, so the two
    commands differ in arguments and nothing else.
*   The argument partition: the core's command carries `--domain` (its
    own), `--acme-email`, `--cert-file`, `--key-file`, and `--enroll-auth`;
    the local command carries `--domain` (the network's core domain),
    `--neighbor`, and `--behind-nat`; both carry the shared `--link-set`,
    `--state`, `--internal`, `--control`, `--slice`, `--host-port`, and
    the data-plane tuning flags, from one shared registration each.
*   The structural refusals: each role's command rejects the other's
    arguments as unknown flags, the parse performing the partition's
    bookkeeping; `--core` retires with no successor flag.
*   The domain's single meaning: each command's `--domain` help and each
    role's missing-domain error state the one meaning that role's operator
    acts on.
*   The unchanged assembly: `services.NodeConfig`, `Validate`, and
    `services.Run` keep their shapes; the validator's role checks keep
    guarding the in-process assemblers, with its two messages that name
    `--core` reworded to name the role.
*   The pinned ping: `cion ping` assembles a local node, registering the
    local command's node arguments; the core's arguments are unknown to
    it.

### Non-goals

*   No assembly behavior change of any kind: the role still derives from
    the configuration each start, persists nowhere, and reaches the same
    identity, trust, and application phases; the integration proofs pass
    unmodified, the harness building `NodeConfig` as it does today.
*   No transitional compatibility: `cion run --core` retires outright —
    [proposal 0024](/docs/proposals/0024-serve-egress-as-a-socks-service.md)'s
    precedent for retiring arguments, with no in-repo caller outside the
    proposals' history — and no alias or hidden flag stands in for it.
*   No core ping: the command stays the standalone application's entry,
    and pinging from a core's state directory is not a case it serves.
*   No new arguments: the tuning flags, the slice pair, and the topology
    source's selection stand exactly as they are, on both commands.
*   No new record: ADR-0008's argument regime stands as a decision at its
    date; this landing repartitions the surface it established and needs
    no architecture record of its own.

## Proposal

### The command tree

`cion run` gains subcommands and loses its run function. The parent keeps
the daemon's description and holds the two roles; a bare invocation prints
its usage — the same stance the root command takes against starting a node
by accident, and cobra's own behavior for a command with children and no
run function. The leaves are `cion run core` — the founding core: TRC
genesis, the issuer every node's chain descends from, and self-enrollment,
serving its own domain — and `cion run local` — a node joining an existing
network through its core.

Both leaves assemble a `services.NodeConfig` with the role preset and hand
it, with the tuning flags, to one shared body: the tuning sanity checks
and the `services.Run` call move there unchanged, so the two commands
differ in their registered arguments and nothing else. The root's usage
text names the three entries an operator types: `cion run core` to found a
network, `cion run local` to join one, `cion ping` to probe a destination.

### The arguments

One registration per partition, shared by the commands that take it:

| Registration | Arguments | Carried by |
| :--- | :--- | :--- |
| shared | `--link-set`, `--state`, `--internal`, `--control`, `--slice`, `--host-port` | both run commands, ping |
| core | `--domain` (the core's own), `--acme-email`, `--cert-file`, `--key-file`, `--enroll-auth` | `run core` |
| local | `--domain` (the network's), `--neighbor`, `--behind-nat` | `run local`, ping |
| tuning | `--processors`, `--batch-size`, `--queue-size` | both run commands |

The domain earns its row in both role registrations rather than the shared
one because its help states the role's single meaning: the core's own
domain — the WebPKI identity of its certificate — on the core, the
network's core domain — the WebPKI identity of the enrollment and TRC
fetch — on the local node. The `(core only)` parentheticals and the
refusal clauses leave the help texts that carried them; the command that
takes an argument is the argument's scope. `--link-set` keeps its
refusal of `--neighbor` as a validation fact rather than a help clause —
the combination remains expressible on the local command, and the
validator's message names it.

`cion ping` registers the shared and local node arguments beside its own
request flags and no tuning flags, assembling the node as a local one:
the command is the standalone application's entry, the local role covers
the sending case, and the core's issuance arguments do not parse under
it.

### The structural refusals

The parse performs what the validator's role checks performed. The core's
command has no `--neighbor` registered, the local command no
`--acme-email`, `--cert-file`, `--key-file`, or `--enroll-auth`, and
neither has `--core`: the other role's arguments fail as unknown flags,
before any validation runs. `Validate` keeps every check it has — the
in-process assemblers build `NodeConfig` fields, not command lines, and
the harness relies on the same refusals — with its two messages that name
`--core` reworded to name the role, so no error text names a flag no
command registers.

## Test plan

*   **The surfaces:** each run command's flag set parses its own
    arguments into the node configuration — the shared arguments on both,
    the role's arguments on theirs, the role preset in the options the
    core command assembles — and ping's flag set parses the local
    surface.
*   **The structural refusals:** the core's command refuses `--neighbor`
    and the local command refuses `--enroll-auth` (and the certificate
    pair) as unknown flags naming the argument; `--core` is refused on
    every command; `--wireguard-config` stays refused as the retired
    argument it is.
*   **The standing validation:** the node configuration's tests pass
    unchanged — the role checks still guard the struct the harness
    builds, and the missing-domain and enrollment refusals keep their
    meanings.
*   **The integration proofs:** `TestJoinByRendezvous` and
    `TestStaticLabByLinkSet` pass unmodified — the harness builds
    `NodeConfig` directly, and no assembly path changes.

## Implementation history
