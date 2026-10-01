# Expose the data plane's counters and log its discards

This proposal makes the node's own instruments readable through the channel
the network already authenticates and its silent failures speakable: the
daemon installs the SDK meter provider whose reader an application mount on
the control endpoint serves — behind the peer-identity middleware, over
SCION paths, where any chain-holding member reads the data plane's counters
in Prometheus text format — and the run argument `--log-level` sets the
default logger's level so a deployment can ask for debug, where every
fast-path discard names its reason through a per-processor rate cap. No
instrument is added and the core claims no new duty
([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)):
the exporter reads what the data plane already counts, and the mount rides
the endpoint every node already serves behind the middleware it already
enforces. Where visibility goes from there — gathered through the network
to a monitor and a backend beside it — is
[ADR-0016](/docs/adrs/0016-gather-observability-through-the-network-and-serve-it-from-a-monitor-node.md)'s
design; this proposal is that record's enabling half.

[TOC]

## Summary

The data plane declares six counter families — input, output, processed,
dropped packets, and bytes — and builds every instrument from the global
meter provider (`NewMetrics`, `pkg/dataplane/metrics.go`), which both the
daemon's assembly (`internal/services/dataplane.go`) and the test harness
call. But the daemon installs no SDK meter provider: nothing outside the
dataplane tests' temporary manual readers ever calls `SetMeterProvider`, so
the provider is the API's built-in no-op and every `Add` lands nowhere —
the counters are dead code, and a deployment running the daemon can read
none of them.

The fast path's failures are invisible beside them. `errorDiscard`
(`pkg/dataplane/processor.go`) documents its own economy — "we do almost
nothing with errors" — and returns the discard disposition with a TODO
for logging standing since the code arrived; its callers already pass the
reason as key-values, and the function drops the words. A packet discarded
for a failed hop MAC or an invalid path leaves no trace at any log level,
and the one aggregate that counts it,
`dropped_packets_total{reason=invalid}`, never reaches a reader.

And the channel that could serve the counters carries none of them: the
control endpoint's application mounts ride the peer-identity middleware
over HTTP/3 (`pkg/controlplane/server.go`), and the measured provider's
link and directory services are the only contributors — a member's reader
has no pattern to ask for. The logger is never configured either — no
call installs a default handler, so the level is slog's built-in info with
no run argument able to lower it.

## Motivation

An operator triaging "traffic does not flow" across a multi-operator
network needs exactly the two instruments this proposal turns on: the drop
counters, which name the interface and the neighbor, and the discard
reason, which names the failure. Today the counters go nowhere and the
reasons go unsaid, so diagnosis starts and ends at the ping application.

Where the counters are served is decided by what the network can reach. A
node behind an unmapped underlay — the common shape in a multi-operator
network — is reachable by no scraper that pulls over plain HTTP: a plain
listener beside the endpoint presupposes a collector co-located with every
node, and a push from each node presupposes a backend the mesh cannot
route to. The reader that exists instead is
[ADR-0016](/docs/adrs/0016-gather-observability-through-the-network-and-serve-it-from-a-monitor-node.md)'s:
a scraper that is itself a node, an application resident on one — and a
peer holding a chain is exactly what the control endpoint's application
mounts already serve (`pkg/controlplane/server.go`): HTTP/3 over SCION
paths, the peer-identity middleware surfacing what the channel verified
against the TRC (`pkg/peeria`, `pkg/controlplane/mtls.go`). The mount
serves the Prometheus text format from the exporter's own registry — the
read stays a pull in a format the ecosystem already speaks, and the push
to a backend is the monitor's business, not the node's.

Who may read is membership, the boundary ADR-0016 states at the seam
instead of inheriting from a bind address: the SCION-native channel
demands a client certificate and verifies it against the pinned TRC
(`pkg/controlplane/mtls.go`), so an instrument a mount serves is readable
by any network member and by nothing else. The counters carry per-neighbor
traffic volumes in their labels; in a multi-operator network those volumes
are the network's shared business — the policy the record chose — and
reading on demand keeps a node's egress at zero until a member asks, the
cardinality that leaves it bounded by the reader's scrape.

The discards log at debug, capped. The level check comes first, so a
deployment not asking for debug pays one check per discard — the
function's documented economy keeps — and a deployment that asks gets at
most ten lines per processor per second, the one-atomic-word window
arithmetic the SCMP notify limiter already carries
(`pkg/dataplane/processor.go`). The aggregate volume lives in the drop
counter the first half of this proposal serves; the log's job is the
reason, not the count. SCMP parameter-problem signaling — the dataplane
TODOs' own suggestion — stays deferred: a log line is cheaper than a wire
protocol and enough to diagnose.

### Goals

*   The provider: the SDK meter provider with the Prometheus exporter as
    its reader, installed globally before the node assembles — no argument
    gates it, for the boundary is membership, not configuration — and the
    instruments `NewMetrics` builds today are the instruments served.
*   The mount: the endpoint serves the exporter's registry at `/metrics`
    behind the peer-identity middleware, beside the topology provider's
    mounts; any chain-holding member reads it over SCION paths on the
    reader's own cadence, and a node's egress stays zero until one asks.
*   The level: `--log-level` — `debug|info|warn|error`, default `info` —
    installs the default logger's handler before the node assembles,
    carried by `run` and `ping` with the other node arguments.
*   The discards: `errorDiscard` logs the caller's reason at debug
    through the default logger, capped per processor per second; fast
    path and slow path share it.

### Non-goals

*   No new instruments: the control plane, the applications, and the
    node's own state count nothing new; what the data plane counts today
    is what ships.
*   No gathering: the monitor application, the directory's status fields,
    and the traceroute sender are
    [ADR-0016](/docs/adrs/0016-gather-observability-through-the-network-and-serve-it-from-a-monitor-node.md)'s
    — this proposal turns on the node's own half alone, and nothing
    gathers until a monitor loads.
*   No plain listener, no probe, no serving argument: nothing new binds —
    no `/healthz`, no `--metrics` — the endpoint the node already serves
    is the whole of the change's serving surface, and no new address
    exists to misconfigure.
*   No SCMP parameter-problem signaling: the dataplane TODOs stand; a
    log line is not a wire message.
*   No OTLP egress from the node, no traces, no log shipping, no JSON log
    format: the node serves reads through the authenticated channel, the
    monitor owns the push
    ([ADR-0016](/docs/adrs/0016-gather-observability-through-the-network-and-serve-it-from-a-monitor-node.md)),
    and the text handler at a settable level is the whole of the logging
    change.

## Proposal

### Serve the counters at the control endpoint

One module joins the direct requirements:
`go.opentelemetry.io/otel/exporters/prometheus`, with the Prometheus
client library arriving transitively — the SDK meter provider's package
is already direct, the dataplane tests' manual readers its only consumer
until now. The alternative, hand-rolling the text format over a manual
reader, trades a vendored tree for owned code that must track the format.

Assembly owns the wiring. `Run` builds the meter provider with the
exporter as its reader and installs it globally before the node assembles
— before `setupMetrics` calls `NewMetrics`, so the instruments the data
plane already increments land in the reader — and the endpoint's assembly
appends the exporter's registry handler to the mounts the topology
provider built (`internal/services/controlplane.go`): the pattern
`/metrics`, wrapped by the peer-identity middleware with every other
mount (`NewServer`, `pkg/controlplane/server.go`). Nothing binds and no
address is chosen — the endpoint's socket is the listener — so no default
joins `DefaultInternal` and `DefaultControl` and no misconfiguration can
refuse a startup. The data plane's code changes not at all, and a network
that later loads a monitor configures no node to serve it: every node
serves its instruments from its first start.

A member reads with the verified client the endpoint's machinery already
exposes as a library (`VerifiedClient`,
`pkg/controlplane/peerclient.go`) — HTTP/3 riding SCION paths, the
member's chain presented, the node's verified — on a cadence the reader
owns.

### Set the logger's level

The command owns the logger. `cmd/cion` maps `--log-level` to a
`slog.Level` and installs `slog.NewTextHandler` over stderr as the
default before the node assembles; the argument registers in
`addSharedNodeFlags`, so `run` and `ping` carry it, and an invalid value
is refused at the flag. Unset is `info` — today's behavior, now stated
rather than inherited.

### Give the discards a voice

`errorDiscard` becomes the processor's own: a method on
`scionPacketProcessor`, whose callers — fast path and slow path alike —
already pass the reason as key-values. The level check comes first: the
default handler's `Enabled` answers for debug before any other work; past
it, the processor's cap decides — one `atomic.Uint64` field holding the
window the SCMP notify limiter holds (second and count packed in one
word, `pkg/dataplane/processor.go`), bounded by a sibling constant
`discardCapPerSecond` (ten, the notify cap's own figure) — and within the
cap the discard logs at debug with the caller's key-values. Past the cap
the discard is silent; the counter carries the volume, and the next
second's window opens clean.

## Test plan

*   Unit, dataplane: the cap's window arithmetic under `testing/synctest`
    — the first ten discards of a second log, the eleventh is silent, and
    the next second's first logs again; a recording handler asserts the
    line carries the caller's reason.
*   Unit, services: the assembled endpoint serves the mount — the mux
    answers `/metrics` behind the peer-identity middleware with the
    families `NewMetrics` declares once an instrument records, with the
    instrument's own labels (interface, local AS, neighbor AS, size
    class) — and the provider is installed before assembly, so the
    daemon's instruments record where the no-op answered nothing.
*   Unit, cmd: `--log-level` selects the handler's level, and an invalid
    value is refused at the flag.
*   Integration, the line lab: one node reads another's mount — after
    pings flow, a scrape over the verified channel carries input, output,
    and processed counters above zero with each node's traffic separated
    by its `local_as` label; a packet whose hop MAC fails verification
    crossing the middle node raises
    `dropped_packets_total{reason="invalid"}` on it and, at debug, the
    capped discard lines name the verification failure — at info the same
    run logs nothing. The harness configures nothing per node: every
    process installs its provider, and the scrape rides a member's chain.

## Implementation history
