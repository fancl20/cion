# Expose the data plane's counters and log its discards

This proposal makes the node's own instruments readable and its silent
failures speakable: the run argument `--metrics` names a plain HTTP
listener — loopback by default, off when empty — where the node serves its
OpenTelemetry instruments in Prometheus text format beside a `/healthz`
liveness probe, and the run argument `--log-level` sets the default
logger's level so a deployment can ask for debug, where every fast-path
discard names its reason through a per-processor rate cap. No instrument
is added and no boundary moves
([ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md)):
the exporter reads what the data plane already counts, and the arguments
carry the defaults a restart needs, as the run arguments do
([ADR-0008](/docs/adrs/0008-form-topology-with-measured-neighbor-selection.md)).

[TOC]

## Summary

The data plane declares six counter families — input, output, processed,
dropped packets, and bytes — and builds every instrument from the global
meter provider (`NewMetrics`, `pkg/dataplane/metrics.go`), which both the
daemon's assembly (`internal/services/dataplane.go`) and the test harness
call. But no SDK meter provider is ever installed: the module carries the
OpenTelemetry API alone, and nothing calls `SetMeterProvider`, so the
provider is the API's built-in no-op and every `Add` lands nowhere — the
counters are dead code, and a deployment running the daemon can read none
of them.

The fast path's failures are invisible beside them. `errorDiscard`
(`pkg/dataplane/processor.go`) documents its own economy — "we do almost
nothing with errors" — and returns the discard disposition with a TODO
for logging standing since the code arrived; its callers already pass the
reason as key-values, and the function drops the words. A packet discarded
for a failed hop MAC or an invalid path leaves no trace at any log level,
and the one aggregate that counts it,
`dropped_packets_total{reason=invalid}`, never reaches an exporter.

Nothing answers "is the node up": the process's listeners are the HTTP/3
control endpoint, the underlay sockets, and the ACME challenge servers; no
probe exists. And the logger is never configured — no call installs a
default handler, so the level is slog's built-in info with no run argument
able to lower it.

## Motivation

An operator triaging "traffic does not flow" across a multi-operator
network needs exactly the two instruments this proposal turns on: the drop
counters, which name the interface and the neighbor, and the discard
reason, which names the failure. Today the counters go nowhere and the
reasons go unsaid, so diagnosis starts and ends at the ping application.

Where the counters are served is decided by what the control endpoint is:
its application mounts ride the peer-identity middleware over HTTP/3
(`pkg/controlplane/server.go`), and a scraper is not a peer — it holds no
chain, and it pulls over plain HTTP. The precedent for a plain listener is
the ACME challenge servers (`pkg/webpki/tls.go`): assembly binds what the
endpoint's mux must not carry. The metrics listener sits beside them and
serves the Prometheus text format — pull, no collector to run, and every
scraper speaks it; an OTLP push would bind each deployment to a collector
the network's scale does not ask for.

The default bind is loopback, joining `--internal` and `--control`
(`internal/services/config.go`): the counters carry per-neighbor traffic
volumes in their labels, which in a multi-operator network is the
operator's own business. The listener authenticates no one; its default
bind is the boundary, and publishing the address is a deliberate act.

The discards log at debug, capped. The level check comes first, so a
deployment not asking for debug pays one check per discard — the
function's documented economy keeps — and a deployment that asks gets at
most ten lines per processor per second, the one-atomic-word window
arithmetic the SCMP notify limiter already carries
(`pkg/dataplane/processor.go`). The aggregate volume lives in the drop
counter the first half of this proposal exposes; the log's job is the
reason, not the count. SCMP parameter-problem signaling — the dataplane
TODOs' own suggestion — stays deferred: a log line is cheaper than a wire
protocol and enough to diagnose.

### Goals

*   The listener: `--metrics` names the address the daemon serves its
    instruments on, in Prometheus text format at `/metrics` with a
    `/healthz` liveness probe beside it — default `127.0.0.1:30043`, off
    when empty, a bind failure fatal at startup.
*   The provider: the SDK meter provider with the Prometheus exporter as
    its reader, installed globally before the node assembles; the
    instruments `NewMetrics` builds today are the instruments served.
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
*   No SCMP parameter-problem signaling: the dataplane TODOs stand; a
    log line is not a wire message.
*   No OTLP push, no traces, no log shipping: the exporter serves the
    scrape; a deployment wanting OTLP bridges it outside the node.
*   No readiness on `/healthz`: liveness of the process; whether links
    serve is the monitor's verdict, not the probe's.
*   No authentication on the listener and no JSON log format: the
    loopback default is the access boundary, and the text handler at a
    settable level is the whole of the logging change.

## Proposal

### Serve the counters on the metrics listener

Two modules join the direct requirements:
`go.opentelemetry.io/otel/sdk` for the meter provider and
`go.opentelemetry.io/otel/exporters/prometheus` for the exporter, with
the Prometheus client library arriving transitively — the alternative,
hand-rolling the text format over a manual reader, trades a vendored
tree for owned code that must track the format.

Assembly owns the wiring. `internal/services` grows the default
`DefaultMetrics` beside `DefaultInternal` and `DefaultControl`, and
`NodeConfig` grows the field the argument fills. When the argument is not
empty, `Run` builds the meter provider with the exporter as its reader,
installs it globally before the node assembles, and binds the listener: a
TCP `http.Server` whose mux carries the exporter's registry at `/metrics`
and the probe at `/healthz`, closing with the node's context the way the
ACME listeners do. A bind failure is fatal at startup — a named address
that cannot bind is a misconfiguration, the underlay binds' own posture.
An empty argument assembles no listener and installs no provider; the
counters stay no-ops exactly as today, and the data plane's code changes
not at all.

### Set the logger's level

The command owns the logger. `cmd/cion` maps `--log-level` to a
`slog.Level` and installs `slog.NewTextHandler` over stderr as the
default before the node assembles; the argument registers in
`addNodeFlags`, so `run` and `ping` carry it, and an invalid value is
refused at the flag. Unset is `info` — today's behavior, now stated
rather than inherited.

### Give the discards a voice

`errorDiscard` becomes the processor's own: a method on
`scionPacketProcessor`, whose callers — fast path and slow path alike —
already pass the reason as key-values. The level check comes first: the
default handler's `Enabled` answers for debug before any other work;
past it, the processor's cap decides — one `atomic.Uint64` field holding
the window the SCMP notify limiter holds (second and count packed in one
word, `pkg/dataplane/processor.go`), bounded by a sibling constant
`discardCapPerSecond` (ten, the notify cap's own figure) — and within the
cap the discard logs at debug with the caller's key-values. Past the cap
the discard is silent; the counter carries the volume, and the next
second's window opens clean.

## Test plan

*   Unit, dataplane: the cap's window arithmetic under
    `testing/synctest` — the first ten discards of a second log, the
    eleventh is silent, and the next second's first logs again; a
    recording handler asserts the line carries the caller's reason.
*   Unit, services: an assembled listener scrapes — `/metrics` answers
    the families `NewMetrics` declares once an instrument records, with
    the instrument's own labels (interface, local AS, neighbor AS, size
    class); `/healthz` answers 200; an empty `--metrics` assembles no
    listener and the global provider stays the no-op.
*   Unit, cmd: `--log-level` selects the handler's level, and an invalid
    value is refused at the flag.
*   Integration, the line lab: the harness installs one provider per
    process and gives its nodes metrics addresses; after pings flow, the
    scrape carries input, output, and processed counters above zero with
    each node's traffic separated by its `local_as` label; a packet whose
    hop MAC fails verification crossing the middle node raises
    `dropped_packets_total{reason="invalid"}` on it and, at debug, the
    capped discard lines name the verification failure — at info the same
    run logs nothing.

## Implementation history
