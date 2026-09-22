# Cut the data plane's per-packet fast-path costs

This proposal is the first change to act on the numbers
[proposal 0016](/docs/proposals/0016-benchmark-dataplane-forwarding.md)
put in the repository: its suite names three per-packet costs the
inherited design never accounted for — the OpenTelemetry `Add` calls the
ingest side pays per packet, the clock read inside hop-expiry validation,
and the CMAC recomputed for every packet of a flow whose input the previous
packet already presented — and this proposal removes all three. One
structural change enables them: the processor drains its queue in batches,
so "per batch" has a boundary. No validation is removed and no verdict
moves
([ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md)): every check the
fast path performs today it performs after, on the same inputs, to the
same disposition.

[TOC]

## Summary

The fast path proper is what its design promised: the transit class runs
217 ns through `processPkt` with zero allocations
([`process_bench_test.go`](/pkg/dataplane/process_bench_test.go)). The
costs the benchmarks add to it sit beside it, on the path every forwarded
packet takes:

*   Three counter `Add` calls per packet — input packets and bytes in
    `connectedLink.receive` (`pkg/dataplane/udpip.go`), one processed
    counter in `runProcessor` (`pkg/dataplane/dataplain.go`). Each costs
    29 ns and allocates twice under the default no-op provider, 67 ns and
    the same two allocations under the configured one
    ([proposal 0017](/docs/proposals/0017-expose-metrics-and-log-discards.md)
    serves the configured case in production). The allocations are the
    option boxing in `metric.WithAttributeSet` and the variadic slice the
    call site builds — paid even when the counter records nothing. The
    egress side already stages its counts per written batch
    (`UpdateOutputMetrics`, `pkg/dataplane/metrics.go`): 3–5 ns per packet
    amortized, four allocations per batch.
*   One `time.Now` per packet in `validateHopExpiry`
    (`pkg/dataplane/processor.go`) — 9.3% of the fast path's samples, for
    a verdict the wire format grades in seconds.
*   One CMAC per packet in `verifyCurrentMAC` — 27% of samples, 36 ns
    alone — whose 16-byte input (info field and hop field, tag zeroed) is
    a constant of the flow's position on the path: every packet of a flow
    that arrives on the same segment presents the same input, and the
    router recomputes the same full MAC each time.

The proposal stages the ingest counters per batch, reads the clock once
per drained batch, remembers computed MACs in a small per-processor cache
keyed on the packet-public input, and gives the processor a batch-drain
loop so the three share a boundary. Against the measured baselines the
estimates are: the `processPkt` transit reading falls by roughly 45 ns
(the clock and the cached MAC), and the accounting around it falls from
roughly 88 ns (no-op) or 202 ns (configured) per packet to single-digit
amortized cost, dropping six allocations per forwarded packet. Settled by
`benchstat` on the 0016 suite, per its conventions; the numbers above were
taken on a two-core laptop-class runner and are explicitly non-canonical.

## Motivation

Proposal 0016's motivation closed on the gap this change fills: the next
change to validation, path rewriting, or metrics would "arrive with an
argument about cost and no measurement to anchor it." This is that change,
with its measurements. Two of them sharpen the argument:

The pooled-buffer design exists to keep the forwarding path
allocation-free — the packet struct is hand-padded to 64 bytes for it —
and the accounting beside it allocates six objects — 240 bytes — per
forwarded packet. Under the provider 0017 installs, that garbage is
produced on the goroutines the router's own latency depends on.

The pipeline layer keeps the whole-plane claim honest. On the two-core
runner the delivered ceiling is 305–311k packets/s and the profile is
54.7% `Syscall6` — kernel-bound, with `processPkt` at 2.8% of samples.
The router's own share is what this proposal cuts; on the runner that
moves the whole-plane number a few percent, on hardware with dedicated
cores the share is larger, and no claim is made here that these cuts lift
the loopback ceiling.

### Goals

*   Stage the input and processed counters per batch — the receive loop
    flushes packets and bytes per `ReadBatch`, the processor flushes the
    processed counter per drained batch — with the same staging arithmetic
    `UpdateOutputMetrics` already carries for output.
*   Read the clock once per drained batch for hop-expiry validation, with
    the staleness bounded by one batch's processing time.
*   Remember computed full MACs per flow position: a small, lock-free,
    per-processor cache keyed on the 16-byte MAC input, filled on the
    compute path, compared against on the hit path.
*   Drain the processor queue in batches bounded by `RunConfig.BatchSize`,
    the knob the design already exposes for tuning.

### Non-goals

*   No validation is removed, reordered, or weakened; verdicts and their
    SCMP consequences are exactly the current ones.
*   No benchmark changes: proposal 0016's layers stay as they are so
    before/after comparisons hold. A batched pipeline harness — the
    two-core runner measures its own per-datagram syscalls as much as the
    router — would be its own follow-up.
*   No architectural change to the per-packet channel handoffs between
    receiver, processor, and sender: the inherited design stands, and
    batch handoff is a future proposal only if these cuts leave the
    numbers asking for it.
*   The documented `net.UDPAddr` allocation for locally delivered packets
    stays: an experimentally verified trade, revisited only if inbound
    dominates.
*   No slow-path SCMP allocation work: the rate caps bound that traffic,
    and its cost is not on the forwarding path.
*   No new instruments — 0017's set is what ships — and no deployment
    tuning: socket buffer, affinity, and core-count guidance belongs to
    operations.

## Proposal

### Drain the processor queue in batches

`runProcessor` takes one packet per `select`, paying the two-case select
and the context check per packet. The change gives it the sender's shape
(`udpConnection.send`): block for the first packet, then drain up to a
bound with the non-blocking `readUpTo` pattern, processing each in turn.
The bound is `RunConfig.BatchSize` — the knob the batching design already
names. Ordering within a queue is preserved because the queue is still
drained in order; backpressure is unchanged because the queue is still
bounded and its overflow still drops with the busy-processor reason. The
processor's supervision
([proposal 0019](/docs/proposals/0019-dataplane-processor-supervision.md))
sees the same goroutine, the same panic recovery, the same lifecycle —
the loop's body changes, not its contract.

The drain is also the boundary the two accountings below flush against.
A drained batch is one pass of the loop: one clock reading, one flush of
the processed counter, and up to `BatchSize` packets that share them.

### Stage the ingest counters per batch

`UpdateOutputMetrics` already demonstrates the mechanism: accumulate
counts in fixed-size staging arrays indexed by size class, then record
once per cell that is non-zero. The proposal generalizes it to the input
side — the connection's receive loop owns the batch boundary, so it
stages packets and bytes per `ReadBatch` and flushes before the next —
and to the processed counter in `runProcessor`, flushed per drained
batch. The input metrics carry no traffic-type dimension, so the staging
is two small arrays. Drop counters stay per-event: they count the rare
and name the reason immediately, which is their job.

### Read the clock once per batch

`validateHopExpiry` asks whether a validity window graded in seconds has
lapsed. The processor holds one clock reading per drained batch;
staleness is bounded by the time one batch takes to process —
microseconds to milliseconds. A packet is verdict-changed only if it
expires inside that stale edge, a tolerance smaller than the wire
format's own granularity. The egress-down rate check keeps its own
`time.Now`: it runs on the failure path, not per packet.

### Remember computed MACs per flow position

`verifyCurrentMAC` computes `CMAC(key, info || hop)` and compares the
packet's six-byte tag against the first six bytes of the result, in
constant time. The input is a constant of the flow's position: packets
of a flow arriving on the same segment present the same info field (the
SegID an upstream router left) and the same hop field. The processor
therefore keeps a small direct-mapped cache — an entry is the 16-byte
input beside the 16-byte full MAC it produced, a few hundred entries,
slot chosen by a hash of the input, disambiguated by comparing the full
key, no locks — and on a hit compares the packet's tag against the
remembered full MAC with the same constant-time comparison the uncached
path performs. A miss computes as today and fills the slot.

The security arithmetic is stated, not assumed. The cache's lookup
depends only on packet-public fields — info and hop values any observer
of the segment reads off the wire — so no secret-dependent branch is
introduced. The secret-dependent operation, the tag comparison, remains
constant-time on every path, cached or not. The stored full MACs are
state the processor already holds (`cachedMac`), and the entries live
and die with the processor: the forwarding key's lifetime is the plane's,
because a new key assembles a new `DataPlane` and its new processors.
An attacker replaying an input learns what resending the same packet
already shows; an attacker probing inputs pays the uncached path. The
cache changes no verdict — a hit is a memoization of a pure function,
and the equivalence is what the tests assert.

## Test plan

*   Unit, MAC cache: verdict equivalence over randomized inputs — for a
    corpus of paths, the cached verdict, tag bytes compared, equals the
    uncached computation; a slot collision (two inputs hashing to one
    slot) disambiguates by the full key and neither borrows the other's
    MAC; an invalid tag presented on a hit still routes to the slow path
    with the invalid-hop-field-MAC code.
*   Unit, clock staging, under `testing/synctest`: packets whose windows
    expire strictly before or strictly after the batch's reading verdict
    correctly, and a packet expiring inside the stale edge is accepted —
    the tolerance, made deliberate.
*   Unit, counter staging: a manual-reader provider records the same
    sums per-packet accounting would produce — packets, bytes, processed
    — over a driven run with mixed sizes; drop counters still record per
    event.
*   Unit, drain: packets of one flow leave in queue order; a full queue
    drops with the busy-processor reason as today; a drain takes at most
    the bound and blocks again for the next first packet.
*   Integration: the two-node line
    ([`twonode_test.go`](/pkg/dataplane/twonode_test.go)) and the
    benchmark generators' correctness test pass unchanged — the
    strongest statement that verdicts did not move.
*   `benchstat` before/after across the 0016 suite, both providers for
    the metrics readings; the history entry records the runner's shape,
    non-canonical per 0016's convention.

## Implementation history

*   The drain: `runProcessor` (`pkg/dataplane/dataplain.go`) took the
    sender's shape — block for the first packet of a batch, then the
    non-blocking `readUpTo` up to `RunConfig.BatchSize` — and one pass of
    its loop became the batch the other accountings flush against.
    Ordering, the bounded queue, and the busy-processor overflow drop are
    as they were; the supervision (0019) sees the same goroutine, panic
    recovery, and lifecycle.
*   The clock: the processor holds one `now`, refreshed once per drained
    batch, and `validateHopExpiry` reads it (`pkg/dataplane/processor.go`).
    The egress-down rate check keeps its own `time.Now`, on the failure
    path where it always lived.
*   The counters: beside `UpdateOutputMetrics` in
    `pkg/dataplane/metrics.go`, `inputMetricsStaging` accumulates packets
    and bytes per size class and is flushed by the connection's receive
    loop once per `ReadBatch` (`pkg/dataplane/udpip.go`);
    `processedStaging` holds one entry per ingress link a batch mixes —
    found by a pointer scan, short because a plane carries a handful of
    links — and flushes once per drained batch. Both copy
    `UpdateOutputMetrics`'s arithmetic: fixed arrays, one record per
    non-zero cell. Drop counters stay per-event.
*   The MAC memo: `macCache` (`pkg/dataplane/processor.go`) — 512
    direct-mapped slots per processor, the 16-byte input beside the full
    16-byte MAC, the slot chosen by the FNV-1a hash the dispatch already
    uses and disambiguated by the full key, no locks. A hit hands the
    remembered MAC to the same constant-time tag comparison; a miss
    computes as before and fills the slot, but only once the tag verified
    — a prober cannot evict what it cannot forge. The empty slots are
    keyed on an input `MACInput` cannot produce (its first two bytes are
    always zero), so a never-filled slot matches no packet.
*   Tests: `processor_test.go` — verdict equivalence over a randomized
    corpus (a cold processor against a warm one, the MAC bytes the tag was
    compared against equal), a searched-for slot collision disambiguated
    by the full key with neither input borrowing the other's MAC, an
    invalid tag presented on a hit routed to the slow path with the
    invalid-hop-field-MAC code and the slot untouched, and the batch clock
    under `testing/synctest`: strictly before and after verdict correctly,
    the stale edge is accepted, and the next batch's fresh reading expires
    the same packet. `batch_test.go` — the drain (queue order across
    batches larger than the bound, reblocking for the next first packet,
    cancellation), the busy-processor overflow drop recorded per event,
    and the staged sums checked against a manual-reader provider over a
    served plane with mixed sizes. The two-node line and the benchmark
    generators' test pass unchanged.
*   Smoke run (non-canonical; the same container and shape as 0016's — an
    Intel i5-14450HX capped at two Go threads, Linux; `benchstat`, six
    counts micro and three pipeline, no benchmark file changed):
    `processPkt` transit 211 → 151 ns (−29%, past the proposal's ~45 ns
    estimate), the cross-over shape 323 → 194 ns (−40%, both of its MACs
    memoized), inbound 258 → 187 ns and outbound 219 → 155 ns, each still
    at its documented allocation count; an SCMP answer, `FullMAC`, the
    metrics `Add` under both providers, and `DecodeLayers` unchanged —
    the suite's controls. The pipeline's delivered rate rose in all
    eighteen configs, geomean 287k → 307k packets/s (+7%), though no
    single config is significant at three counts.
