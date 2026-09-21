# Benchmark the data plane's packet forwarding

This proposal gives `pkg/dataplane` the benchmarks its inherited design has
always implied and the repository has never contained. It grounds on
[ADR-0001](/docs/adrs/0001-adopt-scion-architecture.md), whose accepted
decision the forwarding plane implements, and on the
[architecture overview](/docs/design/architecture.md)'s restatement of the
promise it measures — the data plane forwards by the packet's own path. No
boundary moves and no record is re-decided: the change is benchmark code,
its harness, and the conventions for reading its numbers.

[TOC]

## Summary

The data plane carries a performance design it inherited from the router
lineage — a pooled packet structure aimed at zero allocations on the
forwarding path, batched socket reads and writes, per-packet processors fed
by a flow hash, a fast path of cheap validations around one MAC
verification, and a slow path that answers everything else — and nothing in
the repository measures any of it. The tests prove a packet traverses the
two-node line correctly
([`twonode_test.go`](/pkg/dataplane/twonode_test.go)); none says how many
packets per second, at what per-packet cost, or with how many allocations.
This proposal adds the benchmark suite in three layers: fast-path
micro-benchmarks per reachable traffic class (`in`, `out`, and `br_transit`
— the classes a one-node AS can produce), component benchmarks for the
costs the design itself names (header decode, MAC verification, flow
hashing, the packet pool, the per-packet metrics calls), and a pipeline
throughput benchmark that drives a running `Serve` over loopback UDP across
the `RunConfig` matrix and flow counts, reporting packets per second. A
slow-path benchmark covers SCMP generation, the cost paid per unit of
invalid traffic. Benchmarks only; production code is untouched.

## Motivation

The design's performance claims are stated in comments and never checked.
The packet structure exists "to save on copy *and* garbage collection"
(`packet.go`); the pool, the headroom arithmetic, and the 64-byte packet
struct are all in service of an allocation-free fast path, and the one
deliberate exception — a fresh `net.UDPAddr` per locally delivered packet
in `internalLink.Resolve` — is documented as an experimentally verified
trade. Whether the fast path actually allocates nothing is a property only
a benchmark can observe, and drift is silent: a slice escape or an
interface boxing anywhere on the path would land without any test failing.

The costs the architecture leans on are likewise unmeasured. The fast path
is built around `verifyCurrentMAC` on the assumption that one CMAC
computation dominates everything else it does; batching
(`ReadBatch`/`WriteBatch` and the `RunConfig` knobs `NumProcessors` and
`BatchSize` exist to be tuned) rests on the amortization being real; and
`computeProcID` hashes the flow ID on the theory that flows spread across
processor queues — which also means a single flow strands on one processor,
a scaling limit nobody has quantified. The knobs are exposed and no data
guides them.

Changes to the forwarding path land blind.
[Proposal 0012](/docs/proposals/0012-bfd-liveness-and-two-route-comparator.md)
put a lock-free rate check into the egress-down branch beside the hot path;
the next change to validation, path rewriting, or metrics will similarly
arrive with an argument about cost and no measurement to anchor it. The
`getDstPortSCMP` path carries its own comment — "far too slow for the
dataplane" — with no number attached.

### Goals

*   Fast-path micro-benchmarks, one per reachable traffic class — `br_transit`
    (external in, external out, the canonical forwarding case, over plain,
    cross-over, and non-construction-direction path shapes), `in` (external
    in, local delivery, including the destination resolution and its one
    allocation), and `out` (internal in, external out, including the source
    validations) — measuring ns/op and allocs/op through the real
    `processPkt`.
*   Component benchmarks for the individually named costs: `decodeLayers`
    over the path-shape and size matrix; the MAC computation's share,
    attributed against the transit benchmark; `computeProcID` on a single
    flow and a varied one; packet pool `Get`/`Put`; the per-packet metrics
    calls (`ProcessedPackets.Add`, `UpdateOutputMetrics`) under both the
    default no-op provider and a configured one; and BFD dispatch, the
    control traffic that now shares the fast path.
*   A pipeline throughput benchmark: a running data plane over loopback
    UDP, a sender driving the ingress socket, a receiver counting at the
    egress remote socket, reporting delivered packets per second — across
    `NumProcessors`, `BatchSize`, and single-flow versus many-flow loads.
*   A slow-path benchmark: SCMP error generation through
    `slowPathPacketProcessor.processPacket` — path reversal, quotation, and
    serialization — the per-answer cost behind proposal 0012's rate cap.
*   Conventions that make the numbers comparable: benchmark naming and
    placement per the style guide, `packets/s` through `b.ReportMetric`,
    allocs/op as a first-class reading, and the benchstat workflow for
    before/after comparisons.

### Non-goals

*   Production code changes. A benchmark that exposes a defect or a
    regression hands its finding to a separate change — this proposal
    measures the plane, it does not modify it.
*   The sibling-link traffic classes (`in_transit`, `out_transit`): a
    one-node AS never builds a sibling link, so those branches of `process`
    are unreachable in CION and synthesizing a topology for them would
    benchmark a configuration that cannot exist.
*   Latency percentiles: a ping-pong RTT benchmark on loopback measures
    scheduler and kernel noise more than the plane; if forwarding latency
    is ever wanted, it is its own proposal on real links.
*   External traffic generators, kernel-bypass stacks, multi-node
    deployments, and anything outside `pkg/dataplane` — gateway and
    `pkg/scion` application throughput is a different question.
*   A CI performance gate or canonical hardware reference: benchmarks run
    locally, on the runner's machine, for the comparisons of the moment.

## Proposal

### The harness

The benchmarks live in `pkg/dataplane` itself, in-package like the tests,
because the objects they drive are unexported (`newPacketProcessor`, the
`Packet` internals, the pool). A topology helper builds the transit node
the micro-benchmarks need: one data plane with the internal link and two
external links — interface IDs 1 and 2 — over the UDP provider, assembled
from the pieces the tests already have (`freeUDPAddr`, `NewMetrics`,
`newTestPool`). Packet builders generalize `directPath` from
`twonode_test.go` the way it already chains MACs: a plain two-hop path in
construction direction entering at interface 1 and leaving at interface 2;
a two-segment path that crosses over at this router (exercising `doXover`
and the second MAC verification); the same traversed against construction
direction (SegID updated at ingress, egress read from `ConsIngress`); and
the delivered-to-local shape whose last hop ends here. The L4 payload is
UDP — `dstScionPort` reads its port in two instructions — with SCMP
payloads built only where the SCMP-specific parse is itself the subject. A
size parameter pads the payload; a flow parameter varies the flow ID, the
one field `computeProcID` hashes.

### The fast path, per class

`BenchmarkProcessPkt` runs sub-benchmarks per traffic class and path shape.
Each iteration takes a packet from the pool, copies the template in, sets
the ingress link, and calls `processPkt`; the disposition must be
`pForward` — asserted in a warm-up pass before `b.ResetTimer`, so the
benchmark cannot silently time a discard. The readings are ns/op and
allocs/op: the pooled design owes the transit and outbound classes zero
allocations, and the inbound class exactly the one documented
`net.UDPAddr`.

### The named components

The component benchmarks isolate what the design names, so a regression in
the transit total can be attributed rather than suspected.
`BenchmarkDecodeLayers` parses headers alone across the matrix.
`BenchmarkComputeProcID` hashes one flow and then many — the single-flow
case is also the processor-stranding ceiling made visible.
`BenchmarkPacketPool` measures the `Get`/`Put` channel round trip the pool
discipline charges every packet. `BenchmarkPacketMetrics` pays the per-packet
`Add` calls under the default no-op provider and under a configured
provider, because both sit on every forwarded packet and the no-op is not
free. The MAC's share is read by subtraction — a `path.FullMAC`
micro-benchmark beside the transit total — keeping the attribution in
context rather than benchmarking the hash in isolation from the buffer
reuse around it. `BenchmarkProcessBFD` covers the dispatch the liveness
traffic now takes.

### The pipeline

`BenchmarkForwardPipeline` runs the whole plane: the transit node under a
real `Serve` with a given `RunConfig`, a sender goroutine writing datagrams
to the ingress external socket, and a receiver counting arrivals at the
egress link's remote socket until `b.N` are delivered. The benchmark
reports delivered packets per second and asserts the loss the metrics
counters record is zero — a number measured through drops is a loss
benchmark, not a forwarding one. The matrix is `NumProcessors` 1, 2, and 4;
`BatchSize` 16, 64, and 256; and loads of one flow and many flows, the
pair that shows what the flow hash strands. Loopback includes the kernel's
share of both ends; that is the point of the layer — it measures the
router whole, and it is not comparable against the micro-benchmark layer
above it.

### The slow path

`BenchmarkProcessSCMP` drives a packet engineered to fail a validation —
an expired hop field is the canonical one — through the slow-path
processor: path reversal, the quoted original, SCMP serialization, and the
SCION header prepended in the headroom. This is the per-answer cost the
egress-down cap of proposal 0012 bounds, and the number a resilience
argument about invalid-traffic load wants.

### Reading the numbers

Benchmarks run without `-race` — the correctness suites carry the race
runs — under `-benchmem`, with `benchstat` holding the before/after
comparison and pprof attributing whatever moved. Every custom reading is
`b.ReportMetric`: packets per second from the delivered count, never from
the sent count. The landing records a smoke run's shape in its history
entry — which benchmarks, on what kind of machine — explicitly
non-canonical.

## Test plan

*   **Generator correctness:** a companion test runs each benchmark's
    packet generator through `processPkt` once and asserts the disposition,
    the egress interface, and the traffic type — a benchmark timing a
    discarded or misrouted packet measures nothing, and the generators are
    the one place this suite can lie quietly.
*   **Zero-loss invariant:** the pipeline benchmark fails rather than
    reports when sent and delivered counts diverge, with the drop counters
    naming the reason.
*   **Isolation from correctness suites:** the benchmarks run under the
    same `go test` invocation as the tests without lengthening it —
    `-bench` opts in, and nothing in the harness blocks or sleeps on wall
    time beyond what the running plane itself does.
*   **Reviewer smoke run:** before landing, the suite runs once on the
    author's machine and the numbers are eyeballed for plausibility —
    transit at zero allocs/op, a single flow below many flows on the
    multi-processor matrix — with anomalies resolved before the history
    entry is written.

## Implementation history

*   (To be recorded as the change lands.)
