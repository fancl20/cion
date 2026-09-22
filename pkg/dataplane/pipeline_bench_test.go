package dataplane

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// The pipeline matrix: processor counts, batch sizes, and the single-flow
// versus many-flow loads — the pair that shows what the flow hash strands on
// one processor.
const (
	benchStallTimeout  = 30 * time.Second
	benchDeadlineEvery = 4096
)

func pipelineCases() []struct {
	RunConfig
	flows int
} {
	var cases []struct {
		RunConfig
		flows int
	}
	for _, procs := range []int{1, 2, 4} {
		for _, batch := range []int{16, 64, 256} {
			for _, flows := range []int{1, benchFlowCount} {
				cases = append(cases, struct {
					RunConfig
					flows int
				}{
					RunConfig: RunConfig{
						NumProcessors:         procs,
						NumSlowPathProcessors: 1,
						BatchSize:             batch,
						ReceiveBufferSize:     1 << 20,
						SendBufferSize:        1 << 20,
					},
					flows: flows,
				})
			}
		}
	}
	return cases
}

// BenchmarkForwardPipeline drives the whole plane: the transit topology
// under a real Serve, a sender writing into the ingress link's socket, and a
// receiver counting arrivals at the egress link's far end until b.N packets
// are delivered. It reports delivered packets per second — never sent —
// including the kernel's share of both ends: the layer measures the router
// whole and is not comparable against the micro-benchmarks above it.
//
// The sender keeps at most one batch in flight, and every queue an in-flight
// packet can rest in holds at least a batch, so a healthy run cannot lose
// packets to a full queue. When counts diverge anyway, the benchmark fails
// rather than reports — a number measured through drops is a loss benchmark,
// not a forwarding one — and the drop counters name the reason.
func BenchmarkForwardPipeline(b *testing.B) {
	for _, tc := range pipelineCases() {
		b.Run(fmt.Sprintf("procs=%d/batch=%d/flows=%d",
			tc.NumProcessors, tc.BatchSize, tc.flows), func(b *testing.B) {
			// The configured provider makes the run's drop counters
			// readable, so a divergence can be named.
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			prev := otel.GetMeterProvider()
			otel.SetMeterProvider(mp)
			b.Cleanup(func() {
				otel.SetMeterProvider(prev)
				_ = mp.Shutdown(context.Background())
			})

			n := newBenchNode(b, tc.RunConfig)
			ctx, cancel := context.WithCancel(context.Background())
			serveDone := make(chan struct{})
			go func() {
				defer close(serveDone)
				_ = n.d.Serve(ctx)
			}()
			b.Cleanup(func() {
				cancel()
				<-serveDone
			})

			tmpl := benchCases[0].build(b, n, benchPad)
			datagrams := make([][]byte, tc.flows)
			for i := range datagrams {
				datagrams[i] = varyFlow(tmpl, benchFlow+uint32(i)*benchFlowStep)
			}

			// The sender plays the source AS's router: the socket the
			// ingress link is connected to, writing into the link's own.
			var sent, delivered atomic.Int64
			window := int64(tc.BatchSize)
			senderDone := make(chan struct{})
			go func() {
				defer close(senderDone)
				dst := net.UDPAddrFromAddrPort(n.if1Addr)
				for sent.Load() < int64(b.N) {
					if sent.Load()-delivered.Load() >= window {
						runtime.Gosched()
						continue
					}
					if _, err := n.srcEnd.WriteToUDP(
						datagrams[int(sent.Load())%len(datagrams)], dst,
					); err != nil {
						return
					}
					sent.Add(1)
				}
			}()

			b.ResetTimer()
			buf := make([]byte, bufSize)
			var received int64
			_ = n.dstEnd.SetReadDeadline(time.Now().Add(benchStallTimeout))
			for received < int64(b.N) {
				if received%benchDeadlineEvery == 0 {
					_ = n.dstEnd.SetReadDeadline(time.Now().Add(benchStallTimeout))
				}
				m, err := n.dstEnd.Read(buf)
				if err != nil {
					b.Fatalf("stalled after %d of %d deliveries (sent %d): %v%s",
						received, b.N, sent.Load(), err, dropSummary(reader))
				}
				if m != len(tmpl) {
					b.Fatalf("received %dB datagram, want the %dB template", m, len(tmpl))
				}
				received++
				delivered.Store(received)
			}
			b.StopTimer()

			<-senderDone
			if got := sent.Load(); got != int64(b.N) {
				b.Fatalf("sent %d, want %d", got, b.N)
			}
			if drops := dropSummary(reader); drops != "" {
				b.Fatalf("the run dropped packets:%s", drops)
			}
			b.ReportMetric(float64(received)/b.Elapsed().Seconds(), "packets/s")
		})
	}
}

// dropSummary reads the drop counters the run recorded — the configured
// provider's per-reason view — as the message naming why packets failed to
// arrive.
func dropSummary(reader *sdkmetric.ManualReader) string {
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		return fmt.Sprintf(" (collecting metrics: %v)", err)
	}
	var summary string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "dataplane.dropped_packets_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				if dp.Value != 0 {
					summary += fmt.Sprintf(" %d{%s}",
						dp.Value, dp.Attributes.Encoded(attribute.DefaultEncoder()))
				}
			}
		}
	}
	return summary
}
