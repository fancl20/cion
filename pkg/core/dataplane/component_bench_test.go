package dataplane

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// benchPads pads the UDP payload to the small and the Ethernet-scale ends of
// the size matrix; sub-benchmarks are named by each template's actual
// length, because the shapes' headers differ.
var benchPads = []struct {
	name string
	pad  int
}{
	{"small", 48},
	{"large", 1420},
}

// benchMetricsBatch is the written batch the output-metrics call accounts
// for: the production default batch size.
const benchMetricsBatch = 64

// BenchmarkDecodeLayers measures header parsing alone across the path-shape
// and size matrix, on the layers a processor keeps — as the fast path
// decodes, not a fresh parser per packet. Decode is read-only, so the same
// template serves every iteration uncopied.
func BenchmarkDecodeLayers(b *testing.B) {
	n := newBenchNode(b, benchRunConfig)
	proc := newPacketProcessor(n.d)
	for _, tc := range benchCases {
		for _, sz := range benchPads {
			tmpl := tc.build(b, n, sz.pad)
			b.Run(fmt.Sprintf("%s/%s=%dB", tc.name, sz.name, len(tmpl)), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if _, err := decodeLayers(tmpl,
						&proc.scionLayer, &proc.hbhLayer, &proc.e2eLayer); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkComputeProcID measures the ingress dispatch hash on a single flow
// and on a varied one — the single-flow reading is also the ceiling a flow
// stranded on one processor pays, made visible. The seed is fixed so runs
// stay comparable.
func BenchmarkComputeProcID(b *testing.B) {
	n := newBenchNode(b, benchRunConfig)
	single := benchCases[0].build(b, n, benchPad)
	varied := make([][]byte, benchFlowCount)
	for i := range varied {
		varied[i] = varyFlow(single, benchFlow+uint32(i)*benchFlowStep)
	}
	b.Run("flow=single", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, ok := computeProcID(single, benchMaxProcs, fnv1aOffset32); !ok {
				b.Fatal("dispatch rejected the template")
			}
		}
	})
	b.Run("flow=varied", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := computeProcID(
				varied[i%benchFlowCount], benchMaxProcs, fnv1aOffset32,
			); !ok {
				b.Fatal("dispatch rejected the template")
			}
		}
	})
}

// BenchmarkPacketPool measures the Get/Put channel round trip the pool
// discipline charges every packet.
func BenchmarkPacketPool(b *testing.B) {
	pool := newTestPool(64, minHeadroom)
	b.ReportAllocs()
	for range b.N {
		pool.Put(pool.Get())
	}
}

// BenchmarkFullMAC measures the MAC computation alone — the cost the fast
// path is built around. Its reading is taken against the transit totals of
// BenchmarkProcessPkt to attribute the MAC's share of them.
func BenchmarkFullMAC(b *testing.B) {
	p := transitPath(b, benchKey, util.TimeToSecs(time.Now()))
	info, hop := p.InfoFields[0], p.HopFields[0]
	mac, err := scrypto.InitMac(benchKey)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, path.MACBufferSize)
	if got := path.FullMAC(mac, info, hop, buf)[:path.MacLen]; string(got) != string(hop.Mac[:]) {
		b.Fatalf("computed MAC %x, want the hop field's %x", got, hop.Mac)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		path.FullMAC(mac, info, hop, buf)
	}
}

// BenchmarkProcessBFD measures the dispatch the liveness traffic now takes:
// a SCION-framed control packet parsed on the fast path and handed to the
// link's session. The session counts arrivals and holds no protocol state,
// so the cost measured is the plane's.
func BenchmarkProcessBFD(b *testing.B) {
	n := newBenchNode(b, benchRunConfig)
	tmpl := bfdPacket(b, n.key)
	session := n.if1.BFDSession().(*idleSession)
	pool := newTestPool(64, minHeadroom)
	proc := newPacketProcessor(n.d)

	p := fillBenchPacket(pool.Get(), tmpl, n.if1)
	if disp := proc.processPkt(p); disp != pDone {
		b.Fatalf("warm-up disposition = %d, want %d", disp, pDone)
	}
	if got := session.arrivals.Load(); got != 1 {
		b.Fatalf("warm-up session arrivals = %d, want 1", got)
	}
	pool.Put(p)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		p := fillBenchPacket(pool.Get(), tmpl, n.if1)
		if proc.processPkt(p) != pDone {
			b.Fatal("BFD dispatch drifted off the asserted path")
		}
		pool.Put(p)
	}
}

// BenchmarkPacketMetrics measures the per-packet metrics calls under the
// default no-op provider and under a configured one, because both sit on
// every forwarded packet and the no-op is not free: the processor pays one
// Add per packet, the connection's sender one UpdateOutputMetrics per
// written batch.
func BenchmarkPacketMetrics(b *testing.B) {
	for _, provider := range []struct {
		name   string
		config bool
	}{
		{"noop", false},
		{"configured", true},
	} {
		b.Run("provider="+provider.name, func(b *testing.B) {
			if provider.config {
				mp := sdkmetric.NewMeterProvider(
					sdkmetric.WithReader(sdkmetric.NewManualReader()))
				prev := otel.GetMeterProvider()
				otel.SetMeterProvider(mp)
				b.Cleanup(func() {
					otel.SetMeterProvider(prev)
					_ = mp.Shutdown(context.Background())
				})
			}
			metrics, err := NewMetrics()
			if err != nil {
				b.Fatal(err)
			}
			im := metrics.NewInterfaceMetrics(1, benchLocal, benchSrcAS)
			sc := ClassOfSize(1280)
			ctx := context.Background()

			b.Run("call=Add", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					im[sc].ProcessedPackets.Add(ctx, 1)
				}
			})
			b.Run("call=UpdateOutput", func(b *testing.B) {
				pool := newTestPool(benchMetricsBatch, minHeadroom)
				pkts := make([]*Packet, benchMetricsBatch)
				for i := range pkts {
					pkts[i] = pool.Get()
					pkts[i].RawPacket = pkts[i].RawPacket[:1280]
					pkts[i].trafficType = ttBrTransit
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					UpdateOutputMetrics(ctx, im, pkts)
				}
			})
		})
	}
}
