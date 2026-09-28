package dataplane

import (
	"context"
	"net"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/scionproto/scion/pkg/private/util"
)

// metricKey identifies one recorded counter by the labels the staging
// tests distinguish: the metric's name, the interface, the size class,
// and (for the drop counter) the reason.
type metricKey [4]string

// newTestReader installs a manual-reader meter provider and returns the
// reader, so the counters the plane records are readable. The global
// provider is restored on cleanup.
func newTestReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})
	return reader
}

// collectSums reads the reader and sums the recorded values per metric
// name and label set.
func collectSums(t *testing.T, reader *sdkmetric.ManualReader) map[metricKey]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}
	sums := make(map[metricKey]int64)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				var ifc, sc, reason string
				for _, kv := range dp.Attributes.ToSlice() {
					switch string(kv.Key) {
					case "interface":
						ifc = kv.Value.Emit()
					case "sizeclass":
						sc = kv.Value.Emit()
					case "reason":
						reason = kv.Value.Emit()
					}
				}
				sums[metricKey{m.Name, ifc, sc, reason}] += dp.Value
			}
		}
	}
	return sums
}

// settleSums polls the recorded counters until every wanted sum holds,
// returning the settled snapshot, failing the test at the timeout — the
// flushes are asynchronous, so the episodes read to completion rather than
// sleep.
func settleSums(
	t *testing.T, reader *sdkmetric.ManualReader, want map[metricKey]int64,
) map[metricKey]int64 {

	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		sums := collectSums(t, reader)
		settled := true
		for k, v := range want {
			if sums[k] != v {
				settled = false
				break
			}
		}
		if settled {
			return sums
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters did not settle; got %v, want %v", sums, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestProcessorDrainsInBatches drives the processor's batch-drain loop
// directly: a queue fed more packets than one batch holds is drained in
// order, the processor blocks again for the next first packet once the
// queue empties, and cancellation ends it.
func TestProcessorDrainsInBatches(t *testing.T) {
	rc := RunConfig{
		NumProcessors:         1,
		NumSlowPathProcessors: 1,
		BatchSize:             8,
		ReceiveBufferSize:     1 << 20,
		SendBufferSize:        1 << 20,
	}
	n := newBenchNode(t, rc)
	d := n.d
	d.initPacketPool(4 * rc.BatchSize)

	// The egress queue of interface 2, where the transit template lands.
	var egress chan *Packet
	for _, c := range n.provider.allConnections {
		if cl, ok := c.link.(*connectedLink); ok && cl.IfID() == 2 {
			egress = c.queue
		}
	}
	if egress == nil {
		t.Fatal("no egress queue found for interface 2")
	}

	q := make(chan *Packet, 4*rc.BatchSize+8)
	slowQ := make(chan *Packet, 4*rc.BatchSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.setRunning()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runProcessor(ctx, 0, q, slowQ)
	}()

	tmpl := serializeUDP(t, benchSrcAS, benchDstAS,
		transitPath(t, n.key, util.TimeToSecs(time.Now())), benchFlow, benchPad)
	seq := func(p *Packet) byte { return p.RawPacket[len(p.RawPacket)-1] }

	// More packets than one batch holds, each carrying its queue position
	// in the padding the path does not cover.
	sent := 3*rc.BatchSize + 5
	for i := range sent {
		p := fillBenchPacket(d.packetPool.Get(), tmpl, n.if1)
		p.RawPacket[len(p.RawPacket)-1] = byte(i)
		q <- p
	}
	for i := range sent {
		select {
		case p := <-egress:
			if got := seq(p); got != byte(i) {
				t.Fatalf("egress out of order: packet %d, want %d", got, i)
			}
			d.packetPool.Put(p)
		case <-time.After(testTimeout):
			t.Fatalf("no packet %d of %d on the egress queue", i, sent)
		}
	}

	// The queue has emptied; the processor is back to blocking for the
	// next first packet, and one more packet still goes through.
	p := fillBenchPacket(d.packetPool.Get(), tmpl, n.if1)
	p.RawPacket[len(p.RawPacket)-1] = byte(sent)
	q <- p
	select {
	case p := <-egress:
		if got := seq(p); got != byte(sent) {
			t.Fatalf("packet after reblocking = %d, want %d", got, sent)
		}
		d.packetPool.Put(p)
	case <-time.After(testTimeout):
		t.Fatal("the processor did not pick up the packet after reblocking")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("the processor did not exit on cancellation")
	}
}

// TestProcessorQueueFullDrops checks the overflow the drain leaves alone:
// with the processor queue full, the link's receive drops each further
// packet with the busy-processor reason, one counter event per packet.
func TestProcessorQueueFullDrops(t *testing.T) {
	reader := newTestReader(t)
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(64, minHeadroom)
	q := make(chan *Packet, 1)
	el := n.if1.(*connectedLink)
	el.start(context.Background(), []chan *Packet{q}, pool)

	tmpl := serializeUDP(t, benchSrcAS, benchDstAS,
		transitPath(t, n.key, util.TimeToSecs(time.Now())), benchFlow, benchPad)
	for range 3 {
		p := fillBenchPacket(pool.Get(), tmpl, n.if1)
		el.receive(len(p.RawPacket), &net.UDPAddr{}, p)
	}

	want := metricKey{"dataplane.dropped_packets_total", "1",
		ClassOfSize(len(tmpl)).String(), "busy_processor"}
	if got := collectSums(t, reader)[want]; got != 2 {
		t.Fatalf("busy-processor drops = %d, want 2 (one per overflow event)", got)
	}
	if got := len(q); got != 1 {
		t.Fatalf("queue holds %d packets, want the single one that fit", got)
	}
}

// TestIngestCounterStaging drives a served plane with mixed-size datagrams
// and checks the staged counters against the sums per-packet accounting
// would produce: input packets and bytes per read batch, processed per
// drained batch, and the drops still one event each.
func TestIngestCounterStaging(t *testing.T) {
	reader := newTestReader(t)
	n := newBenchNode(t, benchRunConfig)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- n.d.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-serveDone
	})

	// The internal link's bound address, where a local host writes.
	var internal *net.UDPAddr
	for _, c := range n.provider.allConnections {
		if !c.connected {
			internal = c.conn.conn.LocalAddr().(*net.UDPAddr)
		}
	}
	host, err := net.DialUDP("udp4", nil, internal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	// Datagrams of three size classes; the SCION-like frame is not a
	// valid packet, so each one is also a per-event invalid drop.
	sizes := []struct {
		total int
		count int
	}{{64, 3}, {700, 2}, {1500, 5}}
	want := map[metricKey]int64{}
	for _, s := range sizes {
		sc := ClassOfSize(s.total).String()
		want[metricKey{"dataplane.input_packets_total", "0", sc, ""}] = int64(s.count)
		want[metricKey{"dataplane.input_bytes_total", "0", sc, ""}] = int64(s.count * s.total)
		want[metricKey{"dataplane.processed_packets", "0", sc, ""}] = int64(s.count)
		want[metricKey{"dataplane.dropped_packets_total", "0", sc, "invalid"}] = int64(s.count)
		for range s.count {
			if _, err := host.Write(scionLikeDatagram(make([]byte, s.total-36))); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Nothing else may be recorded against the internal link.
	for k, v := range settleSums(t, reader, want) {
		if k[1] == "0" && v != want[k] {
			t.Fatalf("unexpected %v = %d on the internal link", k, v)
		}
	}
}
