package dataplane

import (
	"context"
	"math/bits"
	"slices"
	"strconv"

	"github.com/scionproto/scion/pkg/addr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// trafficType labels traffic as being of either of the following types: in, out, inTransit,
// outTransit, brTransit. inTransit or outTransit means that traffic is crossing the local AS via
// two routers. If the router being observed is the one receiving the packet from the outside, then
// the type is inTransit; else it is outTransit. brTransit means that traffic is crossing only the
// observed router. Non-scion traffic or somehow malformed traffic has type Other.
// Do not change this type's length without checking the effect it has on router.packet
type trafficType uint8

const (
	ttOther trafficType = iota
	ttIn
	ttOut
	ttInTransit
	ttOutTransit
	ttBrTransit
	ttMax
)

// Returns a human-friendly representation of the given traffic type.
func (t trafficType) String() string {
	switch t {
	case ttIn:
		return "in"
	case ttOut:
		return "out"
	case ttInTransit:
		return "in_transit"
	case ttOutTransit:
		return "out_transit"
	case ttBrTransit:
		return "br_transit"
	}
	return "other"
}

// sizeClass is the number of bits needed to represent some given size. This is quicker than
// computing Log2 and serves the same purpose.
type sizeClass uint8

// maxSizeClass is the smallest NOT-supported sizeClass. This must be enough to support the largest
// valid packet size (defined by bufSize). Since this must be a constant (to allow efficient
// fixed-sized arrays), we have to assert it's large enough for bufSize. Just in case we do get
// packets larger than bufSize, they are simply put in the last class.
const maxSizeClass sizeClass = 15

// This will fail to compile if bufSize cannot fit in (maxSizeClass - 1) bits.
const _ = uint(1<<(maxSizeClass-1) - 1 - bufSize)

// minSizeClass is the smallest sizeClass that we care about.
// All smaller classes are conflated with this one.
const minSizeClass sizeClass = 6

func ClassOfSize(pktSize int) sizeClass {
	cs := sizeClass(bits.Len32(uint32(pktSize)))
	if cs > maxSizeClass-1 {
		return maxSizeClass - 1
	}
	if cs <= minSizeClass {
		return minSizeClass
	}
	return cs
}

// Returns a human-friendly representation of the given size class. Avoid bracket notation to make
// the values possibly easier to use in monitoring queries.
func (sc sizeClass) String() string {
	low := strconv.Itoa((1 << sc) >> 1)
	high := strconv.Itoa((1 << sc) - 1)
	if sc == minSizeClass {
		low = "0"
	}
	return low + "_" + high
}

// UpdateOutputMetrics accounts for the given packets in the output metrics,
// aggregated by traffic type and size class.
func UpdateOutputMetrics(ctx context.Context, metrics *InterfaceMetrics, packets []*Packet) {
	// We need to collect stats by traffic type and size class.
	// Try to reduce the metrics lookup penalty by using some
	// simpler staging data structure.
	writtenPkts := [ttMax][maxSizeClass]int{}
	writtenBytes := [ttMax][maxSizeClass]int{}
	for _, p := range packets {
		s := len(p.RawPacket)
		sc := ClassOfSize(s)
		tt := p.trafficType
		writtenPkts[tt][sc]++
		writtenBytes[tt][sc] += s
	}
	for t := ttOther; t < ttMax; t++ {
		for sc := minSizeClass; sc < maxSizeClass; sc++ {
			if writtenPkts[t][sc] > 0 {
				metrics[sc].Output[t].OutputPacketsTotal.Add(ctx, int64(writtenPkts[t][sc]))
				metrics[sc].Output[t].OutputBytesTotal.Add(ctx, int64(writtenBytes[t][sc]))
			}
		}
	}
}

// interfaceMetrics is the set of metrics that are relevant for one given interface. It is a map
// that associates each (traffic-type, size-class) pair with the set of metrics belonging to that
// interface that have these label values. This set of metrics is itself a trafficMetric structure.
// Explanation: Metrics are labeled by interface, local-as, neighbor-as, packet size, and (for
// output metrics only) traffic type. Instances are grouped in a hierarchical manner for efficient
// access by the using code. forwardingMetrics is a map of interface to interfaceMetrics. To access
// a specific InputPacketsTotal counter, one refers to:
//
//	dataplane.forwardingMetrics[interface][size-class].
//
// trafficMetrics.Output is an array of outputMetrics indexed by traffic type.
type InterfaceMetrics [maxSizeClass]trafficMetrics

// trafficMetrics groups all the metrics instances that all share the same interface AND
// sizeClass label values (but have different names - i.e. they count different things).
type trafficMetrics struct {
	InputBytesTotal             metric.Int64Counter
	InputPacketsTotal           metric.Int64Counter
	DroppedPacketsInvalid       metric.Int64Counter
	DroppedPacketsBusyProcessor metric.Int64Counter
	DroppedPacketsBusyForwarder metric.Int64Counter
	DroppedPacketsBusySlowPath  metric.Int64Counter
	ProcessedPackets            metric.Int64Counter
	Output                      [ttMax]outputMetrics
}

// outputMetrics groups all the metrics about traffic that has reached the output stage. Metrics
// instances in each of these all have the same interface AND sizeClass AND trafficType label
// values.
type outputMetrics struct {
	OutputBytesTotal   metric.Int64Counter
	OutputPacketsTotal metric.Int64Counter
}

// Metrics holds the metric instruments shared by all interfaces of a data
// plane. The instruments are created from the global otel meter provider; if
// none is configured, all counters are no-ops.
type Metrics struct {
	meter            metric.Meter
	inputBytes       metric.Int64Counter
	inputPackets     metric.Int64Counter
	processedPackets metric.Int64Counter
	droppedPackets   metric.Int64Counter
	outputBytes      metric.Int64Counter
	outputPackets    metric.Int64Counter
}

func NewMetrics() (*Metrics, error) {
	meter := otel.GetMeterProvider().Meter("github.com/fancl20/cion/pkg/dataplane")
	m := &Metrics{meter: meter}
	var err error
	if m.inputBytes, err = meter.Int64Counter("dataplane.input_bytes_total"); err != nil {
		return nil, err
	}
	if m.inputPackets, err = meter.Int64Counter("dataplane.input_packets_total"); err != nil {
		return nil, err
	}
	if m.processedPackets, err = meter.Int64Counter("dataplane.processed_packets"); err != nil {
		return nil, err
	}
	if m.droppedPackets, err = meter.Int64Counter("dataplane.dropped_packets_total"); err != nil {
		return nil, err
	}
	if m.outputBytes, err = meter.Int64Counter("dataplane.output_bytes_total"); err != nil {
		return nil, err
	}
	if m.outputPackets, err = meter.Int64Counter("dataplane.output_packets_total"); err != nil {
		return nil, err
	}
	return m, nil
}

// NewInterfaceMetrics returns the metrics for one interface, labeled by the
// given interface ID, local IA, and neighbor IA.
func (m *Metrics) NewInterfaceMetrics(ifID uint16, localIA, neighbor addr.IA) *InterfaceMetrics {
	ifLabels := []attribute.KeyValue{
		attribute.String("interface", strconv.Itoa(int(ifID))),
		attribute.String("local_as", localIA.String()),
		attribute.String("neighbor_as", neighbor.String()),
	}
	im := InterfaceMetrics{}
	for sc := minSizeClass; sc < maxSizeClass; sc++ {
		labels := append(slices.Clone(ifLabels), attribute.String("sizeclass", sc.String()))
		tm := trafficMetrics{
			InputBytesTotal:   m.bind(m.inputBytes, labels),
			InputPacketsTotal: m.bind(m.inputPackets, labels),
			ProcessedPackets:  m.bind(m.processedPackets, labels),
		}
		tm.DroppedPacketsInvalid = m.bind(m.droppedPackets, labels, "reason", "invalid")
		tm.DroppedPacketsBusyProcessor =
			m.bind(m.droppedPackets, labels, "reason", "busy_processor")
		tm.DroppedPacketsBusyForwarder =
			m.bind(m.droppedPackets, labels, "reason", "busy_forwarder")
		tm.DroppedPacketsBusySlowPath = m.bind(m.droppedPackets, labels, "reason", "busy_slow_path")
		for t := ttOther; t < ttMax; t++ {
			tm.Output[t] = outputMetrics{
				OutputBytesTotal:   m.bind(m.outputBytes, labels, "type", t.String()),
				OutputPacketsTotal: m.bind(m.outputPackets, labels, "type", t.String()),
			}
		}
		im[sc] = tm
	}
	return &im
}

// bind returns the given instrument with the label set formed from labels and
// the given extra key/value pair, if any.
func (m *Metrics) bind(
	instrument metric.Int64Counter,
	labels []attribute.KeyValue,
	extra ...string,
) metric.Int64Counter {

	if len(extra) != 0 {
		labels = append(slices.Clone(labels), attribute.String(extra[0], extra[1]))
	}
	return labeledCounter{Int64Counter: instrument, attrs: attribute.NewSet(labels...)}
}

// labeledCounter is an otel counter with a pre-bound attribute set so that
// recording requires only the increment.
type labeledCounter struct {
	metric.Int64Counter
	attrs attribute.Set
}

func (c labeledCounter) Add(ctx context.Context, incr int64, _ ...metric.AddOption) {
	c.Int64Counter.Add(ctx, incr, metric.WithAttributeSet(c.attrs))
}
