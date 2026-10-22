package wireguard

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// collected reads one collection's counters by name, failing unless each is
// a monotonic sum whose points carry the node's local_as alone.
func collected(t *testing.T, reader *sdkmetric.ManualReader, ia addr.IA) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]int64)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic {
				t.Fatalf("%s collects as %T, want a monotonic sum", m.Name, m.Data)
			}
			for _, point := range sum.DataPoints {
				if v, ok := point.Attributes.Value("local_as"); !ok ||
					v.AsString() != ia.String() || point.Attributes.Len() != 1 {

					t.Errorf("%s carries %v, want local_as=%s alone", m.Name,
						point.Attributes.ToSlice(), ia)
				}
				out[m.Name] = point.Value
			}
		}
	}
	return out
}

// TestCountersServed checks the counters' exposure on a meter: every counter
// served under its name with the node's local_as, read afresh at each
// collection, and served no more once the registration is undone.
func TestCountersServed(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter(meterScope)
	ia := addr.MustParseIA("1-ff00:0:110")
	cnt := &counters{}
	served, err := cnt.serve(meter, ia)
	if err != nil {
		t.Fatal(err)
	}
	cnt.droppedPackets.Add(1)
	cnt.hostDatagrams.Add(3)
	want := map[string]int64{
		"wireguard.dropped_packets_total":    1,
		"wireguard.unroutable_packets_total": 0,
		"wireguard.sent_datagrams_total":     0,
		"wireguard.send_failures_total":      0,
		"wireguard.path_refreshes_total":     0,
		"wireguard.route_switches_total":     0,
		"wireguard.published_total":          0,
		"wireguard.host_datagrams_total":     3,
	}
	if diff := cmp.Diff(want, collected(t, reader, ia)); diff != "" {
		t.Errorf("the first collection mismatches (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want, cnt.values()); diff != "" {
		t.Errorf("the snapshot mismatches the collection (-want +got):\n%s", diff)
	}

	cnt.hostDatagrams.Add(2)
	want["wireguard.host_datagrams_total"] = 5
	if diff := cmp.Diff(want, collected(t, reader, ia)); diff != "" {
		t.Errorf("the second collection mismatches (-want +got):\n%s", diff)
	}

	if err := served.Unregister(); err != nil {
		t.Fatal(err)
	}
	if got := collected(t, reader, ia); len(got) != 0 {
		t.Errorf("an unregistered application still serves %v", got)
	}
}
