package services

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/dataplane"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

// metricsLabRuns hands each run of the mount test its own local_as label:
// the process's provider is shared and its counters cumulative, so a rerun
// records on fresh series instead of doubling the old ones.
var metricsLabRuns atomic.Uint32

// TestMetricsMountServesTheDataPlane checks the mount end to end through
// the assembled server: the provider installed ahead of the instruments —
// the order boot guarantees the daemon — so NewMetrics builds living
// counters where the no-op answered nothing, and the mux the endpoint's
// assembly serves answers /metrics — the mount wrapped by the
// peer-identity middleware with every other mount — with the recorded
// families in the instruments' own labels.
func TestMetricsMountServesTheDataPlane(t *testing.T) {
	if err := installMeterProvider(); err != nil {
		t.Fatal(err)
	}
	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	ia := addr.MustIAFrom(20, addr.AS(0xff0000000300)+addr.AS(metricsLabRuns.Add(1)))
	neighbor := addr.MustIAFrom(20, 0xff0000000302)
	im := metrics.NewInterfaceMetrics(7, ia, neighbor)
	ctx := context.Background()
	im[dataplane.ClassOfSize(200)].InputPacketsTotal.Add(ctx, 3)
	im[dataplane.ClassOfSize(200)].ProcessedPackets.Add(ctx, 7)
	im[dataplane.ClassOfSize(200)].DroppedPacketsInvalid.Add(ctx, 5)

	mount, err := metricsMount()
	if err != nil {
		t.Fatal(err)
	}
	handler := controlplane.NewServer(&controlplane.Services{
		Mounts: []scionrpc.Mount{mount},
	}).Handler
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, series := range []struct{ name, tail string }{
		{"dataplane_dropped_packets_total", `reason="invalid",sizeclass="128_255"} 5`},
		{"dataplane_input_packets_total", `sizeclass="128_255"} 3`},
		{"dataplane_processed_packets_total", `sizeclass="128_255"} 7`},
	} {
		labels := `interface="7",local_as="20-ff00:0:301",neighbor_as="20-ff00:0:302",`
		if !strings.Contains(body, series.name+"{"+labels) ||
			!strings.Contains(body, labels+`otel_scope_name="`+
				`github.com/fancl20/cion/pkg/core/dataplane",otel_scope_schema_url="",`+
				`otel_scope_version="",`+series.tail) {
			t.Errorf("the scrape omits %s in the instrument's own labels (%s %s)",
				series.name, labels, series.tail)
		}
	}
}
