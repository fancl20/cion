package services

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

// The process's meter provider and the handler that serves it: the
// Prometheus exporter reading the instruments the node's assembly builds,
// installed once per process before the first node assembles — no argument
// gates it, for the boundary is membership, not configuration. The daemon's
// single node and the several nodes a test process boots share the one
// provider, each node's series separated by its own local_as label, and
// every node's mount serves the same registry.
var servedMetrics struct {
	once    sync.Once
	handler http.Handler
	err     error
}

// installMeterProvider builds the exporter on its own registry, the meter
// provider over it, and installs that provider globally. The first call in
// the process owns it; later calls answer with what the first built, for
// swapping a global provider mid-process would detach the instruments
// already bound to it.
func installMeterProvider() error {
	servedMetrics.once.Do(func() {
		registry := prometheus.NewRegistry()
		exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(registry))
		if err != nil {
			servedMetrics.err = fmt.Errorf("creating the Prometheus exporter: %w", err)
			return
		}
		otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)))
		servedMetrics.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	})
	return servedMetrics.err
}

// metricsMount returns the exporter's registry as one endpoint mount:
// Prometheus text format at /metrics, wrapped by the peer-identity
// middleware with every other mount, so any chain-holding member reads the
// data plane's counters over SCION paths while a node's egress stays zero
// until one asks.
func metricsMount() (scionrpc.Mount, error) {
	if err := installMeterProvider(); err != nil {
		return scionrpc.Mount{}, err
	}
	return scionrpc.Mount{Pattern: "/metrics", Handler: servedMetrics.handler}, nil
}
