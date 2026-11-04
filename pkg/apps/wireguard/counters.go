package wireguard

import (
	"context"
	"sync/atomic"

	"github.com/scionproto/scion/pkg/addr"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// meterScope names the application's instruments on the process's meter.
const meterScope = "github.com/fancl20/cion/pkg/apps/wireguard"

// counters are the application's exposure of its overlay: the operating
// system's tooling cannot see in-process forwarding, so the application
// counts and the process's meter reads the counts at each collection. Every
// counter is a monotonic total since start.
type counters struct {
	// droppedPackets counts packets a full pipe or an oversized inner packet
	// dropped.
	droppedPackets atomic.Int64
	// unroutablePackets counts packets no table entry and no default
	// claimed.
	unroutablePackets atomic.Int64
	// sentDatagrams counts the datagrams the SCION transport carried for the
	// node's own devices: the mesh devices', and the host device's to the
	// nodes that relay its hosts.
	sentDatagrams atomic.Int64
	// sendFailures counts those datagrams a send failed to carry.
	sendFailures atomic.Int64
	// routeSwitches counts the moves of a peer's lease its sends saw: a send
	// riding another path than the peer's previous one.
	routeSwitches atomic.Int64
	// published counts accepted directory publications the core served.
	published atomic.Int64
	// hostDatagrams counts datagrams the shared host port received.
	hostDatagrams atomic.Int64
	// relayedDatagrams counts the datagrams the relay carried, unchanged,
	// between one of the node's hosts and another node, either way.
	relayedDatagrams atomic.Int64
	// relayDrops counts the datagrams the relay dropped: a host's initiation
	// keyed to no directory node's key or past the pending sessions' bounds,
	// a node's initiation toward a host, and a datagram or cookie reply
	// whose way onward failed.
	relayDrops atomic.Int64
	// relayCookies counts the cookie replies the relay sent under load on
	// its nodes' behalf, each to a host whose initiation carried no valid
	// mac2.
	relayCookies atomic.Int64
}

// counterSeries is one counter beside the name the meter serves it by.
type counterSeries struct {
	name  string
	count *atomic.Int64
}

// series lists the counters by the names the meter serves them by.
func (c *counters) series() []counterSeries {
	return []counterSeries{
		{"wireguard.dropped_packets_total", &c.droppedPackets},
		{"wireguard.unroutable_packets_total", &c.unroutablePackets},
		{"wireguard.sent_datagrams_total", &c.sentDatagrams},
		{"wireguard.send_failures_total", &c.sendFailures},
		{"wireguard.route_switches_total", &c.routeSwitches},
		{"wireguard.published_total", &c.published},
		{"wireguard.host_datagrams_total", &c.hostDatagrams},
		{"wireguard.relayed_datagrams_total", &c.relayedDatagrams},
		{"wireguard.relay_drops_total", &c.relayDrops},
		{"wireguard.relay_cookies_total", &c.relayCookies},
	}
}

// serve registers the counters on the meter as observable counters, each
// labeled with the node's ISD-AS and read at every collection, until the
// registration is unregistered.
func (c *counters) serve(meter metric.Meter, ia addr.IA) (metric.Registration, error) {
	series := c.series()
	instruments := make([]metric.Int64ObservableCounter, 0, len(series))
	observables := make([]metric.Observable, 0, len(series))
	for _, s := range series {
		instrument, err := meter.Int64ObservableCounter(s.name)
		if err != nil {
			return nil, err
		}
		instruments = append(instruments, instrument)
		observables = append(observables, instrument)
	}
	labels := metric.WithAttributeSet(attribute.NewSet(attribute.String("local_as", ia.String())))
	return meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for i, s := range series {
			o.ObserveInt64(instruments[i], s.count.Load(), labels)
		}
		return nil
	}, observables...)
}

// values reads the counters by the names the meter serves them by.
func (c *counters) values() map[string]int64 {
	out := make(map[string]int64)
	for _, s := range c.series() {
		out[s.name] = s.count.Load()
	}
	return out
}
