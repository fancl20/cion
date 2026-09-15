package wireguard

import "sync/atomic"

// counters are the application's exposure of its overlay: the operating
// system's tooling cannot see in-process forwarding, so the application
// counts and logs instead (ADR-0005). Every counter is a monotonic total
// since start.
type counters struct {
	// droppedPackets counts packets a full pipe or an oversized inner packet
	// dropped.
	droppedPackets atomic.Int64
	// unroutablePackets counts packets no table entry and no default
	// claimed.
	unroutablePackets atomic.Int64
	// egressDroppedPackets counts packets the egress dropped: unsupported
	// protocols, full flow tables, failed dials.
	egressDroppedPackets atomic.Int64
	// sentDatagrams counts mesh datagrams the SCION transport carried.
	sentDatagrams atomic.Int64
	// sendFailures counts mesh sends that failed even after a path refresh.
	sendFailures atomic.Int64
	// pathRefreshes counts mid-stream path re-resolutions: expiry, near
	// expiry, or a failed send.
	pathRefreshes atomic.Int64
	// published counts accepted directory publications the core served.
	published atomic.Int64
}

// snapshot returns the counters as a slice for structured logging.
func (c *counters) snapshot() []any {
	return []any{
		"dropped", c.droppedPackets.Load(),
		"unroutable", c.unroutablePackets.Load(),
		"egress_dropped", c.egressDroppedPackets.Load(),
		"sent_datagrams", c.sentDatagrams.Load(),
		"send_failures", c.sendFailures.Load(),
		"path_refreshes", c.pathRefreshes.Load(),
		"published", c.published.Load(),
	}
}
