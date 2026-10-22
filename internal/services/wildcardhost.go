package services

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// wildcardHostTTL bounds how long a resolved host stands before the routing
// table is asked again, so a lease that renumbers the interface behind an
// unchanged translation renames the conns within it.
const wildcardHostTTL = 30 * time.Second

// wildcardHost resolves the host the node's wildcard-bound conns name for
// themselves — their packets' source and their service-resolution answers'
// host, the one the local router delivers their replies to: the local
// address the routing table sends from toward the published host. That is
// the published host itself where an interface carries it, and the
// interface's inside address behind a translation, whose public side no
// local socket receives on — the host a concrete bind of that interface
// names. The zero address while nothing is published or no route reaches
// it, and the conns send nothing until a host lands.
type wildcardHost struct {
	published func(context.Context) netip.Addr
	// route asks the routing table for the local address toward a
	// destination; the field is the tests' seam.
	route func(netip.Addr) (netip.Addr, error)

	mtx sync.Mutex
	// toward, at, and host memoize the last resolution: the published host
	// it routed toward, its moment, and its answer.
	toward netip.Addr
	at     time.Time
	host   netip.Addr
}

// newWildcardHost builds the resolution over the node's published host and
// the kernel's routing table, the one a wildcard bind's sockets send by.
func newWildcardHost(published func(context.Context) netip.Addr) *wildcardHost {
	return &wildcardHost{published: published, route: underlay.RouteSource}
}

// resolve returns the host: the memoized answer while the published host
// stands and the answer is younger than wildcardHostTTL, else the routing
// table's answer anew — every conn's every packet asks.
func (w *wildcardHost) resolve(ctx context.Context) netip.Addr {
	published := w.published(ctx)
	if !published.IsValid() {
		return netip.Addr{}
	}
	w.mtx.Lock()
	defer w.mtx.Unlock()
	if published == w.toward && time.Since(w.at) < wildcardHostTTL {
		return w.host
	}
	host, err := w.route(published)
	if err != nil {
		slog.Warn("Routing toward the published host", "published", published, "err", err)
	}
	w.toward, w.at, w.host = published, time.Now(), host
	return host
}
