package services

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// wildcardHostTTL bounds how long a resolved host stands before the routing
// table is asked again, so a lease that renumbers the interface behind an
// unchanged NAT renames the conns within it.
const wildcardHostTTL = 30 * time.Second

// wildcardHost resolves the host the node's wildcard-bound conns name for
// themselves — their packets' source and their service-resolution answers'
// host, the one the local router delivers their replies to: the local
// address the routing table sends from toward the node's own host, or
// toward a link's peer while the node names no host of its own yet. That is
// the node's host itself where an interface carries it, and the interface's
// inside address behind a NAT, whose public side no local socket receives
// on — the host a concrete bind of that interface names. The zero address
// while neither destination exists or no route reaches it, and the conns
// send nothing until a host lands.
type wildcardHost struct {
	// self is the topic of the node's own state, whose host the resolution
	// routes toward; links is the link state topic, whose live entries'
	// recorded peers it routes toward while the node's own state names no
	// host — the bootstrap's seed records one before any conn sends.
	self  *bus.Topic[bus.SelfState]
	links *bus.Topic[bus.LinkState]
	// route asks the routing table for the local address toward a
	// destination: the socket source's.
	route func(netip.Addr) (netip.Addr, error)

	mtx sync.Mutex
	// toward, at, and host memoize the last resolution: the destination it
	// routed toward, its moment, and its answer.
	toward netip.Addr
	at     time.Time
	host   netip.Addr
}

// newWildcardHost builds the resolution over the node's own host, its
// links, and the routing table the socket source's wildcard-bound sockets
// send by.
func newWildcardHost(
	self *bus.Topic[bus.SelfState], links *bus.Topic[bus.LinkState], sockets underlay.Sockets,
) *wildcardHost {

	return &wildcardHost{self: self, links: links, route: sockets.Source}
}

// resolve returns the host: the memoized answer while the destination
// stands and the answer is younger than wildcardHostTTL, else the routing
// table's answer anew — every conn's every packet asks.
func (w *wildcardHost) resolve(context.Context) netip.Addr {
	toward := w.destination()
	if !toward.IsValid() {
		return netip.Addr{}
	}
	w.mtx.Lock()
	defer w.mtx.Unlock()
	if toward == w.toward && time.Since(w.at) < wildcardHostTTL {
		return w.host
	}
	host, err := w.route(toward)
	if err != nil {
		slog.Warn("Routing toward the node's host or peer", "toward", toward, "err", err)
	}
	w.toward, w.at, w.host = toward, time.Now(), host
	return host
}

// destination returns the address the resolution routes toward: the node's
// own host, else the peer the live entry of the least interface ID records;
// zero when neither exists.
func (w *wildcardHost) destination() netip.Addr {
	if host := w.self.Latest().Host; host.IsValid() {
		return host
	}
	state := w.links.Latest()
	for _, ifID := range slices.Sorted(maps.Keys(state.Table())) {
		if remote := state.Remote(ifID); remote.IsValid() {
			return remote.Addr()
		}
	}
	return netip.Addr{}
}
