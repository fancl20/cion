package ping

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

// Resolver returns the responder host in dst, resolved over the path: nil
// for the one-hop path out of a link to dst.
type Resolver func(ctx context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error)

// Resolve resolves the responder host in dst over the path on the conn,
// which nothing else may read meanwhile: the drafts' service resolution of
// dst's control service, whose answer names the host the responder's socket
// is bound to. A nil path resolves over the one-hop path out of a link to
// dst.
func Resolve(ctx context.Context, conn *scion.Conn, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
	host, err := scionrpc.ResolveService(ctx, conn, &scion.Addr{IA: dst, Service: addr.SvcCS, Path: path})
	return host.Addr(), err
}

// errNoPath reports a resolution asked over no path.
var errNoPath = errors.New("no path to resolve over")

// hostsQueued is how many asks wait for Resolve, and how many resolutions
// wait for the caller's loop.
const hostsQueued = 16

// Resolution is one resolution that landed: the destination, and its host
// or the failure that left it unresolved.
type Resolution struct {
	Dst  addr.IA
	Host netip.Addr
	Err  error
}

// Hosts holds the responder hosts of the destinations a caller echoes, and
// resolves each one asked for off the caller's loop: that loop asks for
// hosts and adopts each resolution as it lands, and Resolve, which the caller
// runs on a goroutine of its own, resolves them one at a time. Every method
// but Resolve and Landed belongs to the caller's loop.
type Hosts struct {
	resolve   Resolver
	retry     time.Duration
	asks      chan ask
	landed    chan Resolution
	hosts     map[addr.IA]netip.Addr
	resolving map[addr.IA]bool
	retryAt   map[addr.IA]time.Time
}

// ask is one destination's host asked for, over the paths to try in turn.
type ask struct {
	dst   addr.IA
	paths []*spath.Decoded
}

// NewHosts returns a Hosts that holds no host, resolves by resolve, and
// spaces a failed resolution's retry by retry.
func NewHosts(resolve Resolver, retry time.Duration) *Hosts {
	return &Hosts{
		resolve:   resolve,
		retry:     retry,
		asks:      make(chan ask, hostsQueued),
		landed:    make(chan Resolution, hostsQueued),
		hosts:     make(map[addr.IA]netip.Addr),
		resolving: make(map[addr.IA]bool),
		retryAt:   make(map[addr.IA]time.Time),
	}
}

// Host returns the destination's host; false while none is held.
func (h *Hosts) Host(dst addr.IA) (netip.Addr, bool) {
	host, ok := h.hosts[dst]
	return host, ok
}

// Ask asks for the destination's host over the paths, tried in turn until
// one answers; the host held meanwhile stays. It asks nothing while a
// resolution of the destination is in flight, before a failed one's retry,
// or while the asks waiting fill the queue.
func (h *Hosts) Ask(dst addr.IA, paths []*spath.Decoded, now time.Time) {
	if h.resolving[dst] || now.Before(h.retryAt[dst]) {
		return
	}
	select {
	case h.asks <- ask{dst: dst, paths: paths}:
		h.resolving[dst] = true
	default:
	}
}

// Forget drops the destination's host.
func (h *Hosts) Forget(dst addr.IA) {
	delete(h.hosts, dst)
}

// RetryAt returns when the destination's failed resolution may be asked for
// again; zero before any failed.
func (h *Hosts) RetryAt(dst addr.IA) time.Time {
	return h.retryAt[dst]
}

// Landed delivers each resolution as it lands, for the caller's loop to
// adopt.
func (h *Hosts) Landed() <-chan Resolution {
	return h.landed
}

// Adopt adopts a resolution that landed: its host, or for its failure the
// spacing of the retry.
func (h *Hosts) Adopt(r Resolution, now time.Time) {
	delete(h.resolving, r.Dst)
	if r.Err != nil {
		h.retryAt[r.Dst] = now.Add(h.retry)
		return
	}
	h.hosts[r.Dst] = r.Host
}

// Resolve resolves the hosts asked for until ctx ends, one at a time, each
// over its paths in turn until one answers.
func (h *Hosts) Resolve(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-h.asks:
			r := Resolution{Dst: a.dst, Err: errNoPath}
			for _, path := range a.paths {
				if r.Host, r.Err = h.resolve(ctx, a.dst, path); r.Err == nil {
					break
				}
			}
			select {
			case h.landed <- r:
			case <-ctx.Done():
				return
			}
		}
	}
}
