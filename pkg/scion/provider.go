package scion

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/segment"
)

// PathProvider composes up, core, and down segments into end-to-end SCION
// paths — reversal, expiry filtering, and segment combination written once —
// and is the only consumer seam of ADR-0004: the control transport and every
// application consume identical paths through it.
type PathProvider struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// DB holds the local up segments.
	DB pathdb.DB
	// Lookup resolves down segments for a destination, fetched with
	// expiry-aware caching — the narrowed piece of the control plane's
	// lookup service, so that linking the library does not link the
	// control plane.
	Lookup func(ctx context.Context, dst addr.IA) []*pathdb.Segment
	// Bootstrap yields the reversed data-plane path of the freshest
	// unverified beacon originating at a core: the enrollment route of a
	// node that has not pinned the TRC yet — the WebPKI-authenticated
	// channel protects that exchange (proposal 0004).
	Bootstrap func(core addr.IA) *spath.Decoded
	// Cores enumerates the core ASes of an ISD named by the pinned TRC.
	Cores func(isd addr.ISD) []addr.IA
	// InterfaceDown is the node's shared negative cache of SCMP
	// interface-down signals. Composition consults it at the moment it
	// holds full knowledge — each segment's entries carry their ISD-ASes
	// and interface IDs — skipping a composed path that crosses a signaled
	// interface until the entry lapses, keeping a crossing path only when
	// nothing else exists. Nil composes without the filter.
	InterfaceDown *InterfaceDownCache
}

// LocalPath resolves a data-plane path from local state only: up segments
// and the bootstrap beacon, never a fetch. It is the variant safe to call
// from inside a dial — resolving a route must not spawn RPCs over the very
// transport being dialed.
func (p *PathProvider) LocalPath(dst addr.IA) (*spath.Decoded, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	// A destination with an up segment from here is a core; the reversed
	// freshest one is the route to it.
	if up := p.freshestUp(dst); up != nil {
		return up.PCB.ReversePath(), nil
	}
	// Before any up segment is verified — a fresh node that has not even
	// pinned the TRC — the bootstrap beacon's reversed route serves the
	// core; beacons originate only at cores.
	if p.Bootstrap != nil {
		if bs := p.Bootstrap(dst); bs != nil {
			return bs, nil
		}
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// Path returns a data-plane path from the local AS to dst: to a core, the
// reversed freshest up segment — or, before any is verified, the reversed
// bootstrap beacon; anywhere else, a down segment from a core the node can
// reach — fetched with expiry-aware caching — composed after the reversed up
// segment to that core. A composed path crossing a signaled interface is
// skipped while the cache entry lives; a crossing path stays a last resort.
func (p *PathProvider) Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error) {
	if path, err := p.LocalPath(dst); err == nil {
		return path, nil
	}
	downs := p.Lookup(ctx, dst)
	var crossing *spath.Decoded
	for _, down := range downs {
		var path *spath.Decoded
		var up *pathdb.Segment
		if down.FirstIA().Equal(p.IA) {
			// The local node may itself be the core the down segment starts
			// at; the segment alone is then the complete route.
			path = down.PCB.ForwardPath()
		} else {
			up = p.freshestUp(down.FirstIA())
			if up == nil {
				continue
			}
			composed, err := segment.Compose(up.PCB.ReversePath(), down.PCB.ForwardPath())
			if err != nil {
				continue
			}
			path = composed
		}
		if p.crosses(down) || (up != nil && p.crosses(up)) {
			if crossing == nil {
				crossing = path
			}
			continue
		}
		return path, nil
	}
	if crossing != nil {
		return crossing, nil
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// crosses reports whether the segment's entries traverse a signaled
// interface — the check composition makes of the cache at the moment it
// holds full knowledge, each entry carrying its ISD-AS and interface IDs.
func (p *PathProvider) crosses(seg *pathdb.Segment) bool {
	if p.InterfaceDown == nil {
		return false
	}
	for _, e := range seg.PCB.Entries {
		if e.Hop.ConsIngress != 0 &&
			p.InterfaceDown.Holds(e.IA, e.Hop.ConsIngress) {
			return true
		}
		if e.Hop.ConsEgress != 0 && p.InterfaceDown.Holds(e.IA, e.Hop.ConsEgress) {
			return true
		}
	}
	return false
}

// freshestUp returns the freshest up segment originating at the given core,
// or at any core when the argument is zero — the freshest one that crosses
// no signaled interface, the freshest crossing one kept when nothing else
// exists.
func (p *PathProvider) freshestUp(core addr.IA) *pathdb.Segment {
	q := pathdb.Query{Type: pathdb.SegmentTypeUp}
	if !core.IsZero() {
		q.SrcIA = core
	}
	segs, err := p.DB.Get(context.Background(), q)
	if err != nil {
		return nil
	}
	var best, clean *pathdb.Segment
	for _, seg := range segs {
		best = freshest(best, seg)
		if !p.crosses(seg) {
			clean = freshest(clean, seg)
		}
	}
	if clean != nil {
		return clean
	}
	return best
}

// freshest picks the freshest of two segments — nil keeps the other — by
// the latest creation timestamp; equally fresh segments resolve to the one
// with the fewest entries — a tie names the same origination period, and
// the shorter route through it serves better than an arbitrary one.
func freshest(a, b *pathdb.Segment) *pathdb.Segment {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.PCB.Timestamp().After(a.PCB.Timestamp()):
		return b
	case b.PCB.Timestamp().Equal(a.PCB.Timestamp()) &&
		len(b.PCB.Entries) < len(a.PCB.Entries):
		return b
	default:
		return a
	}
}
