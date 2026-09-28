package scion

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/modules/pathdb"
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
	// A destination an up segment already contains is on a route from here —
	// a core at the segment's origin, an on-path AS mid-segment — and the
	// freshest containing segment's truncated reversed path is the route to
	// it.
	if up, m := p.containingUp(dst); up != nil {
		return up.PCB.ReversePathTo(m)
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

// Path returns a data-plane path from the local AS to dst. What LocalPath
// resolves from local state comes from it; anything else joins a fetched
// down segment to the stored up segments at their deepest common AS entry —
// the shared core the same-origin rule composed at, a common ancestor below
// it, or an endpoint one segment already contains — each part truncated at
// the meeting so the joined path travels no hop beyond it. Among the joins
// fewest hops wins, ties go to the fresher pair, then to the one with fewer
// entries. A joined path whose traversed hops cross a signaled interface is
// skipped while the cache entry lives; a crossing path stays a last resort.
func (p *PathProvider) Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	if path, err := p.LocalPath(dst); err == nil {
		return path, nil
	}
	downs := p.Lookup(ctx, dst)
	ups := p.upSegments()
	var best *spath.Decoded
	var bestRank joinRank
	var crossing *spath.Decoded
	consider := func(up *pathdb.Segment, mUp int, down *pathdb.Segment, mDown int) {
		var parts []*spath.Decoded
		clean := true
		// A meeting at the local node carries no up part: the reversed up
		// segment truncated there is the empty travel.
		if up != nil && mUp < len(up.PCB.Entries)-1 {
			part, err := up.PCB.ReversePathTo(mUp)
			if err != nil {
				return
			}
			parts = append(parts, part)
			clean = !p.crossesFrom(up, mUp)
		}
		// A meeting at the destination carries no down part, the same
		// arithmetic on the far end.
		if mDown < len(down.PCB.Entries)-1 {
			part, err := down.PCB.ForwardPathFrom(mDown)
			if err != nil {
				return
			}
			parts = append(parts, part)
			clean = clean && !p.crossesFrom(down, mDown)
		}
		if len(parts) == 0 {
			// The meeting is both the local node and the destination, which
			// the equal-destination guard excluded; unreachable.
			return
		}
		path, err := segment.Compose(parts...)
		if err != nil {
			return
		}
		if !clean {
			if crossing == nil {
				crossing = path
			}
			return
		}
		rank := joinRank{
			hops:    len(path.HopFields),
			fresh:   down.PCB.Timestamp(),
			entries: len(down.PCB.Entries),
		}
		if up != nil {
			if t := up.PCB.Timestamp(); t.Before(rank.fresh) {
				rank.fresh = t
			}
			rank.entries += len(up.PCB.Entries)
		}
		if best == nil || rank.before(bestRank) {
			best, bestRank = path, rank
		}
	}
	for _, down := range downs {
		// The local node's own entry on the down segment is a meeting no up
		// segment names — the core the segment starts at, or an AS below it
		// the node happens to be.
		if mDown := down.PCB.IndexOfIA(p.IA); mDown >= 0 {
			consider(nil, -1, down, mDown)
		}
		for _, up := range ups {
			mUp, mDown, ok := meeting(up, down)
			if !ok {
				continue
			}
			consider(up, mUp, down, mDown)
		}
	}
	if best != nil {
		return best, nil
	}
	if crossing != nil {
		return crossing, nil
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// meeting returns the deepest AS entry common to an up and a down segment —
// construction-direction depth, the destination and the local node both
// eligible — as its index in each. Beacons propagate away from cores and
// never revisit an AS, so the entries two segments share nest, and the
// deepest common entry truncates both the most.
func meeting(up, down *pathdb.Segment) (mUp, mDown int, ok bool) {
	index := make(map[addr.IA]int, len(up.PCB.Entries))
	for i, e := range up.PCB.Entries {
		index[e.IA] = i
	}
	for j, e := range down.PCB.Entries {
		if i, common := index[e.IA]; common && (!ok || i+j > mUp+mDown) {
			mUp, mDown, ok = i, j, true
		}
	}
	return mUp, mDown, ok
}

// joinRank orders the joins of Path's composition loop: fewest joined hops
// first, then the fresher pair by the staler piece's creation timestamp — a
// join is only as fresh as the piece that expires first — then the pair with
// fewer entries.
type joinRank struct {
	hops    int
	fresh   time.Time
	entries int
}

// before reports whether r outranks o.
func (r joinRank) before(o joinRank) bool {
	if r.hops != o.hops {
		return r.hops < o.hops
	}
	if !r.fresh.Equal(o.fresh) {
		return r.fresh.After(o.fresh)
	}
	return r.entries < o.entries
}

// crossesFrom reports whether the segment's entries from index from — the
// stretch a joined path traverses — cross a signaled interface: the check
// composition makes of the cache at the moment it holds full knowledge, each
// entry carrying its ISD-AS and interface IDs.
func (p *PathProvider) crossesFrom(seg *pathdb.Segment, from int) bool {
	if p.InterfaceDown == nil {
		return false
	}
	for _, e := range seg.PCB.Entries[from:] {
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

// crosses reports whether the segment's entries traverse a signaled
// interface.
func (p *PathProvider) crosses(seg *pathdb.Segment) bool {
	return p.crossesFrom(seg, 0)
}

// upSegments returns every stored up segment. Each is a candidate meeting —
// not only the freshest per origin core — because a staler segment through a
// deeper parent can meet a down segment the freshest one cannot.
func (p *PathProvider) upSegments() []*pathdb.Segment {
	segs, err := p.DB.Get(context.Background(), pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		return nil
	}
	return segs
}

// containingUp returns the freshest up segment whose entries contain the
// given ISD-AS and that entry's index — a core at the origin, an on-path AS
// mid-segment — the freshest one that crosses no signaled interface, the
// freshest crossing one kept when nothing else exists.
func (p *PathProvider) containingUp(ia addr.IA) (*pathdb.Segment, int) {
	var best, clean *pathdb.Segment
	bestAt, cleanAt := -1, -1
	for _, seg := range p.upSegments() {
		at := seg.PCB.IndexOfIA(ia)
		if at < 0 {
			continue
		}
		if freshest(best, seg) == seg {
			best, bestAt = seg, at
		}
		if !p.crosses(seg) && freshest(clean, seg) == seg {
			clean, cleanAt = seg, at
		}
	}
	if clean != nil {
		return clean, cleanAt
	}
	return best, bestAt
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
