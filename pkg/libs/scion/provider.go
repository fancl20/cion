package scion

import (
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// PathProvider composes up, core, and down segments into end-to-end SCION
// paths — reversal, expiry filtering, and segment combination written once —
// and is the segments' only consumer seam: the control transport and every
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
	// Bootstrap yields the reversed data-plane path of the freshest unverified
	// beacon originating at a core: the enrollment route of a node that has not
	// pinned the TRC yet — the WebPKI-authenticated channel protects that
	// exchange.
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
	// Links snapshots the interfaces routes may leave the node through and
	// their neighbors. A segment through an interface the node retired stays
	// until it expires, while the data plane serves the interface no more,
	// and a link whose verdict is down keeps its segments while the data
	// plane refuses its egress: composition drops every path naming one of
	// the node's own interfaces the snapshot lacks, and so does the
	// bootstrap route, never a last resort. Nil, or a nil snapshot, composes
	// without the filter.
	Links func() map[uint16]addr.IA
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
		if bs := p.Bootstrap(dst); bs != nil && !retired(p.liveInterfaces(), egress(bs)) {
			return bs, nil
		}
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// egress returns the interface a path leaves the local AS through: its
// first hop's egress in the direction the path travels.
func egress(p *spath.Decoded) uint16 {
	if p.InfoFields[0].ConsDir {
		return p.HopFields[0].ConsEgress
	}
	return p.HopFields[0].ConsIngress
}

// Path returns a data-plane path from the local AS to dst. What LocalPath
// resolves from local state comes from it; anything else is the first clean
// candidate Enumerate composes, ordered by the carried rank — fewest joined
// hops, ties to the fresher pair, then to the one with fewer entries. A
// candidate crossing a signaled interface stays the last resort: the first
// of them in emission order, never the best-ranked one.
func (p *PathProvider) Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	if path, err := p.LocalPath(dst); err == nil {
		return path, nil
	}
	candidates, err := p.Enumerate(ctx, dst)
	if err != nil {
		return nil, err
	}
	var best, crossing *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.Crossing {
			if crossing == nil {
				crossing = c
			}
			continue
		}
		if best == nil || c.Before(best) {
			best = c
		}
	}
	if best != nil {
		return best.Path, nil
	}
	if crossing != nil {
		return crossing.Path, nil
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// Candidate is one composed path beside the facts composition holds on its
// way to ranking it.
type Candidate struct {
	// Path is the composed data-plane path.
	Path *spath.Decoded
	// Links are the (ISD-AS, interface ID) pairs of the traversed stretch —
	// both interface IDs of each entry — the identity the interface-down
	// cache keys on. Entries dropped by truncation contribute nothing.
	Links []segment.LinkID
	// Hops is the joined hop count.
	Hops int
	// Fresh is the staler piece's creation timestamp: a join is only as
	// fresh as the piece that expires first.
	Fresh time.Time
	// Entries is the joined pieces' total segment entries.
	Entries int
	// Crossing reports whether the traversed stretch crosses a signaled
	// interface — the flag a consumer honors as last resort.
	Crossing bool
	// Latency is the traversed inter-AS edges' declared one-way delays
	// summed, the path's one-way estimate; nil when any traversed edge is
	// declared by neither end: an undeclared edge is unknown, not free.
	Latency *time.Duration
}

// Before reports whether c outranks o: fewest joined hops first, then the
// fresher candidate by the staler piece's creation timestamp, then the one
// with fewer entries — the order Path returns and a consumer sorting the
// candidates reproduces.
func (c *Candidate) Before(o *Candidate) bool {
	if c.Hops != o.Hops {
		return c.Hops < o.Hops
	}
	if !c.Fresh.Equal(o.Fresh) {
		return c.Fresh.After(o.Fresh)
	}
	return c.Entries < o.Entries
}

// Enumerate returns every composed candidate path to dst with its facts, in
// the composition loop's own order: the down-only meeting per fetched down
// segment, then each (up, down) meeting at their deepest common AS entry —
// each part truncated at the meeting so the joined path travels no hop
// beyond it — with one candidate per up segment containing the destination,
// its truncated reversal, beside them: the branch LocalPath short-circuits,
// enumerated so the peers its own up segments hold join the candidate space.
// A pair meeting at the local node or at the destination leaves one part no
// travel and composes nothing: its path is the down-only meeting's or the
// containing branch's, which carry it once rather than once per segment of
// the idle part. A candidate naming one of the node's own interfaces the live
// snapshot lacks never composes, the snapshot taken once per call; a signaled
// interface keeps its demote-to-last-resort semantics, a flagged candidate.
// The local ISD-AS is the one error, a caller mistake failed fast at entry;
// an unreachable destination is the empty answer.
func (p *PathProvider) Enumerate(ctx context.Context, dst addr.IA) ([]Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	live := p.liveInterfaces()
	downs := p.Lookup(ctx, dst)
	ups := p.upSegments()
	var out []Candidate
	emit := func(up *pathdb.Segment, mUp int, down *pathdb.Segment, mDown int) error {
		c, err := p.compose(up, mUp, down, mDown, live)
		if err != nil {
			return err
		}
		if c != nil {
			out = append(out, *c)
		}
		return nil
	}
	for _, down := range downs {
		// The local node's own entry on the down segment is a meeting of its
		// own — the core the segment starts at, or an AS below it the node
		// happens to be: the segment's tail from that entry is the path,
		// whichever up segment ends at the node.
		if mDown := down.PCB.IndexOfIA(p.IA); mDown >= 0 {
			if err := emit(nil, -1, down, mDown); err != nil {
				return nil, err
			}
		}
		for _, up := range ups {
			// A meeting at the up segment's terminator, the local node, or at
			// the down segment's terminator, the destination, leaves that part
			// no travel: the down-only meeting above or the containing branch
			// below emits the path, fresher by its one piece and fewer in
			// entries than the pair.
			mUp, mDown, ok := meeting(up, down)
			if !ok || mUp == len(up.PCB.Entries)-1 || mDown == len(down.PCB.Entries)-1 {
				continue
			}
			if err := emit(up, mUp, down, mDown); err != nil {
				return nil, err
			}
		}
	}
	for _, up := range ups {
		// The destination's entry on a containing up segment is never the
		// segment's own terminator — that is the local node — so the
		// truncation a reversal needs always stands.
		m := up.PCB.IndexOfIA(dst)
		if m < 0 || m > len(up.PCB.Entries)-2 {
			continue
		}
		if err := emit(up, m, nil, -1); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// compose builds the candidate of one meeting — the up segment truncated at
// its entry mUp, the down segment at its entry mDown, either side optional —
// or nil when a hop of either traversed stretch names one of the node's own
// interfaces the live snapshot lacks: the data plane serves no such
// interface, so the candidate is dropped before composition, never a
// flagged survivor.
func (p *PathProvider) compose(
	up *pathdb.Segment, mUp int,
	down *pathdb.Segment, mDown int,
	live map[uint16]addr.IA,
) (*Candidate, error) {

	// A meeting at the local node carries no up part: the reversed up
	// segment truncated there is the empty travel. A meeting at the
	// destination carries no down part, the same arithmetic on the far end.
	upTravel := up != nil && mUp < len(up.PCB.Entries)-1
	downTravel := down != nil && mDown < len(down.PCB.Entries)-1
	var links []segment.LinkID
	latency, known := time.Duration(0), true
	crossing := false
	if upTravel {
		upLinks, sum, upKnown := stretch(up, mUp)
		links = append(links, upLinks...)
		latency += sum
		known = known && upKnown
		crossing = p.crossesFrom(up, mUp)
	}
	if downTravel {
		downLinks, sum, downKnown := stretch(down, mDown)
		links = append(links, downLinks...)
		latency += sum
		known = known && downKnown
		crossing = crossing || p.crossesFrom(down, mDown)
	}
	for _, link := range links {
		if link.IA.Equal(p.IA) && retired(live, link.IfID) {
			return nil, nil
		}
	}
	var parts []*spath.Decoded
	if upTravel {
		part, err := up.PCB.ReversePathTo(mUp)
		if err != nil {
			return nil, fmt.Errorf("reversing the up segment: %w", err)
		}
		parts = append(parts, part)
	}
	if downTravel {
		part, err := down.PCB.ForwardPathFrom(mDown)
		if err != nil {
			return nil, fmt.Errorf("forwarding the down segment: %w", err)
		}
		parts = append(parts, part)
	}
	path, err := segment.Compose(parts...)
	if err != nil {
		return nil, fmt.Errorf("composing the joined path: %w", err)
	}
	// The rank's timestamp and entry count read the joined pieces as a pair:
	// a join is only as fresh as the piece that expires first, and an
	// empty-travel side still beaconed.
	var pieces []*pathdb.Segment
	if up != nil {
		pieces = append(pieces, up)
	}
	if down != nil {
		pieces = append(pieces, down)
	}
	fresh, entries := pieces[0].PCB.Timestamp(), len(pieces[0].PCB.Entries)
	for _, seg := range pieces[1:] {
		if t := seg.PCB.Timestamp(); t.Before(fresh) {
			fresh = t
		}
		entries += len(seg.PCB.Entries)
	}
	c := &Candidate{
		Path:     path,
		Links:    links,
		Hops:     len(path.HopFields),
		Fresh:    fresh,
		Entries:  entries,
		Crossing: crossing,
	}
	if known {
		c.Latency = &latency
	}
	return c, nil
}

// stretch walks a segment's traversed stretch — the entries from index from
// to the segment's end — returning its link pairs and its declared one-way
// sum. Consecutive entries i and i+1 cross the link between AS i's egress
// interface and AS i+1's ingress interface whichever direction travel runs,
// so each edge is priced by lookup on the edge, never on the hop field: an
// up part traversed against construction finds the link's declaration on
// the adjacent upstream entry. Where both ends of an edge declare, the
// higher value wins; where neither declares, the sum is unknown.
func stretch(seg *pathdb.Segment, from int) (links []segment.LinkID, latency time.Duration, known bool) {
	for _, e := range seg.PCB.Entries[from:] {
		if e.Hop.ConsIngress != 0 {
			links = append(links, segment.LinkID{IA: e.IA, IfID: e.Hop.ConsIngress})
		}
		if e.Hop.ConsEgress != 0 {
			links = append(links, segment.LinkID{IA: e.IA, IfID: e.Hop.ConsEgress})
		}
	}
	known = true
	for i := from; i+1 < len(seg.PCB.Entries); i++ {
		e, next := seg.PCB.Entries[i], seg.PCB.Entries[i+1]
		egress, fromUpstream := e.Latency[segment.LinkID{IA: e.IA, IfID: e.Hop.ConsEgress}]
		ingress, fromDownstream := next.Latency[segment.LinkID{IA: next.IA, IfID: next.Hop.ConsIngress}]
		switch {
		case fromUpstream && fromDownstream:
			latency += max(egress, ingress)
		case fromUpstream:
			latency += egress
		case fromDownstream:
			latency += ingress
		default:
			known = false // an undeclared edge is unknown, not free
		}
	}
	return links, latency, known
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
// freshest crossing one kept when nothing else exists. A segment the node
// terminated on an interface the live snapshot lacks serves neither.
func (p *PathProvider) containingUp(ia addr.IA) (*pathdb.Segment, int) {
	live := p.liveInterfaces()
	var best, clean *pathdb.Segment
	bestAt, cleanAt := -1, -1
	for _, seg := range p.upSegments() {
		at := seg.PCB.IndexOfIA(ia)
		if at < 0 {
			continue
		}
		// The node's own entry terminates the segment, its ingress the
		// interface the beacon arrived on.
		if retired(live, seg.PCB.Entries[len(seg.PCB.Entries)-1].Hop.ConsIngress) {
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

// liveInterfaces snapshots the node's live interfaces; nil filters nothing.
func (p *PathProvider) liveInterfaces() map[uint16]addr.IA {
	if p.Links == nil {
		return nil
	}
	return p.Links()
}

// retired reports whether the live snapshot lacks one of the node's own
// interfaces; a nil snapshot lacks none.
func retired(live map[uint16]addr.IA, ifID uint16) bool {
	if live == nil {
		return false
	}
	_, ok := live[ifID]
	return !ok
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
