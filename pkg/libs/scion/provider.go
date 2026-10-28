package scion

import (
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
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
	// control plane. Nil looks up nothing: composition reads the local up
	// segments alone.
	Lookup func(ctx context.Context, dst addr.IA) []*pathdb.Segment
	// Bootstrap yields the reversed data-plane path of the freshest unverified
	// beacon originating at a core: the enrollment route of a node that has not
	// pinned the TRC yet — the WebPKI-authenticated channel protects that
	// exchange.
	Bootstrap func(core addr.IA) *spath.Decoded
	// Cores enumerates the core ASes of an ISD named by the pinned TRC.
	Cores func(isd addr.ISD) []addr.IA
	// InterfaceDown is the node's interface-down topic. Composition reads it
	// where it holds full knowledge — each segment's entries carry their
	// ISD-ASes and interface IDs — and demotes a composed path that crosses
	// a link a held signal names, keeping it only when nothing else exists.
	// A nil topic composes without the filter.
	InterfaceDown *bus.Topic[bus.InterfaceDownState]
	// Links is the node's link state topic, whose usable links are the
	// interfaces routes may leave the node through. A segment through an
	// interface the node retired stays until it expires, while the data plane
	// serves the interface no more, and a link whose verdict is down keeps
	// its segments while the data plane refuses its egress: composition drops
	// every path naming one of the node's own interfaces the usable links
	// lack, and so does the bootstrap route, never a last resort. A nil
	// topic, or one nothing has been published on, composes without the
	// filter.
	Links *bus.Topic[bus.LinkState]
}

// LocalPath resolves a data-plane path from local state only: up segments
// and the bootstrap beacon, never a fetch. It is the variant safe to call
// from inside a dial — resolving a route must not spawn RPCs over the very
// transport being dialed.
func (p *PathProvider) LocalPath(dst addr.IA) (*spath.Decoded, error) {
	c, err := p.local(dst)
	if err != nil {
		return nil, err
	}
	return c.Path, nil
}

// local resolves LocalPath's candidate. The bootstrap route is no
// composition: its candidate carries its path and hop count alone and joins
// no segment.
func (p *PathProvider) local(dst addr.IA) (*Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	v := p.view()
	// A destination an up segment already contains is on a route from here —
	// a core at the segment's origin, an on-path AS mid-segment — and the
	// containing segment whose truncated reversal ranks first is the route
	// to it.
	if c, err := p.containing(dst, v); err != nil || c != nil {
		return c, err
	}
	// Before any up segment is verified — a fresh node that has not even
	// pinned the TRC — the bootstrap beacon's reversed route serves the
	// core; beacons originate only at cores.
	if p.Bootstrap != nil {
		if bs := p.Bootstrap(dst); bs != nil && !v.retired(egress(bs)) {
			return &Candidate{Path: bs, Hops: len(bs.HopFields)}, nil
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

// Path returns a data-plane path from the local AS to dst: the path of the
// candidate Choose takes.
func (p *PathProvider) Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error) {
	c, err := p.Choose(ctx, dst)
	if err != nil {
		return nil, err
	}
	return c.Path, nil
}

// Choose returns the candidate Path takes to dst: the first clean candidate
// Enumerate composes, ordered by Outranks — the containing branches among
// them, ranked with the rest — else the first crossing one in emission
// order, never the best-ranked one, else what LocalPath resolves: the
// bootstrap route before any up segment is verified.
func (p *PathProvider) Choose(ctx context.Context, dst addr.IA) (*Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
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
		if best == nil || c.Outranks(best) {
			best = c
		}
	}
	if best != nil {
		return best, nil
	}
	if crossing != nil {
		return crossing, nil
	}
	return p.local(dst)
}

// StaleAfter is the age past which a candidate's staler piece reads stale.
// Registration refreshes the routes beaconing selects every minute, and a
// fetched down segment is cached for at most a minute, so a selected route's
// pieces stay a few minutes fresh; a route ages past five once the beacons
// stopped refreshing it, because it died or because beaconing selects others.
const StaleAfter = 5 * time.Minute

// Candidate is one composed path beside the facts composition holds on its
// way to ranking it.
type Candidate struct {
	// Path is the composed data-plane path.
	Path *spath.Decoded
	// Links are the (ISD-AS, interface ID) pairs of the traversed stretch —
	// both interface IDs of each entry — the identity interface-down signals
	// name. Entries dropped by truncation contribute nothing.
	Links []segment.LinkID
	// Hops is the joined hop count.
	Hops int
	// Fresh is the staler piece's creation timestamp: a join is only as
	// fresh as the piece that expires first.
	Fresh time.Time
	// Stale reports whether Fresh lies more than StaleAfter in the past at
	// composition.
	Stale bool
	// Entries is the joined pieces' total segment entries.
	Entries int
	// Crossing reports whether the traversed stretch crosses a signaled
	// interface — the flag a consumer honors as last resort.
	Crossing bool
	// Latency is the traversed inter-AS edges' declared one-way delays
	// summed, the path's one-way estimate; nil when any traversed edge is
	// declared by neither end: an undeclared edge is unknown, not free.
	Latency *time.Duration
	// Segments are the stored segments the path joins, in travel order: the
	// up segment before the down segment of a meeting, the one segment of a
	// containing branch or a down-only meeting.
	Segments []*pathdb.Segment
}

// Outranks reports whether c outranks o by the rank Choose picks with: a
// fresh candidate before a stale one, a declared sum before an undeclared
// one — unknown is not free — a smaller declared sum before a larger one,
// and every tie to Before.
func (c *Candidate) Outranks(o *Candidate) bool {
	if c.Stale != o.Stale {
		return !c.Stale
	}
	if (c.Latency == nil) != (o.Latency == nil) {
		return c.Latency != nil
	}
	if c.Latency != nil && *c.Latency != *o.Latency {
		return *c.Latency < *o.Latency
	}
	return c.Before(o)
}

// Before reports whether c outranks o by composition's own order: fewest
// joined hops first, then the fresher candidate by the staler piece's
// creation timestamp, then the one with fewer entries — the order Outranks
// falls back on, and the one a consumer keeping one candidate per route
// picks its freshest instance by.
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
// the idle part. A candidate naming one of the node's own interfaces the
// usable links lack never composes; a candidate crossing a signaled link
// keeps its demote-to-last-resort semantics, a flagged candidate. The link
// state and the interface-down state are read once per call.
// The local ISD-AS is the one error, a caller mistake failed fast at entry;
// an unreachable destination is the empty answer.
func (p *PathProvider) Enumerate(ctx context.Context, dst addr.IA) ([]Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	v := p.view()
	var downs []*pathdb.Segment
	if p.Lookup != nil {
		downs = p.Lookup(ctx, dst)
	}
	ups := p.upSegments()
	var out []Candidate
	emit := func(up *pathdb.Segment, mUp int, down *pathdb.Segment, mDown int) error {
		c, err := p.compose(up, mUp, down, mDown, v)
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
// interfaces the usable links lack: the data plane serves no such interface,
// so the candidate is dropped before composition, never a flagged survivor.
func (p *PathProvider) compose(
	up *pathdb.Segment, mUp int,
	down *pathdb.Segment, mDown int,
	v view,
) (*Candidate, error) {

	// A meeting at the local node carries no up part: the reversed up
	// segment truncated there is the empty travel. A meeting at the
	// destination carries no down part, the same arithmetic on the far end.
	upTravel := up != nil && mUp < len(up.PCB.Entries)-1
	downTravel := down != nil && mDown < len(down.PCB.Entries)-1
	var links []segment.LinkID
	latency, known := time.Duration(0), true
	if upTravel {
		upLinks, sum, upKnown := stretch(up, mUp)
		links = append(links, upLinks...)
		latency += sum
		known = known && upKnown
	}
	if downTravel {
		downLinks, sum, downKnown := stretch(down, mDown)
		links = append(links, downLinks...)
		latency += sum
		known = known && downKnown
	}
	crossing := false
	for _, link := range links {
		if link.IA.Equal(p.IA) && v.retired(link.IfID) {
			return nil, nil
		}
		crossing = crossing || v.down.Holds(link, v.now)
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
		Stale:    time.Since(fresh) > StaleAfter,
		Entries:  entries,
		Crossing: crossing,
		Segments: pieces,
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

// containing composes the truncated reversal of every up segment whose
// entries contain the given ISD-AS — a core at the origin, an on-path AS
// mid-segment — and returns the one Outranks puts first among those crossing
// no signaled interface, the first-ranked crossing one when nothing else
// composes; nil when no up segment contains it. A segment the node
// terminated on an interface the usable links lack composes nothing.
func (p *PathProvider) containing(ia addr.IA, v view) (*Candidate, error) {
	var clean, crossing *Candidate
	for _, seg := range p.upSegments() {
		at := seg.PCB.IndexOfIA(ia)
		if at < 0 {
			continue
		}
		c, err := p.compose(seg, at, nil, -1, v)
		if err != nil {
			return nil, err
		}
		switch {
		case c == nil:
		case c.Crossing:
			if crossing == nil || c.Outranks(crossing) {
				crossing = c
			}
		case clean == nil || c.Outranks(clean):
			clean = c
		}
	}
	if clean != nil {
		return clean, nil
	}
	return crossing, nil
}

// view is the state one call composes from, read once: the node's usable
// links, and the interface-down signals that hold at now.
type view struct {
	live map[uint16]addr.IA
	down bus.InterfaceDownState
	now  time.Time
}

// view reads the link state and the interface-down state.
func (p *PathProvider) view() view {
	return view{live: p.Links.Latest().Usable(), down: p.InterfaceDown.Latest(), now: time.Now()}
}

// retired reports whether the usable links lack one of the node's own
// interfaces; nil usable links lack none.
func (v view) retired(ifID uint16) bool {
	if v.live == nil {
		return false
	}
	_, ok := v.live[ifID]
	return !ok
}
