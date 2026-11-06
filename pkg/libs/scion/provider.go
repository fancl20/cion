package scion

import (
	"context"
	"fmt"
	"slices"
	"sync"
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
	// InterfaceDown is the node's interface-down topic. Health reads it: a
	// composed path crossing a link whose signal arrived after the path's
	// last answer is signaled, and suspect. A nil topic signals nothing.
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
	// Measurements is the node's path measurements topic, whose records give
	// each candidate its health and measured cost. A nil topic, or one
	// nothing has been published on, measures nothing.
	Measurements *bus.Topic[bus.PathMeasurements]
	// Requests is the node's path requests topic, on which each pick and
	// each lease update the paths their destination needs measured. A nil
	// topic requests nothing.
	Requests *bus.Topic[bus.PathRequests]

	// mtx guards the leases, their sweep, and the callers' reports.
	mtx     sync.Mutex
	leases  map[addr.IA]*Lease
	swept   time.Time
	reports map[bus.PathID]report
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

// local resolves LocalPath's candidate, updating the destination's path
// requests when an up segment contains it. The bootstrap route is no
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
	candidates, err := p.containing(dst, v)
	if err != nil {
		return nil, err
	}
	if pick := bestOf(candidates); pick != nil {
		p.request(picksRequester, dst, pick, v.now, candidates, v)
		return pick, nil
	}
	if bs := p.bootstrap(dst, v); bs != nil {
		return bs, nil
	}
	return nil, serrors.New("no path to destination", "isd_as", dst)
}

// bootstrap returns the bootstrap route's candidate, nil when none serves.
// Before any up segment is verified — a fresh node that has not even pinned
// the TRC — the bootstrap beacon's reversed route serves the core; beacons
// originate only at cores.
func (p *PathProvider) bootstrap(dst addr.IA, v view) *Candidate {
	if p.Bootstrap == nil {
		return nil
	}
	bs := p.Bootstrap(dst)
	if bs == nil || v.retired(egress(bs)) {
		return nil
	}
	return &Candidate{Path: bs, Hops: len(bs.HopFields)}
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

// Choose returns the candidate Path takes to dst: the one Enumerate composes
// that ranks above every other, by health, then cost, then Outranks — the
// containing branches among them, ranked with the rest — else what LocalPath
// resolves: the bootstrap route before any up segment is verified. It
// updates the destination's path requests.
func (p *PathProvider) Choose(ctx context.Context, dst addr.IA) (*Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
	v := p.view()
	candidates, err := p.enumerate(ctx, dst, v)
	if err != nil {
		return nil, err
	}
	if pick := bestOf(candidates); pick != nil {
		p.request(picksRequester, dst, pick, v.now, candidates, v)
		return pick, nil
	}
	return p.local(dst)
}

// bestOf returns the candidate ranking above every other, nil for none.
func bestOf(candidates []Candidate) *Candidate {
	var best *Candidate
	for i := range candidates {
		if c := &candidates[i]; best == nil || ranksAbove(c, best) {
			best = c
		}
	}
	return best
}

// StaleAfter is the age past which a candidate's staler piece reads stale.
// Registration refreshes the routes beaconing selects every minute, and a
// lookup serving fetched down segments a minute old refreshes them, so a
// selected route's pieces stay a few minutes fresh; a route ages past five
// once the beacons stopped refreshing it, because it died or because
// beaconing selects others.
const StaleAfter = 5 * time.Minute

// ReadingSpan is how far back a reading reads its round trips: StaleAfter,
// the horizon in which a link change plays out in every node's segments.
const ReadingSpan = StaleAfter

// Reading returns the reading of the round trips, what a measurement over
// them reports: their 80th percentile by nearest rank, the round trip a
// fifth of the others exceed and the highest of up to four; zero for none.
// Up to a fifth of the round trips may stand high and the reading holds,
// while no one low lowers it.
func Reading(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	sorted := slices.Sorted(slices.Values(rtts))
	return sorted[(4*len(sorted)+4)/5-1]
}

// TransitPenalty is what each AS a path crosses between its ends adds to its
// one-way price: the forwarding a transit costs, and one more failure on the
// way. The picks, the leases, and the topology selection charge it alike.
const TransitPenalty = 5 * time.Millisecond

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
	// Latency is the traversed inter-AS edges' declared one-way delays
	// summed, the path's one-way estimate; nil when any traversed edge is
	// declared by neither end: an undeclared edge is unknown, not free.
	Latency *time.Duration
	// Segments are the stored segments the path joins, in travel order: the
	// up segment before the down segment of a meeting, the one segment of a
	// containing branch or a down-only meeting.
	Segments []*pathdb.Segment
	// Crossed are the (ISD-AS, interface ID) pairs the path's packets cross,
	// in travel order: Links less each part's turning entry's core-ward
	// interface, which no packet crosses.
	Crossed []segment.LinkID
	// ID is the path's identity, its crossed pairs, which the segments'
	// refreshes keep; empty for the bootstrap route.
	ID bus.PathID
	// Health is what the measurements, the callers' reports, and the
	// signals said of the path at composition.
	Health Health
	// Signaled reports whether a signal on a link the path crosses arrived
	// after its last answer: a router reported the path failing, and the
	// picks rank it after the other suspects.
	Signaled bool
	// Retry is when an ejected path is due its half-open probe; zero for
	// the others.
	Retry time.Time
	// Cost is the path's round trip: its measured cost, else twice its
	// declared one-way sum; nil when it has neither.
	Cost *time.Duration
	// Reading is the path's round trip as the topology selection compares
	// it: the reading of its probes answered within ReadingSpan, divided by
	// their delivery rate, else twice its declared one-way sum; nil when it
	// has neither.
	Reading *time.Duration
}

// Price returns what the picks and the leases rank the path by: its cost
// charged TransitPenalty for every AS it crosses between its ends, each way.
// False without a cost.
func (c *Candidate) Price() (time.Duration, bool) {
	if c.Cost == nil {
		return 0, false
	}
	ases := make(map[addr.IA]bool, len(c.Links))
	for _, l := range c.Links {
		ases[l.IA] = true
	}
	return *c.Cost + 2*TransitPenalty*time.Duration(max(0, len(ases)-2)), true
}

// Outranks reports whether c outranks o by the prior order, the one the picks
// fall back on past health and price: a fresh candidate before a stale one, a
// declared sum before an undeclared one — unknown is not free — a smaller
// declared sum before a larger one, and every tie to Before.
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
// keeps its demote-to-last-resort semantics, a flagged candidate. Each
// candidate carries its health and cost. The link state, the interface-down
// state, and the path measurements are read once per call.
// The local ISD-AS is the one error, a caller mistake failed fast at entry;
// an unreachable destination is the empty answer.
func (p *PathProvider) Enumerate(ctx context.Context, dst addr.IA) ([]Candidate, error) {
	return p.enumerate(ctx, dst, p.view())
}

// enumerate is Enumerate over a view the caller read.
func (p *PathProvider) enumerate(ctx context.Context, dst addr.IA, v view) ([]Candidate, error) {
	if dst.Equal(p.IA) {
		return nil, serrors.New("destination is the local ISD-AS", "isd_as", dst)
	}
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
	var links, crossed []segment.LinkID
	latency, known := time.Duration(0), true
	if upTravel {
		upLinks, sum, upKnown := stretch(up, mUp)
		links = append(links, upLinks...)
		crossed = append(crossed, crossedLinks(up, mUp, true)...)
		latency += sum
		known = known && upKnown
	}
	if downTravel {
		downLinks, sum, downKnown := stretch(down, mDown)
		links = append(links, downLinks...)
		crossed = append(crossed, crossedLinks(down, mDown, false)...)
		latency += sum
		known = known && downKnown
	}
	for _, link := range links {
		if link.IA.Equal(p.IA) && v.retired(link.IfID) {
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
		Stale:    time.Since(fresh) > StaleAfter,
		Entries:  entries,
		Segments: pieces,
		Crossed:  crossed,
		ID:       bus.PathIDOf(crossed),
	}
	if known {
		c.Latency = &latency
	}
	v.assess(c)
	return c, nil
}

// crossedLinks returns the (ISD-AS, interface ID) pairs a part's packets
// cross in travel order: an up part's from the segment's end back to its
// entry from, against construction; a down part's from its entry from to its
// end. The turning entry's core-ward interface, which no packet crosses, is
// left out.
func crossedLinks(seg *pathdb.Segment, from int, against bool) []segment.LinkID {
	entries := seg.PCB.Entries[from:]
	var out []segment.LinkID
	add := func(ia addr.IA, ifID uint16) {
		if ifID != 0 {
			out = append(out, segment.LinkID{IA: ia, IfID: ifID})
		}
	}
	if against {
		for i, e := range slices.Backward(entries) {
			add(e.IA, e.Hop.ConsEgress)
			if i > 0 {
				add(e.IA, e.Hop.ConsIngress)
			}
		}
		return out
	}
	for i, e := range entries {
		if i > 0 {
			add(e.IA, e.Hop.ConsIngress)
		}
		add(e.IA, e.Hop.ConsEgress)
	}
	return out
}

// stretch walks a segment's traversed stretch — the entries from index from
// to the segment's end — returning its link pairs and its declared one-way
// sum. Consecutive entries i and i+1 cross the link between AS i's egress
// interface and AS i+1's ingress interface whichever direction travel runs,
// so each edge is priced by lookup on the edge, never on the hop field: an
// up part traversed against construction finds the link's declaration on
// the adjacent upstream entry. segment.EdgeDelay prices each edge; where an
// edge is undeclared, the sum is unknown.
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
		d, declared := segment.EdgeDelay(&seg.PCB.Entries[i], &seg.PCB.Entries[i+1])
		if !declared {
			known = false
			continue
		}
		latency += d
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
// mid-segment; none when no up segment contains it. A segment the node
// terminated on an interface the usable links lack composes nothing.
func (p *PathProvider) containing(ia addr.IA, v view) ([]Candidate, error) {
	var out []Candidate
	for _, seg := range p.upSegments() {
		at := seg.PCB.IndexOfIA(ia)
		if at < 0 {
			continue
		}
		c, err := p.compose(seg, at, nil, -1, v)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

// view is the state one call composes from, read once: the node's usable
// links, the interface-down signals that stand at now, the path
// measurements, the links the measured failed paths share, and the callers'
// reports.
type view struct {
	live     map[uint16]addr.IA
	down     bus.InterfaceDownState
	measured bus.PathMeasurements
	suspect  map[segment.LinkID]bool
	reports  map[bus.PathID]report
	now      time.Time
}

// view reads the link state, the interface-down state, the path
// measurements, and the callers' reports, dropping the reports nothing
// added to for RequestLapse.
func (p *PathProvider) view() view {
	now := time.Now()
	measured := p.Measurements.Latest()
	p.mtx.Lock()
	reports := make(map[bus.PathID]report, len(p.reports))
	for id, r := range p.reports {
		if now.Sub(later(r.delivered, r.doubted())) >= bus.RequestLapse {
			delete(p.reports, id)
			continue
		}
		reports[id] = r
	}
	p.mtx.Unlock()
	return view{
		live:     p.Links.Latest().Usable(),
		down:     p.InterfaceDown.Latest(),
		measured: measured,
		suspect:  suspectLinks(measured, now),
		reports:  reports,
		now:      now,
	}
}

// record adds a caller's outcome on the path to its report: a delivery
// replaces the report, a loss joins its latest callerLosses losses. A path
// without an identity records nothing.
func (p *PathProvider) record(id bus.PathID, delivered bool, now time.Time) {
	if id == "" {
		return
	}
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.reports == nil {
		p.reports = make(map[bus.PathID]report)
	}
	r := p.reports[id]
	if delivered {
		r = report{delivered: now}
	} else {
		r.losses = append(r.losses[max(0, len(r.losses)-callerLosses+1):len(r.losses):len(r.losses)], now)
	}
	p.reports[id] = r
}

// later returns the later of two times.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
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
