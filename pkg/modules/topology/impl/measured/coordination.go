package measured

import (
	"maps"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The coordination of link changes between nodes: each node reports the
// round trips it measured, its links, and the changes it is about to make
// in its directory entries; every node reads the published links and round
// trips each window, predicts which promotions come first, and holds its
// own promotion or retirement back while another node's would serve or
// undo it.

// transitCost is what each transit charges a path's round trip, as the
// selection's member prices charge it: the transit penalty each way.
const transitCost = 2 * scion.TransitPenalty

// runnerUpWindows is how many windows another node's lighter pair holds the
// promotions it would serve back after its prediction or its announcement
// first shows: one window for that node's own test or change, one for the
// result to reach the others. Past them the next lighter candidate goes.
const runnerUpWindows = 2

// rttStep is the least relative change of a measured round trip the node
// reports again, beside rttFloor, the least absolute one: a round trip
// within both of the reported one keeps the report, so jitter moves no
// pair's weight in the other nodes' views.
const (
	rttStep  = 0.1
	rttFloor = 500 * time.Microsecond
)

// pair is an unordered pair of ISD-ASes, the lesser first.
type pair struct {
	lo, hi addr.IA
}

func pairOf(a, b addr.IA) pair {
	if b < a {
		a, b = b, a
	}
	return pair{lo: a, hi: b}
}

// lighter orders two pairs by weight, ties to the lesser pair.
func lighter(p pair, w time.Duration, o pair, ow time.Duration) bool {
	if w != ow {
		return w < ow
	}
	if p.lo != o.lo {
		return p.lo < o.lo
	}
	return p.hi < o.hi
}

// retirement is a retirement a node announced: the node, and the links the
// routes it judged its link by cross.
type retirement struct {
	by     addr.IA
	relies []segment.LinkID
}

// coordView is the window's reading of the published reports: every pair a
// node reported, at the estimate its ends' reports state together — the
// larger of their round trips, of their lower bounds, and of their upper
// bounds; the pairs linked, each end's interface on them; the announced
// changes; the cluster each signer joined; the cheapest path between every
// two nodes over the linked pairs; and the window's units, which a node set
// for its own clustering.
type coordView struct {
	rtts      map[pair]evidence.Estimate
	linked    map[pair]bool
	ends      map[pair][]segment.LinkID
	promoting map[pair]addr.IA
	retiring  map[pair]retirement
	clusters  map[addr.IA]addr.IA
	index     map[addr.IA]int
	dist      paths
	units     *units
}

// paths holds the cheapest path between every two nodes, by their indices,
// as the least of the estimates of all the paths between them states it:
// the least value, the least lower bound, and the least upper bound, each
// over the paths, infinite where none joins them.
type paths struct {
	value, lo, hi [][]time.Duration
}

// unjoined is the infinite cost of no path.
const unjoined = time.Duration(1<<63 - 1)

// newCoordView reads the directory's reports. A pair is linked when an end
// reports a link to the other and no end reports none; an end that reports
// nothing of the pair holds no vote.
func newCoordView(d bus.Directory) *coordView {
	v := &coordView{
		rtts:      make(map[pair]evidence.Estimate),
		linked:    make(map[pair]bool),
		ends:      make(map[pair][]segment.LinkID),
		promoting: make(map[pair]addr.IA),
		retiring:  make(map[pair]retirement),
		clusters:  make(map[addr.IA]addr.IA),
		index:     make(map[addr.IA]int),
	}
	type report struct {
		signer addr.IA
		bus.PeerReport
	}
	seen := make(map[[2]addr.IA]bool)
	signed := make(map[addr.IA]time.Time)
	var reports []report
	for _, s := range d.Scopes() {
		for _, e := range s.Entries() {
			if at, ok := signed[e.IA]; !ok || e.Published.After(at) {
				signed[e.IA], v.clusters[e.IA] = e.Published, e.Cluster
			}
			for _, r := range e.Peers {
				if r.IA == e.IA || seen[[2]addr.IA{e.IA, r.IA}] {
					continue
				}
				seen[[2]addr.IA{e.IA, r.IA}] = true
				reports = append(reports, report{signer: e.IA, PeerReport: r})
			}
		}
	}
	type reported struct {
		rtt, low, high time.Duration
	}
	byPair := make(map[pair]reported)
	down := make(map[pair]bool)
	for _, r := range reports {
		p := pairOf(r.signer, r.IA)
		b := byPair[p]
		byPair[p] = reported{rtt: max(b.rtt, r.RTT), low: max(b.low, r.Low), high: max(b.high, r.High)}
		if r.IfID != 0 {
			v.ends[p] = append(v.ends[p], segment.LinkID{IA: r.signer, IfID: r.IfID})
		} else {
			down[p] = true
		}
		if r.Promoting {
			v.promoting[p] = r.signer
		}
		if r.Retiring {
			v.retiring[p] = retirement{by: r.signer, relies: r.Relies}
		}
		for _, ia := range []addr.IA{r.signer, r.IA} {
			if _, ok := v.index[ia]; !ok {
				v.index[ia] = len(v.index)
			}
		}
	}
	for p, b := range byPair {
		if e := scion.PublishedEstimate(b.rtt, b.low, b.high); e.Answered > 0 {
			v.rtts[p] = e
		}
	}
	for p, ends := range v.ends {
		if len(ends) > 0 && !down[p] {
			v.linked[p] = true
		}
	}
	v.dist = v.cheapestPaths()
	return v
}

// cheapestPaths prices the cheapest path between every two nodes over the
// linked pairs a report weighs: each path's estimate the sum of its pairs',
// charged transitCost for every node between the ends, as evidence.Sum has
// it — a missing lower bound counting zero, a missing upper bound leaving
// the path none — and the least of the paths' as evidence.Min has it,
// each of the value and the bounds over its own paths.
func (v *coordView) cheapestPaths() paths {
	n := len(v.index)
	square := func() [][]time.Duration {
		m := make([][]time.Duration, n)
		for i := range m {
			m[i] = make([]time.Duration, n)
			for j := range m[i] {
				if i != j {
					m[i][j] = unjoined
				}
			}
		}
		return m
	}
	ps := paths{value: square(), lo: square(), hi: square()}
	for p := range v.linked {
		e, ok := v.rtts[p]
		if !ok {
			continue
		}
		i, j := v.index[p.lo], v.index[p.hi]
		ps.value[i][j], ps.value[j][i] = e.Value+transitCost, e.Value+transitCost
		ps.lo[i][j], ps.lo[j][i] = e.Lo+transitCost, e.Lo+transitCost
		if e.HasHi {
			ps.hi[i][j], ps.hi[j][i] = e.Hi+transitCost, e.Hi+transitCost
		}
	}
	for _, m := range [][][]time.Duration{ps.value, ps.lo, ps.hi} {
		for k := range n {
			for i := range n {
				if m[i][k] == unjoined {
					continue
				}
				for j := range n {
					if m[k][j] != unjoined && m[i][k]+m[k][j] < m[i][j] {
						m[i][j] = m[i][k] + m[k][j]
					}
				}
			}
		}
		for i := range n {
			for j := range n {
				if i != j && m[i][j] != unjoined {
					m[i][j] -= transitCost
				}
			}
		}
	}
	return ps
}

// cost returns the estimate of the cheapest path between two distinct nodes
// over the linked pairs, and false when no path joins them.
func (v *coordView) cost(a, b addr.IA) (evidence.Estimate, bool) {
	i, ok := v.index[a]
	j, ok2 := v.index[b]
	if !ok || !ok2 || v.dist.value[i][j] == unjoined {
		return evidence.Estimate{}, false
	}
	hi := v.dist.hi[i][j]
	if hi == unjoined {
		hi = 0
	}
	return scion.PublishedEstimate(v.dist.value[i][j], v.dist.lo[i][j], hi), true
}

// through returns the estimate of the cheapest path between two nodes that
// crosses the pair at its estimate, the least of the two ways across it,
// and whether any path would join them so.
func (v *coordView) through(a, b addr.IA, q pair) (evidence.Estimate, bool) {
	var ways []evidence.Estimate
	for _, ends := range [][2]addr.IA{{q.lo, q.hi}, {q.hi, q.lo}} {
		parts := []evidence.Estimate{v.rtts[q]}
		var charge time.Duration
		for _, leg := range [][2]addr.IA{{a, ends[0]}, {ends[1], b}} {
			if leg[0] == leg[1] {
				continue
			}
			c, ok := v.cost(leg[0], leg[1])
			if !ok {
				parts = nil
				break
			}
			parts, charge = append(parts, c), charge+transitCost
		}
		if way := evidence.Sum(parts...); way.Answered > 0 {
			ways = append(ways, way.Add(charge))
		}
	}
	way := evidence.Min(ways...)
	return way, way.Answered > 0
}

// costWith returns the estimate of the cheapest path between two nodes were
// the pair linked at its estimate, and whether any path would join them.
func (v *coordView) costWith(a, b addr.IA, q pair) (evidence.Estimate, bool) {
	path, _ := v.cost(a, b)
	with, _ := v.through(a, b, q)
	least := evidence.Min(path, with)
	return least, least.Answered > 0
}

// onPath reports whether a linked pair lies on a cheapest path between two
// nodes, by value.
func (v *coordView) onPath(a, b addr.IA, p pair) bool {
	path, joined := v.cost(a, b)
	c, ok := v.through(a, b, p)
	return joined && ok && c.Value == path.Value
}

// beatsPath weighs whether a pair beats the cheapest path between its ends
// as buys weighs it: better for a pair no path joins.
func beatsPath(w, path evidence.Estimate, joined bool) evidence.Verdict {
	if !joined {
		return evidence.Better
	}
	return buys(w, path)
}

// buys weighs whether a pair's round trip a buys a link on the reports
// against the round trip b it would replace: a beats b's buy ceiling, and
// beats b by MarginFloor, a smaller gain being jitter on a fast link. Both
// must hold.
func buys(a, b evidence.Estimate) evidence.Verdict {
	return fold([]evidence.Verdict{
		evidence.Beats(a, buyCeiling(b), 0),
		evidence.Beats(a, b, MarginFloor),
	})
}

// buyCeiling returns the most a pair's round trip may be to buy a link
// against a round trip it would replace: that round trip scaled by
// PromotionRatio.
func buyCeiling(e evidence.Estimate) evidence.Estimate {
	return e.Mul(PromotionRatio)
}

// violates reports whether an unlinked pair the clustering allows beats the
// cheapest path between its ends.
func (v *coordView) violates(p pair) bool {
	if v.linked[p] || v.units != nil && !v.units.allowed(v, p.lo, p.hi) {
		return false
	}
	path, joined := v.cost(p.lo, p.hi)
	return beatsPath(v.rtts[p], path, joined) == evidence.Better
}

// crosses reports whether any of the links is one of the interfaces the
// linked pair's ends report on it.
func (v *coordView) crosses(links []segment.LinkID, p pair) bool {
	for _, end := range v.ends[p] {
		if slices.Contains(links, end) {
			return true
		}
	}
	return false
}

// cycleOf returns the announced retirements that rest on the pair's and on
// which it rests, each through announced retirements: a retirement rests on
// another while the routes it judged its link by cross that link. The
// pair's own rest on relies, whatever its announcement holds.
func (v *coordView) cycleOf(mine pair, relies []segment.LinkID) map[pair]bool {
	restsOn := func(p, q pair) bool {
		if p == mine {
			return v.crosses(relies, q)
		}
		return v.crosses(v.retiring[p].relies, q)
	}
	others := slices.DeleteFunc(slices.Collect(maps.Keys(v.retiring)), func(p pair) bool { return p == mine })
	reach := func(from pair, edge func(a, b pair) bool) map[pair]bool {
		seen := map[pair]bool{}
		frontier := []pair{from}
		for len(frontier) > 0 {
			x := frontier[0]
			frontier = frontier[1:]
			for _, y := range others {
				if !seen[y] && edge(x, y) {
					seen[y] = true
					frontier = append(frontier, y)
				}
			}
		}
		return seen
	}
	ahead := reach(mine, restsOn)
	behind := reach(mine, func(a, b pair) bool { return restsOn(b, a) })
	cycle := map[pair]bool{}
	for p := range ahead {
		if behind[p] {
			cycle[p] = true
		}
	}
	return cycle
}

// departedLink is a link that left after its node announced its
// retirement: when, and its ends' interfaces.
type departedLink struct {
	at   time.Time
	ends []segment.LinkID
}

// ownRetirement is a retirement the node announced: the window it was first
// announced in, and the links the routes it judged its link by cross.
type ownRetirement struct {
	since  int
	relies []segment.LinkID
}

// coordState is what the coordination carries across windows: the window
// count; when each violating pair was first predicted and each announced
// promotion first seen; when each linked pair was first seen linked; the
// announced retirements whose links left; and the node's own announcements
// and reported round trips.
type coordState struct {
	window      int
	predicted   map[pair]int
	announced   map[pair]int
	linkedSince map[pair]time.Time
	retired     map[pair]departedLink
	last        *coordView

	// promote is the peer whose promotion the node announced, zero for
	// none.
	promote addr.IA
	// retiring holds the node's announced retirements, by peer.
	retiring map[addr.IA]ownRetirement
	// rtts, lows, and highs hold the round trip and the bounds the node
	// last reported per peer.
	rtts, lows, highs map[addr.IA]time.Duration
}

// observe advances the state to the window's view: a violating pair gets its
// first prediction and a pair that stopped violating loses it, an announced
// promotion gets its first sighting and one withdrawn loses it, a new link
// gets its first sighting and a link gone loses it, and an announced
// retirement whose link left records when, beside its ends.
func (c *coordState) observe(v *coordView, now time.Time) {
	c.window++
	if c.linkedSince == nil {
		c.linkedSince = make(map[pair]time.Time)
		c.retired = make(map[pair]departedLink)
		c.predicted = make(map[pair]int)
		c.announced = make(map[pair]int)
		c.rtts = make(map[addr.IA]time.Duration)
		c.lows = make(map[addr.IA]time.Duration)
		c.highs = make(map[addr.IA]time.Duration)
	}
	for p := range v.rtts {
		if !v.violates(p) {
			delete(c.predicted, p)
		} else if _, ok := c.predicted[p]; !ok {
			c.predicted[p] = c.window
		}
	}
	for p := range c.predicted {
		if _, ok := v.rtts[p]; !ok {
			delete(c.predicted, p)
		}
	}
	for p := range v.promoting {
		if _, ok := c.announced[p]; !ok {
			c.announced[p] = c.window
		}
	}
	for p := range c.announced {
		if _, ok := v.promoting[p]; !ok {
			delete(c.announced, p)
		}
	}
	for p := range v.linked {
		if _, ok := c.linkedSince[p]; !ok {
			c.linkedSince[p] = now
		}
	}
	for p := range c.linkedSince {
		if !v.linked[p] {
			delete(c.linkedSince, p)
		}
	}
	if c.last != nil {
		for p := range c.last.retiring {
			if c.last.linked[p] && !v.linked[p] {
				c.retired[p] = departedLink{at: now, ends: c.last.ends[p]}
			}
		}
	}
	for p, r := range c.retired {
		if now.Sub(r.at) > scion.StaleAfter {
			delete(c.retired, p)
		}
	}
	c.last = v
}

// holds reports whether another node's pair holds back the promotions it
// would serve this window: its promotion announced, or the pair violating,
// first seen no more than runnerUpWindows windows ago.
func (c *coordState) holds(q pair) bool {
	for _, since := range []map[pair]int{c.announced, c.predicted} {
		if first, ok := since[q]; ok && c.window-first <= runnerUpWindows {
			return true
		}
	}
	return false
}

// waitsToPromote reports whether the node's promotion of the peer waits on
// another node's change: while its pair beats the published path between
// its ends and a lighter pair of another node that holds promotions back
// would leave it beating the path no more were it linked; or while its pair
// does not beat the published path and a link on that path, first seen
// linked within scion.StaleAfter, crosses none of the node's routes to the
// peer yet: the node's prices cannot see it. A pair the view holds no
// report of waits on nothing.
func (c *coordState) waitsToPromote(
	v *coordView, self, peer addr.IA, routes []scion.Candidate, now time.Time,
) bool {
	mine := pairOf(self, peer)
	w, ok := v.rtts[mine]
	if !ok {
		return false
	}
	if path, joined := v.cost(self, peer); beatsPath(w, path, joined) != evidence.Better {
		return c.lagging(v, self, peer, routes, now)
	}
	for q, qw := range v.rtts {
		if q.lo == self || q.hi == self || v.linked[q] || !lighter(q, qw.Value, mine, w.Value) || !c.holds(q) {
			continue
		}
		if path, joined := v.costWith(self, peer, q); beatsPath(w, path, joined) != evidence.Better {
			return true
		}
	}
	return false
}

// lagging reports whether a link on a cheapest published path between the
// node and the peer, first seen linked within scion.StaleAfter, crosses none
// of the node's routes to the peer.
func (c *coordState) lagging(
	v *coordView, self, peer addr.IA, routes []scion.Candidate, now time.Time,
) bool {
	var crossed []segment.LinkID
	for _, r := range routes {
		crossed = append(crossed, r.Links...)
	}
	for p, since := range c.linkedSince {
		if now.Sub(since) > scion.StaleAfter || v.crosses(crossed, p) {
			continue
		}
		if v.onPath(self, peer, p) {
			return true
		}
	}
	return false
}

// waitsToRetire reports whether the node's retirement of its link to the
// peer waits on another node's: while the routes it judged the link by cross
// a link another node announced to retire — unless the two retirements rest
// on each other, directly or through other announced retirements, and this
// link is the heaviest of the cycle, which then goes first — or a link whose
// announced retirement left the links within scion.StaleAfter, whose routes
// the measurements may not have caught dead yet.
func (c *coordState) waitsToRetire(v *coordView, self, peer addr.IA, relies []segment.LinkID) bool {
	mine := pairOf(self, peer)
	cycle := v.cycleOf(mine, relies)
	heaviest := !slices.ContainsFunc(slices.Collect(maps.Keys(cycle)), func(p pair) bool {
		return lighter(mine, v.rtts[mine].Value, p, v.rtts[p].Value)
	})
	for p, r := range v.retiring {
		if r.by == self || p == mine || !v.crosses(relies, p) {
			continue
		}
		if cycle[p] && heaviest {
			continue
		}
		return true
	}
	for p, r := range c.retired {
		if p == mine {
			continue
		}
		for _, end := range r.ends {
			if slices.Contains(relies, end) {
				return true
			}
		}
	}
	return false
}

// reportRTT returns the round trip to report for the peer: the one last
// reported unless the measurement moved past rttStep of it and rttFloor.
func (c *coordState) reportRTT(ia addr.IA, measured time.Duration) time.Duration {
	return stepped(c.rtts, ia, measured)
}

// reportBounds returns the bounds to report for the peer, each stepped as
// round trips are.
func (c *coordState) reportBounds(ia addr.IA, low, high time.Duration) (time.Duration, time.Duration) {
	return stepped(c.lows, ia, low), stepped(c.highs, ia, high)
}

// stepped returns the value to report for the peer, and records it: the
// one last reported unless the measured one moved past rttStep of it and
// rttFloor.
func stepped(last map[addr.IA]time.Duration, ia addr.IA, measured time.Duration) time.Duration {
	prev, ok := last[ia]
	moved := measured - prev
	if moved < 0 {
		moved = -moved
	}
	if !ok || moved > max(time.Duration(float64(prev)*rttStep), rttFloor) {
		last[ia] = measured
		return measured
	}
	return prev
}

// reliance returns the links the routes an excluded measurement judged its
// link by cross: the freshest survivor's and each member's cheapest.
func reliance(ex excludedSample) []segment.LinkID {
	var out []segment.LinkID
	add := func(c *scion.Candidate) {
		if c == nil {
			return
		}
		for _, l := range c.Links {
			if !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
	}
	add(ex.survivor)
	for _, c := range ex.cheapest {
		add(c)
	}
	slices.SortFunc(out, func(a, b segment.LinkID) int {
		if a.IA != b.IA {
			if a.IA < b.IA {
				return -1
			}
			return 1
		}
		return int(a.IfID) - int(b.IfID)
	})
	return out
}
