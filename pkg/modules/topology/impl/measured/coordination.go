package measured

import (
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
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
// node reported, weighed by the larger of the round trips its ends report,
// and bounded by the larger of their lower and of their upper bounds; the
// pairs linked, each end's interface on them; the announced changes; the
// cluster each signer joined; the path cost between every two nodes over
// the linked pairs; and the window's units, which a node set for its own
// clustering.
type coordView struct {
	weight    map[pair]time.Duration
	low, high map[pair]time.Duration
	linked    map[pair]bool
	ends      map[pair][]segment.LinkID
	promoting map[pair]addr.IA
	retiring  map[pair]retirement
	clusters  map[addr.IA]addr.IA
	index     map[addr.IA]int
	dist      [][]time.Duration
	units     *units
}

// newCoordView reads the directory's reports. A pair is linked when an end
// reports a link to the other and no end reports none; an end that reports
// nothing of the pair holds no vote.
func newCoordView(d bus.Directory) *coordView {
	v := &coordView{
		weight:    make(map[pair]time.Duration),
		low:       make(map[pair]time.Duration),
		high:      make(map[pair]time.Duration),
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
	down := make(map[pair]bool)
	for _, r := range reports {
		p := pairOf(r.signer, r.IA)
		v.weight[p] = max(v.weight[p], r.RTT)
		v.low[p], v.high[p] = max(v.low[p], r.Low), max(v.high[p], r.High)
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
	for p, ends := range v.ends {
		if len(ends) > 0 && !down[p] {
			v.linked[p] = true
		}
	}
	v.paths()
	return v
}

// paths prices the path between every two nodes over the linked pairs: the
// summed weights, charged transitCost for every node between the ends.
func (v *coordView) paths() {
	const inf = time.Duration(1<<63 - 1)
	n := len(v.index)
	v.dist = make([][]time.Duration, n)
	for i := range v.dist {
		v.dist[i] = make([]time.Duration, n)
		for j := range v.dist[i] {
			if i != j {
				v.dist[i][j] = inf
			}
		}
	}
	for p := range v.linked {
		i, j := v.index[p.lo], v.index[p.hi]
		w := v.weight[p] + transitCost
		v.dist[i][j], v.dist[j][i] = min(v.dist[i][j], w), min(v.dist[j][i], w)
	}
	for k := range n {
		for i := range n {
			if v.dist[i][k] == inf {
				continue
			}
			for j := range n {
				if v.dist[k][j] != inf && v.dist[i][k]+v.dist[k][j] < v.dist[i][j] {
					v.dist[i][j] = v.dist[i][k] + v.dist[k][j]
				}
			}
		}
	}
	for i := range n {
		for j := range n {
			if i != j && v.dist[i][j] != inf {
				v.dist[i][j] -= transitCost
			}
		}
	}
}

// cost returns the path cost between two nodes over the linked pairs, zero
// from a node to itself, and false when no path joins them.
func (v *coordView) cost(a, b addr.IA) (time.Duration, bool) {
	if a == b {
		return 0, true
	}
	i, ok := v.index[a]
	j, ok2 := v.index[b]
	if !ok || !ok2 {
		return 0, false
	}
	d := v.dist[i][j]
	return d, d != time.Duration(1<<63-1)
}

// through returns the cost of the cheapest path between two nodes that
// crosses the pair at its weight, and whether any path would join them so.
func (v *coordView) through(a, b addr.IA, q pair) (time.Duration, bool) {
	var best time.Duration
	joined := false
	for _, ends := range [][2]addr.IA{{q.lo, q.hi}, {q.hi, q.lo}} {
		ax, ok := v.cost(a, ends[0])
		yb, ok2 := v.cost(ends[1], b)
		if !ok || !ok2 {
			continue
		}
		c := ax + v.weight[q] + yb
		if ends[0] != a {
			c += transitCost
		}
		if ends[1] != b {
			c += transitCost
		}
		if !joined || c < best {
			best, joined = c, true
		}
	}
	return best, joined
}

// costWith returns the path cost between two nodes were the pair linked at
// its weight, and whether any path would join them.
func (v *coordView) costWith(a, b addr.IA, q pair) (time.Duration, bool) {
	best, joined := v.cost(a, b)
	if c, ok := v.through(a, b, q); ok && (!joined || c < best) {
		return c, true
	}
	return best, joined
}

// onPath reports whether a linked pair lies on a cheapest path between two
// nodes.
func (v *coordView) onPath(a, b addr.IA, p pair) bool {
	path, joined := v.cost(a, b)
	c, ok := v.through(a, b, p)
	return joined && ok && c == path
}

// violatesAt reports whether a pair of the given weight beats a path cost by
// the promotion ratio and the margin floor, as the selection's priced case
// beats a member's price; a pair no path joins violates.
func violatesAt(w, path time.Duration, joined bool) bool {
	return !joined || w < ratioOf(path, PromotionRatio) && path-w >= MarginFloor
}

// violates reports whether an unlinked pair the clustering allows beats the
// path between its ends.
func (v *coordView) violates(p pair) bool {
	if v.linked[p] || v.units != nil && !v.units.allowed(v, p.lo, p.hi) {
		return false
	}
	path, joined := v.cost(p.lo, p.hi)
	return violatesAt(v.weight[p], path, joined)
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
	for p := range v.weight {
		if !v.violates(p) {
			delete(c.predicted, p)
		} else if _, ok := c.predicted[p]; !ok {
			c.predicted[p] = c.window
		}
	}
	for p := range c.predicted {
		if _, ok := v.weight[p]; !ok {
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
// another node's change: while a lighter pair of another node that holds
// promotions back would serve the node's pair were it linked — leave it
// violating no more over the published links — or while the published
// links already serve the pair and a link on its path, first seen linked
// within scion.StaleAfter, crosses none of the node's routes to the peer
// yet: the node's prices cannot see it. A pair the view holds no report of
// waits on nothing.
func (c *coordState) waitsToPromote(
	v *coordView, self, peer addr.IA, routes []scion.Candidate, now time.Time,
) bool {
	mine := pairOf(self, peer)
	w, ok := v.weight[mine]
	if !ok {
		return false
	}
	if path, joined := v.cost(self, peer); !violatesAt(w, path, joined) {
		return c.lagging(v, self, peer, routes, now)
	}
	for q, qw := range v.weight {
		if q.lo == self || q.hi == self || v.linked[q] || !lighter(q, qw, mine, w) || !c.holds(q) {
			continue
		}
		if path, joined := v.costWith(self, peer, q); !violatesAt(w, path, joined) {
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
// a link another node announced to retire — unless that node's routes cross
// this link too and this link is the heavier, which then goes first — or a
// link whose announced retirement left the links within scion.StaleAfter,
// whose routes the measurements may not have caught dead yet.
func (c *coordState) waitsToRetire(v *coordView, self, peer addr.IA, relies []segment.LinkID) bool {
	mine := pairOf(self, peer)
	for p, r := range v.retiring {
		if r.by == self || p == mine || !v.crosses(relies, p) {
			continue
		}
		if v.crosses(r.relies, mine) && lighter(p, v.weight[p], mine, v.weight[mine]) {
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
