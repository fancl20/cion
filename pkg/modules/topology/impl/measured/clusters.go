package measured

import (
	"cmp"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/evidence"
)

// The clusters of nearby nodes. Every node computes them from the estimates
// the directory's reports state, so nodes holding the same entries agree. A node names the cluster it joined in its entries; the
// nodes naming one cluster form one unit, and every other node is a unit of
// one. Members are each other's candidates; between two units, links run
// only between the member pairs the round trips choose.

// ClusterGap is the least multiple of a cluster's diameter its separation
// reaches. Joined through their clusters' closest members, two nodes in
// different clusters travel at most the two diameters beyond their round
// trip, so at this gap the share stays within the line to buy on the
// reports: no more than 1/PromotionRatio of the round trip.
const ClusterGap = 2 / (1/PromotionRatio - 1)

// edge is a pair of nodes with the bound that orders it.
type edge struct {
	p pair
	w time.Duration
}

// naturalClusters returns the clusters the reports confirm, each its
// members ascending: the single-linkage dendrogram joins the pairs an upper
// bound weighs, lightest first, ties to the lesser pair, and a dendrogram
// cluster of two nodes or more, short of all, is natural when its diameter,
// scaled by ClusterGap, beats its separation. Of overlapping natural
// clusters, the one whose separation's lower bound is the greatest multiple
// of its diameter's upper bound stands, ties to the least member.
func naturalClusters(v *coordView) [][]addr.IA {
	nodes := make([]addr.IA, 0, len(v.index))
	for ia := range v.index {
		nodes = append(nodes, ia)
	}
	slices.Sort(nodes)
	var edges []edge
	for p, e := range v.rtts {
		if e.HasHi {
			edges = append(edges, edge{p: p, w: e.Hi})
		}
	}
	slices.SortFunc(edges, func(a, b edge) int {
		if c := cmp.Compare(a.w, b.w); c != 0 {
			return c
		}
		if c := cmp.Compare(a.p.lo, b.p.lo); c != 0 {
			return c
		}
		return cmp.Compare(a.p.hi, b.p.hi)
	})
	parent := make(map[addr.IA]addr.IA, len(nodes))
	members := make(map[addr.IA][]addr.IA, len(nodes))
	for _, ia := range nodes {
		parent[ia], members[ia] = ia, []addr.IA{ia}
	}
	var find func(addr.IA) addr.IA
	find = func(ia addr.IA) addr.IA {
		if parent[ia] != ia {
			parent[ia] = find(parent[ia])
		}
		return parent[ia]
	}
	type candidate struct {
		members []addr.IA
		gap     float64
	}
	var cands []candidate
	for _, e := range edges {
		a, b := find(e.p.lo), find(e.p.hi)
		if a == b {
			continue
		}
		parent[b] = a
		joined := append(members[a], members[b]...)
		slices.Sort(joined)
		members[a] = joined
		delete(members, b)
		diameter, separation, ok := spread(v, joined)
		if !ok || evidence.Beats(separationFloor(diameter), separation, 0) != evidence.Better {
			continue
		}
		cands = append(cands, candidate{
			members: slices.Clone(joined),
			gap:     float64(separation.Lo) / float64(diameter.Hi),
		})
	}
	slices.SortStableFunc(cands, func(a, b candidate) int {
		if c := cmp.Compare(b.gap, a.gap); c != 0 {
			return c
		}
		return cmp.Compare(a.members[0], b.members[0])
	})
	taken := make(map[addr.IA]bool)
	var out [][]addr.IA
	for _, c := range cands {
		if slices.ContainsFunc(c.members, func(ia addr.IA) bool { return taken[ia] }) {
			continue
		}
		for _, ia := range c.members {
			taken[ia] = true
		}
		out = append(out, c.members)
	}
	slices.SortFunc(out, func(a, b []addr.IA) int { return cmp.Compare(a[0], b[0]) })
	return out
}

// separationFloor returns the least separation a natural cluster of the
// diameter has: the diameter scaled by ClusterGap.
func separationFloor(diameter evidence.Estimate) evidence.Estimate {
	return diameter.Mul(ClusterGap)
}

// spread returns a node set's diameter, the most of the estimates of the
// pairs inside it, and its separation, the least of those of the pairs from
// it to the nodes outside that a report weighs, with whether the reports
// weigh both: every pair inside, and at least one pair to a node outside.
func spread(v *coordView, set []addr.IA) (diameter, separation evidence.Estimate, ok bool) {
	inside := make(map[addr.IA]bool, len(set))
	for _, ia := range set {
		inside[ia] = true
	}
	var in, out []evidence.Estimate
	for i, a := range set {
		for _, b := range set[i+1:] {
			e, ok := v.rtts[pairOf(a, b)]
			if !ok {
				return evidence.Estimate{}, evidence.Estimate{}, false
			}
			in = append(in, e)
		}
	}
	for p, e := range v.rtts {
		if inside[p.lo] != inside[p.hi] {
			out = append(out, e)
		}
	}
	return evidence.Max(in...), evidence.Min(out...), len(in) > 0 && len(out) > 0
}

// units are the window's units: the nodes naming one cluster form one, and
// every other node the view or the node itself names is a unit of one.
type units struct {
	// of holds each node's unit, an index into members.
	of map[addr.IA]int
	// members holds each unit's members, ascending.
	members [][]addr.IA
	// pairs holds the chosen pairs between two units once computed, by the
	// units' indices, the lesser first.
	pairs map[[2]int][]pair
}

// newUnits groups the view's nodes, and the node itself, by the clusters
// they name; the node's own name is the one given, not its entry's.
func newUnits(v *coordView, self, cluster addr.IA) *units {
	names := make(map[addr.IA]addr.IA, len(v.index)+1)
	for ia := range v.index {
		names[ia] = v.clusters[ia]
	}
	names[self] = cluster
	nodes := make([]addr.IA, 0, len(names))
	for ia := range names {
		nodes = append(nodes, ia)
	}
	slices.Sort(nodes)
	u := &units{of: make(map[addr.IA]int, len(nodes)), pairs: make(map[[2]int][]pair)}
	byName := make(map[addr.IA]int)
	for _, ia := range nodes {
		name := names[ia]
		if name == 0 {
			u.of[ia] = len(u.members)
			u.members = append(u.members, []addr.IA{ia})
			continue
		}
		i, ok := byName[name]
		if !ok {
			i = len(u.members)
			byName[name] = i
			u.members = append(u.members, nil)
		}
		u.of[ia] = i
		u.members[i] = append(u.members[i], ia)
	}
	return u
}

// chosen returns the member pairs that link two units: the pair keptPair
// returns across them, and the one it returns on two other members, a unit
// of one keeping its node, the first alone between two units of one. Pairs
// no reading weighs are never chosen.
func (u *units) chosen(v *coordView, x, y int) []pair {
	key := [2]int{min(x, y), max(x, y)}
	if ps, ok := u.pairs[key]; ok {
		return ps
	}
	ps := u.choose(v, x, y)
	u.pairs[key] = ps
	return ps
}

// choose computes chosen's pairs.
func (u *units) choose(v *coordView, x, y int) []pair {
	first, ok := keptPair(v, u.members[x], u.members[y], nil)
	if !ok {
		return nil
	}
	if len(u.members[x]) == 1 && len(u.members[y]) == 1 {
		return []pair{first}
	}
	skip := map[addr.IA]bool{first.lo: true, first.hi: true}
	if len(u.members[x]) == 1 || len(u.members[y]) == 1 {
		single := u.members[x][0]
		if len(u.members[y]) == 1 {
			single = u.members[y][0]
		}
		delete(skip, single)
	}
	second, ok := keptPair(v, u.members[x], u.members[y], skip)
	if !ok {
		return []pair{first}
	}
	return []pair{first, second}
}

// keptPair returns the pair across two member sets, neither end skipped,
// that links them: the lightest linked pair until the lightest pair outruns
// it, else the lightest pair.
func keptPair(v *coordView, xs, ys []addr.IA, skip map[addr.IA]bool) (pair, bool) {
	best, ok := lightestPair(v, xs, ys, skip, false)
	if !ok {
		return pair{}, false
	}
	if held, ok := lightestPair(v, xs, ys, skip, true); ok && !outruns(v, best, held) {
		return held, true
	}
	return best, true
}

// outruns reports whether one pair's round trip buys a link against
// another's, as buys weighs it.
func outruns(v *coordView, p, q pair) bool {
	return buys(v.rtts[p], v.rtts[q]) == evidence.Better
}

// lightestPair returns the pair across two member sets that the lightest
// round trip weighs, ties to the lesser pair, neither end skipped, and
// linked in the view where asked.
func lightestPair(v *coordView, xs, ys []addr.IA, skip map[addr.IA]bool, linked bool) (pair, bool) {
	var best pair
	var bestW time.Duration
	found := false
	for _, a := range xs {
		if skip[a] {
			continue
		}
		for _, b := range ys {
			if skip[b] {
				continue
			}
			p := pairOf(a, b)
			e, ok := v.rtts[p]
			if !ok || linked && !v.linked[p] {
				continue
			}
			if !found || lighter(p, e.Value, best, bestW) {
				best, bestW, found = p, e.Value, true
			}
		}
	}
	return best, found
}

// allowed reports whether a link between two nodes belongs to the
// clustering: both in one unit, a chosen pair of their units — their own,
// for two units of one — or any pair of two units no report joins. A node
// the view does not hold is allowed everywhere.
func (u *units) allowed(v *coordView, a, b addr.IA) bool {
	x, ok := u.of[a]
	y, ok2 := u.of[b]
	if !ok || !ok2 || x == y {
		return true
	}
	ps := u.chosen(v, x, y)
	return len(ps) == 0 || slices.Contains(ps, pairOf(a, b))
}

// joined reports whether a chosen pair of the two nodes' units is linked in
// the view.
func (u *units) joined(v *coordView, a, b addr.IA) bool {
	x, ok := u.of[a]
	y, ok2 := u.of[b]
	if !ok || !ok2 || x == y {
		return false
	}
	return slices.ContainsFunc(u.chosen(v, x, y), func(p pair) bool { return v.linked[p] })
}

// predict returns the estimate of the round trip between two nodes in
// different units through their units' closest members, the lightest pair
// between them by round trip: the sum of its hops' estimates — a hop from a
// node to itself weighs nothing — and whether a report weighs every hop.
func (u *units) predict(v *coordView, a, b addr.IA) (evidence.Estimate, bool) {
	closest, ok := lightestPair(v, u.members[u.of[a]], u.members[u.of[b]], nil, false)
	if !ok {
		return evidence.Estimate{}, false
	}
	near, far := closest.lo, closest.hi
	if u.of[near] != u.of[a] {
		near, far = far, near
	}
	var hops []evidence.Estimate
	for _, hop := range [][2]addr.IA{{a, near}, {near, far}, {far, b}} {
		if hop[0] == hop[1] {
			continue
		}
		e, ok := v.rtts[pairOf(hop[0], hop[1])]
		if !ok {
			return evidence.Estimate{}, false
		}
		hops = append(hops, e)
	}
	return evidence.Sum(hops...), true
}

// broken returns the first pair across the unit's edge whose direct round
// trip buys a link against the round trip through the clusters, as buys
// weighs it, beside the two estimates weighed: the unit breaks the budget
// for it. False when no pair breaks it.
func (u *units) broken(v *coordView, unit int) (direct, through evidence.Estimate, ok bool) {
	for _, a := range u.members[unit] {
		for b, y := range u.of {
			if y == unit {
				continue
			}
			direct, ok := v.rtts[pairOf(a, b)]
			if !ok {
				continue
			}
			through, ok := u.predict(v, a, b)
			if ok && buys(direct, through) == evidence.Better {
				return direct, through, true
			}
		}
	}
	return evidence.Estimate{}, evidence.Estimate{}, false
}

// joinCluster returns the cluster the node names this window, beside the
// verdict that names it: the natural cluster holding it, named as an
// existing member names it where every node naming that cluster lies
// inside, else by its least ISD-AS; otherwise the cluster it named, while
// another node names it too and no pair across the unit's edge breaks the
// budget; otherwise none, for its unit fell below two members or a pair
// broke the budget.
func joinCluster(v *coordView, self, named addr.IA) (addr.IA, verdict) {
	for _, c := range naturalClusters(v) {
		if slices.Contains(c, self) {
			return clusterName(v, c, self, named), naturalVerdict(v, c)
		}
	}
	if named == 0 {
		return 0, verdict{}
	}
	u := newUnits(v, self, named)
	unit := u.of[self]
	if len(u.members[unit]) < 2 {
		return 0, verdict{why: "its unit fell below two members"}
	}
	if direct, through, ok := u.broken(v, unit); ok {
		return 0, brokenVerdict(direct, through)
	}
	return named, verdict{why: "its unit holds"}
}

// clusterName returns the name a natural cluster takes: the least name one
// of its members uses that no node outside it uses, else its least member
// whose ISD-AS no node outside names. The node's own name is the one given.
func clusterName(v *coordView, c []addr.IA, self, named addr.IA) addr.IA {
	nameOf := func(ia addr.IA) addr.IA {
		if ia == self {
			return named
		}
		return v.clusters[ia]
	}
	inside := make(map[addr.IA]bool, len(c))
	for _, ia := range c {
		inside[ia] = true
	}
	outside := make(map[addr.IA]bool)
	for ia, name := range v.clusters {
		if ia != self && name != 0 && !inside[ia] {
			outside[name] = true
		}
	}
	var best addr.IA
	for _, ia := range c {
		name := nameOf(ia)
		if name != 0 && !outside[name] && (best == 0 || name < best) {
			best = name
		}
	}
	if best != 0 {
		return best
	}
	for _, ia := range c {
		if !outside[ia] {
			return ia
		}
	}
	return c[0]
}
