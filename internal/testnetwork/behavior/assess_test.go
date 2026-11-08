package behavior

import (
	"cmp"
	"context"
	"fmt"
	"hash"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// penalty is the cost a path pays for each node it crosses between its
// ends, unless a benchmark sets its own.
const penalty = 5 * time.Millisecond

// unreachable is the cost between nodes no sequence of edges joins.
const unreachable = time.Duration(math.MaxInt64 / 4)

// lookupBudget bounds each path lookup a read makes: a lookup whose fetch
// from the core cannot complete would otherwise hold the read, and the
// bubble's clock, for the fetch's own timeouts. It leaves a fresh fetch
// across the slowest lab's delays several round trips.
const lookupBudget = 2 * time.Second

// assessment grades a settled network's paths at one penalty: the grading
// beside the segment records the chosen paths join and the links a single
// cut would need.
type assessment struct {
	grading
	// upChosen and downChosen count the stored up and down segment records
	// some pair's chosen path joins, of upStored and downStored.
	upChosen, upStored, downChosen, downStored int
	// cuts are the formed links whose removal would leave some node
	// unreachable over the rest.
	cuts [][2]int
	// clusters are the clusters the nodes joined.
	clusters [][]int
}

func (a assessment) String() string {
	return fmt.Sprintf("%v; up segments chosen %d of %d, down %d of %d; single cuts %v; clusters %v",
		a.grading, a.upChosen, a.upStored, a.downChosen, a.downStored, a.cuts, a.clusters)
}

// grading grades one read of a network's paths at one penalty against the
// shortest paths every pair's delay allows.
type grading struct {
	// penalty is the cost each transit node adds to a path.
	penalty time.Duration
	// pairs counts the ordered pairs; reached, those whose chosen path
	// crosses only formed links to its destination; links, the formed
	// links.
	pairs, reached, links int
	// ratio and excess grade each reached pair's chosen path against the
	// global reference: its cost over the reference's, and the
	// milliseconds above it.
	ratio, excess summary
	// topology is the formed links' shortest over the reference, for every
	// pair the formed links join; choice is the chosen path over the formed
	// links' shortest, for every reached pair.
	topology, choice summary
	// bestReached counts the pairs with a candidate crossing only formed
	// links, and best grades the cheapest such candidate against the
	// reference; surfaced reports that every pair's cheapest candidate costs
	// the formed links' shortest. All three need the candidates read.
	bestReached int
	best        summary
	surfaced    bool
}

func (g grading) String() string {
	return fmt.Sprintf("%d links; reached %d of %d pairs; cost over the reference %v; excess ms %v; "+
		"topology %v; choice %v", g.links, g.reached, g.pairs, g.ratio, g.excess, g.topology, g.choice)
}

// summary is a distribution's mean, 95th percentile, and maximum.
type summary struct{ mean, p95, max float64 }

func (s summary) String() string {
	return fmt.Sprintf("mean %.2f p95 %.2f max %.2f", s.mean, s.p95, s.max)
}

// summarize returns the distribution's summary; zero for none.
func summarize(xs []float64) summary {
	if len(xs) == 0 {
		return summary{}
	}
	sorted := slices.Sorted(slices.Values(xs))
	sum := 0.0
	for _, x := range sorted {
		sum += x
	}
	return summary{
		mean: sum / float64(len(sorted)),
		p95:  sorted[int(math.Ceil(0.95*float64(len(sorted))))-1],
		max:  sorted[len(sorted)-1],
	}
}

// assess grades the settled network's paths at each penalty, beside the
// segment records the chosen paths join and the formed links a single cut
// would need. The founding core is the network's first node.
func assess(t *testing.T, n *network, penalties ...time.Duration) []assessment {
	t.Helper()
	r := readMoved(t, n)
	upChosen, upStored := countChosen(t, n.nodes[1:], pathdb.SegmentTypeUp, r.routes)
	downChosen, downStored := countChosen(t, n.nodes[:1], pathdb.SegmentTypeDown, r.routes)
	cuts := singleCuts(len(n.nodes), r.formed.edges)
	joined := clusters(n)
	var out []assessment
	for _, p := range penalties {
		out = append(out, assessment{
			grading:  r.grade(n, p),
			upChosen: upChosen, upStored: upStored, downChosen: downChosen, downStored: downStored,
			cuts: cuts, clusters: joined,
		})
	}
	return out
}

// paths is one read of a network's paths.
type paths struct {
	formed formed
	// set names the formed links as linkSet does.
	set string
	// chosen holds each reached ordered pair's chosen path as the nodes it
	// crosses, and routes the routes the chosen paths join.
	chosen map[[2]int][]int
	routes map[string]bool
	// live holds each ordered pair's candidates that cross only formed
	// links, as the nodes they cross, when candidates were read.
	live       map[[2]int][][]int
	candidates bool
}

// readPaths reads every ordered pair's chosen path — the path the source's
// lease of the destination holds, read as a send reads it — walked over the
// formed links, and with candidates set every candidate the pair's segments
// compose. A lookup that outlasts lookupBudget finds no segment it would
// have fetched.
func readPaths(t *testing.T, n *network, candidates bool) paths {
	t.Helper()
	lookup := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(t.Context(), lookupBudget)
	}
	r := paths{
		formed:     formedLinks(t, n),
		set:        linkSet(t.Context(), n.nodes),
		chosen:     map[[2]int][]int{},
		routes:     map[string]bool{},
		live:       map[[2]int][][]int{},
		candidates: candidates,
	}
	for s := range n.nodes {
		for d := range n.nodes {
			if s == d {
				continue
			}
			provider, dst := n.nodes[s].App().Provider(), n.nodes[d].App().IA()
			ctx, cancel := lookup()
			leased, err := provider.Lease(dst).Await(ctx)
			cancel()
			if err == nil {
				for _, seg := range leased.Segments {
					r.routes[routeKey(seg)] = true
				}
				if hops, ok := r.formed.walk(s, d, leased.Path); ok {
					r.chosen[[2]int{s, d}] = hops
				}
			}
			if !candidates {
				continue
			}
			ctx, cancel = lookup()
			cands, err := provider.Enumerate(ctx, dst)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cands {
				if hops, ok := r.formed.walk(s, d, c.Path); ok {
					r.live[[2]int{s, d}] = append(r.live[[2]int{s, d}], hops)
				}
			}
		}
	}
	return r
}

// readMoved reads every ordered pair's chosen path as a flow that starts
// reading its leases holds it once they had time to move, for a network
// that read no lease for a while: a lease moves to a cheaper path once its
// evaluations found the path healthy and cheaper for scion.LeaseSwitchHold,
// and a destination nothing read lets its paths' probes lapse. The first
// read requests the destinations' paths, which the prober probes at once;
// the second finds a cheaper path healthy; the third, past the hold, finds
// the lease moved. It returns the third read.
func readMoved(t *testing.T, n *network) paths {
	t.Helper()
	for range 2 {
		readPaths(t, n, false)
		time.Sleep(scion.LeaseSwitchHold + scion.LeaseEvaluation)
	}
	return readPaths(t, n, false)
}

// grade grades the read at the penalty against the penalized shortest
// paths over every pair's delay and over the formed links.
func (r paths) grade(n *network, p time.Duration) grading {
	size := len(n.nodes)
	reference := penalizedShortest(size, n.delay, p)
	shortest := penalizedShortest(size, r.formed.delay(n), p)
	g := grading{penalty: p, surfaced: r.candidates, links: len(r.formed.edges)}
	var ratio, excess, topology, choice, best []float64
	for s := range size {
		for d := range size {
			if s == d {
				continue
			}
			g.pairs++
			ref, short := reference[s][d], shortest[s][d]
			if ref == unreachable {
				continue
			}
			if short != unreachable {
				topology = append(topology, float64(short)/float64(ref))
			}
			if hops, ok := r.chosen[[2]int{s, d}]; ok {
				g.reached++
				cost := pathCost(hops, n.delay, p)
				ratio = append(ratio, float64(cost)/float64(ref))
				excess = append(excess, float64(cost-ref)/float64(time.Millisecond))
				choice = append(choice, float64(cost)/float64(short))
			}
			if !r.candidates {
				continue
			}
			cheapest := unreachable
			for _, hops := range r.live[[2]int{s, d}] {
				cheapest = min(cheapest, pathCost(hops, n.delay, p))
			}
			if cheapest != unreachable {
				g.bestReached++
				best = append(best, float64(cheapest)/float64(ref))
			}
			if short != unreachable && cheapest != short {
				g.surfaced = false
			}
		}
	}
	g.ratio, g.excess = summarize(ratio), summarize(excess)
	g.topology, g.choice, g.best = summarize(topology), summarize(choice), summarize(best)
	return g
}

// countChosen counts the nodes' stored segment records of the type, and
// those whose routes the chosen paths join.
func countChosen(t *testing.T, nodes []*testnetwork.Node, kind pathdb.SegmentType, chosen map[string]bool) (picked, stored int) {
	t.Helper()
	for _, node := range nodes {
		segs, err := node.App().PathDB().Get(t.Context(), pathdb.Query{Type: kind})
		if err != nil {
			t.Fatal(err)
		}
		for _, seg := range segs {
			stored++
			if chosen[routeKey(seg)] {
				picked++
			}
		}
	}
	return picked, stored
}

// routeKey names a segment record by its type and route, the identity the
// path database keeps: a fetched copy of a down segment and the core's
// record of it share one.
func routeKey(s *pathdb.Segment) string {
	return fmt.Sprint(s.Key())
}

// iface is one node's interface.
type iface struct {
	node int
	ifID uint16
}

// formed holds a network's formed links: each interface established and up
// with the node it leads to, and the pairs whose link is up at both ends.
type formed struct {
	up    map[iface]int
	edges map[[2]int]bool
}

// formedLinks reads the network's formed links: a link the fabric cuts
// counts as down whatever its ends still believe.
func formedLinks(t *testing.T, n *network) formed {
	t.Helper()
	index := make(map[addr.IA]int, len(n.nodes))
	for i, node := range n.nodes {
		index[node.App().IA()] = i
	}
	f := formed{up: map[iface]int{}, edges: map[[2]int]bool{}}
	directed := map[[2]int]bool{}
	for i, node := range n.nodes {
		entries, err := node.App().Links().All(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range entries {
			j, ok := index[l.NeighborIA]
			if !ok || l.State != links.StateEstablished || !node.App().Monitor().Up(l.IfID) || n.cut[pair(i, j)] {
				continue
			}
			f.up[iface{i, l.IfID}] = j
			directed[[2]int{i, j}] = true
		}
	}
	for ends := range directed {
		if directed[[2]int{ends[1], ends[0]}] {
			f.edges[pair(ends[0], ends[1])] = true
		}
	}
	return f
}

// delay returns the network's delays over the formed links alone.
func (f formed) delay(n *network) func(i, j int) (time.Duration, bool) {
	return func(i, j int) (time.Duration, bool) {
		if !f.edges[pair(i, j)] {
			return 0, false
		}
		return n.delay(i, j)
	}
}

// walk follows a data-plane path from src hop field by hop field, returning
// the nodes it crosses and whether every link it takes is up at both ends
// and it ends at dst. A segment's last hop field and the next segment's
// first name the same node, the crossover between them.
func (f formed) walk(src, dst int, p *spath.Decoded) ([]int, bool) {
	hops := []int{src}
	at, first := src, 0
	for seg := range p.NumINF {
		n := int(p.PathMeta.SegLen[seg])
		forward := p.InfoFields[seg].ConsDir
		for k := first; k+1 < first+n; k++ {
			egress, ingress := p.HopFields[k].ConsIngress, p.HopFields[k+1].ConsEgress
			if forward {
				egress, ingress = p.HopFields[k].ConsEgress, p.HopFields[k+1].ConsIngress
			}
			next, ok := f.up[iface{at, egress}]
			if !ok {
				return hops, false
			}
			if back, ok := f.up[iface{next, ingress}]; !ok || back != at {
				return hops, false
			}
			at = next
			hops = append(hops, at)
		}
		first += n
	}
	return hops, at == dst
}

// penalizedShortest returns every pair's shortest cost over the edges delay
// admits, each node a path crosses between its ends charged p: the graph
// whose every node splits into an in-node and an out-node joined by an edge
// weighing p, which charges each edge p and refunds the destination's.
func penalizedShortest(size int, delay func(i, j int) (time.Duration, bool), p time.Duration) [][]time.Duration {
	d := make([][]time.Duration, size)
	for i := range size {
		d[i] = make([]time.Duration, size)
		for j := range size {
			switch w, ok := delay(i, j); {
			case i == j:
				d[i][j] = 0
			case ok:
				d[i][j] = w + p
			default:
				d[i][j] = unreachable
			}
		}
	}
	for k := range size {
		for i := range size {
			for j := range size {
				if d[i][k]+d[k][j] < d[i][j] {
					d[i][j] = d[i][k] + d[k][j]
				}
			}
		}
	}
	for i := range size {
		for j := range size {
			if i != j && d[i][j] < unreachable {
				d[i][j] -= p
			}
		}
	}
	return d
}

// pathCost is a walked path's cost: its links' delays and p for each node
// it crosses between its ends.
func pathCost(hops []int, delay func(i, j int) (time.Duration, bool), p time.Duration) time.Duration {
	var cost time.Duration
	for k := 0; k+1 < len(hops); k++ {
		d, _ := delay(hops[k], hops[k+1])
		cost += d
	}
	if len(hops) > 2 {
		cost += time.Duration(len(hops)-2) * p
	}
	return cost
}

// singleCuts returns the edges whose removal would leave some node
// unreachable over the rest.
func singleCuts(size int, edges map[[2]int]bool) [][2]int {
	var cuts [][2]int
	for e := range edges {
		if !connected(size, edges, e) {
			cuts = append(cuts, e)
		}
	}
	slices.SortFunc(cuts, func(a, b [2]int) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	return cuts
}

// connected reports whether the edges, the skipped one aside, join every
// node.
func connected(size int, edges map[[2]int]bool, skip [2]int) bool {
	reached := map[int]bool{0: true}
	frontier := []int{0}
	for len(frontier) > 0 {
		x := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for e := range edges {
			if e == skip || (e[0] != x && e[1] != x) {
				continue
			}
			if y := e[0] + e[1] - x; !reached[y] {
				reached[y] = true
				frontier = append(frontier, y)
			}
		}
	}
	return len(reached) == size
}

// matrix is a test delay function over a symmetric matrix of
// milliseconds, a zero off the diagonal reading as no edge.
func matrix(ms [][]int) func(i, j int) (time.Duration, bool) {
	return func(i, j int) (time.Duration, bool) {
		return time.Duration(ms[i][j]) * time.Millisecond, ms[i][j] != 0
	}
}

// TestPenalizedShortestSplitsNodes checks the penalized shortest costs
// against the graph whose nodes are split: out-node to in-node along each
// edge, in-node to out-node at the penalty, a path from the source's
// out-node to the destination's in-node. The delays break the triangle
// inequality, so a relay beats a direct edge until the penalty outweighs
// what it saves.
func TestPenalizedShortestSplitsNodes(t *testing.T) {
	ms := [][]int{
		{0, 2, 9, 0, 30},
		{2, 0, 3, 8, 0},
		{9, 3, 0, 1, 7},
		{0, 8, 1, 0, 2},
		{30, 0, 7, 2, 0},
	}
	delay := matrix(ms)
	size := len(ms)
	for _, p := range []time.Duration{0, 3 * time.Millisecond, 50 * time.Millisecond} {
		// Node i's in-node is 2i, its out-node 2i+1.
		split := make([][]time.Duration, 2*size)
		for i := range split {
			split[i] = make([]time.Duration, 2*size)
			for j := range split[i] {
				if i != j {
					split[i][j] = unreachable
				}
			}
		}
		for i := range size {
			split[2*i][2*i+1] = p
			for j := range size {
				if w, ok := delay(i, j); ok && i != j {
					split[2*i+1][2*j] = w
				}
			}
		}
		for k := range split {
			for i := range split {
				for j := range split {
					if split[i][k]+split[k][j] < split[i][j] {
						split[i][j] = split[i][k] + split[k][j]
					}
				}
			}
		}
		got := penalizedShortest(size, delay, p)
		for i := range size {
			for j := range size {
				if i != j && got[i][j] != split[2*i+1][2*j] {
					t.Errorf("penalty %v: %d to %d costs %v, want the split graph's %v",
						p, i, j, got[i][j], split[2*i+1][2*j])
				}
			}
		}
	}
	if got := penalizedShortest(size, delay, 0)[0][4]; got != 8*time.Millisecond {
		t.Errorf("0 to 4 at no penalty costs %v, want the relays' 8ms", got)
	}
}

// TestPathCostChargesTransits checks that a path pays its links' delays and
// the penalty once per node between its ends.
func TestPathCostChargesTransits(t *testing.T) {
	delay := matrix([][]int{
		{0, 2, 0, 0},
		{2, 0, 3, 0},
		{0, 3, 0, 4},
		{0, 0, 4, 0},
	})
	p := 5 * time.Millisecond
	for _, tc := range []struct {
		hops []int
		want time.Duration
	}{
		{[]int{0, 1}, 2 * time.Millisecond},
		{[]int{0, 1, 2}, 10 * time.Millisecond},
		{[]int{0, 1, 2, 3}, 19 * time.Millisecond},
	} {
		if got := pathCost(tc.hops, delay, p); got != tc.want {
			t.Errorf("path %v costs %v, want %v", tc.hops, got, tc.want)
		}
	}
}

// TestSingleCuts checks the cut reading: a ring needs no single cut, every
// link of a tree is one, and a pendant off a ring is the one link a cut
// takes it by.
func TestSingleCuts(t *testing.T) {
	edges := func(pairs ...[2]int) map[[2]int]bool {
		m := map[[2]int]bool{}
		for _, p := range pairs {
			m[p] = true
		}
		return m
	}
	for _, tc := range []struct {
		name  string
		size  int
		edges map[[2]int]bool
		want  [][2]int
	}{
		{"ring", 4, edges([2]int{0, 1}, [2]int{1, 2}, [2]int{2, 3}, [2]int{0, 3}), nil},
		{"tree", 4, edges([2]int{0, 1}, [2]int{1, 2}, [2]int{1, 3}),
			[][2]int{{0, 1}, {1, 2}, {1, 3}}},
		{"ring and pendant", 5, edges([2]int{0, 1}, [2]int{1, 2}, [2]int{2, 3}, [2]int{0, 3}, [2]int{2, 4}),
			[][2]int{{2, 4}}},
	} {
		if got := singleCuts(tc.size, tc.edges); !slices.Equal(got, tc.want) {
			t.Errorf("%s: single cuts %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestWalkFollowsHopFields checks the walk over the formed links: a forward
// segment, a reversed one, and a crossover between them reach their
// destination, and a link down at either end stops the walk.
func TestWalkFollowsHopFields(t *testing.T) {
	// Nodes 0, 1, and 2 in a line: 0's interface 1 leads to 1's interface
	// 2, and 1's interface 3 to 2's interface 4.
	f := formed{up: map[iface]int{
		{0, 1}: 1, {1, 2}: 0,
		{1, 3}: 2, {2, 4}: 1,
	}}
	hop := func(ingress, egress uint16) path.HopField {
		return path.HopField{ConsIngress: ingress, ConsEgress: egress}
	}
	decoded := func(dirs []bool, segs ...[]path.HopField) *spath.Decoded {
		p := &spath.Decoded{}
		for i, hops := range segs {
			p.InfoFields = append(p.InfoFields, path.InfoField{ConsDir: dirs[i]})
			p.HopFields = append(p.HopFields, hops...)
			p.PathMeta.SegLen[i] = uint8(len(hops))
		}
		p.NumINF, p.NumHops = len(segs), len(p.HopFields)
		return p
	}
	forward := decoded([]bool{true}, []path.HopField{hop(0, 1), hop(2, 3), hop(4, 0)})
	reversed := decoded([]bool{false}, []path.HopField{hop(4, 0), hop(2, 3), hop(0, 1)})
	// 0 climbs to 1 along a segment built from 1 to 0, crosses over at 1,
	// and descends to 2 along a segment built from 1 to 2.
	crossover := decoded([]bool{false, true},
		[]path.HopField{hop(1, 0), hop(0, 2)},
		[]path.HopField{hop(0, 3), hop(4, 0)})
	for _, tc := range []struct {
		name     string
		p        *spath.Decoded
		src, dst int
	}{
		{"forward", forward, 0, 2},
		{"reversed", reversed, 2, 0},
		{"crossover", crossover, 0, 2},
	} {
		hops, ok := f.walk(tc.src, tc.dst, tc.p)
		want := []int{tc.src, 1, tc.dst}
		if !ok || !slices.Equal(hops, want) {
			t.Errorf("%s: walk = %v %v, want %v reached", tc.name, hops, ok, want)
		}
	}
	delete(f.up, iface{2, 4})
	if _, ok := f.walk(0, 2, forward); ok {
		t.Error("the walk reached over a link down at its far end")
	}
}

// TestRouteKeyIgnoresOrigination checks that records of one route share a
// key whatever origination they carry, and records of two routes do not.
func TestRouteKeyIgnoresOrigination(t *testing.T) {
	mac := func() hash.Hash {
		h, err := scrypto.InitMac(make([]byte, 16))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	core, mid, leaf := addr.MustIAFrom(20, 1), addr.MustIAFrom(20, 2), addr.MustIAFrom(20, 3)
	record := func(ts time.Time, id uint16, ias ...addr.IA) *pathdb.Segment {
		pcb, err := segment.PCBWithID(ts, id)
		if err != nil {
			t.Fatal(err)
		}
		for i, ia := range ias {
			opts := segment.EntryOptions{}
			if i > 0 {
				opts.IngressIfID = 1
			}
			if i < len(ias)-1 {
				opts.EgressIfID = 1
			}
			if _, err := pcb.AppendRouteHop(ia, opts, mac); err != nil {
				t.Fatal(err)
			}
		}
		return &pathdb.Segment{Type: pathdb.SegmentTypeDown, PCB: pcb}
	}
	now := time.Now()
	first := record(now, 1, core, mid, leaf)
	later := record(now.Add(time.Minute), 2, core, mid, leaf)
	other := record(now, 1, core, leaf)
	if routeKey(first) != routeKey(later) {
		t.Error("two originations of one route keyed apart")
	}
	if routeKey(first) == routeKey(other) {
		t.Error("two routes keyed alike")
	}
}
