package behavior

import (
	"cmp"
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
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// penalty is the cost a path pays for each node it crosses between its
// ends, unless a benchmark sets its own.
const penalty = 5 * time.Millisecond

// unreachable is the cost between nodes no sequence of edges joins.
const unreachable = time.Duration(math.MaxInt64 / 4)

// assessment grades a network's chosen paths at one penalty against the
// shortest paths every pair's delay allows.
type assessment struct {
	// penalty is the cost each transit node adds to a path.
	penalty time.Duration
	// pairs counts the ordered pairs; reached, those whose chosen path
	// crosses only links up at both ends to its destination.
	pairs, reached int
	// ratio and excess grade each reached pair's chosen path against the
	// global reference: its cost over the reference's, and the
	// milliseconds above it.
	ratio, excess summary
	// topology is the formed links' shortest over the reference, for every
	// pair the formed links join; choice is the chosen path over the formed
	// links' shortest, for every reached pair.
	topology, choice summary
	// upChosen and downChosen count the stored up and down segment records
	// some pair's chosen path joins, of upStored and downStored.
	upChosen, upStored, downChosen, downStored int
	// cuts are the formed links whose removal would leave some node
	// unreachable over the rest.
	cuts [][2]int
}

func (a assessment) String() string {
	return fmt.Sprintf("reached %d of %d pairs; cost over the reference %v; excess ms %v; "+
		"topology %v; choice %v; up segments chosen %d of %d, down %d of %d; single cuts %v",
		a.reached, a.pairs, a.ratio, a.excess, a.topology, a.choice,
		a.upChosen, a.upStored, a.downChosen, a.downStored, a.cuts)
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

// assess grades the network's chosen paths at each penalty: every ordered
// pair's choice, walked over the links up at both ends and costed against
// the penalized shortest paths over every pair's delay and over the formed
// links, beside the segment records the choices join and the formed links
// a single cut would need. The founding core is the network's first node.
func assess(t *testing.T, n *network, penalties ...time.Duration) []assessment {
	t.Helper()
	f := formedLinks(t, n.nodes)
	size := len(n.nodes)
	type walked struct {
		src, dst int
		hops     []int
		reached  bool
	}
	var walks []walked
	chosen := map[string]bool{}
	for s := range size {
		for d := range size {
			if s == d {
				continue
			}
			w := walked{src: s, dst: d}
			c, err := n.nodes[s].App().Provider().Choose(t.Context(), n.nodes[d].App().IA())
			if err == nil {
				for _, seg := range c.Segments {
					chosen[routeKey(seg)] = true
				}
				w.hops, w.reached = f.walk(s, d, c.Path)
			}
			walks = append(walks, w)
		}
	}
	upChosen, upStored := countChosen(t, n.nodes[1:], pathdb.SegmentTypeUp, chosen)
	downChosen, downStored := countChosen(t, n.nodes[:1], pathdb.SegmentTypeDown, chosen)
	cuts := singleCuts(size, f.edges)
	formedDelay := func(i, j int) (time.Duration, bool) {
		if !f.edges[[2]int{min(i, j), max(i, j)}] {
			return 0, false
		}
		return n.delay(i, j)
	}

	var out []assessment
	for _, p := range penalties {
		reference := penalizedShortest(size, n.delay, p)
		shortest := penalizedShortest(size, formedDelay, p)
		a := assessment{
			penalty: p, pairs: len(walks),
			upChosen: upChosen, upStored: upStored, downChosen: downChosen, downStored: downStored,
			cuts: cuts,
		}
		var ratio, excess, topology, choice []float64
		for _, w := range walks {
			ref, best := reference[w.src][w.dst], shortest[w.src][w.dst]
			if ref == unreachable {
				continue
			}
			if best != unreachable {
				topology = append(topology, float64(best)/float64(ref))
			}
			if !w.reached {
				continue
			}
			a.reached++
			cost := pathCost(w.hops, n.delay, p)
			ratio = append(ratio, float64(cost)/float64(ref))
			excess = append(excess, float64(cost-ref)/float64(time.Millisecond))
			choice = append(choice, float64(cost)/float64(best))
		}
		a.ratio, a.excess = summarize(ratio), summarize(excess)
		a.topology, a.choice = summarize(topology), summarize(choice)
		out = append(out, a)
	}
	return out
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

// formedLinks reads the nodes' formed links.
func formedLinks(t *testing.T, nodes []*testnetwork.Node) formed {
	t.Helper()
	index := make(map[addr.IA]int, len(nodes))
	for i, node := range nodes {
		index[node.App().IA()] = i
	}
	f := formed{up: map[iface]int{}, edges: map[[2]int]bool{}}
	directed := map[[2]int]bool{}
	for i, node := range nodes {
		entries, err := node.App().Links().All(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range entries {
			j, ok := index[l.NeighborIA]
			if !ok || l.State != links.StateEstablished || !node.App().Monitor().Up(l.IfID) {
				continue
			}
			f.up[iface{i, l.IfID}] = j
			directed[[2]int{i, j}] = true
		}
	}
	for pair := range directed {
		if directed[[2]int{pair[1], pair[0]}] {
			f.edges[[2]int{min(pair[0], pair[1]), max(pair[0], pair[1])}] = true
		}
	}
	return f
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
