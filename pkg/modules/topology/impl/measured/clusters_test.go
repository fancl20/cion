package measured

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// clNodes are the nodes of the clusters' tests, ascending.
var clNodes = func() []addr.IA {
	out := make([]addr.IA, 12)
	for i := range out {
		out[i] = addr.MustIAFrom(20, 0xfd0000000201+addr.AS(i))
	}
	return out
}()

// clPair is one pair the tests' first node reports: its round trip and the
// bounds, zero for none, and whether it holds a link to the other.
type clPair struct {
	a, b           int
	rtt, low, high time.Duration
	linked         bool
}

// clView builds the coordination's view of one scope from the pairs each
// first node reports and the cluster each node names, by index.
func clView(pairs []clPair, names map[int]int) *coordView {
	reports := make(map[addr.IA][]bus.PeerReport)
	for _, p := range pairs {
		a, b := clNodes[p.a], clNodes[p.b]
		r := bus.PeerReport{IA: b, RTT: p.rtt, Low: p.low, High: p.high}
		if p.linked {
			r.IfID = uint16(len(reports[a]) + 1)
		}
		reports[a] = append(reports[a], r)
		if _, ok := reports[b]; !ok {
			reports[b] = nil
		}
	}
	for i := range names {
		if _, ok := reports[clNodes[i]]; !ok {
			reports[clNodes[i]] = nil
		}
	}
	var entries []bus.DirectoryEntry
	for _, ia := range slices.Sorted(maps.Keys(reports)) {
		e := bus.DirectoryEntry{IA: ia, Peers: reports[ia]}
		if name, ok := names[slices.Index(clNodes, ia)]; ok {
			e.Cluster = clNodes[name]
		}
		entries = append(entries, e)
	}
	return newCoordView(bus.NewDirectory(nil, bus.NewScope(bus.DirectoryID{1}, entries...)))
}

// clTight returns a pair whose bounds lie a twentieth around its round trip.
func clTight(a, b int, rtt time.Duration) clPair {
	return clPair{a: a, b: b, rtt: rtt, low: rtt - rtt/20, high: rtt + rtt/20}
}

// clMesh returns every pair of the nodes given at the round trip the
// function gives, each bounded tightly.
func clMesh(nodes []int, rtt func(a, b int) time.Duration) []clPair {
	var out []clPair
	for i, a := range nodes {
		for _, b := range nodes[i+1:] {
			out = append(out, clTight(a, b, rtt(a, b)))
		}
	}
	return out
}

// clIAs returns the nodes the indices name.
func clIAs(idx ...int) []addr.IA {
	out := make([]addr.IA, len(idx))
	for k, i := range idx {
		out[k] = clNodes[i]
	}
	return out
}

// clMetros returns a mesh of two metros, nodes 0 to 2 and 3 to 5, each 2ms
// across, 40ms apart.
func clMetros() []clPair {
	return clMesh([]int{0, 1, 2, 3, 4, 5}, func(a, b int) time.Duration {
		if a/3 == b/3 {
			return 2 * time.Millisecond
		}
		return 40 * time.Millisecond
	})
}

// TestClusterGap checks the gap the budget sets: eight diameters.
func TestClusterGap(t *testing.T) {
	if ClusterGap != 8 {
		t.Errorf("ClusterGap = %v, want 8", ClusterGap)
	}
}

// TestNaturalClusters checks the natural clusters: two metros apart by far
// more than the gap; one at the gap on its bounds, and one a microsecond
// short of it; a missing bound inside, or to a node outside a reading
// weighs; the most separated of nested clusters; and an even spread.
func TestNaturalClusters(t *testing.T) {
	ms := time.Millisecond
	atGap := func(short time.Duration) []clPair {
		return []clPair{
			{a: 0, b: 1, rtt: 2 * ms, low: 2 * ms, high: 2 * ms},
			{a: 0, b: 2, rtt: 20 * ms, low: 16*ms - short, high: 20 * ms},
			{a: 1, b: 2, rtt: 20 * ms, low: 17 * ms, high: 20 * ms},
		}
	}
	noHigh := clMetros()
	noHigh[0].high = 0 // 0-1
	noLow := clMetros()
	for i, p := range noLow {
		if p.a == 0 && p.b == 3 {
			noLow[i].low = 0
		}
	}
	// Nodes 0 and 1 sit apart by the inner round trip inside the metro 0
	// to 2, 6ms across, and the other metro sits the outer round trip away.
	nested := func(inner, outer time.Duration) []clPair {
		return clMesh([]int{0, 1, 2, 3, 4, 5}, func(a, b int) time.Duration {
			switch {
			case a == 0 && b == 1:
				return inner
			case a/3 == b/3 && a < 3:
				return 6 * ms
			case a/3 == b/3:
				return 2 * ms
			}
			return outer
		})
	}
	even := clMesh([]int{0, 1, 2, 3}, func(a, b int) time.Duration {
		return time.Duration(10*(b-a)) * ms
	})
	for _, tc := range []struct {
		name  string
		pairs []clPair
		want  [][]addr.IA
	}{
		{"two metros", clMetros(), [][]addr.IA{clIAs(0, 1, 2), clIAs(3, 4, 5)}},
		{"at the gap", atGap(0), [][]addr.IA{clIAs(0, 1)}},
		{"short of the gap", atGap(time.Microsecond), nil},
		{"a missing upper bound inside", noHigh, [][]addr.IA{clIAs(3, 4, 5)}},
		{"a missing lower bound outside", noLow, nil},
		{"nested, the metro standing out", nested(ms/2, 100*ms), [][]addr.IA{clIAs(0, 1, 2), clIAs(3, 4, 5)}},
		{"nested, the pair standing out", nested(ms/5, 60*ms), [][]addr.IA{clIAs(0, 1), clIAs(3, 4, 5)}},
		{"an even spread", even, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, naturalClusters(clView(tc.pairs, nil))); diff != "" {
				t.Errorf("natural clusters (-want +got):\n%s", diff)
			}
		})
	}
}

// TestUnits checks the units: the nodes naming one cluster form one, every
// other node a unit of one, and the node's own name is the one given.
func TestUnits(t *testing.T) {
	v := clView(clMetros(), map[int]int{0: 0, 1: 0, 3: 3, 4: 3})
	u := newUnits(v, clNodes[2], clNodes[0])
	var got [][]addr.IA
	for _, ia := range clIAs(0, 2, 3, 5) {
		got = append(got, u.members[u.of[ia]])
	}
	want := [][]addr.IA{clIAs(0, 1, 2), clIAs(0, 1, 2), clIAs(3, 4), clIAs(5)}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("units of 0, 2, 3, and 5 (-want +got):\n%s", diff)
	}
}

// TestChosenPairs checks the pairs that link two units: between two
// clusters the lightest pair and the lightest on two other members, ties to
// the lesser pair; between a cluster and a unit of one, the unit of one
// keeping its node; between two units of one, their pair; none where no
// reading joins them.
func TestChosenPairs(t *testing.T) {
	ms := time.Millisecond
	pairs := clMesh([]int{0, 1, 2, 3, 4, 5, 6}, func(a, b int) time.Duration {
		switch {
		case a/3 == b/3:
			return 2 * ms
		case b == 6:
			return time.Duration(30+a) * ms
		}
		return time.Duration(40+a+b) * ms
	})
	// Across the clusters, 0-3 is the lightest at 43ms, and 1-4 the
	// lightest of the rest at 45ms, tying 2-3 but on two other members.
	pairs = append(pairs, clTight(7, 8, 9*ms))
	v := clView(pairs, map[int]int{0: 0, 1: 0, 2: 0, 3: 3, 4: 3, 5: 3})
	u := newUnits(v, clNodes[0], clNodes[0])
	unit := func(i int) int { return u.of[clNodes[i]] }
	for _, tc := range []struct {
		name string
		x, y int
		want []pair
	}{
		{"two clusters", 0, 3, []pair{pairOf(clNodes[0], clNodes[3]), pairOf(clNodes[1], clNodes[4])}},
		{"a cluster and a unit of one", 0, 6, []pair{pairOf(clNodes[0], clNodes[6]), pairOf(clNodes[1], clNodes[6])}},
		{"two units of one", 7, 8, []pair{pairOf(clNodes[7], clNodes[8])}},
		{"no reading", 0, 7, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := u.chosen(v, unit(tc.x), unit(tc.y))
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(pair{})); diff != "" {
				t.Errorf("chosen pairs (-want +got):\n%s", diff)
			}
		})
	}
}

// TestChosenPairsKeepTheirLinks checks the line to buy between pairs: in
// either place, a linked pair stays chosen until the lightest pair's reading
// beats it by the line to buy at its reading and at its lower bound, and
// gives way once it does; neither alone moves it, nor a missing lower bound.
func TestChosenPairsKeepTheirLinks(t *testing.T) {
	ms := time.Millisecond
	// Across the clusters, pair a-b weighs 40+a+b ms, bounded a twentieth
	// around it, 0-3 the lightest at 43ms and 1-4 the lightest on two other
	// members at 45ms; 2-5 weighs slow, its lower bound low.
	mesh := func(slow, low time.Duration, linked ...[2]int) []clPair {
		pairs := clMesh([]int{0, 1, 2, 3, 4, 5}, func(a, b int) time.Duration {
			switch {
			case a/3 == b/3:
				return 2 * ms
			case a == 2 && b == 5:
				return slow
			}
			return time.Duration(40+a+b) * ms
		})
		for i, p := range pairs {
			pairs[i].linked = slices.Contains(linked, [2]int{p.a, p.b})
			if p.a == 2 && p.b == 5 {
				pairs[i].low = low
			}
		}
		return pairs
	}
	p := func(a, b int) pair { return pairOf(clNodes[a], clNodes[b]) }
	for _, tc := range []struct {
		name  string
		pairs []clPair
		want  []pair
	}{
		{"none linked", mesh(47*ms, 45*ms), []pair{p(0, 3), p(1, 4)}},
		{"a linked pair within the line", mesh(47*ms, 45*ms, [2]int{2, 5}), []pair{p(2, 5), p(0, 3)}},
		{"a linked pair beyond it", mesh(80*ms, 76*ms, [2]int{2, 5}), []pair{p(0, 3), p(1, 4)}},
		{"beyond it at its reading alone", mesh(80*ms, 40*ms, [2]int{2, 5}), []pair{p(2, 5), p(0, 3)}},
		{"beyond it at its lower bound alone", mesh(50*ms, 60*ms, [2]int{2, 5}), []pair{p(2, 5), p(0, 3)}},
		{"a linked pair without a lower bound", mesh(80*ms, 0, [2]int{2, 5}), []pair{p(2, 5), p(0, 3)}},
		{"the second within the line", mesh(47*ms, 45*ms, [2]int{0, 3}, [2]int{2, 5}), []pair{p(0, 3), p(2, 5)}},
		{"the second beyond it", mesh(80*ms, 76*ms, [2]int{0, 3}, [2]int{2, 5}), []pair{p(0, 3), p(1, 4)}},
		{"the second beyond it at its reading alone", mesh(80*ms, 40*ms, [2]int{0, 3}, [2]int{2, 5}),
			[]pair{p(0, 3), p(2, 5)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := clView(tc.pairs, map[int]int{0: 0, 1: 0, 2: 0, 3: 3, 4: 3, 5: 3})
			u := newUnits(v, clNodes[0], clNodes[0])
			got := u.chosen(v, u.of[clNodes[0]], u.of[clNodes[3]])
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(pair{})); diff != "" {
				t.Errorf("chosen pairs (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAllowedLinks checks which links the clustering allows: inside a unit,
// between two units of one, a chosen pair, and any pair between units no
// reading joins, but no other pair across two units; a node the view does
// not hold is allowed everywhere.
func TestAllowedLinks(t *testing.T) {
	pairs := append(clMetros(), clTight(6, 7, 9*time.Millisecond), clTight(0, 6, 50*time.Millisecond))
	v := clView(pairs, map[int]int{0: 0, 1: 0, 2: 0, 3: 3, 4: 3, 5: 3})
	u := newUnits(v, clNodes[0], clNodes[0])
	for _, tc := range []struct {
		a, b int
		want bool
	}{
		{0, 2, true},   // one unit
		{6, 7, true},   // two units of one
		{0, 3, true},   // the first chosen pair: ties to the lesser pair
		{1, 4, true},   // the second
		{2, 5, false},  // another pair across the clusters
		{0, 6, true},   // a cluster and a unit of one: the first chosen pair
		{2, 7, true},   // no reading joins 7 to the cluster
		{0, 11, true},  // a node the view does not hold
		{11, 10, true}, // nor these
	} {
		if got := u.allowed(v, clNodes[tc.a], clNodes[tc.b]); got != tc.want {
			t.Errorf("allowed(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestPredict checks the prediction: through the closest members, whatever
// pair the links keep, a hop from a node to itself weighing nothing, and
// none where a reading misses.
func TestPredict(t *testing.T) {
	ms := time.Millisecond
	pairs := []clPair{
		clTight(0, 1, 2*ms), clTight(2, 3, 3*ms), clTight(0, 2, 40*ms),
		clTight(1, 3, 45*ms), clTight(0, 3, 44*ms),
	}
	v := clView(pairs, map[int]int{0: 0, 1: 0, 2: 2, 3: 2})
	u := newUnits(v, clNodes[0], clNodes[0])
	reading := func(p pair) time.Duration { return v.weight[p] }
	for _, tc := range []struct {
		a, b int
		want time.Duration
		ok   bool
	}{
		{1, 3, 2*ms + 40*ms + 3*ms, true},
		{0, 2, 40 * ms, true},
		{1, 2, 42 * ms, true},
	} {
		got, ok := u.predict(v, clNodes[tc.a], clNodes[tc.b], reading)
		if got != tc.want || ok != tc.ok {
			t.Errorf("predict(%d, %d) = %v, %v, want %v, %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
	kept := slices.Clone(pairs)
	kept[4].linked = true // 0-3, chosen over 0-2 within the line to buy
	kv := clView(kept, map[int]int{0: 0, 1: 0, 2: 2, 3: 2})
	keptReading := func(p pair) time.Duration { return kv.weight[p] }
	if got, _ := newUnits(kv, clNodes[0], clNodes[0]).predict(kv, clNodes[1], clNodes[2], keptReading); got != 42*ms {
		t.Errorf("predict(1, 2) beside the linked 0-3 = %v, want 42ms", got)
	}
	missing := clView(pairs[2:], map[int]int{0: 0, 1: 0, 2: 2, 3: 2})
	missed := func(p pair) time.Duration { return missing.weight[p] }
	if _, ok := newUnits(missing, clNodes[0], clNodes[0]).predict(missing, clNodes[1], clNodes[3], missed); ok {
		t.Error("predicted a pair a reading misses")
	}
}

// TestWithinBudget checks the budget at its edges: the line to buy on the
// readings, and the margin floor.
func TestWithinBudget(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		through, direct time.Duration
		want            bool
	}{
		{25 * ms, 20 * ms, true},
		{25*ms + time.Microsecond, 20 * ms, false},
		{5*ms - time.Microsecond, 3 * ms, true}, // short of the margin floor
		{5 * ms, 3 * ms, false},
		{2500 * time.Microsecond, time.Millisecond, true},
	} {
		if got := withinBudget(tc.through, tc.direct); got != tc.want {
			t.Errorf("withinBudget(%v, %v) = %v, want %v", tc.through, tc.direct, got, tc.want)
		}
	}
}

// TestJoinCluster checks the cluster a node names: the natural cluster
// holding it, by its least member or by the name its members use, never a
// name a node outside uses; the cluster it named, while another node names
// it and no break is confirmed; and none on a confirmed break, or when no
// other node names it.
func TestJoinCluster(t *testing.T) {
	ms := time.Millisecond
	// A pair 10ms apart and a node 20 and 21ms from it: no natural
	// cluster. Through 0, node 1 reaches 2 at 30ms against 21ms direct:
	// the readings break the budget. At the lower bounds, 28ms through 0
	// breaks it against the direct reading but not against the direct
	// upper bound, 30ms; confirmed, 29ms breaks it against 22ms.
	broken := func(confirmed bool) []clPair {
		ps := []clPair{
			{a: 0, b: 1, rtt: 10 * ms, low: 9 * ms, high: 12 * ms},
			{a: 0, b: 2, rtt: 20 * ms, low: 19 * ms, high: 22 * ms},
			{a: 1, b: 2, rtt: 21 * ms, low: 19 * ms, high: 30 * ms},
		}
		if confirmed {
			ps[0].low, ps[1].low, ps[2].high = 9500*time.Microsecond, 19500*time.Microsecond, 22*ms
		}
		return ps
	}
	// The same pair 3ms apart: 2 is reached through 0 within the budget.
	holds := []clPair{
		{a: 0, b: 1, rtt: 3 * ms, low: 2 * ms, high: 4 * ms},
		{a: 0, b: 2, rtt: 21 * ms, low: 20 * ms, high: 22 * ms},
		{a: 1, b: 2, rtt: 22 * ms, low: 21 * ms, high: 23 * ms},
	}
	// The pair just came 3ms apart, its history still slower: at the lower
	// bounds, 28.5ms through 0 breaks the budget against 22ms, but the
	// readings, 23ms against 22ms, no longer do.
	recovered := []clPair{
		{a: 0, b: 1, rtt: 3 * ms, low: 9 * ms, high: 10 * ms},
		{a: 0, b: 2, rtt: 20 * ms, low: 19500 * time.Microsecond, high: 22 * ms},
		{a: 1, b: 2, rtt: 22 * ms, low: 21 * ms, high: 22 * ms},
	}
	for _, tc := range []struct {
		name  string
		pairs []clPair
		names map[int]int
		self  int
		named int
		want  int
	}{
		{"a fresh natural cluster", clMetros(), nil, 1, -1, 0},
		{"its members' name", clMetros(), map[int]int{2: 2, 0: 2}, 1, -1, 2},
		{"a name used outside", clMetros(), map[int]int{2: 2, 4: 2, 0: 0, 3: 0}, 1, -1, 1},
		{"kept while the budget holds", holds, map[int]int{0: 0}, 1, 0, 0},
		{"alone", holds, nil, 1, 0, -1},
		{"a break the bounds do not confirm", broken(false), map[int]int{0: 0}, 1, 0, 0},
		{"a break the readings no longer show", recovered, map[int]int{0: 0}, 1, 0, 0},
		{"a confirmed break", broken(true), map[int]int{0: 0}, 1, 0, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ia := func(i int) addr.IA {
				if i < 0 {
					return 0
				}
				return clNodes[i]
			}
			got := joinCluster(clView(tc.pairs, tc.names), clNodes[tc.self], ia(tc.named))
			if got != ia(tc.want) {
				t.Errorf("joinCluster = %v, want %v", got, ia(tc.want))
			}
		})
	}
}
