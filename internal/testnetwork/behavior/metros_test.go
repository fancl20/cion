package behavior

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// metrosOneWay is the metros lab's one-way delay matrix in microseconds.
// Metro A is nodes 0 to 3, metro B nodes 4 to 7, and metro C nodes 8 to
// 11. A metro is 3 to 4ms across in round trips; A and B sit 40 to 44ms
// apart, B and C 60 to 64ms, and A and C 84 to 88ms. Every node has eleven
// peers, more than the cap.
var metrosOneWay = [12][12]int{
	{0, 600, 1100, 1700, 20000, 20400, 20800, 21200, 42000, 42300, 42600, 42900},
	{600, 0, 800, 1400, 20300, 20700, 21100, 21500, 42300, 42600, 42900, 43200},
	{1100, 800, 0, 900, 20600, 21000, 21400, 21800, 42600, 42900, 43200, 43500},
	{1700, 1400, 900, 0, 20900, 21300, 21700, 22100, 42900, 43200, 43500, 43800},
	{20000, 20300, 20600, 20900, 0, 700, 1300, 1900, 30000, 30350, 30700, 31050},
	{20400, 20700, 21000, 21300, 700, 0, 900, 1500, 30250, 30600, 30950, 31300},
	{20800, 21100, 21400, 21700, 1300, 900, 0, 1000, 30500, 30850, 31200, 31550},
	{21200, 21500, 21800, 22100, 1900, 1500, 1000, 0, 30750, 31100, 31450, 31800},
	{42000, 42300, 42600, 42900, 30000, 30250, 30500, 30750, 0, 500, 1200, 1600},
	{42300, 42600, 42900, 43200, 30350, 30600, 30850, 31100, 500, 0, 1000, 1300},
	{42600, 42900, 43200, 43500, 30700, 30950, 31200, 31450, 1200, 1000, 0, 700},
	{42900, 43200, 43500, 43800, 31050, 31300, 31550, 31800, 1600, 1300, 700, 0},
}

// metrosGroups are the metros lab's metros.
var metrosGroups = [][]int{{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}}

// The metros lab's spanning tree, joined from the founder outward: each
// node of metrosOrder joins through its parent alone.
var (
	metrosParent = map[int]int{1: 0, 2: 0, 3: 0, 4: 0, 5: 4, 6: 4, 7: 4, 8: 4, 9: 8, 10: 8, 11: 8}
	metrosOrder  = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
)

// metrosBudget bounds the metros lab's run in virtual time.
const metrosBudget = time.Hour

// TestMetrosSettle checks the clusters at the daemon's own pacing: twelve
// nodes in three metros, joined outward from the founder along a spanning
// tree, each join one metro apiece, every pair then reaching over its
// chosen path within reachBudget, and the link set settles within
// metrosBudget.
func TestMetrosSettle(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootMetros(t, fab, wpki)
		awaitClusters(t, n, metrosGroups, metrosBudget)
		awaitSettled(t, n, settleQuiet, metrosBudget)
		awaitReach(t, n, reachBudget)
	})
}

// TestBenchMetrosSettled benchmarks the metros network once its clusters
// formed and it settled.
func TestBenchMetrosSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootMetros(t, fab, wpki)
		s := awaitSettled(t, n, settleQuiet, metrosBudget)
		report(t, "MetrosSettled", s, assess(t, n, penalty, 0))
	})
}

// TestBenchMetrosCut benchmarks the metros network's answer to a cut and
// its lift.
func TestBenchMetrosCut(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchCut(t, metrosSettled(t, fab, wpki), "MetrosCut")
	})
}

// TestBenchMetrosDelayRaised benchmarks the metros network's answer to a
// used link's delay tripled and restored.
func TestBenchMetrosDelayRaised(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchDelayRaised(t, metrosSettled(t, fab, wpki), "MetrosDelayRaised")
	})
}

// TestBenchMetrosDelayLowered benchmarks the clusters' answer to a pair
// across two metros brought near: the unlinked pair the formed links join at
// the highest delay falls to a tenth of that delay, and later returns. It
// reports when the pair links and when a node first leaves its metro's
// cluster, from the fall, metrosBudget for never; each phase's link-set
// changes and when its last came; the worst pair once the fall settled; and
// whether the metros hold their clusters at the end.
func TestBenchMetrosDelayLowered(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := metrosSettled(t, fab, wpki)
		unlinked, cost, ok := worstUnlinked(n, readPaths(t, n, false))
		if !ok {
			t.Skip("every pair is linked")
		}
		formed := func() bool { return slices.EqualFunc(clusters(n), metrosGroups, slices.Equal) }
		isLinked := func() bool { return formedLinks(t, n).edges[unlinked] }
		start := time.Now()
		linked, left := metrosBudget, metrosBudget
		each := func() {
			if linked == metrosBudget && isLinked() {
				linked = time.Since(start)
			}
			if left == metrosBudget && !formed() {
				left = time.Since(start)
			}
		}
		old := n.oneWay[unlinked[0]][unlinked[1]]
		n.setDelay(unlinked[0], unlinked[1], cost/10)
		lowered := watchPhase(t, n, isLinked, each)
		worst := readMoved(t, n).grade(n, 0)
		n.setDelay(unlinked[0], unlinked[1], old)
		restored := watchPhase(t, n, func() bool { return true }, each)
		held := 0.0
		if formed() {
			held = 1
		}
		reportValues(t, "MetrosDelayLowered",
			benchValue{linked.Seconds(), "linked-s"},
			benchValue{left.Seconds(), "left-s"},
			benchValue{float64(lowered.changes), "lowered-changes"},
			benchValue{lowered.at.Minutes(), "lowered-last-min"},
			benchValue{worst.ratio.max, "lowered-ratio-max"},
			benchValue{float64(restored.changes), "restored-changes"},
			benchValue{restored.at.Minutes(), "restored-last-min"},
			benchValue{held, "formed"},
		)
	})
}

// phaseWatch bounds the wait for a phase's condition in virtual time.
const phaseWatch = 45 * time.Minute

// watchPhase reads the network every settleSample, calling each at every
// read once the bubble has parked, until the condition held or phaseWatch
// passed and the link set then held for settleQuiet. It returns the
// link-set changes and when the last came, from its start.
func watchPhase(t *testing.T, n *network, cond func() bool, each func()) settling {
	t.Helper()
	ctx := t.Context()
	start := time.Now()
	last, changed := linkSet(ctx, n.nodes), start
	var s settling
	for {
		synctest.Wait()
		each()
		if now := linkSet(ctx, n.nodes); now != last {
			last, changed = now, time.Now()
			s.changes++
		}
		ready := cond() || time.Since(start) >= phaseWatch
		if ready && time.Since(changed) >= settleQuiet && n.settled(ctx, n.nodes) {
			s.at = changed.Sub(start)
			return s
		}
		time.Sleep(settleSample)
	}
}

// metrosSettled boots the metros network and waits for it to settle.
func metrosSettled(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := bootMetros(t, fab, wpki)
	awaitSettled(t, n, settleQuiet, metrosBudget)
	return n
}

// bootMetros boots the metros lab's network: twelve nodes over
// metrosOneWay's delays, joined outward from the founder along the spanning
// tree.
func bootMetros(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := newNetwork(t, fab, len(metrosOneWay))
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			n.setDelay(i, j, time.Duration(metrosOneWay[i][j])*time.Microsecond)
		}
	}
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	for _, i := range metrosOrder {
		parent := n.nodes[metrosParent[i]]
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(parent)}
			cfg.RootCAs = wpki.Pool
		})
	}
	return n
}

// clusters returns the clusters the nodes joined, as each node's own entry
// names it: the nodes naming one cluster, ascending, the clusters ordered by
// their first node.
func clusters(n *network) [][]int {
	byName := map[addr.IA][]int{}
	for i, node := range n.nodes {
		ia := node.App().IA()
		for _, s := range node.App().Bus().Directory().Latest().Scopes() {
			if e, ok := s.Entry(ia); ok && e.Cluster != 0 {
				byName[e.Cluster] = append(byName[e.Cluster], i)
				break
			}
		}
	}
	var out [][]int
	for _, members := range byName {
		out = append(out, members)
	}
	slices.SortFunc(out, func(a, b []int) int { return a[0] - b[0] })
	return out
}

// awaitClusters waits until the nodes joined exactly the clusters given.
func awaitClusters(t *testing.T, n *network, want [][]int, budget time.Duration) {
	t.Helper()
	testnetwork.PollVirtual(t, budget, "the nodes to join their clusters", func() bool {
		return slices.EqualFunc(clusters(n), want, slices.Equal)
	})
}
