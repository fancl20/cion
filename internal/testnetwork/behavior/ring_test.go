package behavior

import (
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// The ring lab: ringSize nodes around a ring, each ringStep from its two
// neighbors one way, a pair's delay the steps between them the shorter way
// around. Every node has more peers than the cap, and no group stands apart,
// so no cluster forms and the cap binds. The lab runs as benchmarks alone:
// the suite, run twice, has no room left in its budget for twelve more
// nodes to settle.
const (
	ringSize = 12
	ringStep = 4 * time.Millisecond
)

// ringBudget bounds the ring lab's run in virtual time.
const ringBudget = time.Hour

// ringDelay returns the ring lab's one-way delay between two nodes.
func ringDelay(i, j int) time.Duration {
	steps := (j - i + ringSize) % ringSize
	return time.Duration(min(steps, ringSize-steps)) * ringStep
}

// TestBenchRingSettled benchmarks the ring once it settled, beside the
// nodes its links hold at the cap: twelve nodes joined around the ring, each
// through the one before, settle within ringBudget with no cluster formed.
func TestBenchRingSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRing(t, fab, wpki)
		s := awaitSettled(t, n.nodes, settleQuiet, ringBudget)
		if got := clusters(n); len(got) != 0 {
			t.Errorf("the ring formed clusters %v, want none", got)
		}
		report(t, "RingSettled", s, assess(t, n, penalty, 0))
		reportValues(t, "RingSettled/cap", benchValue{float64(capped(t, n)), "capped"})
	})
}

// TestBenchRingDelayLowered benchmarks the cap's answer to a pair brought
// near: the unlinked pair the formed links join at the highest delay falls
// to a tenth of that delay, and later returns. It reports how many of the
// pair's ends the cap held, when the pair links from the fall, ringBudget
// for never, each phase's link-set changes and when its last came, and the
// worst pair once the fall settled.
func TestBenchRingDelayLowered(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRing(t, fab, wpki)
		awaitSettled(t, n.nodes, settleQuiet, ringBudget)
		unlinked, cost, ok := worstUnlinked(n, readPaths(t, n, false))
		if !ok {
			t.Skip("every pair is linked")
		}
		degrees := degreesOf(t, n)
		atCap := 0
		for _, i := range unlinked {
			if degrees[i] >= measured.MaxNeighbors {
				atCap++
			}
		}
		isLinked := func() bool { return formedLinks(t, n).edges[unlinked] }
		start := time.Now()
		linked := ringBudget
		each := func() {
			if linked == ringBudget && isLinked() {
				linked = time.Since(start)
			}
		}
		old := n.oneWay[unlinked[0]][unlinked[1]]
		n.setDelay(unlinked[0], unlinked[1], cost/10)
		lowered := watchPhase(t, n, isLinked, each)
		worst := readMoved(t, n).grade(n, 0)
		n.setDelay(unlinked[0], unlinked[1], old)
		restored := watchPhase(t, n, func() bool { return true }, each)
		reportValues(t, "RingDelayLowered",
			benchValue{float64(atCap), "capped-ends"},
			benchValue{linked.Seconds(), "linked-s"},
			benchValue{float64(lowered.changes), "lowered-changes"},
			benchValue{lowered.at.Minutes(), "lowered-last-min"},
			benchValue{worst.ratio.max, "lowered-ratio-max"},
			benchValue{float64(restored.changes), "restored-changes"},
			benchValue{restored.at.Minutes(), "restored-last-min"},
		)
	})
}

// TestBenchRingBursts benchmarks the ring's answer to bursts of delay on its
// formed links while the cap binds.
func TestBenchRingBursts(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRing(t, fab, wpki)
		awaitSettled(t, n.nodes, settleQuiet, ringBudget)
		benchBursts(t, n, "RingBursts")
	})
}

// TestBenchRingJitter benchmarks the ring under network-wide jitter while
// the cap binds.
func TestBenchRingJitter(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRing(t, fab, wpki)
		awaitSettled(t, n.nodes, settleQuiet, ringBudget)
		reportJitter(t, "RingJitter", sweepJitter(t, n))
	})
}

// bootRing boots the ring lab's network: node 0 the founding core, each
// other node joining through the one before it.
func bootRing(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := newNetwork(t, fab, ringSize)
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			n.setDelay(i, j, ringDelay(i, j))
		}
	}
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	for i := 1; i < ringSize; i++ {
		parent := n.nodes[i-1]
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(parent)}
			cfg.RootCAs = wpki.Pool
		})
	}
	return n
}

// degreesOf returns each node's formed links, by node.
func degreesOf(t *testing.T, n *network) []int {
	t.Helper()
	degrees := make([]int, len(n.nodes))
	for e := range formedLinks(t, n).edges {
		degrees[e[0]]++
		degrees[e[1]]++
	}
	return degrees
}

// capped returns how many nodes hold the cap's count of formed links.
func capped(t *testing.T, n *network) int {
	t.Helper()
	count := 0
	for _, d := range degreesOf(t, n) {
		if d >= measured.MaxNeighbors {
			count++
		}
	}
	return count
}
