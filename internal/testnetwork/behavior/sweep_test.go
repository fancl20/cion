package behavior

import (
	"fmt"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// impairment is what a sweep steps a link through: its name in the
// benchmark lines, its levels on the way up — the way back down retraces
// them — and the tap one level other than zero draws on the link.
type impairment struct {
	name   string
	levels []float64
	draw   func(n *network, link [2]int, value float64) func()
}

// lossSweep steps the link's loss rate from none to total.
var lossSweep = impairment{
	name:   "loss",
	levels: []float64{0, 0.01, 0.02, 0.05, 0.10, 0.20, 0.50, 1},
	draw: func(n *network, link [2]int, loss float64) func() {
		return n.fab.Loss(n.hosts[link[0]], n.hosts[link[1]], loss)
	},
}

const (
	// levelQuiet is how long the link's standing and the link set must hold
	// for a sweep's level to count as settled.
	levelQuiet = 5 * time.Minute
	// levelBudget bounds one level of a sweep in virtual time.
	levelBudget = 15 * time.Minute
)

// level is how the network held one level of a sweep.
type level struct {
	// value is the level, and down reports the way back down.
	value float64
	down  bool
	// stands reports that the link was formed and up at both ends when the
	// level ended.
	stands bool
	// flaps counts the link's turns between standing and not during the
	// level, and changes the link-set changes.
	flaps, changes int
	// settled reports that the link's standing and the link set held for
	// levelQuiet before levelBudget ran out.
	settled bool
	// crossing counts the reached pairs whose chosen path crossed the link
	// when the level ended, each inheriting the level's impairment.
	crossing int
	// grading grades the paths when the level ended.
	grading grading
}

// linkStands reports whether the pair's link is formed and up at both ends.
func linkStands(t *testing.T, n *network, link [2]int) bool {
	ctx, a, b := t.Context(), n.nodes[link[0]], n.nodes[link[1]]
	return upTo(ctx, a, b) && upTo(ctx, b, a)
}

// crosses reports whether a walked path crosses the link.
func crosses(hops []int, link [2]int) bool {
	for k := 0; k+1 < len(hops); k++ {
		if pair(hops[k], hops[k+1]) == link {
			return true
		}
	}
	return false
}

// sweep steps the link through the impairment's levels and back down,
// holding each level until the link's standing and the link set hold for
// levelQuiet or levelBudget runs out, and reports how the network held
// every level.
func sweep(t *testing.T, n *network, link [2]int, imp impairment) []level {
	t.Helper()
	var lift func()
	set := func(value float64) {
		if lift != nil {
			lift()
			lift = nil
		}
		if value > 0 {
			lift = imp.draw(n, link, value)
		}
	}
	steps := slices.Clone(imp.levels)
	for i := len(imp.levels) - 2; i >= 0; i-- {
		steps = append(steps, imp.levels[i])
	}
	var levels []level
	for i, value := range steps {
		set(value)
		lv := level{value: value, down: i >= len(imp.levels)}
		start := time.Now()
		stands, set := linkStands(t, n, link), linkSet(t.Context(), n.nodes)
		quiet := start
		for time.Since(start) < levelBudget {
			time.Sleep(time.Second)
			synctest.Wait()
			if now := linkStands(t, n, link); now != stands {
				stands, quiet = now, time.Now()
				lv.flaps++
			}
			if now := linkSet(t.Context(), n.nodes); now != set {
				set, quiet = now, time.Now()
				lv.changes++
			}
			if time.Since(quiet) >= levelQuiet {
				lv.settled = true
				break
			}
		}
		lv.stands = stands
		read := readPaths(t, n, false)
		lv.grading = read.grade(n, penalty)
		for _, hops := range read.chosen {
			if crosses(hops, link) {
				lv.crossing++
			}
		}
		levels = append(levels, lv)
	}
	set(0)
	return levels
}

// reportSweep logs every level of the impairment's sweep and prints it as a
// benchmark result line, beside a summary line: the level at which the
// network dropped the link on the way up, the level at which it took the
// link back on the way down, and the levels that never settled.
func reportSweep(t *testing.T, name string, imp impairment, link [2]int, levels []level) {
	t.Helper()
	flag := func(ok bool) int {
		if ok {
			return 1
		}
		return 0
	}
	var dropped, takenBack bool
	var dropAt, takeBackAt float64
	unsettled := 0
	for _, lv := range levels {
		dir := "up"
		if lv.down {
			dir = "down"
		}
		t.Logf("%s %v %s at %s %v: stands %v after %d flaps and %d link-set changes, settled %v; "+
			"%d chosen paths cross it; %v",
			name, link, dir, imp.name, lv.value, lv.stands, lv.flaps, lv.changes, lv.settled, lv.crossing,
			lv.grading)
		fmt.Printf("Benchmark%s/dir=%s/%s=%s 1 %d stands %d flaps %d changes %d settled %d crossing "+
			"%d reached %d pairs %g ratio-mean %g ratio-max\n",
			name, dir, imp.name, strconv.FormatFloat(lv.value, 'f', -1, 64), flag(lv.stands), lv.flaps,
			lv.changes, flag(lv.settled), lv.crossing, lv.grading.reached, lv.grading.pairs,
			lv.grading.ratio.mean, lv.grading.ratio.max)
		if !lv.settled {
			unsettled++
		}
		switch {
		case !lv.down && !lv.stands && !dropped:
			dropped, dropAt = true, lv.value
		case lv.down && dropped && lv.stands && !takenBack:
			takenBack, takeBackAt = true, lv.value
		}
	}
	fmt.Printf("Benchmark%s/summary 1 %d dropped %g drop-%s %d taken-back %g take-back-%s %d unsettled\n",
		name, flag(dropped), dropAt, imp.name, flag(takenBack), takeBackAt, imp.name, unsettled)
}

// benchSweep sweeps the impairment on the formed link the most chosen
// paths cross that no single cut needs.
func benchSweep(t *testing.T, n *network, name string, imp impairment) {
	t.Helper()
	link, ok := mostCrossed(n, readPaths(t, n, false))
	if !ok {
		t.Skip("every formed link is a single cut")
	}
	reportSweep(t, name, imp, link, sweep(t, n, link, imp))
}

// TestBenchRegionsLoss benchmarks the regions network's answer to a used
// link's loss swept up and back down.
func TestBenchRegionsLoss(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchSweep(t, regionsSettled(t, fab, wpki), "RegionsLoss", lossSweep)
	})
}

// TestBenchStrandedLoss benchmarks the stranded network's answer to a used
// link's loss swept up and back down.
func TestBenchStrandedLoss(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchSweep(t, strandedSettled(t, fab, wpki), "StrandedLoss", lossSweep)
	})
}
