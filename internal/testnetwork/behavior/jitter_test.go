package behavior

import (
	"cmp"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// linkJitterSweep steps the link's jitter, its mean a multiple of the
// link's own one-way delay, from none to twice that delay: a link whose
// round trips vary ever more around a steady base.
var linkJitterSweep = impairment{
	name:   "jitter",
	levels: []float64{0, 0.1, 0.2, 0.5, 1, 2},
	draw: func(n *network, link [2]int, x float64) func() {
		mean := time.Duration(x * float64(n.oneWay[link[0]][link[1]]))
		return n.jitterPair(link[0], link[1], mean)
	},
}

// jitterLevels are the jitter means a network-wide sweep draws on every
// pair on its way up, the way back down retracing them: the queueing a
// path adds, from none to a congested access link's.
var jitterLevels = []time.Duration{
	0,
	time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	20 * time.Millisecond,
}

// spread is how the network held one jitter level drawn on every pair.
type spread struct {
	// mean is the level's jitter mean, and down reports the way back down.
	mean time.Duration
	down bool
	// changes counts the level's link-set changes, and settled reports that
	// the link set held for levelQuiet before levelBudget ran out.
	changes int
	settled bool
	// grading grades the paths when the level ended.
	grading grading
}

// sweepJitter draws each of jitterLevels on every pair of the network, up
// and back down, holding each level until the link set holds for
// levelQuiet or levelBudget runs out, and reports how the network held
// every level.
func sweepJitter(t *testing.T, n *network) []spread {
	t.Helper()
	var lifts []func()
	set := func(mean time.Duration) {
		for _, lift := range lifts {
			lift()
		}
		lifts = nil
		if mean == 0 {
			return
		}
		for i := range n.nodes {
			for j := i + 1; j < len(n.nodes); j++ {
				lifts = append(lifts, n.jitterPair(i, j, mean))
			}
		}
	}
	steps := slices.Clone(jitterLevels)
	for i := len(jitterLevels) - 2; i >= 0; i-- {
		steps = append(steps, jitterLevels[i])
	}
	var spreads []spread
	for i, mean := range steps {
		set(mean)
		sp := spread{mean: mean, down: i >= len(jitterLevels)}
		start := time.Now()
		links := linkSet(t.Context(), n.nodes)
		quiet := start
		for time.Since(start) < levelBudget {
			time.Sleep(time.Second)
			synctest.Wait()
			if now := linkSet(t.Context(), n.nodes); now != links {
				links, quiet = now, time.Now()
				sp.changes++
			}
			if time.Since(quiet) >= levelQuiet {
				sp.settled = true
				break
			}
		}
		sp.grading = readPaths(t, n, false).grade(n, penalty)
		spreads = append(spreads, sp)
	}
	set(0)
	return spreads
}

// reportJitter logs every level of a network-wide jitter sweep and prints
// it as a benchmark result line, beside a summary line: the link-set
// changes over the sweep and the levels that never settled.
func reportJitter(t *testing.T, name string, spreads []spread) {
	t.Helper()
	changes, unsettled := 0, 0
	for _, sp := range spreads {
		dir := "up"
		if sp.down {
			dir = "down"
		}
		settled := 0
		if sp.settled {
			settled = 1
		} else {
			unsettled++
		}
		changes += sp.changes
		t.Logf("%s %s at jitter %v: %d link-set changes, settled %v; %v",
			name, dir, sp.mean, sp.changes, sp.settled, sp.grading)
		fmt.Printf("Benchmark%s/dir=%s/jitter=%v 1 %d changes %d settled %d reached %d pairs "+
			"%g ratio-mean %g ratio-max\n",
			name, dir, sp.mean, sp.changes, settled, sp.grading.reached, sp.grading.pairs,
			sp.grading.ratio.mean, sp.grading.ratio.max)
	}
	fmt.Printf("Benchmark%s/summary 1 %d changes %d unsettled\n", name, changes, unsettled)
}

const (
	// burstSpan is how long a burst scenario draws bursts.
	burstSpan = 30 * time.Minute
	// burstEvery is the mean time between two bursts' starts, and
	// burstLength a burst's mean length, each drawn from an exponential
	// distribution; burstFactor multiplies a bursting link's one-way delay.
	burstEvery  = 2 * time.Minute
	burstLength = 30 * time.Second
	burstFactor = 3
	// burstSeed seeds the burst schedule's draw, so every run draws the
	// same starts and lengths.
	burstSeed = 1
)

// burst is one burst of a schedule: its start and length from the
// scenario's start, and where among the formed links it falls, a fraction
// of their count.
type burst struct {
	start, length time.Duration
	at            float64
}

// burstSchedule draws the bursts that start within burstSpan from
// burstSeed.
func burstSchedule() []burst {
	draw := rand.New(rand.NewPCG(burstSeed, burstSeed))
	exp := func(mean time.Duration) time.Duration {
		return time.Duration(draw.ExpFloat64() * float64(mean))
	}
	var out []burst
	for start := exp(burstEvery); start < burstSpan; start += exp(burstEvery) {
		out = append(out, burst{start: start, length: exp(burstLength), at: draw.Float64()})
	}
	return out
}

// compareLinks orders two pairs of nodes by their first node, then their
// second.
func compareLinks(a, b [2]int) int {
	return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
}

// benchBursts draws burstSchedule on the formed links — each burst
// multiplying a formed link's one-way delay by burstFactor for its length
// — reading the link set and the reach every settle sample, then measures
// how the network settles once the bursts stop. A burst due on a link
// already bursting is skipped.
func benchBursts(t *testing.T, n *network, name string) {
	t.Helper()
	before := readPaths(t, n, false)
	target := before.grade(n, penalty).reached
	schedule := burstSchedule()
	// active holds the bursting links, each with its delay before the
	// burst and when the burst ends.
	type bursting struct {
		oneWay time.Duration
		until  time.Time
	}
	active := map[[2]int]bursting{}
	start := time.Now()
	links := before.set
	bursts, changes, reads, dips, worst := 0, 0, 0, 0, target
	for time.Since(start) < burstSpan {
		time.Sleep(settleSample)
		synctest.Wait()
		now := time.Now()
		for _, link := range slices.SortedFunc(maps.Keys(active), compareLinks) {
			if b := active[link]; !now.Before(b.until) {
				n.setDelay(link[0], link[1], b.oneWay)
				delete(active, link)
				t.Logf("%s: the burst on %v ended", name, link)
			}
		}
		for len(schedule) > 0 && !now.Before(start.Add(schedule[0].start)) {
			b := schedule[0]
			schedule = schedule[1:]
			formed := slices.SortedFunc(maps.Keys(formedLinks(t, n).edges), compareLinks)
			if len(formed) == 0 {
				continue
			}
			link := formed[int(b.at*float64(len(formed)))]
			if _, busy := active[link]; busy {
				continue
			}
			old := n.oneWay[link[0]][link[1]]
			n.setDelay(link[0], link[1], burstFactor*old)
			active[link] = bursting{oneWay: old, until: now.Add(b.length)}
			bursts++
			t.Logf("%s: a burst on %v, %v to %v for %v", name, link, old, burstFactor*old, b.length)
		}
		read := readPaths(t, n, false)
		reads++
		if read.set != links {
			links = read.set
			changes++
		}
		if reached := read.grade(n, penalty).reached; reached < target {
			dips++
			worst = min(worst, reached)
		}
	}
	for _, link := range slices.SortedFunc(maps.Keys(active), compareLinks) {
		n.setDelay(link[0], link[1], active[link].oneWay)
	}
	t.Logf("%s: %d bursts over %v; %d link-set changes; %d of %d reads below the %d pairs reached before, "+
		"the worst %d", name, bursts, burstSpan, changes, dips, reads, target, worst)
	fmt.Printf("Benchmark%s/phase=bursts 1 %d bursts %d changes %d dips %d reads %d worst-reached %d target\n",
		name, bursts, changes, dips, reads, worst, target)
	before = readPaths(t, n, false)
	reportResponse(t, name+"/phase=after", respond(t, n, before, target, nil))
}

// TestBenchRegionsJitter benchmarks the regions network's answer to a
// jitter on every pair swept up and back down.
func TestBenchRegionsJitter(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		reportJitter(t, "RegionsJitter", sweepJitter(t, regionsSettled(t, fab, wpki)))
	})
}

// TestBenchStrandedJitter benchmarks the stranded network's answer to a
// jitter on every pair swept up and back down.
func TestBenchStrandedJitter(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		reportJitter(t, "StrandedJitter", sweepJitter(t, strandedSettled(t, fab, wpki)))
	})
}

// TestBenchRegionsLinkJitter benchmarks the regions network's answer to a
// used link's jitter swept up and back down.
func TestBenchRegionsLinkJitter(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchSweep(t, regionsSettled(t, fab, wpki), "RegionsLinkJitter", linkJitterSweep)
	})
}

// TestBenchStrandedLinkJitter benchmarks the stranded network's answer to
// a used link's jitter swept up and back down.
func TestBenchStrandedLinkJitter(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchSweep(t, strandedSettled(t, fab, wpki), "StrandedLinkJitter", linkJitterSweep)
	})
}

// TestBenchRegionsBursts benchmarks the regions network's answer to bursts
// of delay on its formed links.
func TestBenchRegionsBursts(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchBursts(t, regionsSettled(t, fab, wpki), "RegionsBursts")
	})
}

// TestBenchStrandedBursts benchmarks the stranded network's answer to
// bursts of delay on its formed links.
func TestBenchStrandedBursts(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchBursts(t, strandedSettled(t, fab, wpki), "StrandedBursts")
	})
}
