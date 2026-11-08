package behavior

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

const (
	// changeQuiet is how long a link set must hold unchanged after a change
	// to count as settled again.
	changeQuiet = 5 * time.Minute
	// changeBudget bounds a network's answer to one change in virtual time.
	changeBudget = 30 * time.Minute
)

// response is how a network answered one change.
type response struct {
	// detect is how long the network took to answer the change: for a cut,
	// until either end's verdict on the link went down; otherwise until the
	// link set first changed. A chosen path's change is no answer: a choice
	// ranked by freshness moves among equal routes unprompted.
	detect   time.Duration
	detected bool
	// interim grades the paths right after the change: the chosen ones,
	// and the cheapest candidates the segments present then offer.
	interim grading
	// recover is how long until as many pairs reached as before the
	// scenario's first change and stayed so: the start of the final run of
	// reads at that reach, for a read's reach can lift before it holds. A
	// stale segment can hold a pair unreached before any change.
	recover   time.Duration
	recovered bool
	// surface is how long until every pair's cheapest candidate cost the
	// formed links' shortest.
	surface  time.Duration
	surfaced bool
	// settle is how long until the last link-set change before the link set
	// held for changeQuiet, and changes counts the link-set changes on the
	// way.
	settle  time.Duration
	settled bool
	changes int
	// final grades the paths once settled, or once the budget ran out.
	final grading
}

// respond measures the network's answer to a change just applied. before
// is the read from just before the change, target the pairs reached before
// the first change of the scenario, and verdict, set for a cut alone,
// reports whether liveness has caught the cut.
func respond(t *testing.T, n *network, before paths, target int, verdict func() bool) response {
	t.Helper()
	start := time.Now()
	// Liveness is watched every second from the change on, beside the
	// reads: a verdict on a link reads up again once the link retires.
	caught := make(chan time.Duration, 1)
	stop := make(chan struct{})
	defer close(stop)
	if verdict != nil {
		go func() {
			for {
				if verdict() {
					caught <- time.Since(start)
					return
				}
				select {
				case <-stop:
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}
	r := response{interim: readPaths(t, n, true).grade(n, penalty)}
	last, changed := before.set, start
	for {
		synctest.Wait()
		read := readPaths(t, n, true)
		g := read.grade(n, penalty)
		since := time.Since(start)
		if read.set != last {
			last, changed = read.set, time.Now()
			r.changes++
		}
		select {
		case d := <-caught:
			r.detect, r.detected = d, true
		default:
		}
		if !r.detected && verdict == nil && read.set != before.set {
			r.detect, r.detected = since, true
		}
		switch {
		case g.reached < target:
			r.recovered = false
		case !r.recovered:
			r.recover, r.recovered = since, true
		}
		if !r.surfaced && g.surfaced {
			r.surface, r.surfaced = since, true
		}
		if time.Since(changed) >= changeQuiet && n.settled(t.Context(), n.nodes) {
			r.settle, r.settled = changed.Sub(start), true
			r.final = g
			return r
		}
		if since >= changeBudget {
			r.final = g
			return r
		}
		time.Sleep(settleSample)
	}
}

// mostCrossed returns the formed link the most reached pairs' chosen paths
// cross that no single cut needs, ties to the lowest pair; false when every
// formed link is a single cut.
func mostCrossed(n *network, r paths) ([2]int, bool) {
	crossed := map[[2]int]int{}
	for _, hops := range r.chosen {
		for k := 0; k+1 < len(hops); k++ {
			crossed[pair(hops[k], hops[k+1])]++
		}
	}
	cuts := singleCuts(len(n.nodes), r.formed.edges)
	var best [2]int
	found := false
	for e := range r.formed.edges {
		if slices.Contains(cuts, e) {
			continue
		}
		if !found || crossed[e] > crossed[best] ||
			(crossed[e] == crossed[best] && (e[0] < best[0] || (e[0] == best[0] && e[1] < best[1]))) {
			best, found = e, true
		}
	}
	return best, found
}

// worstUnlinked returns the pair the formed links join at the highest
// delay, among the pairs neither formed nor cut, and that delay.
func worstUnlinked(n *network, r paths) ([2]int, time.Duration, bool) {
	shortest := penalizedShortest(len(n.nodes), r.formed.delay(n), 0)
	var worst [2]int
	var cost time.Duration
	found := false
	for i := range n.nodes {
		for j := i + 1; j < len(n.nodes); j++ {
			e := [2]int{i, j}
			if r.formed.edges[e] || n.cut[e] || shortest[i][j] == unreachable {
				continue
			}
			if !found || shortest[i][j] > cost {
				worst, cost, found = e, shortest[i][j], true
			}
		}
	}
	return worst, cost, found
}

// reportResponse logs the response and prints it as a benchmark result
// line, with any extra value-unit pairs the scenario adds.
func reportResponse(t *testing.T, name string, r response, extra ...string) {
	t.Helper()
	t.Logf("%s: detected %v after %v; interim %v, best candidates reach %d at %v; "+
		"recovered %v after %v; surfaced %v after %v; settled %v after %v and %d link-set changes; final %v %s",
		name, r.detected, r.detect, r.interim, r.interim.bestReached, r.interim.best,
		r.recovered, r.recover, r.surfaced, r.surface, r.settled, r.settle, r.changes, r.final,
		strings.Join(extra, " "))
	when := func(d time.Duration, ok bool) string {
		if !ok {
			d = changeBudget
		}
		return fmt.Sprintf("%g", d.Seconds())
	}
	flag := func(ok bool) string {
		if ok {
			return "1"
		}
		return "0"
	}
	fields := []string{
		when(r.detect, r.detected), "detect-s",
		flag(r.detected), "detected",
		fmt.Sprintf("%d", r.interim.reached), "interim-reached",
		fmt.Sprintf("%g", r.interim.ratio.mean), "interim-ratio-mean",
		fmt.Sprintf("%g", r.interim.ratio.max), "interim-ratio-max",
		fmt.Sprintf("%d", r.interim.bestReached), "interim-best-reached",
		fmt.Sprintf("%g", r.interim.best.mean), "interim-best-ratio-mean",
		fmt.Sprintf("%g", r.interim.best.max), "interim-best-ratio-max",
		when(r.recover, r.recovered), "recover-s",
		flag(r.recovered), "recovered",
		when(r.surface, r.surfaced), "surface-s",
		flag(r.surfaced), "surfaced",
		when(r.settle, r.settled), "settle-s",
		flag(r.settled), "settled",
		fmt.Sprintf("%d", r.changes), "changes",
		fmt.Sprintf("%d", r.final.reached), "final-reached",
		fmt.Sprintf("%d", r.final.pairs), "pairs",
		fmt.Sprintf("%g", r.final.ratio.mean), "final-ratio-mean",
		fmt.Sprintf("%g", r.final.ratio.max), "final-ratio-max",
	}
	fields = append(fields, extra...)
	fmt.Printf("Benchmark%s 1 %s\n", name, strings.Join(fields, " "))
}

// benchCut cuts the formed link the most chosen paths cross, measures the
// network's answer, lifts the cut, and measures the answer again.
func benchCut(t *testing.T, n *network, name string) {
	t.Helper()
	before := readPaths(t, n, false)
	target := before.grade(n, penalty).reached
	link, ok := mostCrossed(n, before)
	if !ok {
		t.Skip("every formed link is a single cut")
	}
	var ends []iface
	for end, to := range before.formed.up {
		if pair(end.node, to) == link {
			ends = append(ends, end)
		}
	}
	verdict := func() bool {
		for _, end := range ends {
			if !n.nodes[end.node].App().Monitor().Up(end.ifID) {
				return true
			}
		}
		return false
	}
	lift := n.cutPair(link[0], link[1])
	reportResponse(t, name+"/phase=cut", respond(t, n, before, target, verdict))
	before = readPaths(t, n, false)
	lift()
	reportResponse(t, name+"/phase=restore", respond(t, n, before, target, nil))
}

// benchDelayRaised triples the delay of the formed link the most chosen
// paths cross, measures the network's answer, restores the delay, and
// measures the answer again.
func benchDelayRaised(t *testing.T, n *network, name string) {
	t.Helper()
	before := readPaths(t, n, false)
	target := before.grade(n, penalty).reached
	link, ok := mostCrossed(n, before)
	if !ok {
		t.Skip("every formed link is a single cut")
	}
	old := n.oneWay[link[0]][link[1]]
	n.setDelay(link[0], link[1], 3*old)
	reportResponse(t, name+"/phase=raise", respond(t, n, before, target, nil))
	before = readPaths(t, n, false)
	n.setDelay(link[0], link[1], old)
	reportResponse(t, name+"/phase=restore", respond(t, n, before, target, nil))
}

// benchDelayLowered lowers the delay of the unlinked pair the formed links
// join at the highest delay to a tenth of that delay, measures the
// network's answer and whether it links the pair, restores the delay, and
// measures the answer again.
func benchDelayLowered(t *testing.T, n *network, name string) {
	t.Helper()
	before := readPaths(t, n, false)
	target := before.grade(n, penalty).reached
	unlinked, cost, ok := worstUnlinked(n, before)
	if !ok {
		t.Skip("every pair is linked")
	}
	linked := func() string {
		if formedLinks(t, n).edges[unlinked] {
			return "1"
		}
		return "0"
	}
	old := n.oneWay[unlinked[0]][unlinked[1]]
	n.setDelay(unlinked[0], unlinked[1], cost/10)
	r := respond(t, n, before, target, nil)
	reportResponse(t, name+"/phase=lower", r, linked(), "linked")
	before = readPaths(t, n, false)
	n.setDelay(unlinked[0], unlinked[1], old)
	r = respond(t, n, before, target, nil)
	reportResponse(t, name+"/phase=restore", r, linked(), "linked")
}

// regionsSettled boots the regions network and waits for it to settle.
func regionsSettled(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := bootRegions(t, fab, wpki)
	awaitSettled(t, n, settleQuiet, regionsBudget)
	return n
}

// strandedSettled heals the stranded network and waits for it to settle.
func strandedSettled(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := healStranded(t, fab, wpki)
	awaitSettled(t, n, settleQuiet, strandedBudget)
	return n
}

// TestBenchRegionsCut benchmarks the regions network's answer to a cut and
// its lift.
func TestBenchRegionsCut(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchCut(t, regionsSettled(t, fab, wpki), "RegionsCut")
	})
}

// TestBenchRegionsDelayRaised benchmarks the regions network's answer to a
// used link's delay tripled and restored.
func TestBenchRegionsDelayRaised(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchDelayRaised(t, regionsSettled(t, fab, wpki), "RegionsDelayRaised")
	})
}

// TestBenchRegionsDelayLowered benchmarks the regions network's answer to
// an unlinked pair's delay lowered and restored.
func TestBenchRegionsDelayLowered(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchDelayLowered(t, regionsSettled(t, fab, wpki), "RegionsDelayLowered")
	})
}

// TestBenchStrandedCut benchmarks the stranded network's answer to a cut
// and its lift.
func TestBenchStrandedCut(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchCut(t, strandedSettled(t, fab, wpki), "StrandedCut")
	})
}

// TestBenchStrandedDelayRaised benchmarks the stranded network's answer to
// a used link's delay tripled and restored.
func TestBenchStrandedDelayRaised(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchDelayRaised(t, strandedSettled(t, fab, wpki), "StrandedDelayRaised")
	})
}

// TestBenchStrandedDelayLowered benchmarks the stranded network's answer
// to an unlinked pair's delay lowered and restored.
func TestBenchStrandedDelayLowered(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		benchDelayLowered(t, strandedSettled(t, fab, wpki), "StrandedDelayLowered")
	})
}
