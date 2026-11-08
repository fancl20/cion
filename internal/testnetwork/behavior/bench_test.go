package behavior

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// requireBench skips a benchmark unless CION_BENCH asks for the
// benchmarks: they grade how well a network serves, not whether it works,
// and cost minutes of wall time each.
func requireBench(t *testing.T) {
	t.Helper()
	if os.Getenv("CION_BENCH") == "" {
		t.Skip("a benchmark: set CION_BENCH to run it")
	}
}

// report logs each assessment and prints it as a benchmark result line,
// one per penalty, on the test's standard output, where benchstat reads it.
func report(t *testing.T, name string, s settling, as []assessment) {
	t.Helper()
	for _, a := range as {
		t.Logf("%s at penalty %v, settled after %d link-set changes in %v: %v",
			name, a.penalty, s.changes, s.at, a)
		fmt.Printf("Benchmark%s/penalty=%v 1 %s\n", name, a.penalty, metrics(a, s))
	}
}

// benchValue is one value-unit pair of a benchmark result line.
type benchValue struct {
	value float64
	unit  string
}

// fields renders value-unit pairs as a benchmark result's fields.
func fields(values []benchValue) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf("%g %s", v.value, v.unit))
	}
	return strings.Join(out, " ")
}

// reportValues logs a scenario's values and prints them as a benchmark
// result line on the test's standard output, where benchstat reads it.
func reportValues(t *testing.T, name string, values ...benchValue) {
	t.Helper()
	line := fields(values)
	t.Logf("%s: %s", name, line)
	fmt.Printf("Benchmark%s 1 %s\n", name, line)
}

// probeSpan is how long reportProbes tallies the probes: three reading
// spans.
const probeSpan = 3 * scion.ReadingSpan

// reportProbes tallies the datagrams the nodes send to each other's
// rendezvous sockets — the candidates' probes — over probeSpan, and reports
// them per node and minute, between two nodes of one group and across two
// groups.
func reportProbes(t *testing.T, n *network, name string, groups [][]int) {
	t.Helper()
	counts := n.fab.Tally(measured.RendezvousPort)
	time.Sleep(probeSpan)
	group := make(map[netip.Addr]int)
	for g, members := range groups {
		for _, i := range members {
			group[n.hosts[i]], group[n.wire[i]] = g, g
		}
	}
	var inside, across int
	for pair, c := range counts() {
		from, ok := group[pair[0]]
		to, ok2 := group[pair[1]]
		switch {
		case !ok || !ok2:
		case from == to:
			inside += c
		default:
			across += c
		}
	}
	perNodeMinute := func(c int) float64 {
		return float64(c) / float64(len(n.nodes)) / probeSpan.Minutes()
	}
	reportValues(t, name,
		benchValue{perNodeMinute(inside), "inside-per-node-min"},
		benchValue{perNodeMinute(across), "across-per-node-min"},
	)
}

// metrics renders an assessment and the settling before it as a benchmark
// result's value-unit pairs.
func metrics(a assessment, s settling) string {
	values := []benchValue{
		{float64(a.reached), "reached"},
		{float64(a.pairs), "pairs"},
		{float64(a.links), "links"},
		{a.ratio.mean, "ratio-mean"},
		{a.ratio.p95, "ratio-p95"},
		{a.ratio.max, "ratio-max"},
		{a.excess.mean, "excess-ms-mean"},
		{a.excess.p95, "excess-ms-p95"},
		{a.excess.max, "excess-ms-max"},
		{a.topology.mean, "topology-mean"},
		{a.topology.max, "topology-max"},
		{a.choice.mean, "choice-mean"},
		{a.choice.max, "choice-max"},
		{float64(a.upChosen), "up-chosen"},
		{float64(a.upStored), "up-stored"},
		{float64(a.downChosen), "down-chosen"},
		{float64(a.downStored), "down-stored"},
		{float64(len(a.cuts)), "single-cuts"},
		{float64(len(a.clusters)), "clusters"},
		{float64(s.changes), "changes"},
		{s.at.Minutes(), "settle-min"},
	}
	return fields(values)
}

// TestBenchRegionsSettled benchmarks the regions network once it settles.
func TestBenchRegionsSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRegions(t, fab, wpki)
		s := awaitSettled(t, n, settleQuiet, regionsBudget)
		report(t, "RegionsSettled", s, assess(t, n, penalty, 0))
	})
}

// TestBenchStrandedSettled benchmarks the stranded network once its tier
// has healed and the whole network has settled.
func TestBenchStrandedSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := healStranded(t, fab, wpki)
		s := awaitSettled(t, n, settleQuiet, strandedBudget)
		report(t, "StrandedSettled", s, assess(t, n, penalty, 0))
	})
}
