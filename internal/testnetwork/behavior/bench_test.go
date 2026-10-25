package behavior

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
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

// metrics renders an assessment and the settling before it as a benchmark
// result's value-unit pairs.
func metrics(a assessment, s settling) string {
	values := []struct {
		value float64
		unit  string
	}{
		{float64(a.reached), "reached"},
		{float64(a.pairs), "pairs"},
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
		{float64(s.changes), "changes"},
		{s.at.Minutes(), "settle-min"},
	}
	fields := make([]string, 0, len(values))
	for _, v := range values {
		fields = append(fields, fmt.Sprintf("%g %s", v.value, v.unit))
	}
	return strings.Join(fields, " ")
}

// TestBenchRegionsSettled benchmarks the regions network once it settles.
func TestBenchRegionsSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootRegions(t, fab, wpki)
		s := awaitSettled(t, n.nodes, settleQuiet, regionsBudget)
		report(t, "RegionsSettled", s, assess(t, n, penalty, 0))
	})
}

// TestBenchStrandedSettled benchmarks the stranded network once its tier
// has healed and the whole network has settled.
func TestBenchStrandedSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := healStranded(t, fab, wpki)
		s := awaitSettled(t, n.nodes, settleQuiet, strandedBudget)
		report(t, "StrandedSettled", s, assess(t, n, penalty, 0))
	})
}
