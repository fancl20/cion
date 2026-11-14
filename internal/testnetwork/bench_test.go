package testnetwork

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/testnetwork/fabric"
)

// requireBench skips a benchmark unless CION_BENCH asks for the
// benchmarks: they grade how well a braked link serves, not whether it
// brakes, and cost a minute or more of wall time each.
func requireBench(t *testing.T) {
	t.Helper()
	if os.Getenv("CION_BENCH") == "" {
		t.Skip("a benchmark: set CION_BENCH to run it")
	}
}

// benchValue is one value-unit pair of a benchmark result line.
type benchValue struct {
	value float64
	unit  string
}

// reportValues logs a lab's values and prints them as a benchmark result
// line on the test's standard output, where benchstat reads it.
func reportValues(t *testing.T, name string, values ...benchValue) {
	t.Helper()
	fields := make([]string, 0, len(values))
	for _, v := range values {
		fields = append(fields, fmt.Sprintf("%g %s", v.value, v.unit))
	}
	line := strings.Join(fields, " ")
	t.Logf("%s: %s", name, line)
	fmt.Printf("Benchmark%s 1 %s\n", name, line)
}

// ms renders a duration in milliseconds.
func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// lineValues renders the window a line kept over span, at rate bits per
// second, as a benchmark's values, each unit prefixed with the line's name:
// the share of what it was offered it dropped, the share of its rate it
// carried, and its mean and longest wait.
func lineValues(name string, w fabric.LineWindow, rate float64, span time.Duration) []benchValue {
	return []benchValue{
		{w.DropShare(), name + "-dropped"},
		{float64(w.Bytes*8) / span.Seconds() / rate, name + "-used"},
		{ms(w.MeanWait()), name + "-wait-ms-mean"},
		{ms(w.MaxWait), name + "-wait-ms-max"},
	}
}

// flowValues renders a flow's window as a benchmark's values, each unit
// prefixed with the flow's name: the share of what it offered it delivered,
// and its delays' median and 95th percentile.
func flowValues(name string, w FlowWindow) []benchValue {
	return []benchValue{
		{w.DeliveredShare(), name + "-delivered"},
		{ms(w.Quantile(0.5)), name + "-ms-p50"},
		{ms(w.Quantile(0.95)), name + "-ms-p95"},
	}
}
