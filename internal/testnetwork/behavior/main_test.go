package behavior

import (
	"fmt"
	"os"
	"testing"
)

// TestMain runs the labs only without the race detector.
func TestMain(m *testing.M) {
	if raceEnabled {
		fmt.Fprintln(os.Stderr, "the behavior labs run without the race detector")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
