package testnetwork

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestPollUntilSpendsVirtualTime checks the virtual poll's schedule: a
// condition that never holds gives up at exactly its budget of virtual
// time, and one that comes to hold ends the poll at the first check after
// it does.
func TestPollUntilSpendsVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		if pollUntil(time.Hour, func() bool { return false }) {
			t.Fatal("a condition that never holds was met")
		}
		if spent := time.Since(start); spent != time.Hour {
			t.Errorf("the poll gave up after %v of virtual time, want exactly %v", spent, time.Hour)
		}

		start = time.Now()
		ready := start.Add(90*time.Second + virtualPollInterval/2)
		if !pollUntil(time.Hour, func() bool { return !time.Now().Before(ready) }) {
			t.Fatal("a condition that came to hold was never met")
		}
		if spent, want := time.Since(start), 91*time.Second; spent != want {
			t.Errorf("the poll ended after %v of virtual time, want the first check past the condition at %v",
				spent, want)
		}
	})
}
