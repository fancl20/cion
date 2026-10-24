package testnetwork

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// inBubble runs a lab's body inside a synctest bubble, on virtual time: the
// fabric, its stacks UDP-only, and the test CA are made inside the bubble,
// for the fabric's clock and the CA's validity window both read the time at
// their creation — the CA's twenty-four hours then bound the lab's virtual
// run. Every cleanup the body registers runs inside the bubble before the
// bubble drains, so a goroutine the lab leaks fails the lab at its exit. A
// lab that needs a process of its own re-executes before it enters: the
// re-execution cannot run inside a bubble.
func inBubble(t *testing.T, body func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		body(t, fabric.New(t, fabric.UDPOnly()), webpkitest.New(t))
	})
}

// bootInBubble boots a node on a bubble's fabric at the daemon's own
// pacing: under virtual time a lab's cost is the work each virtual second
// carries, so the production intervals are the cheap ones, and they are
// the ratios the node runs at.
func bootInBubble(
	t *testing.T, f *fabric.Fabric, host netip.Addr,
	mutate func(*services.NodeConfig),
) *assemblyNode {

	t.Helper()
	return bootOnFabric(t, f, host, func(cfg *services.NodeConfig) {
		cfg.Pacing = services.NodePacing{}
		if mutate != nil {
			mutate(cfg)
		}
	})
}

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
