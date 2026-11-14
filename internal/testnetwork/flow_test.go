package testnetwork

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// The flow lab's line: the sender's uplink rate and queue, the pair's
// one-way delay, and the port the receiver reads.
const (
	flowLabRate   = 2_000_000
	flowLabQueue  = 100 * time.Millisecond
	flowLabOneWay = 10 * time.Millisecond
	flowLabPort   = 15000
	flowLabSize   = 1000
	// flowLabSpan is how long each of the lab's loads runs, and how long a
	// benchmark reads a braked link's line.
	flowLabSpan = 30 * time.Second
	// flowLabSettle bounds how long a link takes to brake once a flow past
	// its line starts, and is how long a benchmark lets the braked link's
	// rate settle before it reads the line.
	flowLabSettle = 30 * time.Second
)

// thinUplink is the flow lab: two nodes 10ms apart, the joiner on a 2
// Mbit/s uplink queuing 100ms, its one link the core's, and a flow of a
// third of the line from the joiner to the core that has begun to arrive.
type thinUplink struct {
	core, joiner *Node
	up           *fabric.Uplink
	fits         *Flow
}

// startThinUplink boots the flow lab and starts its flow that fits.
func startThinUplink(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) thinUplink {
	t.Helper()
	core, joiner := HostSlot(t), HostSlot(t)
	fab.Delay(core, joiner, flowLabOneWay)
	a := BootInBubble(t, fab, core, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	b := BootInBubble(t, fab, joiner, func(cfg *services.NodeConfig) {
		cfg.Neighbors = []string{netip.AddrPortFrom(a.Host(), measured.RendezvousPort).String()}
		cfg.RootCAs = wpki.Pool
	})
	lab := thinUplink{
		core:   a,
		joiner: b,
		up:     fab.Uplink(flowLabRate, flowLabQueue, joiner),
		fits:   StartFlow(t, b, a, flowLabPort, flowLabRate/3, flowLabSize),
	}
	if !pollUntil(5*time.Minute, func() bool { return lab.fits.Window().Received() > 0 }) {
		t.Fatal("the flow that fits delivered nothing within five minutes")
	}
	return lab
}

// braked reports whether one of the node's usable links holds a rate.
func braked(n *Node) bool {
	for ifID := range n.App().Bus().Links().Latest().Usable() {
		if n.App().Congestion().Rate(ifID) > 0 {
			return true
		}
	}
	return false
}

// TestFlowCrossesAThinUplink checks the flows, the uplinks, and the brake
// together on the flow lab. The flow that fits arrives nearly whole, its
// random arrivals' rare bursts past the queue aside, each datagram within
// its one-way delay and a wait short of the queue's bound. Beside a flow
// twice the line, the joiner's link brakes, and the joiner's control traffic
// still reaches the core.
func TestFlowCrossesAThinUplink(t *testing.T) {
	InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startThinUplink(t, fab, wpki)

		// A flow that fits: once its first datagram arrives, every one does,
		// each within the line's one-way delay and serialization, beside a
		// wait behind the node's own control traffic.
		_ = lab.up.Window()
		time.Sleep(flowLabSpan)
		w := lab.fits.Window()
		if !slices.IsSorted(w.Delays) {
			t.Error("the flow's window holds its delays out of order")
		}
		if w.DeliveredShare() < 0.97 {
			t.Errorf("the flow that fits delivered %d of %d datagrams", w.Received(), w.Offered)
		}
		if p95, most := w.Quantile(0.95), flowLabOneWay+flowLabQueue; p95 > most {
			t.Errorf("the flow that fits arrived within %v at its 95th percentile, want within %v", p95, most)
		}
		if w := lab.up.Window(); w.DropShare() > 0.02 {
			t.Errorf("the uplink dropped %d of %d packets under a flow that fits", w.Dropped, w.Sent+w.Dropped)
		}

		// A flow twice the line brakes the joiner's link, and the joiner's
		// echoes to the core still come back.
		StartFlow(t, lab.joiner, lab.core, flowLabPort+1, 2*flowLabRate, flowLabSize)
		if !pollUntil(flowLabSettle, func() bool { return braked(lab.joiner) }) {
			t.Errorf("the joiner's link never braked within %v of a flow twice its line", flowLabSettle)
		}
		if !pollUntil(10*time.Second, func() bool {
			return pingFrom(t.Context(), lab.joiner, lab.core.App().IA(), lab.core.Host())
		}) {
			t.Error("the joiner's echoes to the core went unanswered beside the flows")
		}
	})
}

// TestBenchBrakeThinUplink benchmarks the flow lab under a flow twice the
// line beside the flow that fits, once the joiner's rate settles: what the
// uplink dropped and carried and how long it waited, and what the flows
// delivered.
func TestBenchBrakeThinUplink(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startThinUplink(t, fab, wpki)
		over := StartFlow(t, lab.joiner, lab.core, flowLabPort+1, 2*flowLabRate, flowLabSize)
		time.Sleep(flowLabSettle)
		_, _, _ = over.Window(), lab.fits.Window(), lab.up.Window()
		time.Sleep(flowLabSpan)
		reportValues(t, "BrakeThinUplink", slices.Concat(
			lineValues("uplink", lab.up.Window(), flowLabRate, flowLabSpan),
			flowValues("flows", over.Window().Add(lab.fits.Window())),
		)...)
	})
}
