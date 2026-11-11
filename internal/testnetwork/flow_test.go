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
	flowLabRate   = 500_000
	flowLabQueue  = 100 * time.Millisecond
	flowLabOneWay = 10 * time.Millisecond
	flowLabPort   = 15000
	flowLabSize   = 1000
	// flowLabSpan is how long each of the lab's loads runs.
	flowLabSpan = 30 * time.Second
)

// TestFlowCrossesAThinUplink checks the flows and the uplinks together: two
// nodes 10ms apart, the joiner on a 500 kbit/s uplink queuing 100ms. A flow
// of a third of the line arrives nearly whole, its random arrivals' rare
// bursts past the queue aside, each datagram within its one-way delay and
// a wait short of the queue's bound; a flow twice the line delivers a share
// of what the flows offer, each datagram after the standing queue, while
// the uplink drops the rest. The share also loses what the flows offer
// while the path library, which reads congestion's losses as a path's,
// holds the path ejected.
func TestFlowCrossesAThinUplink(t *testing.T) {
	InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
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
		up := fab.Uplink(flowLabRate, flowLabQueue, joiner)

		// A flow that fits: once its first datagram arrives, every one does,
		// each within the line's one-way delay and serialization, beside a
		// wait behind the node's own control traffic.
		fits := StartFlow(t, b, a, flowLabPort, flowLabRate/3, flowLabSize)
		if !pollUntil(5*time.Minute, func() bool { return fits.Window().Received() > 0 }) {
			t.Fatal("the flow that fits delivered nothing within five minutes")
		}
		_ = up.Window()
		time.Sleep(flowLabSpan)
		w := fits.Window()
		if !slices.IsSorted(w.Delays) {
			t.Error("the flow's window holds its delays out of order")
		}
		if w.DeliveredShare() < 0.97 {
			t.Errorf("the flow that fits delivered %d of %d datagrams", w.Received(), w.Offered)
		}
		if p95, most := w.Quantile(0.95), flowLabOneWay+flowLabQueue; p95 > most {
			t.Errorf("the flow that fits arrived within %v at its 95th percentile, want within %v", p95, most)
		}
		if w := up.Window(); w.DropShare() > 0.02 {
			t.Errorf("the uplink dropped %d of %d packets under a flow that fits", w.Dropped, w.Sent+w.Dropped)
		}

		// A flow twice the line: the queue stands at its bound, the uplink
		// drops the rest, and each datagram arrives after the standing wait.
		over := StartFlow(t, b, a, flowLabPort+1, 2*flowLabRate, flowLabSize)
		time.Sleep(flowLabSpan / 3)
		_ = over.Window()
		_ = fits.Window()
		_ = up.Window()
		time.Sleep(flowLabSpan)
		ow := over.Window()
		both := ow.Add(fits.Window())
		if share := both.DeliveredShare(); share < 0.15 || share > 0.6 {
			t.Errorf("the flows past the line delivered %d of %d datagrams, want 15 to 60 percent",
				both.Received(), both.Offered)
		}
		median, p95 := ow.Quantile(0.5), ow.Quantile(0.95)
		if least, most := flowLabQueue*4/5, flowLabOneWay+flowLabQueue+flowLabQueue/2; median < least || p95 > most {
			t.Errorf("the flow past the line arrived at a median %v and a 95th percentile %v, "+
				"want past %v and within %v", median, p95, least, most)
		}
		if uw := up.Window(); uw.Dropped == 0 || uw.MaxWait > flowLabQueue {
			t.Errorf("the uplink dropped %d packets and waited at most %v, want drops and at most %v",
				uw.Dropped, uw.MaxWait, flowLabQueue)
		}
	})
}
