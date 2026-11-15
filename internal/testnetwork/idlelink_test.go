package testnetwork

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// The idle-link lab's two nodes, idleA the founding core, and the interface
// both pin on their link.
var (
	idleA = addr.MustIAFrom(20, 0xff00000000d1)
	idleB = addr.MustIAFrom(20, 0xff00000000d2)
)

const idleIfID = 7

// The idle-link lab's bounds.
const (
	// idleBudget bounds each wait on the lab's network.
	idleBudget = 5 * time.Minute
	// idleWatch is how long the lab watches the link's sessions.
	idleWatch = 10 * time.Second
	// idleDown is how soon after the cut each end marks the link down: the
	// detection time from its peer's last control message, which crossed
	// within an interval before the cut, read at the next interval.
	idleDown = liveness.BFDDetectMultiplier*liveness.BFDTransmissionInterval +
		liveness.BFDTransmissionInterval
)

// TestBFDIdleLinkInAsynchronousMode checks a link that carries no traffic of
// its own: its sessions stay in asynchronous mode, each sending a control
// message every interval, since no load loses them; once the line is cut,
// each end marks the link down within idleDown; and once the line is
// restored, the link comes back up.
func TestBFDIdleLinkInAsynchronousMode(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		nodes := bootFabricTopology(t, f, wpki, staticTopology{
			core:  idleA,
			nodes: []addr.IA{idleA, idleB},
			links: [][2]addr.IA{{idleA, idleB}},
			pins:  map[[2]addr.IA]uint16{{idleA, idleB}: idleIfID, {idleB, idleA}: idleIfID},
		})
		a, b := nodes[idleA], nodes[idleB]
		ctx := t.Context()
		up := func() bool {
			return a.App().Monitor().Up(idleIfID) && b.App().Monitor().Up(idleIfID)
		}
		PollVirtual(t, idleBudget, "the link to stand", func() bool {
			return establishedOf(ctx, a, idleB) && establishedOf(ctx, b, idleA) && up()
		})
		sessionA := a.App().Monitor().Session(entryOf(ctx, a, idleB))
		sessionB := b.App().Monitor().Session(entryOf(ctx, b, idleA))
		sentA, sentB := sessionA.Transmitted(), sessionB.Transmitted()
		time.Sleep(idleWatch)
		least := uint64(idleWatch/liveness.BFDTransmissionInterval) - 1
		if gotA, gotB := sessionA.Transmitted()-sentA, sessionB.Transmitted()-sentB; gotA < least || gotB < least {
			t.Errorf("control messages sent in %v = %d/%d, want at least %d at each end", idleWatch,
				gotA, gotB, least)
		}
		if !up() {
			t.Fatal("the idle link went down")
		}

		lift := f.Cut(a.Host(), b.Host())
		cut := time.Now()
		var downA, downB time.Duration
		for downA == 0 || downB == 0 {
			if time.Since(cut) > idleBudget {
				t.Fatal("the cut link never went down at both ends")
			}
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
			if downA == 0 && !a.App().Monitor().Up(idleIfID) {
				downA = time.Since(cut)
			}
			if downB == 0 && !b.App().Monitor().Up(idleIfID) {
				downB = time.Since(cut)
			}
		}
		if downA > idleDown || downB > idleDown {
			t.Errorf("the cut link went down %v/%v after the cut at its two ends, want within %v",
				downA, downB, idleDown)
		}

		lift()
		PollVirtual(t, idleBudget, "the restored link to come back up", up)
	})
}
