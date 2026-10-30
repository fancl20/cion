package testnetwork

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// directoryBudget bounds each step of the directory lab in virtual time:
// the joins and the enrollments of a three-node line, or a restart.
const directoryBudget = 3 * time.Minute

// holdsEntries reports whether the node's view of the node directory holds
// an entry of each ISD-AS.
func holdsEntries(n *Node, ias ...addr.IA) bool {
	view := n.app.Bus().Directory().Latest()
	for _, ia := range ias {
		if _, ok := view.Entry(ia); !ok {
			return false
		}
	}
	return true
}

// TestNodeDirectoryOnEveryNode checks the node directory every node holds,
// on a fabric line at the daemon's own pacing: the founder A, B joined to
// it, and C joined to B. Every node's view holds every node's entry. The
// founder stops, withdrawing its entry, and the other two keep each other's.
// C stops too, and B drops it; restarted on its state with an empty
// directory, C holds B's entry once its link comes up, and B holds the entry
// C signed anew, which outranks its withdrawal.
func TestNodeDirectoryOnEveryNode(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		ipA, ipB, ipC := HostSlot(t), HostSlot(t), HostSlot(t)
		a := BootInBubble(t, f, ipA, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
		b := BootInBubble(t, f, ipB, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{a.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		c := BootInBubble(t, f, ipC, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{b.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		ias := []addr.IA{a.app.IA(), b.app.IA(), c.app.IA()}
		for _, n := range []*Node{a, b, c} {
			PollVirtual(t, directoryBudget, n.app.IA().String()+" to hold every node's entry",
				func() bool { return holdsEntries(n, ias...) })
		}

		a.Stop(t)
		for _, n := range []*Node{b, c} {
			PollVirtual(t, directoryBudget, n.app.IA().String()+" to drop the stopped founder alone",
				func() bool {
					_, founder := n.app.Bus().Directory().Latest().Entry(a.app.IA())
					return !founder && holdsEntries(n, b.app.IA(), c.app.IA())
				})
		}

		state := c.StateDir()
		c.Stop(t)
		PollVirtual(t, directoryBudget, "B to drop the stopped C", func() bool {
			return !holdsEntries(b, c.app.IA())
		})
		start := time.Now()
		restarted := BootInBubble(t, f, ipC, func(cfg *services.NodeConfig) {
			cfg.State = state
			cfg.RootCAs = wpki.Pool
		})
		PollVirtual(t, directoryBudget, "the restarted C to hold B's entry", func() bool {
			return holdsEntries(restarted, b.app.IA(), c.app.IA())
		})
		PollVirtual(t, directoryBudget, "B to hold the entry C signed anew", func() bool {
			return holdsEntries(b, c.app.IA())
		})
		t.Logf("B held the entry C signed anew %v after C's restart", time.Since(start))
	})
}
