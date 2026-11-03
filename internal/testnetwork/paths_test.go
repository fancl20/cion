package testnetwork

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The picks lab's topology: the core A reaches D over two branches, B, and
// C then E, the one through B of fewer hops. B's interface toward D is
// pinned so the lab names the link it cuts.
var (
	branchD = addr.MustIAFrom(20, 0xff00000000a1)
	branchE = addr.MustIAFrom(20, 0xff00000000a2)
	viaB    = segment.LinkID{IA: nodeIA, IfID: 7}
)

// The picks lab's bounds, in virtual time, each with a poll's second.
const (
	// branchesBudget bounds each wait on the network: five nodes' links and
	// enrollments and both branches' segments, or a link's return.
	branchesBudget = 10 * time.Minute
	// leaveBound bounds how long after a cut the pick leaves the cut link: a
	// heartbeat and its wait, then a burst and its last probe's wait.
	leaveBound = ping.Heartbeat + 2*ping.ProbeWait + ping.BurstProbes*ping.BurstSpacing +
		virtualPollInterval
	// returnBound bounds how long after the cut link is up again the pick
	// returns to it: the half-open backoff's one-minute cap and a burst.
	returnBound = time.Minute + ping.BurstProbes*ping.BurstSpacing + virtualPollInterval
)

// bootFabricTopology boots a static topology on a bubble's fabric: each
// node's ISD-AS written to its state before any boot, each link's addresses
// drawn on its two nodes' stacks, the founding core booted first.
func bootFabricTopology(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA,
	topo staticTopology) map[addr.IA]*Node {

	t.Helper()
	hosts := make(map[addr.IA]netip.Addr, len(topo.nodes))
	states := make(map[addr.IA]string, len(topo.nodes))
	for _, ia := range topo.nodes {
		hosts[ia] = HostSlot(t)
		states[ia] = t.TempDir()
		persistIAFile(t, states[ia], ia)
	}
	entries := topo.entries(func(ia addr.IA) string {
		return netip.AddrPortFrom(hosts[ia], f.Node(hosts[ia]).DrawPort()).String()
	})
	boot := func(ia addr.IA) *Node {
		set := linkSetPath(t)
		writeStaticSet(t, set, entries[ia]...)
		return BootInBubble(t, f, hosts[ia], func(cfg *services.NodeConfig) {
			cfg.Core = ia == topo.core
			cfg.LinkSet = set
			cfg.State = states[ia]
			if cfg.Core {
				cfg.CertFile, cfg.KeyFile = wpki.CertFile, wpki.KeyFile
			} else {
				cfg.RootCAs = wpki.Pool
			}
			if topo.mutate != nil {
				topo.mutate(cfg)
			}
		})
	}
	nodes := map[addr.IA]*Node{topo.core: boot(topo.core)}
	for _, ia := range topo.nodes {
		if ia != topo.core {
			nodes[ia] = boot(ia)
		}
	}
	return nodes
}

// branches is the picks lab's network: the core A, B, and D.
type branches struct {
	ctx     context.Context
	a, b, d *Node
}

// bootBranches boots the picks lab's topology on the fabric, every node's
// run arguments taking mutate last, and waits for A to pick the branch
// through B and reach D over it.
func bootBranches(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA,
	mutate func(*services.NodeConfig)) branches {

	t.Helper()
	nodes := bootFabricTopology(t, f, wpki, staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA, branchD, branchE},
		links: [][2]addr.IA{
			{coreIA, nodeIA}, {nodeIA, branchD},
			{coreIA, lineCIA}, {lineCIA, branchE}, {branchE, branchD},
		},
		pins:   map[[2]addr.IA]uint16{{nodeIA, branchD}: viaB.IfID},
		mutate: mutate,
	})
	n := branches{ctx: t.Context(), a: nodes[coreIA], b: nodes[nodeIA], d: nodes[branchD]}
	PollVirtual(t, branchesBudget, "A to reach D through B", func() bool {
		return n.throughB() && pingFrom(n.ctx, n.a, branchD, n.d.host)
	})
	return n
}

// pick picks A's path to D as a caller does, refreshing D's requests:
// whether the pick crosses B's link to D, and whether A picked one at all.
func (n branches) pick() (throughB, ok bool) {
	c, err := n.a.app.Provider().Choose(n.ctx, branchD)
	if err != nil {
		return false, false
	}
	return slices.Contains(c.Links, viaB), true
}

// throughB reports whether A's pick crosses B's link to D.
func (n branches) throughB() bool {
	through, _ := n.pick()
	return through
}

// aroundB reports whether A picked a path avoiding B's link to D.
func (n branches) aroundB() bool {
	through, ok := n.pick()
	return ok && !through
}

// TestPicksFollowMeasuredHealth is the measured picks' proof on the fabric,
// in virtual time: the core A reaches D over two branches, B and C then E,
// and picks the one through B, of fewer hops.
func TestPicksFollowMeasuredHealth(t *testing.T) {
	// With the ping application measuring the pick and its standby, a cut
	// of B's link to D moves the pick around B within a heartbeat and a
	// burst, and the pick stays there after the interface-down hold lapses,
	// the path through B ejected. Once the link is up again, the pick
	// returns at the next half-open probe.
	t.Run("measured", func(t *testing.T) {
		InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
			n := bootBranches(t, f, wpki, nil)
			PollVirtual(t, branchesBudget, "A to measure the branch around B", func() bool {
				n.throughB()
				for _, r := range n.a.app.Bus().PathMeasurements().Latest().All() {
					if r.Dst == branchD && !r.LastAnswer.IsZero() && !slices.Contains(r.Links, viaB) {
						return true
					}
				}
				return false
			})

			lift := f.Cut(n.b.Host(), n.d.Host())
			cut := time.Now()
			PollVirtual(t, leaveBound, "A's pick to leave the cut link", n.aroundB)
			t.Logf("A's pick left the cut link %v after the cut", time.Since(cut))
			for range 3 * scion.InterfaceDownHold / virtualPollInterval {
				time.Sleep(virtualPollInterval)
				synctest.Wait()
				if !n.aroundB() {
					t.Fatalf("A's pick returned to the cut link %v after the cut", time.Since(cut))
				}
			}

			lift()
			dIfID := entryOf(n.ctx, n.d, nodeIA).IfID
			PollVirtual(t, branchesBudget, "B's link to D to come up again", func() bool {
				n.throughB()
				return n.b.app.Monitor().Up(viaB.IfID) && n.d.app.Monitor().Up(dIfID)
			})
			up := time.Now()
			PollVirtual(t, returnBound, "A's pick to return to B's link to D", n.throughB)
			t.Logf("A's pick returned %v after the link came up", time.Since(up))
		})
	})

	// A core run without the ping application holds no measurements and
	// keeps the interface-down hold alone: an echo over its pick across the
	// cut link draws the signal and moves the pick around B, and the pick
	// returns to the cut link once the hold lapses.
	t.Run("without ping", func(t *testing.T) {
		InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
			n := bootBranches(t, f, wpki, func(cfg *services.NodeConfig) {
				if cfg.Core {
					cfg.Applications = []string{}
				}
			})
			for id := range n.a.app.Bus().PathMeasurements().Latest().All() {
				t.Fatalf("A holds a record of %s without the ping application", id)
			}

			f.Cut(n.b.Host(), n.d.Host())
			PollVirtual(t, branchesBudget, "B to mark its link to D down", func() bool {
				return !n.b.app.Monitor().Up(viaB.IfID)
			})
			PollVirtual(t, branchesBudget, "A's pick to leave the signaled link", func() bool {
				pingFrom(n.ctx, n.a, branchD, n.d.host)
				return n.aroundB()
			})
			PollVirtual(t, scion.InterfaceDownHold+2*virtualPollInterval,
				"A's pick to return to the cut link", n.throughB)
		})
	})
}
