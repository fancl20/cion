package behavior

import (
	"net/netip"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// TestStrandedTierHeals is the stranded clause's integration proof with the
// floor met. Two sides — the founding core A with F and G, and C, D, and E —
// joined outward from A and bridged by C's and D's links to A, on the
// userspace fabric's taps shaped to one-way delays of 1ms within a side,
// 15ms between A and C, D, or E, and 40ms between F or G and C, D, or E.
// While the sides form, F and G are blackholed from the far side and E from
// A: a node whose joins are not yet proven links any candidate it reaches
// for its floor, and a third bridge would leave each bridge useless beside
// the other two. Each side then settles with every node at its floor, not
// meshed: the siblings within a side share a tier, and a sibling's own link
// prices that tier as cheaply as a further link would, so the end that
// dialed such a link retires it as useless above its floor, and a node at
// its floor earns none. The two bridges are each other's only alternative,
// so excluding either changes the route count; and no direct round trip
// across the sides beats or seconds the routes through them. Lifting the
// blackholes while the bridges stand lets every node probe the other side.
// A node that measures the other side before a route into it answers reads
// that tier stranded, and the link its rescue buys may stand beside the
// bridges, so the cut takes every pair a link crosses: A from C, D, and E,
// and whatever pair a rescue linked. Every route into the other side then
// crosses the cut. A node the cut drops below its floor restores it within
// its side, a sibling answering faster than anything across, so only the
// stranded clause can link the sides again, over a pair the cut spared:
// whatever prices the other side — a stale route's declarations near 34ms,
// or nothing — an 80ms round trip neither beats nor seconds it. Once the
// sides are linked again and the network settles, every ordered pair reaches
// over its chosen path within reachBudget: the far side verifies what the
// new link carries with material its sender holds, and the segments the
// links gone since killed age behind the fresh ones. The lab draws its bands
// as taps on the fabric and runs inside a synctest bubble at the daemon's
// own pacing.
func TestStrandedTierHeals(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := healStranded(t, fab, wpki)
		awaitSettled(t, n, settleQuiet, strandedBudget)
		awaitReach(t, n, reachBudget)
	})
}

// healStranded runs the stranded lab on a fresh network and returns it once
// the stranded clause has linked the sides again: A, F, G, C, D, and E, the
// founder first, with the pairs the lab cut.
func healStranded(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := newNetwork(t, fab, 6)
	ipA, ipF, ipG, ipC, ipD, ipE := n.hosts[0], n.hosts[1], n.hosts[2], n.hosts[3], n.hosts[4], n.hosts[5]
	for _, side := range [][]int{{0, 1, 2}, {3, 4, 5}} {
		for i := range side {
			for _, other := range side[i+1:] {
				n.setDelay(side[i], other, 1*time.Millisecond)
			}
		}
	}
	var blackholes []func()
	for _, far := range []int{3, 4, 5} {
		n.setDelay(0, far, 15*time.Millisecond)
		for _, near := range []int{1, 2} {
			n.setDelay(near, far, 40*time.Millisecond)
			blackholes = append(blackholes, fab.Blackhole(n.hosts[near], n.hosts[far]))
		}
	}
	blackholes = append(blackholes, fab.Blackhole(ipA, ipE))

	a := testnetwork.BootInBubble(t, fab, ipA, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	join := func(ip netip.Addr, neighbors ...*testnetwork.Node) *testnetwork.Node {
		return testnetwork.BootInBubble(t, fab, ip, func(cfg *services.NodeConfig) {
			for _, neighbor := range neighbors {
				cfg.Neighbors = append(cfg.Neighbors, rendezvous(neighbor))
			}
			cfg.RootCAs = wpki.Pool
		})
	}
	f := join(ipF, a)
	g := join(ipG, a, f)
	c := join(ipC, a)
	d := join(ipD, a, c)
	e := join(ipE, c, d)
	n.nodes = []*testnetwork.Node{a, f, g, c, d, e}
	near, far := []*testnetwork.Node{a, f, g}, []*testnetwork.Node{c, d, e}
	ctx := t.Context()

	testnetwork.PollVirtual(t, strandedBudget, "each side to settle and the bridges to stand", func() bool {
		return n.settled(ctx, near) && n.settled(ctx, far) &&
			meshed(ctx, []*testnetwork.Node{a, c}) && meshed(ctx, []*testnetwork.Node{a, d})
	})

	// The blackholes lift while A links the sides: every node of each
	// side probes the other's — the founder among them, standing in the
	// directory — its datagram reaching the other's rendezvous socket.
	probes := watchRendezvous(fab, n.nodes)
	for _, lift := range blackholes {
		lift()
	}
	testnetwork.PollVirtual(t, strandedBudget, "the sides' probes to land", func() bool {
		for _, x := range near {
			for _, y := range far {
				if !probes.probedBy(ctx, x, y) || !probes.probedBy(ctx, y, x) {
					return false
				}
			}
		}
		return true
	})

	cut := map[[2]*testnetwork.Node]bool{}
	for i := range far {
		n.cutPair(0, 3+i)
	}
	for i, x := range near[1:] {
		for j, y := range far {
			if upTo(ctx, x, y) || upTo(ctx, y, x) {
				n.cutPair(1+i, 3+j)
				cut[[2]*testnetwork.Node{x, y}] = true
			}
		}
	}
	testnetwork.PollVirtual(t, strandedBudget, "the stranded clause to link the sides", func() bool {
		return crossLink(ctx, near[1:], far, cut) != "" && n.settled(ctx, near) && n.settled(ctx, far)
	})
	return n
}

// strandedBudget bounds each of the stranded lab's waits in virtual time:
// the sides settle within ten minutes at the daemon's own pacing.
const strandedBudget = 30 * time.Minute
