package testnetwork

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// The lab's filter groups, by priority: the cut overrides the blackhole,
// which overrides the delays.
const (
	prioCut       = 1
	prioBlackhole = 2
	prioDelay     = 10
)

// TestStrandedTierHeals is the stranded clause's integration proof with the
// floor met. Two sides — the founding core A with F and G, and C, D, and E —
// each a full mesh by its joins, bridged by C's and D's links to A, on a
// loopback shaped to one-way delays of 1ms within a side, 15ms between A and
// C, D, or E, and 40ms between F or G and C, D, or E. While the sides form,
// F and G are blackholed from the far side and E from A: a node whose joins
// are not yet proven links any candidate it reaches for its floor, and a
// third bridge would leave each bridge useless beside the other two. The
// joins' topology then stands: a detour through a sibling doubles a round
// trip within a side, so no link within a side is useless; the two bridges
// are each other's only alternative, so excluding either changes the route
// count; and no direct round trip across the sides beats or seconds the
// routes through them. Lifting the blackholes while the bridges stand lets
// every node probe the other side, and nothing strands. Cutting A from C, D,
// and E then leaves every node its floor and every route into the other side
// crossing the cut. Only the stranded clause can link the sides: no node
// falls below the floor, and whatever prices the other side — a stale
// route's declarations near 34ms, or nothing — an 80ms round trip neither
// beats nor seconds it. The lab shapes the loopback with tc in a network
// namespace of its own.
func TestStrandedTierHeals(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	shapeLoopback(t)
	wpki := webpkitest.New(t)
	ipA, ipF, ipG := hostSlot(t), hostSlot(t), hostSlot(t)
	ipC, ipD, ipE := hostSlot(t), hostSlot(t), hostSlot(t)
	for _, side := range [][]netip.Addr{{ipA, ipF, ipG}, {ipC, ipD, ipE}} {
		for i := range side {
			for _, other := range side[i+1:] {
				steer(t, prioDelay, band1ms, side[i], other)
			}
		}
	}
	for _, far := range []netip.Addr{ipC, ipD, ipE} {
		steer(t, prioDelay, band15ms, ipA, far)
		for _, near := range []netip.Addr{ipF, ipG} {
			steer(t, prioDelay, band40ms, near, far)
			steer(t, prioBlackhole, bandLoss, near, far)
		}
	}
	steer(t, prioBlackhole, bandLoss, ipA, ipE)

	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	join := func(ip netip.Addr, neighbors ...*assemblyNode) *assemblyNode {
		return bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.State = t.TempDir()
			cfg.Internal = PinnedUDPAddrOn(t, ip)
			cfg.Control = FreeUDPAddrOn(t, ip)
			for _, n := range neighbors {
				cfg.Neighbors = append(cfg.Neighbors, n.rendezvousOf())
			}
			cfg.RootCAs = wpki.Pool
		})
	}
	f := join(ipF, a)
	g := join(ipG, a, f)
	c := join(ipC, a)
	d := join(ipD, a, c)
	e := join(ipE, c, d)
	near, far := []*assemblyNode{a, f, g}, []*assemblyNode{c, d, e}
	ctx := t.Context()

	PollFor(t, 3*time.Minute, "each side to mesh and the bridges to stand", func() bool {
		return meshed(ctx, near) && meshed(ctx, far) &&
			meshed(ctx, []*assemblyNode{a, c}) && meshed(ctx, []*assemblyNode{a, d})
	})

	// The blackholes lift while A links the sides: every node of each side
	// probes the other's, landing an entry on its acceptor, and the routes
	// through A answer, so no tier strands and no link crosses.
	lift(t, prioBlackhole)
	PollFor(t, 2*time.Minute, "the sides' probes to land", func() bool {
		for _, x := range near[1:] {
			for _, y := range far {
				if !probedBy(ctx, x, y) || !probedBy(ctx, y, x) {
					return false
				}
			}
		}
		return true
	})
	if pair := crossLink(ctx, near[1:], far); pair != "" {
		t.Fatalf("the sides linked before the cut: %s", pair)
	}

	for _, n := range far {
		steer(t, prioCut, bandLoss, ipA, n.host)
	}
	PollFor(t, 4*time.Minute, "the stranded clause to link the sides", func() bool {
		if crossLink(ctx, near[1:], far) == "" || !meshed(ctx, near) {
			return false
		}
		for _, n := range append(near, far...) {
			if upLinks(ctx, n) < measured.NeighborFloor {
				return false
			}
		}
		return true
	})
}

// meshed reports whether every pair of the nodes holds an up link
// established at both ends.
func meshed(ctx context.Context, nodes []*assemblyNode) bool {
	for i, x := range nodes {
		for _, y := range nodes[i+1:] {
			if !upTo(ctx, x, y) || !upTo(ctx, y, x) {
				return false
			}
		}
	}
	return true
}

// crossLink names the first pair across the two sets that holds an up link
// established at both ends; empty when none does.
func crossLink(ctx context.Context, xs, ys []*assemblyNode) string {
	for _, x := range xs {
		for _, y := range ys {
			if upTo(ctx, x, y) && upTo(ctx, y, x) {
				return fmt.Sprintf("%s–%s", x.app.IA(), y.app.IA())
			}
		}
	}
	return ""
}

// upTo reports whether the node holds an established link to the peer
// whose verdict is up.
func upTo(ctx context.Context, n, peer *assemblyNode) bool {
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(peer.app.IA()) && l.State == links.StateEstablished &&
			n.app.Monitor().Up(l.IfID) {
			return true
		}
	}
	return false
}

// upLinks counts the node's established links whose verdicts are up.
func upLinks(ctx context.Context, n *assemblyNode) int {
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return 0
	}
	up := 0
	for _, l := range entries {
		if l.State == links.StateEstablished && n.app.Monitor().Up(l.IfID) {
			up++
		}
	}
	return up
}

// probedBy reports whether the prober's rendezvous probe ever landed on the
// node's acceptor: the probe mints an entry aimed at the prober's host,
// which proves the prober's directory holds the node.
func probedBy(ctx context.Context, n, prober *assemblyNode) bool {
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.Remote.Addr() == prober.host {
			return true
		}
	}
	return false
}
