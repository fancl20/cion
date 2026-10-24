package testnetwork

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
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
// prices that tier as cheaply as a further link would, so a node above its
// floor retires such a link as useless and a node at its floor earns none.
// The two bridges are each other's only alternative, so excluding either
// changes the route count; and no direct round trip across the sides beats
// or seconds the routes through them. Lifting the blackholes while the
// bridges stand lets every node probe the other side, and nothing strands.
// Cutting A from C, D, and E then leaves every route into the other side
// crossing the cut. A node the cut drops below its floor restores it within
// its side, a sibling answering faster than anything across, so only the
// stranded clause can link the sides: whatever prices the other side — a
// stale route's declarations near 34ms, or nothing — an 80ms round trip
// neither beats nor seconds it. The lab draws its bands as taps on the
// fabric, in no namespace and with no privileges.
func TestStrandedTierHeals(t *testing.T) {
	if !solo(t) {
		return
	}
	fab := fabric.New(t)
	wpki := webpkitest.New(t)
	ipA, ipF, ipG := hostSlot(t), hostSlot(t), hostSlot(t)
	ipC, ipD, ipE := hostSlot(t), hostSlot(t), hostSlot(t)
	for _, side := range [][]netip.Addr{{ipA, ipF, ipG}, {ipC, ipD, ipE}} {
		for i := range side {
			for _, other := range side[i+1:] {
				fab.Delay(side[i], other, 1*time.Millisecond)
			}
		}
	}
	var blackholes []func()
	for _, far := range []netip.Addr{ipC, ipD, ipE} {
		fab.Delay(ipA, far, 15*time.Millisecond)
		for _, near := range []netip.Addr{ipF, ipG} {
			fab.Delay(near, far, 40*time.Millisecond)
			blackholes = append(blackholes, fab.Blackhole(near, far))
		}
	}
	blackholes = append(blackholes, fab.Blackhole(ipA, ipE))

	a := bootOnFabric(t, fab, ipA, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	join := func(ip netip.Addr, neighbors ...*assemblyNode) *assemblyNode {
		return bootOnFabric(t, fab, ip, func(cfg *services.NodeConfig) {
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

	PollFor(t, 5*time.Minute, "each side to settle and the bridges to stand", func() bool {
		return settled(ctx, near) && settled(ctx, far) &&
			meshed(ctx, []*assemblyNode{a, c}) && meshed(ctx, []*assemblyNode{a, d})
	})

	// The blackholes lift while A links the sides: every node of each side
	// probes the other's, landing an entry on its acceptor, and the routes
	// through A answer, so no tier strands and no link crosses.
	for _, lift := range blackholes {
		lift()
	}
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
		fab.Cut(ipA, n.host)
	}
	PollFor(t, 4*time.Minute, "the stranded clause to link the sides", func() bool {
		return crossLink(ctx, near[1:], far) != "" && settled(ctx, near) && settled(ctx, far)
	})
}

// settled reports whether every one of the nodes holds at least the floor
// of up links and the up links established at both ends among them connect
// them all.
func settled(ctx context.Context, nodes []*assemblyNode) bool {
	for _, n := range nodes {
		if upLinks(ctx, n) < measured.NeighborFloor {
			return false
		}
	}
	reached := map[*assemblyNode]bool{nodes[0]: true}
	frontier := []*assemblyNode{nodes[0]}
	for len(frontier) > 0 {
		x := frontier[0]
		frontier = frontier[1:]
		for _, y := range nodes {
			if !reached[y] && upTo(ctx, x, y) && upTo(ctx, y, x) {
				reached[y] = true
				frontier = append(frontier, y)
			}
		}
	}
	return len(reached) == len(nodes)
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
