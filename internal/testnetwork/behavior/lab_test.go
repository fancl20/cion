package behavior

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// rendezvous returns the node's advertised rendezvous address: its host on
// the fixed rendezvous port.
func rendezvous(n *testnetwork.Node) string {
	return netip.AddrPortFrom(n.Host(), measured.RendezvousPort).String()
}

const (
	// settleQuiet is how long a link set must hold unchanged to count as
	// settled: twenty selection windows at the daemon's pacing.
	settleQuiet = 10 * time.Minute
	// settleSample spaces the reads of a settling link set.
	settleSample = 10 * time.Second
)

// network is a lab's booted network: its nodes, the founding core first,
// the one-way delay the fabric holds between each pair, and the pairs the
// lab cut.
type network struct {
	nodes  []*testnetwork.Node
	oneWay [][]time.Duration
	cut    map[[2]int]bool
}

// delay returns the one-way delay the fabric holds between two of the
// network's nodes; false for a pair the lab cut.
func (n *network) delay(i, j int) (time.Duration, bool) {
	if n.cut[[2]int{min(i, j), max(i, j)}] {
		return 0, false
	}
	return n.oneWay[i][j], true
}

// settling is how a link set settled: the changes it went through and how
// long after the first read the last one came.
type settling struct {
	changes int
	at      time.Duration
}

// awaitSettled reads the nodes' link set every settleSample until it holds
// unchanged for quiet with the nodes settled, and fails the test once
// budget passes first.
func awaitSettled(t *testing.T, nodes []*testnetwork.Node, quiet, budget time.Duration) settling {
	t.Helper()
	ctx := t.Context()
	start := time.Now()
	var s settling
	var last string
	changed := start
	for {
		synctest.Wait()
		if now := linkSet(ctx, nodes); now != last {
			last, changed = now, time.Now()
			s.changes++
		}
		if time.Since(changed) >= quiet && settled(ctx, nodes) {
			s.at = changed.Sub(start)
			return s
		}
		if time.Since(start) >= budget {
			t.Fatalf("the link set changed %d times in %v and never held for %v; last: %s",
				s.changes, budget, quiet, last)
		}
		time.Sleep(settleSample)
	}
}

// settled reports whether every one of the nodes holds at least the floor
// of up links and the up links established at both ends among them connect
// them all.
func settled(ctx context.Context, nodes []*testnetwork.Node) bool {
	for _, n := range nodes {
		if upLinks(ctx, n) < measured.NeighborFloor {
			return false
		}
	}
	reached := map[*testnetwork.Node]bool{nodes[0]: true}
	frontier := []*testnetwork.Node{nodes[0]}
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
func meshed(ctx context.Context, nodes []*testnetwork.Node) bool {
	for i, x := range nodes {
		for _, y := range nodes[i+1:] {
			if !upTo(ctx, x, y) || !upTo(ctx, y, x) {
				return false
			}
		}
	}
	return true
}

// crossLink names the first pair across the two sets, the skipped pairs
// aside, that holds an up link established at both ends; empty when none
// does.
func crossLink(ctx context.Context, xs, ys []*testnetwork.Node, skip map[[2]*testnetwork.Node]bool) string {
	for _, x := range xs {
		for _, y := range ys {
			if !skip[[2]*testnetwork.Node{x, y}] && upTo(ctx, x, y) && upTo(ctx, y, x) {
				return fmt.Sprintf("%s–%s", x.App().IA(), y.App().IA())
			}
		}
	}
	return ""
}

// upTo reports whether the node holds an established link to the peer
// whose verdict is up.
func upTo(ctx context.Context, n, peer *testnetwork.Node) bool {
	entries, err := n.App().Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(peer.App().IA()) && l.State == links.StateEstablished &&
			n.App().Monitor().Up(l.IfID) {
			return true
		}
	}
	return false
}

// upLinks counts the node's established links whose verdicts are up.
func upLinks(ctx context.Context, n *testnetwork.Node) int {
	entries, err := n.App().Links().All(ctx)
	if err != nil {
		return 0
	}
	up := 0
	for _, l := range entries {
		if l.State == links.StateEstablished && n.App().Monitor().Up(l.IfID) {
			up++
		}
	}
	return up
}

// probedBy reports whether the prober's rendezvous probe ever landed on the
// node's acceptor: the probe mints an entry aimed at the prober's host,
// which proves the prober's directory holds the node.
func probedBy(ctx context.Context, n, prober *testnetwork.Node) bool {
	entries, err := n.App().Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.Remote.Addr() == prober.Host() {
			return true
		}
	}
	return false
}

// linkSet names the nodes' links by index pair: a pair whose up link is
// established at both ends plainly, one established at one end alone marked
// with a tilde.
func linkSet(ctx context.Context, nodes []*testnetwork.Node) string {
	index := make(map[addr.IA]int, len(nodes))
	for i, n := range nodes {
		index[n.App().IA()] = i
	}
	ends := map[[2]int]int{}
	for i, n := range nodes {
		entries, err := n.App().Links().All(ctx)
		if err != nil {
			continue
		}
		for _, l := range entries {
			j, ok := index[l.NeighborIA]
			if !ok || l.State != links.StateEstablished || !n.App().Monitor().Up(l.IfID) {
				continue
			}
			ends[[2]int{min(i, j), max(i, j)}]++
		}
	}
	var pairs []string
	for pair, count := range ends {
		mark := ""
		if count == 1 {
			mark = "~"
		}
		pairs = append(pairs, fmt.Sprintf("%s%d-%d", mark, pair[0], pair[1]))
	}
	slices.Sort(pairs)
	return strings.Join(pairs, " ")
}
