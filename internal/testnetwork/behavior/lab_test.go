package behavior

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/libs/scion"
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
// on the fabric's hosts — some behind NATs, where a lab draws them —
// the one-way delay the fabric holds between each pair, and the pairs cut.
type network struct {
	fab   *fabric.Fabric
	hosts []netip.Addr
	// wire holds each node's address on the wire, where its peers' packets
	// go: its host, or the gateway of the NAT it sits behind.
	wire   []netip.Addr
	nodes  []*testnetwork.Node
	oneWay [][]time.Duration
	taps   map[[2]int]func()
	cut    map[[2]int]bool
}

// newNetwork draws hosts for a network of the given size on the fabric.
func newNetwork(t *testing.T, fab *fabric.Fabric, size int) *network {
	t.Helper()
	n := &network{
		fab:    fab,
		hosts:  make([]netip.Addr, size),
		wire:   make([]netip.Addr, size),
		nodes:  make([]*testnetwork.Node, size),
		oneWay: make([][]time.Duration, size),
		taps:   map[[2]int]func(){},
		cut:    map[[2]int]bool{},
	}
	for i := range size {
		n.hosts[i] = testnetwork.HostSlot(t)
		n.wire[i] = n.hosts[i]
		n.oneWay[i] = make([]time.Duration, size)
	}
	return n
}

// placeNATs places the nodes behind a NAT each, of the behavior
// given, on a gateway drawn for it: their peers' packets go to the
// gateway, and theirs leave from it. A lab places its NATs before it
// draws delays, for the taps follow the addresses on the wire.
func (n *network) placeNATs(t *testing.T, behaviors map[int]fabric.Behavior) map[int]*fabric.NAT {
	t.Helper()
	nats := make(map[int]*fabric.NAT, len(behaviors))
	for _, i := range slices.Sorted(maps.Keys(behaviors)) {
		nats[i] = n.fab.NAT(behaviors[i], testnetwork.HostSlot(t), n.hosts[i])
		n.wire[i] = nats[i].Gateway()
	}
	return nats
}

// site places the nodes behind one NAT of the behavior given, on a
// gateway drawn for it: their packets to each other cross nothing, every
// other node's go to the gateway, and theirs to every other node leave from
// it. A lab places a site before it draws delays, for the taps follow the
// addresses on the wire.
func (n *network) site(t *testing.T, behavior fabric.Behavior, members ...int) *fabric.NAT {
	t.Helper()
	inside := make([]netip.Addr, len(members))
	for k, i := range members {
		inside[k] = n.hosts[i]
	}
	b := n.fab.NAT(behavior, testnetwork.HostSlot(t), inside...)
	for _, i := range members {
		n.wire[i] = b.Gateway()
	}
	return b
}

// drawPair draws a tap for each direction the pair's packets take: from
// each node's host — the fabric shapes a packet before any NAT
// translates it — to the other's address on the wire. One tap covers both
// directions of a pair whose packets go host to host: two public
// nodes, or two behind one NAT.
func (n *network) drawPair(i, j int, draw func(a, b netip.Addr) func()) func() {
	if n.wire[i] == n.wire[j] || n.wire[i] == n.hosts[i] && n.wire[j] == n.hosts[j] {
		return draw(n.hosts[i], n.hosts[j])
	}
	there, back := draw(n.hosts[i], n.wire[j]), draw(n.hosts[j], n.wire[i])
	return func() {
		there()
		back()
	}
}

// pair names an unordered pair of the network's nodes.
func pair(i, j int) [2]int {
	return [2]int{min(i, j), max(i, j)}
}

// setDelay draws the pair's one-way delay on the fabric, lifting the delay
// drawn for the pair before.
func (n *network) setDelay(i, j int, oneWay time.Duration) {
	if lift := n.taps[pair(i, j)]; lift != nil {
		lift()
	}
	n.taps[pair(i, j)] = n.drawPair(i, j, func(a, b netip.Addr) func() {
		return n.fab.Delay(a, b, oneWay)
	})
	n.oneWay[i][j], n.oneWay[j][i] = oneWay, oneWay
}

// cutPair cuts the pair on the fabric; the returned lift restores it.
func (n *network) cutPair(i, j int) func() {
	lift := n.drawPair(i, j, n.fab.Cut)
	n.cut[pair(i, j)] = true
	return func() {
		lift()
		delete(n.cut, pair(i, j))
	}
}

// delay returns the one-way delay the fabric holds between two of the
// network's nodes; false for a cut pair.
func (n *network) delay(i, j int) (time.Duration, bool) {
	if n.cut[pair(i, j)] {
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
	return awaitSettledEach(t, nodes, quiet, budget, func() {})
}

// awaitSettledEach is awaitSettled calling each at every read, once the
// bubble has parked.
func awaitSettledEach(
	t *testing.T, nodes []*testnetwork.Node, quiet, budget time.Duration, each func(),
) settling {

	t.Helper()
	ctx := t.Context()
	start := time.Now()
	var s settling
	var last string
	changed := start
	for {
		synctest.Wait()
		each()
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

// reachBudget bounds the wait for every pair to reach over its chosen path:
// twice the staleness window, past which a segment through a link gone
// elsewhere ranks behind every fresh candidate.
const reachBudget = 2 * scion.StaleAfter

// awaitReach reads every ordered pair's chosen path each settleSample until
// every one crosses only links up at both ends — the assessment's
// reachability — and fails the test, naming the pairs left, once budget
// passes first.
func awaitReach(t *testing.T, n *network, budget time.Duration) {
	t.Helper()
	start := time.Now()
	for {
		synctest.Wait()
		r := readPaths(t, n, false)
		var unreached []string
		for s := range n.nodes {
			for d := range n.nodes {
				if _, ok := r.chosen[[2]int{s, d}]; s != d && !ok {
					unreached = append(unreached, fmt.Sprintf("%d->%d", s, d))
				}
			}
		}
		if len(unreached) == 0 {
			return
		}
		if time.Since(start) >= budget {
			t.Fatalf("%d pairs reached over no chosen path within %v: %s",
				len(unreached), budget, strings.Join(unreached, " "))
		}
		time.Sleep(settleSample)
	}
}

// settled reports whether every one of the nodes holds at least the floor
// of up links — a link to each peer its directories name, where they name
// fewer — and the up links established at both ends among them connect
// them all.
func settled(ctx context.Context, nodes []*testnetwork.Node) bool {
	for _, n := range nodes {
		if upLinks(ctx, n) < min(measured.NeighborFloor, namedPeers(n)) {
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

// namedPeers counts the peers the node's directories name.
func namedPeers(n *testnetwork.Node) int {
	self := n.App().IA()
	named := make(map[addr.IA]bool)
	for _, s := range n.App().Bus().Directory().Latest().Scopes() {
		for _, e := range s.Entries() {
			if !e.IA.Equal(self) {
				named[e.IA] = true
			}
		}
	}
	return len(named)
}

// rendezvousWatch hears each node's rendezvous socket on the fabric, from
// the moment it is drawn.
type rendezvousWatch map[*testnetwork.Node]func(src netip.Addr) bool

// watchRendezvous draws a watch on each node's rendezvous socket.
func watchRendezvous(fab *fabric.Fabric, nodes []*testnetwork.Node) rendezvousWatch {
	w := make(rendezvousWatch, len(nodes))
	for _, n := range nodes {
		w[n] = fab.Watch(netip.AddrPortFrom(n.Host(), measured.RendezvousPort))
	}
	return w
}

// probedBy reports whether the prober reached the node since the watch was
// drawn — a datagram of its own heard at the node's rendezvous socket, the
// probe that proves the prober's directory holds the node — or the node
// holds an entry aimed at the prober's host: a link, whose ends measure each
// other over it.
func (w rendezvousWatch) probedBy(ctx context.Context, n, prober *testnetwork.Node) bool {
	if w[n](prober.Host()) {
		return true
	}
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
