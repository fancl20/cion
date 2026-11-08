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

// rendezvousFrom returns the parent's rendezvous address as the node
// reaches it: a router's inside host from behind its NAT, the parent's
// advertised address otherwise.
func (n *network) rendezvousFrom(node, parent int) string {
	if inside, ok := n.inside[parent]; ok && n.wire[node] == n.hosts[parent] {
		return netip.AddrPortFrom(inside, measured.RendezvousPort).String()
	}
	return rendezvous(n.nodes[parent])
}

const (
	// settleQuiet is how long a link set must hold unchanged to count as
	// settled: twenty selection windows at the daemon's pacing.
	settleQuiet = 10 * time.Minute
	// settleSample spaces the reads of a settling link set.
	settleSample = 10 * time.Second
)

// network is a lab's booted network: its nodes, the founding core first,
// on the fabric's hosts — some behind NATs, where a lab draws them, and
// some on a NAT's router —
// the one-way delay the fabric holds between each pair, and the pairs cut.
type network struct {
	fab   *fabric.Fabric
	hosts []netip.Addr
	// wire holds each node's address on the wire, where its peers' packets
	// go: its host, or the gateway of the NAT it sits behind.
	wire []netip.Addr
	// inside holds each router's inside host, by node: where the nodes
	// behind its NAT reach it.
	inside map[int]netip.Addr
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
		inside: map[int]netip.Addr{},
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

// routedSite places the members behind one NAT of the behavior given,
// whose router the router node runs on: the router's host is the NAT's
// gateway, and an inside host drawn for it is where the members reach it.
// The router's packets to the members leave from its inside host and cross
// nothing, its packets to every other node leave from the gateway, and the
// members' packets to every other node leave from the gateway translated.
// A lab places a routed site before it boots the router or draws delays.
func (n *network) routedSite(
	t *testing.T, behavior fabric.Behavior, router int, members ...int,
) *fabric.NAT {

	t.Helper()
	n.inside[router] = testnetwork.HostSlot(t)
	inside := []netip.Addr{n.inside[router]}
	for _, i := range members {
		inside = append(inside, n.hosts[i])
	}
	b := n.fab.NAT(behavior, n.hosts[router], inside...)
	b.Router(n.inside[router])
	for _, i := range members {
		n.wire[i] = b.Gateway()
	}
	return b
}

// drawPair draws a tap for each direction the pair's packets take: from
// each node's host — the fabric shapes a packet before any NAT
// translates it — to the other's address on the wire. One tap covers both
// directions of a pair whose packets go host to host: two public
// nodes, two behind one NAT, or a router and a node behind its NAT, at the
// router's inside host. A pair across a router's NAT draws one direction
// alone, from the node behind it: the other's packets go to the gateway,
// which the router's own pair with the other node shapes.
func (n *network) drawPair(i, j int, draw func(a, b netip.Addr) func()) func() {
	if inside, ok := n.inside[i]; ok && n.wire[j] == n.hosts[i] {
		return draw(inside, n.hosts[j])
	}
	if inside, ok := n.inside[j]; ok && n.wire[i] == n.hosts[j] {
		return draw(n.hosts[i], inside)
	}
	if n.wire[i] == n.wire[j] || n.wire[i] == n.hosts[i] && n.wire[j] == n.hosts[j] {
		return draw(n.hosts[i], n.hosts[j])
	}
	if n.routed(n.wire[i]) {
		return draw(n.hosts[i], n.wire[j])
	}
	if n.routed(n.wire[j]) {
		return draw(n.hosts[j], n.wire[i])
	}
	there, back := draw(n.hosts[i], n.wire[j]), draw(n.hosts[j], n.wire[i])
	return func() {
		there()
		back()
	}
}

// routed reports whether a router holds the address: a gateway one of the
// network's nodes runs on.
func (n *network) routed(addr netip.Addr) bool {
	for router := range n.inside {
		if n.hosts[router] == addr {
			return true
		}
	}
	return false
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

// jitterPair draws a jitter of the given mean on the pair's packets on the
// fabric, beside its delay; the returned lift removes it.
func (n *network) jitterPair(i, j int, mean time.Duration) func() {
	return n.drawPair(i, j, func(a, b netip.Addr) func() {
		return n.fab.Jitter(a, b, mean)
	})
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

// awaitSettled reads the network's link set every settleSample until it
// holds unchanged for quiet with the network settled, and fails the test
// once budget passes first.
func awaitSettled(t *testing.T, n *network, quiet, budget time.Duration) settling {
	t.Helper()
	return awaitSettledEach(t, n, quiet, budget, func() {})
}

// awaitSettledEach is awaitSettled calling each at every read, once the
// bubble has parked.
func awaitSettledEach(
	t *testing.T, n *network, quiet, budget time.Duration, each func(),
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
		if now := linkSet(ctx, n.nodes); now != last {
			last, changed = now, time.Now()
			s.changes++
		}
		if time.Since(changed) >= quiet && n.settled(ctx, n.nodes) {
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
// of up links — a link to each peer its directories name that the network
// has not cut it from, where those are fewer — and the up links established
// at both ends among them connect them all.
func (n *network) settled(ctx context.Context, nodes []*testnetwork.Node) bool {
	for _, x := range nodes {
		if upLinks(ctx, x) < min(measured.NeighborFloor, n.reachablePeers(x)) {
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

// linkDelays returns, by peer, the one-way delay node i's selection last
// measured on each of its established links to the network's nodes, and
// the delay the network drew for the pair.
func linkDelays(t *testing.T, n *network, i int) (measured, drawn map[int]time.Duration) {
	t.Helper()
	index := make(map[addr.IA]int, len(n.nodes))
	for j, node := range n.nodes {
		index[node.App().IA()] = j
	}
	entries, err := n.nodes[i].App().Links().All(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	latencies := n.nodes[i].App().Bus().Latencies().Latest()
	measured, drawn = map[int]time.Duration{}, map[int]time.Duration{}
	for _, l := range entries {
		j, ok := index[l.NeighborIA]
		if !ok || l.State != links.StateEstablished {
			continue
		}
		measured[j] = latencies.Of(l.IfID)
		drawn[j], _ = n.delay(i, j)
	}
	return measured, drawn
}

// reachablePeers counts the peers the node's directories name that the
// network has not cut it from.
func (n *network) reachablePeers(x *testnetwork.Node) int {
	index := make(map[addr.IA]int, len(n.nodes))
	for i, node := range n.nodes {
		index[node.App().IA()] = i
	}
	self := x.App().IA()
	i := index[self]
	named := make(map[addr.IA]bool)
	for _, s := range x.App().Bus().Directory().Latest().Scopes() {
		for _, e := range s.Entries() {
			if j, ok := index[e.IA]; e.IA.Equal(self) || ok && n.cut[pair(i, j)] {
				continue
			}
			named[e.IA] = true
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
