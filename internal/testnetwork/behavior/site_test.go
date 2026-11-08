package behavior

import (
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/bus"
)

// The site network: the founder 0, the authoritative core 1, and the public
// node 2, 10ms apart, and the site's nodes 3 to 6 behind one port-restricted
// NAT, 2ms apart and 20ms from every public node. Each node joins through the
// neighbors one of the site's three ways of joining gives it.
var (
	siteOrder   = []int{1, 2, 3, 4, 5, 6}
	siteMembers = []int{3, 4, 5, 6}
	// siteJoins are the ways the site's nodes join: every one through a
	// public parent; 5 through 3 and 6 through 4, each at its parent's
	// inside address; or each after the first through a public parent and a
	// site node already joined, at its inside address.
	siteJoins = []struct {
		name    string
		parents map[int][]int
	}{
		{name: "outside", parents: map[int][]int{1: {0}, 2: {0}, 3: {1}, 4: {2}, 5: {0}, 6: {2}}},
		{name: "inside", parents: map[int][]int{1: {0}, 2: {0}, 3: {1}, 4: {2}, 5: {3}, 6: {4}}},
		{name: "both", parents: map[int][]int{1: {0}, 2: {0}, 3: {1}, 4: {2, 3}, 5: {0, 3}, 6: {2, 4}}},
	}
)

// siteWatch is how long a benchmark reads the site network beyond its
// settling.
const siteWatch = 10 * time.Minute

// bootSite boots the site network, each node joining through its parents,
// and returns it with the site's NAT. The one-way delays are the
// NAT network's: a pair of public nodes, a pair of site nodes, and a
// pair across.
func bootSite(
	t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA, parents map[int][]int,
) (*network, *fabric.NAT) {

	t.Helper()
	n := newNetwork(t, fab, 7)
	site := n.site(t, fabric.PortRestricted, siteMembers...)
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			n.setDelay(i, j, natOneWay(i, j))
		}
	}
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		// The founder's vote admits the authoritative core.
		cfg.EnrollAuth = "cidrs=127.0.0.0/8"
	})
	for _, i := range siteOrder {
		var neighbors []string
		for _, parent := range parents[i] {
			neighbors = append(neighbors, rendezvous(n.nodes[parent]))
		}
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = neighbors
			cfg.RootCAs = wpki.Pool
			cfg.Core = i == 1
		})
	}
	return n, site
}

// insideLinks counts the site's pairs holding an up link established at
// both ends: links at their inside addresses, for the NAT carries no
// site node's packet back inside.
func insideLinks(t *testing.T, n *network) int {
	t.Helper()
	ctx := t.Context()
	count := 0
	for k, i := range siteMembers {
		for _, j := range siteMembers[k+1:] {
			if upTo(ctx, n.nodes[i], n.nodes[j]) && upTo(ctx, n.nodes[j], n.nodes[i]) {
				count++
			}
		}
	}
	return count
}

// TestSiteNetworkReaches checks what the site network serves, in each way
// of joining: it settles, and every ordered pair reaches over its chosen
// path and answers a ping — the site's nodes over their inside links or
// through a public node. The founder's views hold no site node's inside
// address in any way; joined both ways, the site's nodes share a directory
// the founder does not hold, where each names its inside address.
func TestSiteNetworkReaches(t *testing.T) {
	for _, joins := range siteJoins {
		t.Run(joins.name, func(t *testing.T) {
			testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
				n, _ := bootSite(t, fab, wpki, joins.parents)
				awaitPinned(t, n, allNodes(n)...)
				awaitSettled(t, n, settleQuiet, natBudget)
				awaitReach(t, n, reachBudget)
				awaitPings(t, n, allNodes(n), reachBudget)
				if inside := foundersInsideHosts(n); len(inside) != 0 {
					t.Errorf("the founder's views hold the inside addresses of %v", inside)
				}
				if joins.name == "both" && !siteScoped(n) {
					t.Error("the site's nodes share no directory of their inside addresses " +
						"the founder does not hold")
				}
			})
		})
	}
}

// foundersInsideHosts returns the site nodes whose inside address an entry
// the founder's views show names.
func foundersInsideHosts(n *network) []int {
	view := n.nodes[0].App().Bus().Directory().Latest()
	var out []int
	for _, i := range siteMembers {
		for _, s := range view.Scopes() {
			e, ok := s.Entry(n.nodes[i].App().IA())
			if !ok {
				continue
			}
			for _, a := range e.Addresses {
				if a.RendezvousAddr.Addr() == n.hosts[i] {
					out = append(out, i)
				}
			}
		}
	}
	return out
}

// siteScoped reports whether the site's nodes hold a directory the founder
// does not, whose view at every site node shows each site node's entry
// naming its inside address.
func siteScoped(n *network) bool {
	founder := n.nodes[0].App().Bus().Directory().Latest()
	first := n.nodes[siteMembers[0]].App().Bus().Directory().Latest()
	for _, candidate := range first.Scopes() {
		if _, ok := founder.Scope(candidate.ID()); ok {
			continue
		}
		shared := true
		for _, i := range siteMembers {
			s, ok := n.nodes[i].App().Bus().Directory().Latest().Scope(candidate.ID())
			if !ok {
				shared = false
				break
			}
			for _, j := range siteMembers {
				e, ok := s.Entry(n.nodes[j].App().IA())
				if !ok || len(e.Addresses) == 0 || e.Addresses[0].RendezvousAddr.Addr() != n.hosts[j] {
					shared = false
				}
			}
		}
		if shared {
			return true
		}
	}
	return false
}

// TestBenchSiteSettled benchmarks the site network once it settles, in each
// way of joining: the standard assessment, beside the site's pairs linked at
// their inside addresses.
func TestBenchSiteSettled(t *testing.T) {
	requireBench(t)
	for _, joins := range siteJoins {
		t.Run(joins.name, func(t *testing.T) {
			testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
				n, _ := bootSite(t, fab, wpki, joins.parents)
				awaitPinned(t, n, allNodes(n)...)
				s := awaitSettled(t, n, settleQuiet, natBudget)
				report(t, "SiteSettled/joins="+joins.name, s, assess(t, n, penalty, 0))
				reportLinks(t, "SiteLinks/joins="+joins.name, n)
			})
		})
	}
}

// reportLinks reports the site's pairs linked at their inside addresses,
// of all its pairs.
func reportLinks(t *testing.T, name string, n *network) {
	t.Helper()
	pairs := len(siteMembers) * (len(siteMembers) - 1) / 2
	reportValues(t, name,
		benchValue{float64(insideLinks(t, n)), "inside-links"},
		benchValue{float64(pairs), "site-pairs"},
	)
}

// siteReads records the founder's views read by read: for each site node,
// the host its latest entry names first — its inside address or the site's
// gateway — and the tag that address's report earns, counting the changes
// of each, those after the network settled, and the reads that found the
// inside address.
type siteReads struct {
	n       *network
	gateway netip.Addr
	settled bool
	nodes   map[int]*nodeReads
}

// nodeReads is one site node's record; seen marks its first entry read.
type nodeReads struct {
	seen        bool
	host, tag   string
	hostChanges int
	tagChanges  int
	lateChanges int
	insideReads int
}

func newSiteReads(n *network, gateway netip.Addr) *siteReads {
	r := &siteReads{n: n, gateway: gateway, nodes: make(map[int]*nodeReads)}
	for _, i := range siteMembers {
		r.nodes[i] = &nodeReads{}
	}
	return r
}

// read records one read of the founder's views; a node the views hold no
// entry naming an address of records nothing.
func (r *siteReads) read() {
	directory := r.n.nodes[0].App().Bus().Directory().Latest()
	for _, i := range siteMembers {
		e, ok := directory.Latest(r.n.nodes[i].App().IA())
		if !ok || len(e.Addresses) == 0 {
			continue
		}
		host := "other"
		switch e.Addresses[0].RendezvousAddr.Addr() {
		case r.n.hosts[i]:
			host = "inside"
		case r.gateway:
			host = "gateway"
		}
		tag := tagOf(e.Addresses[0].Reach)
		nr := r.nodes[i]
		if host == "inside" {
			nr.insideReads++
		}
		if nr.seen && host != nr.host {
			nr.hostChanges++
			if r.settled {
				nr.lateChanges++
			}
		}
		if nr.seen && tag != nr.tag {
			nr.tagChanges++
			if r.settled {
				nr.lateChanges++
			}
		}
		nr.seen, nr.host, nr.tag = true, host, tag
	}
}

// tagOf names the tag a report earns on the portal: NAT when peers cannot
// dial the node behind a NAT, Degraded when they cannot dial it
// otherwise, none while they can or nothing was observed.
func tagOf(r bus.Reach) string {
	switch {
	case !r.RendezvousUnanswered:
		return "none"
	case r.BehindNAT:
		return "nat"
	default:
		return "degraded"
	}
}

// TestBenchSiteHosts benchmarks the hosts the site's nodes publish and the
// tags their reports earn, as the founder's views hold them,
// in each way of joining: read each settleSample from the boot until the
// network settles and siteWatch beyond, beside the site's pairs linked at
// their inside addresses at the end.
func TestBenchSiteHosts(t *testing.T) {
	requireBench(t)
	for _, joins := range siteJoins {
		t.Run(joins.name, func(t *testing.T) {
			testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
				n, site := bootSite(t, fab, wpki, joins.parents)
				reads := newSiteReads(n, site.Gateway())
				awaitSettledEach(t, n, settleQuiet, natBudget, reads.read)
				reads.settled = true
				watch := time.Now()
				for time.Since(watch) < siteWatch {
					time.Sleep(settleSample)
					synctest.Wait()
					reads.read()
				}
				for _, i := range siteMembers {
					nr := reads.nodes[i]
					reportValues(t, fmt.Sprintf("SiteHosts/joins=%s/node=%d", joins.name, i),
						benchValue{float64(nr.hostChanges), "host-changes"},
						benchValue{float64(nr.insideReads), "inside-reads"},
						benchValue{float64(nr.tagChanges), "tag-changes"},
						benchValue{float64(nr.lateChanges), "late-changes"},
						benchValue{flag(nr.host == "gateway"), "gateway-final"},
						benchValue{flag(nr.tag == "nat"), "nat-final"},
					)
				}
				reportLinks(t, "SiteHostsLinks/joins="+joins.name, n)
			})
		})
	}
}

// The gateway site network: the site network with the authoritative core 1
// on the site's router — it holds the NAT's gateway, 20ms from the founder
// and the public node 2, and an inside host, 2ms from the site's nodes —
// bound to the wildcard, as the daemon is by default. Each site node joins
// through core 1 alone, at its inside host.
var gatewayParents = map[int][]int{1: {0}, 2: {0}, 3: {1}, 4: {1}, 5: {1}, 6: {1}}

// gatewayRouter is the gateway site network's router: core 1.
const gatewayRouter = 1

// gatewayOneWay is the one-way delay between two of the gateway site
// network's nodes: 10ms between the public nodes, 2ms on the site's side,
// core 1 among them, and 20ms across.
func gatewayOneWay(i, j int) time.Duration {
	public := func(k int) bool { return k == 0 || k == 2 }
	switch {
	case public(i) && public(j):
		return 10 * time.Millisecond
	case !public(i) && !public(j):
		return 2 * time.Millisecond
	default:
		return 20 * time.Millisecond
	}
}

// bootGatewaySite boots the gateway site network, the site's nodes behind
// a port-restricted NAT whose router core 1 runs on.
func bootGatewaySite(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) *network {
	t.Helper()
	n := newNetwork(t, fab, 7)
	n.routedSite(t, fabric.PortRestricted, gatewayRouter, siteMembers...)
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			n.setDelay(i, j, gatewayOneWay(i, j))
		}
	}
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		// The founder's vote admits the authoritative core.
		cfg.EnrollAuth = "cidrs=127.0.0.0/8"
	})
	for _, i := range siteOrder {
		var neighbors []string
		for _, parent := range gatewayParents[i] {
			neighbors = append(neighbors, n.rendezvousFrom(i, parent))
		}
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = neighbors
			cfg.RootCAs = wpki.Pool
			cfg.Core = i == gatewayRouter
			if i == gatewayRouter {
				cfg.Control = testnetwork.Wildcard(cfg.Control)
			}
		})
	}
	return n
}

// TestGatewaySiteReaches checks what the gateway site network serves: it
// settles, and every ordered pair reaches over its chosen path and answers
// a ping — the site's nodes reaching the public ones through core 1, which
// measures each of its links at the delay the network drew. Core 1's entry
// names the gateway in the founder's directory, untagged, and its inside
// host in the directory the site's nodes share, each naming its inside
// address there, which the founder does not hold; the founder's views hold
// no site node's inside address; and the founder's membership listing — the
// console's node list — holds every node, the site's included.
func TestGatewaySiteReaches(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootGatewaySite(t, fab, wpki)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n, settleQuiet, natBudget)
		awaitReach(t, n, reachBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		if measured, drawn := linkDelays(t, n, gatewayRouter); !maps.Equal(measured, drawn) {
			t.Errorf("core 1 measures its links at %v by peer, want the delays drawn, %v", measured, drawn)
		}
		if public, inside := routerHosts(n); public != n.hosts[gatewayRouter] ||
			inside != n.inside[gatewayRouter] {
			t.Errorf("core 1's entries name %v beside the founder's and %v beside the site's, "+
				"want the gateway %v and the inside host %v",
				public, inside, n.hosts[gatewayRouter], n.inside[gatewayRouter])
		}
		if got := reports(n)[gatewayRouter]; got != (bus.Reach{}) {
			t.Errorf("the founder's views report core 1 as %+v, want neither behind a NAT nor unanswered", got)
		}
		if !siteScoped(n) {
			t.Error("the site's nodes share no directory of their inside addresses " +
				"the founder does not hold")
		}
		if inside := foundersInsideHosts(n); len(inside) != 0 {
			t.Errorf("the founder's views hold the inside addresses of %v", inside)
		}
		if unlisted := unlistedMembers(t, n); len(unlisted) != 0 {
			t.Errorf("the founder lists no membership of %v", unlisted)
		}
	})
}

// unlistedMembers returns the nodes the founder's membership listing leaves
// out.
func unlistedMembers(t *testing.T, n *network) []addr.IA {
	t.Helper()
	list, err := n.nodes[0].App().Memberships(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[addr.IA]bool, len(list))
	for _, m := range list {
		listed[m.IA] = true
	}
	var unlisted []addr.IA
	for _, node := range n.nodes {
		if ia := node.App().IA(); !listed[ia] {
			unlisted = append(unlisted, ia)
		}
	}
	return unlisted
}

// routerHosts returns the hosts core 1's views show its own entries naming
// first: in the directory that holds the founder's entry, and in one that
// holds every site node's; the zero address where it holds no such entry.
func routerHosts(n *network) (public, inside netip.Addr) {
	router := n.nodes[gatewayRouter].App().IA()
	for _, s := range n.nodes[gatewayRouter].App().Bus().Directory().Latest().Scopes() {
		e, ok := s.Entry(router)
		if !ok || len(e.Addresses) == 0 {
			continue
		}
		if _, ok := s.Entry(n.nodes[0].App().IA()); ok {
			public = e.Addresses[0].RendezvousAddr.Addr()
			continue
		}
		site := true
		for _, i := range siteMembers {
			if _, ok := s.Entry(n.nodes[i].App().IA()); !ok {
				site = false
			}
		}
		if site {
			inside = e.Addresses[0].RendezvousAddr.Addr()
		}
	}
	return public, inside
}

// TestBenchGatewaySiteSettled benchmarks the gateway site network once it
// settles: the standard assessment, beside the site's pairs linked at their
// inside addresses.
func TestBenchGatewaySiteSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n := bootGatewaySite(t, fab, wpki)
		awaitPinned(t, n, allNodes(n)...)
		s := awaitSettled(t, n, settleQuiet, natBudget)
		report(t, "GatewaySiteSettled", s, assess(t, n, penalty, 0))
		reportLinks(t, "GatewaySiteLinks", n)
	})
}
