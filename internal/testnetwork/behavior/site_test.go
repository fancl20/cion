package behavior

import (
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/bus"
)

// The site network: the founder 0, the authoritative core 1, and the public
// node 2, 10ms apart, and the site's nodes 3 to 6 behind one port-restricted
// NAT, 2ms apart and 20ms from every public node. Each node joins
// through its parent alone, in one of the site's two ways of joining.
var (
	siteOrder   = []int{1, 2, 3, 4, 5, 6}
	siteMembers = []int{3, 4, 5, 6}
	// siteJoins are the ways the site's nodes join: every one through a
	// public parent, or 5 through 3 and 6 through 4, each at its parent's
	// inside address.
	siteJoins = []struct {
		name    string
		parents map[int]int
	}{
		{name: "outside", parents: map[int]int{1: 0, 2: 0, 3: 1, 4: 2, 5: 0, 6: 2}},
		{name: "inside", parents: map[int]int{1: 0, 2: 0, 3: 1, 4: 2, 5: 3, 6: 4}},
	}
)

// siteWatch is how long a benchmark reads the site network beyond its
// settling.
const siteWatch = 10 * time.Minute

// bootSite boots the site network, each node joining through its parent,
// and returns it with the site's NAT. The one-way delays are the
// NAT network's: a pair of public nodes, a pair of site nodes, and a
// pair across.
func bootSite(
	t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA, parents map[int]int,
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
		parent := n.nodes[parents[i]]
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(parent)}
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
// through a public node.
func TestSiteNetworkReaches(t *testing.T) {
	for _, joins := range siteJoins {
		t.Run(joins.name, func(t *testing.T) {
			testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
				n, _ := bootSite(t, fab, wpki, joins.parents)
				awaitPinned(t, n, allNodes(n)...)
				awaitSettled(t, n.nodes, settleQuiet, natBudget)
				awaitReach(t, n, reachBudget)
				awaitPings(t, n, allNodes(n), reachBudget)
			})
		})
	}
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
				s := awaitSettled(t, n.nodes, settleQuiet, natBudget)
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

// siteReads records the founder's view of the directory read by read: for
// each site node, the host its entry publishes — its inside address or the
// site's gateway — and the tag its report earns, counting the changes of
// each, those after the network settled, and the reads that found the
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

// read records one read of the founder's view of the directory; a node the
// view holds no entry of records nothing.
func (r *siteReads) read() {
	directory := r.n.nodes[0].App().Bus().Directory().Latest()
	for _, i := range siteMembers {
		e, ok := directory.Entry(r.n.nodes[i].App().IA())
		if !ok {
			continue
		}
		host := "other"
		switch e.RendezvousAddr.Addr() {
		case r.n.hosts[i]:
			host = "inside"
		case r.gateway:
			host = "gateway"
		}
		tag := tagOf(e.Reach)
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
// tags their reports earn, as the founder's view of the directory holds them,
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
				awaitSettledEach(t, n.nodes, settleQuiet, natBudget, reads.read)
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
