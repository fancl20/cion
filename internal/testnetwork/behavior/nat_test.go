package behavior

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The NAT network: the founder 0, the authoritative core 1, and the
// public node 2, 10ms apart, and nodes 3 to 6, each behind a NAT of its
// own, 2ms apart and 20ms from every public node. Each node joins through
// its parent alone; 5's parent is the founder.
var (
	natParent = map[int]int{1: 0, 2: 0, 3: 1, 4: 2, 5: 0, 6: 2}
	natOrder  = []int{1, 2, 3, 4, 5, 6}
	// coneNATs places nodes 3 to 6 behind the NATs the network serves
	// through today.
	coneNATs = map[int]fabric.Behavior{
		3: fabric.FullCone, 4: fabric.FullCone, 5: fabric.PortRestricted, 6: fabric.PortRestricted,
	}
)

const (
	// natBudget bounds the NAT network's join and settling
	// in virtual time.
	natBudget = 30 * time.Minute
	// natWatch is how long a benchmark reads the NAT
	// network's answer to a change.
	natWatch = 10 * time.Minute
	// natCores is the count of cores the network's TRC names once
	// the authoritative core joined.
	natCores = 2
	// natRepunch bounds, in virtual time, a remapped node's punched link's
	// fall and its return.
	natRepunch = 30 * time.Second
)

// natOneWay is the one-way delay between two of the NAT
// network's nodes.
func natOneWay(i, j int) time.Duration {
	public := func(k int) bool { return k < 3 }
	switch {
	case public(i) && public(j):
		return 10 * time.Millisecond
	case !public(i) && !public(j):
		return 2 * time.Millisecond
	default:
		return 20 * time.Millisecond
	}
}

// bootNAT boots the NAT network, nodes 3 to 6 behind NATs of the
// behaviors given, and returns it with the NATs.
func bootNAT(
	t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA, behaviors map[int]fabric.Behavior,
) (*network, map[int]*fabric.NAT) {

	t.Helper()
	n := newNetwork(t, fab, 7)
	nats := n.placeNATs(t, behaviors)
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
	for _, i := range natOrder {
		parent := n.nodes[natParent[i]]
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(parent)}
			cfg.RootCAs = wpki.Pool
			cfg.Core = i == 1
		})
	}
	return n, nats
}

// pinnedCores is the count of cores the node's newest pinned TRC names;
// zero before any pin.
func pinnedCores(t *testing.T, node *testnetwork.Node) int {
	t.Helper()
	trc, err := node.App().TrustDB().SignedTRC(t.Context(), cppki.TRCID{
		ISD: node.App().IA().ISD(), Base: scrypto.LatestVer, Serial: scrypto.LatestVer,
	})
	if err != nil || trc.IsZero() {
		return 0
	}
	return len(trc.TRC.CoreASes)
}

// awaitPinned waits for each of the named nodes to pin the TRC naming both
// cores.
func awaitPinned(t *testing.T, n *network, which ...int) {
	t.Helper()
	testnetwork.PollVirtual(t, natBudget, "the nodes to pin the TRC naming both cores", func() bool {
		for _, i := range which {
			if pinnedCores(t, n.nodes[i]) != natCores {
				return false
			}
		}
		return true
	})
}

// pings reports whether s's single ping to d's host gets its answer.
func pings(t *testing.T, n *network, s, d int) bool {
	t.Helper()
	conn, err := n.nodes[s].App().Conn(0)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	report, err := ping.Run(t.Context(), ping.Config{
		Conn:     conn,
		Paths:    n.nodes[s].App().Provider(),
		Dst:      n.nodes[d].App().IA(),
		DstHost:  n.nodes[d].Host(),
		Count:    1,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	return err == nil && report.Received == 1
}

// pingsWith counts the peers among the given nodes whose pings to node i
// get their answers, and those i's pings to get theirs.
func pingsWith(t *testing.T, n *network, i int, peers []int) (to, from int) {
	t.Helper()
	for _, p := range peers {
		if p == i {
			continue
		}
		if pings(t, n, p, i) {
			to++
		}
		if pings(t, n, i, p) {
			from++
		}
	}
	return to, from
}

// pingAll pings every ordered pair of the given nodes each settleSample
// until every one gets its answer or budget passes, and returns how long it
// read and the pairs whose last ping went unanswered.
func pingAll(t *testing.T, n *network, which []int, budget time.Duration) (time.Duration, []string) {
	t.Helper()
	start := time.Now()
	for {
		synctest.Wait()
		var silent []string
		for _, s := range which {
			for _, d := range which {
				if s != d && !pings(t, n, s, d) {
					silent = append(silent, fmt.Sprintf("%d->%d", s, d))
				}
			}
		}
		if len(silent) == 0 || time.Since(start) >= budget {
			return time.Since(start), silent
		}
		time.Sleep(settleSample)
	}
}

// awaitPings fails the test, naming the pairs left, unless every ordered
// pair of the given nodes answers its ping within budget.
func awaitPings(t *testing.T, n *network, which []int, budget time.Duration) {
	t.Helper()
	if _, silent := pingAll(t, n, which, budget); len(silent) != 0 {
		t.Fatalf("%d pairs' pings went unanswered within %v: %s",
			len(silent), budget, strings.Join(silent, " "))
	}
}

// establishedLinks counts the node's established links.
func establishedLinks(t *testing.T, node *testnetwork.Node) int {
	t.Helper()
	entries, err := node.App().Links().All(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, l := range entries {
		if l.State == links.StateEstablished {
			count++
		}
	}
	return count
}

// holdsLinkTo reports whether the node holds an established link to the
// neighbor.
func holdsLinkTo(t *testing.T, node, neighbor *testnetwork.Node) bool {
	t.Helper()
	l, err := node.App().Links().ByNeighbor(t.Context(), neighbor.App().IA())
	return err == nil && l != nil && l.State == links.StateEstablished
}

// allNodes lists the indices of the network's nodes.
func allNodes(n *network) []int {
	which := make([]int, len(n.nodes))
	for i := range which {
		which[i] = i
	}
	return which
}

// reports maps each node's index to the reach the founder's views report of
// its first address, by the node's latest entry.
func reports(n *network) map[int]bus.Reach {
	directory := n.nodes[0].App().Bus().Directory().Latest()
	got := make(map[int]bus.Reach, len(n.nodes))
	for i, node := range n.nodes {
		if e, ok := directory.Latest(node.App().IA()); ok && len(e.Addresses) != 0 {
			got[i] = e.Addresses[0].Reach
		} else {
			got[i] = bus.Reach{}
		}
	}
	return got
}

// awaitReports fails the test, naming what differs, unless the founder's
// view of the directory reports each node's reach as want holds it within
// budget.
func awaitReports(t *testing.T, n *network, want map[int]bus.Reach, budget time.Duration) {
	t.Helper()
	start := time.Now()
	for {
		synctest.Wait()
		diff := cmp.Diff(want, reports(n))
		if diff == "" {
			return
		}
		if time.Since(start) >= budget {
			t.Fatalf("the founder's view reports mismatch after %v (-want +got):\n%s",
				budget, diff)
		}
		time.Sleep(settleSample)
	}
}

// awaitNATLinks fails the test, naming the pairs left, unless every pair of
// the given nodes behind NATs holds an established link at both ends within
// budget.
func awaitNATLinks(t *testing.T, n *network, which []int, budget time.Duration) {
	t.Helper()
	start := time.Now()
	for {
		synctest.Wait()
		var unlinked []string
		for a, i := range which {
			for _, j := range which[a+1:] {
				if !holdsLinkTo(t, n.nodes[i], n.nodes[j]) || !holdsLinkTo(t, n.nodes[j], n.nodes[i]) {
					unlinked = append(unlinked, fmt.Sprintf("%d-%d", i, j))
				}
			}
		}
		if len(unlinked) == 0 {
			return
		}
		if time.Since(start) >= budget {
			t.Fatalf("%d pairs of nodes behind NATs hold no link within %v: %s",
				len(unlinked), budget, strings.Join(unlinked, " "))
		}
		time.Sleep(settleSample)
	}
}

// TestNATNetworkReaches checks what the NAT network serves behind
// full-cone and port-restricted NATs: it settles, and every ordered pair
// reaches over its chosen path and answers a ping — the links of the nodes
// behind NATs to the public nodes carrying their traffic both ways, and
// every pair of nodes behind NATs holding a link punched through both
// NATs. The founder's view of the directory reports each node behind a NAT
// as behind one with its published rendezvous address unanswered, and each
// public node as neither.
func TestNATNetworkReaches(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootNAT(t, fab, wpki, coneNATs)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, natBudget)
		awaitReach(t, n, reachBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		awaitNATLinks(t, n, []int{3, 4, 5, 6}, reachBudget)
		nat := bus.Reach{BehindNAT: true, RendezvousUnanswered: true}
		awaitReports(t, n, map[int]bus.Reach{
			0: {}, 1: {}, 2: {}, 3: nat, 4: nat, 5: nat, 6: nat,
		}, reachBudget)
	})
}

// TestNATNetworkRecovers checks that each link's locator follows the
// link's own flow, and that a punched link a remap took down is punched
// again: a node behind a symmetric NAT joins, and every ordered pair
// answers a ping; again once a NAT drops node 3's mappings — its link to
// node 5, behind a port-restricted NAT, going down and, with its link to
// node 4, standing again within natRepunch on the interfaces it had; and
// again once node 2, the parent of 4 and 6, restarts on its state.
func TestNATNetworkRecovers(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		behaviors := maps.Clone(coneNATs)
		behaviors[6] = fabric.Symmetric
		n, nats := bootNAT(t, fab, wpki, behaviors)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, natBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		awaitNATLinks(t, n, []int{3, 4, 5}, reachBudget)

		const rebound = 3
		ends := linkEnds(t, n, rebound, 4, 5)
		nats[rebound].Rebind()
		testnetwork.PollVirtual(t, natRepunch, "node 3's link to node 5 to go down", func() bool {
			return !n.nodes[rebound].App().Monitor().Up(ends[5][0])
		})
		testnetwork.PollVirtual(t, natRepunch, "node 3's links to nodes 4 and 5 to stand again",
			func() bool { return linksStand(t, n, rebound, ends) })
		awaitPings(t, n, allNodes(n), natWatch)

		restart(t, fab, wpki, n, 2)
		awaitPings(t, n, allNodes(n), natWatch)
	})
}

// linkTo returns the node's live entry for the neighbor, nil when it holds
// none.
func linkTo(t *testing.T, node, neighbor *testnetwork.Node) *links.Link {
	t.Helper()
	l, err := node.App().Links().ByNeighbor(t.Context(), neighbor.App().IA())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// linkEnds returns the interface IDs of the node's links to the peers, by
// peer: the node's own, then the peer's.
func linkEnds(t *testing.T, n *network, node int, peers ...int) map[int][2]uint16 {
	t.Helper()
	ends := make(map[int][2]uint16, len(peers))
	for _, p := range peers {
		ends[p] = [2]uint16{
			linkTo(t, n.nodes[node], n.nodes[p]).IfID,
			linkTo(t, n.nodes[p], n.nodes[node]).IfID,
		}
	}
	return ends
}

// linksStand reports whether each of the node's links to the peers is
// established and up at both ends, on the interfaces given.
func linksStand(t *testing.T, n *network, node int, ends map[int][2]uint16) bool {
	t.Helper()
	for p, ifIDs := range ends {
		mine, theirs := linkTo(t, n.nodes[node], n.nodes[p]), linkTo(t, n.nodes[p], n.nodes[node])
		if mine == nil || theirs == nil || mine.IfID != ifIDs[0] || theirs.IfID != ifIDs[1] ||
			mine.State != links.StateEstablished || theirs.State != links.StateEstablished ||
			!n.nodes[node].App().Monitor().Up(mine.IfID) || !n.nodes[p].App().Monitor().Up(theirs.IfID) {
			return false
		}
	}
	return true
}

// restart stops the node and boots it again on its state at once.
func restart(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA, n *network, i int) {
	t.Helper()
	host, state := n.nodes[i].Host(), n.nodes[i].StateDir()
	n.nodes[i].Stop(t)
	n.nodes[i] = testnetwork.BootInBubble(t, fab, host, func(cfg *services.NodeConfig) {
		cfg.State = state
		cfg.RootCAs = wpki.Pool
	})
}

// TestBenchNATSettled benchmarks the NAT network once it
// settles behind full-cone and port-restricted NATs.
func TestBenchNATSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootNAT(t, fab, wpki, coneNATs)
		awaitPinned(t, n, allNodes(n)...)
		s := awaitSettled(t, n.nodes, settleQuiet, natBudget)
		report(t, "NATSettled", s, assess(t, n, penalty, 0))
	})
}

// TestBenchNATRebind benchmarks a NAT dropping a settled
// node's mappings: the pings to and from node 3 are read each settleSample
// until every peer's answer returns or natWatch passes, beside the
// links node 3 still holds established.
func TestBenchNATRebind(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, nats := bootNAT(t, fab, wpki, coneNATs)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, natBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		const rebound = 3
		peers := len(n.nodes) - 1

		nats[rebound].Rebind()
		start := time.Now()
		recovery, recovered := natWatch, false
		var to, from int
		for {
			synctest.Wait()
			to, from = pingsWith(t, n, rebound, allNodes(n))
			if to == peers && from == peers {
				recovery, recovered = time.Since(start), true
				break
			}
			if time.Since(start) >= natWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "NATRebind",
			benchValue{recovery.Seconds(), "recover-s"},
			benchValue{flag(recovered), "recovered"},
			benchValue{float64(to), "pinged-to"},
			benchValue{float64(from), "pinged-from"},
			benchValue{float64(peers), "peers"},
			benchValue{float64(establishedLinks(t, n.nodes[rebound])), "links"},
		)
	})
}

// TestBenchNATSymmetric benchmarks a node behind a symmetric
// NAT: whether it pins the TRC naming both cores and answers every
// peer's ping within natWatch of the others' pins.
func TestBenchNATSymmetric(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		behaviors := maps.Clone(coneNATs)
		const symmetric = 6
		behaviors[symmetric] = fabric.Symmetric
		n, _ := bootNAT(t, fab, wpki, behaviors)
		awaitPinned(t, n, 0, 1, 2, 3, 4, 5)
		peers := len(n.nodes) - 1

		start := time.Now()
		join, joined := natWatch, false
		for {
			synctest.Wait()
			if pinnedCores(t, n.nodes[symmetric]) == natCores {
				if to, from := pingsWith(t, n, symmetric, allNodes(n)); to == peers && from == peers {
					join, joined = time.Since(start), true
					break
				}
			}
			if time.Since(start) >= natWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "NATSymmetric",
			benchValue{join.Seconds(), "join-s"},
			benchValue{flag(joined), "joined"},
			benchValue{flag(pinnedCores(t, n.nodes[symmetric]) == natCores), "pinned"},
			benchValue{float64(establishedLinks(t, n.nodes[symmetric])), "links"},
		)
	})
}

// readReach reads every ordered pair of the given nodes' chosen path each
// settleSample until watch passes, each lookup bounded by lookupBudget, and
// returns the fewest pairs a read reached over the formed links, and the
// slowest and the mean lookup.
func readReach(
	t *testing.T, n *network, which []int, watch time.Duration,
) (fewest int, slowest, mean time.Duration) {

	t.Helper()
	fewest = len(which) * (len(which) - 1)
	var total time.Duration
	lookups := 0
	start := time.Now()
	for {
		synctest.Wait()
		f := formedLinks(t, n)
		reached := 0
		for _, s := range which {
			for _, d := range which {
				if s == d {
					continue
				}
				ctx, cancel := context.WithTimeout(t.Context(), lookupBudget)
				began := time.Now()
				c, err := n.nodes[s].App().Provider().Choose(ctx, n.nodes[d].App().IA())
				took := time.Since(began)
				cancel()
				slowest = max(slowest, took)
				total += took
				lookups++
				if err != nil {
					continue
				}
				if _, ok := f.walk(s, d, c.Path); ok {
					reached++
				}
			}
		}
		fewest = min(fewest, reached)
		if time.Since(start) >= watch {
			return fewest, slowest, total / time.Duration(lookups)
		}
		time.Sleep(settleSample)
	}
}

// TestBenchNATFounderDown benchmarks the NAT network losing
// its founder: every pair the founder holds is cut, and the time until
// every surviving pair answers its pings is read. Then every surviving
// pair's chosen path is read each settleSample for natWatch, each lookup
// bounded by lookupBudget: the fewest pairs a read reached over the formed
// links, and the slowest and the mean lookup. Then node 5, whose parent
// is the founder, stops; once its peers retired its links it boots again on
// its state, and the time until every survivor's ping to it and its pings
// to every survivor answer is read.
func TestBenchNATFounderDown(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootNAT(t, fab, wpki, coneNATs)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, natBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		survivors := allNodes(n)[1:]
		for _, j := range survivors {
			n.cutPair(0, j)
		}
		survive, silent := pingAll(t, n, survivors, natWatch)
		reached, slowest, mean := readReach(t, n, survivors, natWatch)

		const restarted = 5
		host, state := n.nodes[restarted].Host(), n.nodes[restarted].StateDir()
		n.nodes[restarted].Stop(t)
		testnetwork.PollVirtual(t, natWatch, "the peers to retire the stopped node's links", func() bool {
			for _, j := range survivors {
				if j != restarted && holdsLinkTo(t, n.nodes[j], n.nodes[restarted]) {
					return false
				}
			}
			return true
		})
		n.nodes[restarted] = testnetwork.BootInBubble(t, fab, host, func(cfg *services.NodeConfig) {
			cfg.State = state
			cfg.Neighbors = []string{rendezvous(n.nodes[0])}
			cfg.RootCAs = wpki.Pool
		})
		start := time.Now()
		ret, returned := natWatch, false
		peers := len(survivors) - 1
		for {
			synctest.Wait()
			if to, from := pingsWith(t, n, restarted, survivors); to == peers && from == peers {
				ret, returned = time.Since(start), true
				break
			}
			if time.Since(start) >= natWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "NATFounderDown",
			benchValue{survive.Seconds(), "survive-s"},
			benchValue{flag(len(silent) == 0), "survived"},
			benchValue{float64(reached), "reads-reached-min"},
			benchValue{slowest.Seconds(), "reads-lookup-max-s"},
			benchValue{mean.Seconds(), "reads-lookup-mean-s"},
			benchValue{ret.Seconds(), "return-s"},
			benchValue{flag(returned), "returned"},
		)
	})
}

// flag reads a condition as a benchmark value: 1 when it holds.
func flag(ok bool) float64 {
	if ok {
		return 1
	}
	return 0
}

// TestBenchNATPeerRestart benchmarks a public node's restart under
// its neighbors behind NATs: node 2, the parent of 4 and 6, stops and boots
// again on its state at once, and the pings between it and every other
// node are read each settleSample until every one answers or
// natWatch passes.
func TestBenchNATPeerRestart(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootNAT(t, fab, wpki, coneNATs)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, natBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		const restarted = 2
		restart(t, fab, wpki, n, restarted)
		peers := len(n.nodes) - 1
		start := time.Now()
		recovery, recovered := natWatch, false
		var to, from int
		for {
			synctest.Wait()
			to, from = pingsWith(t, n, restarted, allNodes(n))
			if to == peers && from == peers {
				recovery, recovered = time.Since(start), true
				break
			}
			if time.Since(start) >= natWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "NATPeerRestart",
			benchValue{recovery.Seconds(), "recover-s"},
			benchValue{flag(recovered), "recovered"},
			benchValue{float64(to), "pinged-to"},
			benchValue{float64(from), "pinged-from"},
			benchValue{float64(peers), "peers"},
		)
	})
}
