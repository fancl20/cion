package behavior

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The translated network: the founder 0, the authoritative core 1, and the
// public node 2, 10ms apart, and the translated nodes 3 to 6, each behind a
// translator of its own, 2ms apart and 20ms from every public node. Each
// node joins through its parent alone; 5's parent is the founder.
var (
	translatedParent = map[int]int{1: 0, 2: 0, 3: 1, 4: 2, 5: 0, 6: 2}
	translatedOrder  = []int{1, 2, 3, 4, 5, 6}
	// coneTranslators places the translated nodes behind the translators
	// the network serves through today.
	coneTranslators = map[int]fabric.Behavior{
		3: fabric.FullCone, 4: fabric.FullCone, 5: fabric.PortRestricted, 6: fabric.PortRestricted,
	}
)

const (
	// translatedBudget bounds the translated network's join and settling
	// in virtual time.
	translatedBudget = 30 * time.Minute
	// translatedWatch is how long a benchmark reads the translated
	// network's answer to a change.
	translatedWatch = 10 * time.Minute
	// translatedCores is the count of cores the network's TRC names once
	// the authoritative core joined.
	translatedCores = 2
)

// translatedOneWay is the one-way delay between two of the translated
// network's nodes.
func translatedOneWay(i, j int) time.Duration {
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

// bootTranslated boots the translated network, its translated nodes behind
// translators of the behaviors given, and returns it with the translators.
func bootTranslated(
	t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA, behaviors map[int]fabric.Behavior,
) (*network, map[int]*fabric.Boundary) {

	t.Helper()
	n := newNetwork(t, fab, 7)
	bounds := n.translate(t, behaviors)
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			n.setDelay(i, j, translatedOneWay(i, j))
		}
	}
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		// The founder's vote admits the authoritative core.
		cfg.EnrollAuth = "cidrs=127.0.0.0/8"
	})
	for _, i := range translatedOrder {
		parent := n.nodes[translatedParent[i]]
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(parent)}
			cfg.RootCAs = wpki.Pool
			cfg.Core = i == 1
		})
	}
	return n, bounds
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
	testnetwork.PollVirtual(t, translatedBudget, "the nodes to pin the TRC naming both cores", func() bool {
		for _, i := range which {
			if pinnedCores(t, n.nodes[i]) != translatedCores {
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

// TestTranslatedNetworkReaches checks what the translated network serves
// behind full-cone and port-restricted translators: it settles, and every
// ordered pair reaches over its chosen path and answers a ping — the
// translated nodes' links to the public nodes carrying their traffic both
// ways, and every pair of translated nodes reaching through a public node.
func TestTranslatedNetworkReaches(t *testing.T) {
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootTranslated(t, fab, wpki, coneTranslators)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, translatedBudget)
		awaitReach(t, n, reachBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
	})
}

// TestBenchTranslatedSettled benchmarks the translated network once it
// settles behind full-cone and port-restricted translators.
func TestBenchTranslatedSettled(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootTranslated(t, fab, wpki, coneTranslators)
		awaitPinned(t, n, allNodes(n)...)
		s := awaitSettled(t, n.nodes, settleQuiet, translatedBudget)
		report(t, "TranslatedSettled", s, assess(t, n, penalty, 0))
	})
}

// TestBenchTranslatedRebind benchmarks a translator dropping a settled
// node's mappings: the pings to and from node 3 are read each settleSample
// until every peer's answer returns or translatedWatch passes, beside the
// links node 3 still holds established.
func TestBenchTranslatedRebind(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, bounds := bootTranslated(t, fab, wpki, coneTranslators)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, translatedBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		const rebound = 3
		peers := len(n.nodes) - 1

		bounds[rebound].Rebind()
		start := time.Now()
		recovery, recovered := translatedWatch, false
		var to, from int
		for {
			synctest.Wait()
			to, from = pingsWith(t, n, rebound, allNodes(n))
			if to == peers && from == peers {
				recovery, recovered = time.Since(start), true
				break
			}
			if time.Since(start) >= translatedWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "TranslatedRebind",
			benchValue{recovery.Seconds(), "recover-s"},
			benchValue{flag(recovered), "recovered"},
			benchValue{float64(to), "pinged-to"},
			benchValue{float64(from), "pinged-from"},
			benchValue{float64(peers), "peers"},
			benchValue{float64(establishedLinks(t, n.nodes[rebound])), "links"},
		)
	})
}

// TestBenchTranslatedSymmetric benchmarks a node behind a symmetric
// translator: whether it pins the TRC naming both cores and answers every
// peer's ping within translatedWatch of the others' pins.
func TestBenchTranslatedSymmetric(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		behaviors := maps.Clone(coneTranslators)
		const symmetric = 6
		behaviors[symmetric] = fabric.Symmetric
		n, _ := bootTranslated(t, fab, wpki, behaviors)
		awaitPinned(t, n, 0, 1, 2, 3, 4, 5)
		peers := len(n.nodes) - 1

		start := time.Now()
		join, joined := translatedWatch, false
		for {
			synctest.Wait()
			if pinnedCores(t, n.nodes[symmetric]) == translatedCores {
				if to, from := pingsWith(t, n, symmetric, allNodes(n)); to == peers && from == peers {
					join, joined = time.Since(start), true
					break
				}
			}
			if time.Since(start) >= translatedWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "TranslatedSymmetric",
			benchValue{join.Seconds(), "join-s"},
			benchValue{flag(joined), "joined"},
			benchValue{flag(pinnedCores(t, n.nodes[symmetric]) == translatedCores), "pinned"},
			benchValue{float64(establishedLinks(t, n.nodes[symmetric])), "links"},
		)
	})
}

// TestBenchTranslatedFounderDown benchmarks the translated network losing
// its founder: every pair the founder holds is cut, and the time until
// every surviving pair answers its pings is read. Then node 5, whose parent
// is the founder, stops; once its peers retired its links it boots again on
// its state, and the time until every survivor's ping to it and its pings
// to every survivor answer is read.
func TestBenchTranslatedFounderDown(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, _ := bootTranslated(t, fab, wpki, coneTranslators)
		awaitPinned(t, n, allNodes(n)...)
		awaitSettled(t, n.nodes, settleQuiet, translatedBudget)
		awaitPings(t, n, allNodes(n), reachBudget)
		survivors := allNodes(n)[1:]
		for _, j := range survivors {
			n.cutPair(0, j)
		}
		survive, silent := pingAll(t, n, survivors, translatedWatch)

		const restarted = 5
		host, state := n.nodes[restarted].Host(), n.nodes[restarted].StateDir()
		n.nodes[restarted].Stop(t)
		testnetwork.PollVirtual(t, translatedWatch, "the peers to retire the stopped node's links", func() bool {
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
		ret, returned := translatedWatch, false
		peers := len(survivors) - 1
		for {
			synctest.Wait()
			if to, from := pingsWith(t, n, restarted, survivors); to == peers && from == peers {
				ret, returned = time.Since(start), true
				break
			}
			if time.Since(start) >= translatedWatch {
				break
			}
			time.Sleep(settleSample)
		}
		reportValues(t, "TranslatedFounderDown",
			benchValue{survive.Seconds(), "survive-s"},
			benchValue{flag(len(silent) == 0), "survived"},
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
