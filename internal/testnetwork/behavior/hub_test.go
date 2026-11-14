package behavior

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// The hub lab: node 0 is the founding core and node 1 the hub, which sits
// hubArm one way from every node, while every other pair sits hubSpan
// apart. A route through the hub costs twice hubArm and a transit, against
// hubSpan direct, so the measured topology links every node to the hub and
// carries their transit through it. The hub's uplink carries hubRate and
// queues hubQueue; the other nodes' uplinks are unbounded. Each flow's
// share of the uplink stays above 256 kbit/s, even at its fallen rate, so a
// brake can read every link the flows load.
const (
	hubSize   = 7
	hubNode   = 1
	hubArm    = 5 * time.Millisecond
	hubSpan   = 20 * time.Millisecond
	hubRate   = 4_000_000
	hubQueue  = 250 * time.Millisecond
	hubBudget = time.Hour
	// hubTransits counts the transit flows, each between a pair of nodes
	// whose chosen path crosses the hub, no node in two.
	hubTransits = 3
	// hubFlowSize is each flow's datagram, and hubFlowPort the port the
	// first flow's receiver reads, the rest the ports after it.
	hubFlowSize = 1000
	hubFlowPort = 15000
	// hubWarm is how long the flows run before a phase counts them: their
	// leases resolved and their queues filled.
	hubWarm = 30 * time.Second
	// hubLivenessSample is how often a phase reads every link's liveness:
	// half the BFD interval, which a link's down verdict lasts at least.
	hubLivenessSample = liveness.BFDTransmissionInterval / 2
)

// bootHub boots the hub lab's network, the hub's uplink drawn first, every
// node joining through the founder.
func bootHub(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) (*network, *fabric.Uplink) {
	t.Helper()
	n := newNetwork(t, fab, hubSize)
	for i := range n.hosts {
		for j := i + 1; j < len(n.hosts); j++ {
			oneWay := hubSpan
			if i == hubNode || j == hubNode {
				oneWay = hubArm
			}
			n.setDelay(i, j, oneWay)
		}
	}
	up := fab.Uplink(hubRate, hubQueue, n.hosts[hubNode])
	n.nodes[0] = testnetwork.BootInBubble(t, fab, n.hosts[0], func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	for i := 1; i < hubSize; i++ {
		n.nodes[i] = testnetwork.BootInBubble(t, fab, n.hosts[i], func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{rendezvous(n.nodes[0])}
			cfg.RootCAs = wpki.Pool
		})
	}
	return n, up
}

// hubLoad is the hub lab's flows: the transit flows, and the hub's own.
type hubLoad struct {
	transits []*testnetwork.Flow
	own      *testnetwork.Flow
}

// startHubLoad starts hubTransits flows of transitRate between pairs of
// nodes whose chosen paths cross the hub, no node in two, the lowest pairs
// first, and the hub's own flow of ownRate to the founder; it fails the
// test when too few paths cross the hub.
func startHubLoad(t *testing.T, n *network, transitRate, ownRate int64) hubLoad {
	t.Helper()
	r := readPaths(t, n, false)
	used := map[int]bool{hubNode: true}
	var load hubLoad
pairs:
	for s := range n.nodes {
		for d := range n.nodes {
			if len(load.transits) == hubTransits {
				break pairs
			}
			path := r.chosen[[2]int{s, d}]
			if used[s] || used[d] || s == d || len(path) < 3 || !slices.Contains(path[1:len(path)-1], hubNode) {
				continue
			}
			used[s], used[d] = true, true
			load.transits = append(load.transits, testnetwork.StartFlow(t, n.nodes[s], n.nodes[d],
				hubFlowPort+uint16(len(load.transits)), transitRate, hubFlowSize))
		}
	}
	if len(load.transits) < hubTransits {
		t.Fatalf("%d pairs of distinct nodes cross the hub, want %d", len(load.transits), hubTransits)
	}
	load.own = testnetwork.StartFlow(t, n.nodes[hubNode], n.nodes[0], hubFlowPort+hubTransits, ownRate, hubFlowSize)
	return load
}

// window returns the transit flows' window, merged, and the hub's own.
func (l hubLoad) window() (transit, own testnetwork.FlowWindow) {
	for _, f := range l.transits {
		transit = transit.Add(f.Window())
	}
	return transit, l.own.Window()
}

// stop ends every flow.
func (l hubLoad) stop() {
	for _, f := range l.transits {
		f.Stop()
	}
	l.own.Stop()
}

// hubPhase is what one phase of a hub benchmark measured: the flows, the
// hub's uplink, the leases that moved, the link-set changes, the links lost
// and those retired, and the network's assessment at the phase's end.
type hubPhase struct {
	transit, own testnetwork.FlowWindow
	uplink       fabric.LineWindow
	moves        int
	changes      int
	lost         int
	retired      int
	end          assessment
}

// runHubPhase runs a phase of warm and then span: from its start it counts
// the links lost every hubLivenessSample and the link-set changes every
// settleSample, once warm has passed it starts the windows of the load, if
// any, and of the uplink, and at its end it reads the windows, the leases
// that moved, the links retired, and the network's assessment. A link is
// lost when its liveness fails while both its ends hold it; a retirement,
// which one end takes back first, is not.
func runHubPhase(t *testing.T, n *network, up *fabric.Uplink, load *hubLoad, warm, span time.Duration) hubPhase {
	t.Helper()
	marks := changeMarks(n)
	var p hubPhase
	start, windowed := time.Now(), false
	last, live, read := linkSet(t.Context(), n.nodes), liveLinks(t.Context(), n.nodes), start
	for end := start.Add(warm + span); time.Now().Before(end); {
		if !windowed && time.Since(start) >= warm {
			windowed = true
			if load != nil {
				load.window()
			}
			up.Window()
		}
		time.Sleep(hubLivenessSample)
		now := liveLinks(t.Context(), n.nodes)
		for pair, wasUp := range live {
			if isUp, held := now[pair]; wasUp && held && !isUp {
				p.lost++
			}
		}
		live = now
		if time.Since(read) < settleSample {
			continue
		}
		read = time.Now()
		if now := linkSet(t.Context(), n.nodes); now != last {
			last = now
			p.changes++
		}
	}
	if load != nil {
		p.transit, p.own = load.window()
	}
	p.uplink = up.Window()
	p.moves = leaseMoves(n, marks)
	p.retired = linksRetired(n, marks)
	p.end = assess(t, n, penalty)[0]
	return p
}

// liveLinks returns, for each pair of nodes whose link both ends hold
// established, whether its liveness is up at both.
func liveLinks(ctx context.Context, nodes []*testnetwork.Node) map[[2]int]bool {
	index := make(map[addr.IA]int, len(nodes))
	for i, n := range nodes {
		index[n.App().IA()] = i
	}
	// Each end sets its own bit of a pair's held, and of its up while its
	// link is up.
	held, up := map[[2]int]uint8{}, map[[2]int]uint8{}
	for i, n := range nodes {
		entries, err := n.App().Links().All(ctx)
		if err != nil {
			continue
		}
		for _, l := range entries {
			j, ok := index[l.NeighborIA]
			if !ok || l.State != links.StateEstablished {
				continue
			}
			pair, end := [2]int{min(i, j), max(i, j)}, uint8(1)
			if i > j {
				end = 2
			}
			held[pair] |= end
			if n.App().Monitor().Up(l.IfID) {
				up[pair] |= end
			}
		}
	}
	live := make(map[[2]int]bool, len(held))
	for pair, ends := range held {
		if ends == 3 {
			live[pair] = up[pair] == 3
		}
	}
	return live
}

// linksRetired counts the links the nodes retired from the marks on.
func linksRetired(n *network, marks []uint64) int {
	retired := 0
	for i, node := range n.nodes {
		changes, _ := node.App().Bus().Changes().Since(marks[i])
		for _, c := range changes {
			if r, ok := c.(evidence.Record); ok && r.Change == measured.LinkRetired {
				retired++
			}
		}
	}
	return retired
}

// reportHubPhase reports a phase as a benchmark result line.
func reportHubPhase(t *testing.T, name string, p hubPhase) {
	t.Helper()
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	reportValues(t, name,
		benchValue{p.own.DeliveredShare(), "own-delivered"},
		benchValue{ms(p.own.Quantile(0.5)), "own-ms-p50"},
		benchValue{ms(p.own.Quantile(0.95)), "own-ms-p95"},
		benchValue{p.transit.DeliveredShare(), "transit-delivered"},
		benchValue{ms(p.transit.Quantile(0.5)), "transit-ms-p50"},
		benchValue{ms(p.transit.Quantile(0.95)), "transit-ms-p95"},
		benchValue{p.uplink.DropShare(), "uplink-dropped"},
		benchValue{ms(p.uplink.MeanWait()), "uplink-wait-ms-mean"},
		benchValue{ms(p.uplink.MaxWait), "uplink-wait-ms-max"},
		benchValue{float64(p.moves), "moves"},
		benchValue{float64(p.changes), "changes"},
		benchValue{float64(p.lost), "links-lost"},
		benchValue{float64(p.retired), "links-retired"},
		benchValue{float64(p.end.links), "links"},
		benchValue{float64(p.end.reached), "reached"},
		benchValue{p.end.ratio.mean, "ratio-mean"},
	)
}

// TestBenchHubLoaded benchmarks the hub lab under steady load: once the
// link set settles, three transit flows of 1.6 Mbit/s and the hub's own
// flow of 800 kbit/s, 5.6 Mbit/s into the hub's 4 Mbit/s uplink, for ten
// minutes, then ten minutes after the flows stop.
func TestBenchHubLoaded(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, up := bootHub(t, fab, wpki)
		s := awaitSettled(t, n, settleQuiet, hubBudget)
		t.Logf("the hub lab settled after %d link-set changes in %v: %s", s.changes, s.at,
			linkSet(t.Context(), n.nodes))
		reportHubPhase(t, "HubLoaded/phase=settled", runHubPhase(t, n, up, nil, 0, time.Minute))
		load := startHubLoad(t, n, 1_600_000, 800_000)
		reportHubPhase(t, "HubLoaded/phase=load", runHubPhase(t, n, up, &load, hubWarm, 10*time.Minute))
		load.stop()
		reportHubPhase(t, "HubLoaded/phase=after", runHubPhase(t, n, up, nil, 0, 10*time.Minute))
	})
}

// TestBenchHubRateFalls benchmarks the hub lab under a load its uplink
// carries until the uplink's rate falls: once the link set settles, three
// transit flows of 600 kbit/s and the hub's own of 400 kbit/s for five
// minutes, the uplink's rate then 1.6 Mbit/s for ten, then 4 Mbit/s again
// for ten.
func TestBenchHubRateFalls(t *testing.T) {
	requireBench(t)
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		n, up := bootHub(t, fab, wpki)
		s := awaitSettled(t, n, settleQuiet, hubBudget)
		t.Logf("the hub lab settled after %d link-set changes in %v: %s", s.changes, s.at,
			linkSet(t.Context(), n.nodes))
		load := startHubLoad(t, n, 600_000, 400_000)
		reportHubPhase(t, "HubRateFalls/phase=fits", runHubPhase(t, n, up, &load, hubWarm, 5*time.Minute))
		for _, phase := range []struct {
			name string
			rate int64
		}{{"fallen", 1_600_000}, {"restored", hubRate}} {
			up.SetRate(phase.rate)
			reportHubPhase(t, fmt.Sprintf("HubRateFalls/phase=%s", phase.name),
				runHubPhase(t, n, up, &load, 0, 10*time.Minute))
		}
	})
}
