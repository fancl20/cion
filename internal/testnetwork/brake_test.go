package testnetwork

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The brake labs' nodes: brakeA is the founding core of each, the others
// its peers, each lab drawing the links it names between them.
var (
	brakeA = addr.MustIAFrom(20, 0xff00000000c1)
	brakeB = addr.MustIAFrom(20, 0xff00000000c2)
	brakeC = addr.MustIAFrom(20, 0xff00000000c3)
	brakeD = addr.MustIAFrom(20, 0xff00000000c4)
)

// The brake labs' pinned interfaces and their bounds.
const (
	// brakeIfID and otherIfID are the interfaces a lab pins on the links
	// it watches the brake of.
	brakeIfID = 7
	otherIfID = 8
	// brakeBudget bounds each wait on a lab's network: its nodes' links,
	// enrollments, and segments.
	brakeBudget = 10 * time.Minute
	// brakeQuiet is how long a lab watches a link that carries its flow
	// within its capacity, which never brakes.
	brakeQuiet = 15 * time.Second
)

// brakeWatch is what a lab saw of the brakes it watched, once a second:
// how many seconds each watched link held a rate.
type brakeWatch map[segment.LinkID]int

// watchBrakes polls the rate each watched link's node holds for it once a
// second for span, and returns the seconds each held one.
func watchBrakes(span time.Duration, links map[segment.LinkID]*Node) brakeWatch {
	held := make(brakeWatch, len(links))
	for end := time.Now().Add(span); time.Now().Before(end); {
		time.Sleep(time.Second)
		for l, n := range links {
			if n.App().Congestion().Rate(l.IfID) > 0 {
				held[l]++
			}
		}
	}
	return held
}

// towardAQueue is the lab of a queue past one neighbor: the core sends past
// its link's capacity to a peer behind a thin downlink, and within its
// capacity to another peer.
type towardAQueue struct {
	down        *fabric.Downlink
	toB, toC    *Flow
	thin, other segment.LinkID
	watched     map[segment.LinkID]*Node
}

// startTowardAQueue boots the queue past one neighbor and starts its flows.
func startTowardAQueue(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) towardAQueue {
	t.Helper()
	nodes := bootFabricTopology(t, f, wpki, staticTopology{
		core:  brakeA,
		nodes: []addr.IA{brakeA, brakeB, brakeC},
		links: [][2]addr.IA{{brakeA, brakeB}, {brakeA, brakeC}},
		pins:  map[[2]addr.IA]uint16{{brakeA, brakeB}: brakeIfID, {brakeA, brakeC}: otherIfID},
	})
	a, b, c := nodes[brakeA], nodes[brakeB], nodes[brakeC]
	PollVirtual(t, brakeBudget, "the core to reach both peers", func() bool {
		return pingFrom(t.Context(), a, brakeB, b.Host()) && pingFrom(t.Context(), a, brakeC, c.Host())
	})
	lab := towardAQueue{
		down:  f.Downlink(flowLabRate, flowLabQueue, b.Host()),
		toB:   StartFlow(t, a, b, flowLabPort, 2*flowLabRate, flowLabSize),
		toC:   StartFlow(t, a, c, flowLabPort+1, flowLabRate/2, flowLabSize),
		thin:  segment.LinkID{IA: brakeA, IfID: brakeIfID},
		other: segment.LinkID{IA: brakeA, IfID: otherIfID},
	}
	lab.watched = map[segment.LinkID]*Node{lab.thin: a, lab.other: a}
	return lab
}

// TestBrakeHoldsOnlyTheLinkTowardAQueue checks a queue past one neighbor:
// the core sends past its link's capacity to a peer behind a thin downlink,
// and within its capacity to another peer. The link toward the thin peer
// brakes, and the link toward the other peer never does.
func TestBrakeHoldsOnlyTheLinkTowardAQueue(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startTowardAQueue(t, f, wpki)
		held := watchBrakes(flowLabSettle, lab.watched)
		if held[lab.thin] == 0 {
			t.Error("the link toward the thin peer never braked")
		}
		if s := held[lab.other]; s != 0 {
			t.Errorf("the link toward the other peer braked for %ds, want never", s)
		}
	})
}

// TestBenchBrakeTowardAQueue benchmarks the queue past one neighbor once the
// thin peer's link settles: what the thin downlink dropped and carried and
// how long it waited, what each flow delivered, and the seconds each link
// held a rate.
func TestBenchBrakeTowardAQueue(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startTowardAQueue(t, f, wpki)
		time.Sleep(flowLabSettle)
		_, _, _ = lab.toB.Window(), lab.toC.Window(), lab.down.Window()
		held := watchBrakes(flowLabSpan, lab.watched)
		reportValues(t, "BrakeTowardAQueue", slices.Concat(
			lineValues("downlink", lab.down.Window(), flowLabRate, flowLabSpan),
			flowValues("thin", lab.toB.Window()),
			flowValues("other", lab.toC.Window()),
			[]benchValue{
				{float64(held[lab.thin]), "thin-held-s"},
				{float64(held[lab.other]), "other-held-s"},
			},
		)...)
	})
}

// trafficMoves is the lab of traffic moving between links: the core's flow
// to D rides the quicker branch through B, whose thin uplink brakes B's link
// to D, until the core's link to B is cut and the flow moves to the branch
// through C, whose link to D carries it within its capacity. Its cut is when
// the core's link to B was cut, letGo when B's link first held no rate
// after, zero while it holds one, and moved when the core's lease of D, which
// the flow rides, first crossed C's link.
type trafficMoves struct {
	b, c              *Node
	toD               *Flow
	viaB, viaC        segment.LinkID
	cut, letGo, moved time.Time
}

// startTrafficMoves boots the lab, starts the flow, waits for B's link to
// brake, cuts the core's link to B, and waits for the flow's lease to cross
// C's link.
func startTrafficMoves(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) trafficMoves {
	t.Helper()
	nodes := bootFabricTopology(t, f, wpki, staticTopology{
		core:  brakeA,
		nodes: []addr.IA{brakeA, brakeB, brakeC, brakeD},
		links: [][2]addr.IA{{brakeA, brakeB}, {brakeB, brakeD}, {brakeA, brakeC}, {brakeC, brakeD}},
		pins:  map[[2]addr.IA]uint16{{brakeB, brakeD}: brakeIfID, {brakeC, brakeD}: otherIfID},
	})
	a, b, c, d := nodes[brakeA], nodes[brakeB], nodes[brakeC], nodes[brakeD]
	f.Delay(a.Host(), b.Host(), 5*time.Millisecond)
	f.Delay(b.Host(), d.Host(), 5*time.Millisecond)
	f.Delay(a.Host(), c.Host(), 20*time.Millisecond)
	f.Delay(c.Host(), d.Host(), 20*time.Millisecond)
	lab := trafficMoves{
		b:    b,
		c:    c,
		viaB: segment.LinkID{IA: brakeB, IfID: brakeIfID},
		viaC: segment.LinkID{IA: brakeC, IfID: otherIfID},
	}
	PollVirtual(t, brakeBudget, "the core to reach D through B", func() bool {
		pick, err := a.App().Provider().Choose(t.Context(), brakeD)
		return err == nil && slices.Contains(pick.Links, lab.viaB) && pingFrom(t.Context(), a, brakeD, d.Host())
	})
	f.Uplink(flowLabRate, flowLabQueue, b.Host())

	lab.toD = StartFlow(t, a, d, flowLabPort, 2*flowLabRate, flowLabSize)
	if !pollUntil(flowLabSettle, func() bool { return b.App().Congestion().Rate(brakeIfID) > 0 }) {
		t.Fatal("B's link to D never braked under the flow past its uplink")
	}
	f.Cut(a.Host(), b.Host())
	lab.cut = time.Now()
	viaC := string(bus.PathIDOf([]segment.LinkID{lab.viaC}))
	PollVirtual(t, brakeBudget, "the flow's lease to cross C's link", func() bool {
		if lab.letGo.IsZero() && b.App().Congestion().Rate(brakeIfID) == 0 {
			lab.letGo = time.Now()
		}
		leased, err := a.App().Provider().Lease(brakeD).Path()
		return err == nil && slices.Contains(strings.Fields(string(leased.ID)), viaC)
	})
	lab.moved = time.Now()
	return lab
}

// TestBrakeLetsGoWhenTrafficLeaves checks traffic moving between links:
// once the flow leaves B's braked link for the branch through C, B's brake
// lets go within seconds, and C's link to D, which carries the flow within
// its capacity, never brakes.
func TestBrakeLetsGoWhenTrafficLeaves(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startTrafficMoves(t, f, wpki)
		if !pollUntil(15*time.Second, func() bool { return lab.b.App().Congestion().Rate(brakeIfID) == 0 }) {
			t.Error("B's brake held 15s after the flow left its link")
		}
		if s := watchBrakes(brakeQuiet, map[segment.LinkID]*Node{lab.viaC: lab.c})[lab.viaC]; s != 0 {
			t.Errorf("C's link to D braked for %ds under a flow within its capacity, want never", s)
		}
	})
}

// TestBenchBrakeTrafficMoves benchmarks traffic moving between links: the
// seconds from the cut until the flow's lease crossed C's link and until B's
// brake let go, and, once both, what the flow delivered through C and the
// seconds C's link held a rate.
func TestBenchBrakeTrafficMoves(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startTrafficMoves(t, f, wpki)
		if lab.letGo.IsZero() {
			PollVirtual(t, brakeBudget, "B's brake to let go", func() bool {
				return lab.b.App().Congestion().Rate(brakeIfID) == 0
			})
			lab.letGo = time.Now()
		}
		_ = lab.toD.Window()
		held := watchBrakes(flowLabSpan, map[segment.LinkID]*Node{lab.viaC: lab.c})
		reportValues(t, "BrakeTrafficMoves", slices.Concat(
			[]benchValue{
				{lab.moved.Sub(lab.cut).Seconds(), "move-s"},
				{lab.letGo.Sub(lab.cut).Seconds(), "let-go-s"},
			},
			flowValues("moved", lab.toD.Window()),
			[]benchValue{{float64(held[lab.viaC]), "moved-held-s"}},
		)...)
	})
}

// bothQueues is the lab of a path across two queues: the core's flow to C
// crosses its own thin uplink toward B, then B's thinner one toward C. A
// flow within both lines runs first, so each link reads its least delay
// before the queues fill; a flow past both lines then joins it.
type bothQueues struct {
	second      *fabric.Uplink
	thinner     float64
	fits, over  *Flow
	first, last segment.LinkID
	watched     map[segment.LinkID]*Node
}

// startBothQueues boots the path across two queues and starts its flows.
func startBothQueues(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) bothQueues {
	t.Helper()
	nodes := bootFabricTopology(t, f, wpki, staticTopology{
		core:  brakeA,
		nodes: []addr.IA{brakeA, brakeB, brakeC},
		links: [][2]addr.IA{{brakeA, brakeB}, {brakeB, brakeC}},
		pins:  map[[2]addr.IA]uint16{{brakeA, brakeB}: brakeIfID, {brakeB, brakeC}: otherIfID},
	})
	a, b, c := nodes[brakeA], nodes[brakeB], nodes[brakeC]
	PollVirtual(t, brakeBudget, "the core to reach C", func() bool {
		return pingFrom(t.Context(), a, brakeC, c.Host())
	})
	const thinner = 3 * flowLabRate / 4
	f.Uplink(flowLabRate, flowLabQueue, a.Host())
	lab := bothQueues{
		second:  f.Uplink(thinner, flowLabQueue, b.Host()),
		thinner: thinner,
		first:   segment.LinkID{IA: brakeA, IfID: brakeIfID},
		last:    segment.LinkID{IA: brakeB, IfID: otherIfID},
	}
	lab.watched = map[segment.LinkID]*Node{lab.first: a, lab.last: b}
	lab.fits = StartFlow(t, a, c, flowLabPort, thinner/3, flowLabSize)
	time.Sleep(flowLabSpan)
	lab.over = StartFlow(t, a, c, flowLabPort+1, 2*flowLabRate, flowLabSize)
	return lab
}

// TestBrakeAtBothQueues checks a path that crosses two queues: the core's
// flow to C crosses its own thin uplink toward B, then B's thinner one
// toward C. Beside a flow within both lines, a flow past both brakes both
// links.
func TestBrakeAtBothQueues(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startBothQueues(t, f, wpki)
		held := watchBrakes(flowLabSettle, lab.watched)
		for _, l := range []segment.LinkID{lab.first, lab.last} {
			if held[l] == 0 {
				t.Errorf("the link %v never braked", l)
			}
		}
	})
}

// TestBenchBrakeBothQueues benchmarks the path across two queues once its
// links' rates settle: what B's thinner uplink dropped and carried and how
// long it waited, what the flows delivered, also as a share of the thinner
// uplink's rate, and the seconds each link held a rate.
func TestBenchBrakeBothQueues(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		lab := startBothQueues(t, f, wpki)
		time.Sleep(flowLabSettle)
		_, _, _ = lab.fits.Window(), lab.over.Window(), lab.second.Window()
		held := watchBrakes(flowLabSpan, lab.watched)
		w := lab.fits.Window().Add(lab.over.Window())
		share := float64(w.Received()*flowLabSize*8) / flowLabSpan.Seconds() / lab.thinner
		reportValues(t, "BrakeBothQueues", slices.Concat(
			lineValues("uplink", lab.second.Window(), lab.thinner, flowLabSpan),
			flowValues("flows", w),
			[]benchValue{
				{share, "flows-thinner-share"},
				{float64(held[lab.first]), "first-held-s"},
				{float64(held[lab.last]), "last-held-s"},
			},
		)...)
	})
}

// TestBenchBrakeJitter benchmarks jitter on a loaded link: a flow a third
// of the core's uplink crosses a link whose packets each wait a further
// draw of 10ms on average, in order. Once the flow settles, it reports the
// seconds the link held a rate and what the flow delivered.
func TestBenchBrakeJitter(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		nodes := bootFabricTopology(t, f, wpki, staticTopology{
			core:  brakeA,
			nodes: []addr.IA{brakeA, brakeB},
			links: [][2]addr.IA{{brakeA, brakeB}},
			pins:  map[[2]addr.IA]uint16{{brakeA, brakeB}: brakeIfID},
		})
		a, b := nodes[brakeA], nodes[brakeB]
		f.Delay(a.Host(), b.Host(), flowLabOneWay)
		f.Jitter(a.Host(), b.Host(), 10*time.Millisecond)
		PollVirtual(t, brakeBudget, "the core to reach B", func() bool {
			return pingFrom(t.Context(), a, brakeB, b.Host())
		})
		f.Uplink(flowLabRate, flowLabQueue, a.Host())

		toB := StartFlow(t, a, b, flowLabPort, flowLabRate/3, flowLabSize)
		time.Sleep(flowLabSettle)
		_ = toB.Window()
		l := segment.LinkID{IA: brakeA, IfID: brakeIfID}
		held := watchBrakes(flowLabSpan, map[segment.LinkID]*Node{l: a})
		reportValues(t, "BrakeJitter", slices.Concat(
			[]benchValue{{float64(held[l]), "held-s"}},
			flowValues("flow", toB.Window()),
		)...)
	})
}

// TestBenchBrakeRoundTripStep benchmarks a lasting change in a link's round
// trip under a flow a third of the core's uplink: the link's one-way delay
// rises by 20ms mid-flow, which reads as queue until the round trips from
// before the step age out of the least. From a minute and a half after the
// step, it reports the seconds the link held a rate and what the flow
// delivered.
func TestBenchBrakeRoundTripStep(t *testing.T) {
	requireBench(t)
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		nodes := bootFabricTopology(t, f, wpki, staticTopology{
			core:  brakeA,
			nodes: []addr.IA{brakeA, brakeB},
			links: [][2]addr.IA{{brakeA, brakeB}},
			pins:  map[[2]addr.IA]uint16{{brakeA, brakeB}: brakeIfID},
		})
		a, b := nodes[brakeA], nodes[brakeB]
		f.Delay(a.Host(), b.Host(), flowLabOneWay)
		PollVirtual(t, brakeBudget, "the core to reach B", func() bool {
			return pingFrom(t.Context(), a, brakeB, b.Host())
		})
		f.Uplink(flowLabRate, flowLabQueue, a.Host())

		toB := StartFlow(t, a, b, flowLabPort, flowLabRate/3, flowLabSize)
		time.Sleep(flowLabSettle)
		f.Delay(a.Host(), b.Host(), 20*time.Millisecond)
		time.Sleep(90 * time.Second)
		_ = toB.Window()
		l := segment.LinkID{IA: brakeA, IfID: brakeIfID}
		held := watchBrakes(flowLabSpan, map[segment.LinkID]*Node{l: a})
		reportValues(t, "BrakeRoundTripStep", slices.Concat(
			[]benchValue{{float64(held[l]), "held-s"}},
			flowValues("flow", toB.Window()),
		)...)
	})
}
