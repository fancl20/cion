package controlplane

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The ASes of the selection's pure tests: F the founder, O another origin,
// and M, N, K on their routes.
var (
	selF = addr.MustIAFrom(30, 0xff0000000001)
	selO = addr.MustIAFrom(30, 0xff0000000002)
	selM = addr.MustIAFrom(30, 0xff0000000003)
	selN = addr.MustIAFrom(30, 0xff0000000004)
	selK = addr.MustIAFrom(30, 0xff0000000005)
)

const ms = time.Millisecond

// hopSpec is one AS entry of a route a test builds: the AS, its interfaces
// in construction direction, and its egress link's declared one-way delay,
// none when zero.
type hopSpec struct {
	ia              addr.IA
	ingress, egress uint16
	latency         time.Duration
}

// rawRoute builds an unsigned candidate for the selection's pure tests: the
// hops in construction order, originated at ts, arrived over ingress.
func rawRoute(ingress uint16, ts time.Time, hops ...hopSpec) Candidate {
	pcb := &segment.PCB{Info: segment.Info{Timestamp: ts}}
	for _, h := range hops {
		e := segment.ASEntry{IA: h.ia, Hop: path.HopField{ConsIngress: h.ingress, ConsEgress: h.egress}}
		if h.latency != 0 {
			e.Latency = map[segment.LinkID]time.Duration{{IA: h.ia, IfID: h.egress}: h.latency}
		}
		pcb.Entries = append(pcb.Entries, e)
	}
	return Candidate{Ingress: ingress, PCB: pcb}
}

// labeled holds the candidates a test built, by label.
type labeled map[string]Candidate

// all returns the candidates in label order.
func (l labeled) all() []Candidate {
	var out []Candidate
	for _, name := range slices.Sorted(maps.Keys(l)) {
		out = append(out, l[name])
	}
	return out
}

// names returns the labels of the candidates, in their order.
func (l labeled) names(cands []Candidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		for name, built := range l {
			if built.PCB == c.PCB && built.Ingress == c.Ingress {
				out = append(out, name)
			}
		}
	}
	return out
}

// TestPriceOf checks a route's price: twice its declared one-way delay plus
// twice the transit penalty for each AS between the node and the origin,
// the higher declaration where both ends of an edge declare, and no price
// where any edge, the one into the node included, is undeclared.
func TestPriceOf(t *testing.T) {
	now := time.Now()
	bothEnds := rawRoute(1, now, hopSpec{selF, 0, 1, 2 * ms}, hopSpec{selM, 2, 3, 3 * ms})
	bothEnds.PCB.Entries[1].Latency[segment.LinkID{IA: selM, IfID: 2}] = 4 * ms
	for _, tc := range []struct {
		name   string
		c      Candidate
		want   time.Duration
		priced bool
	}{
		{"from the origin", rawRoute(1, now, hopSpec{selF, 0, 1, 2 * ms}), 4 * ms, true},
		{"through a transit",
			rawRoute(1, now, hopSpec{selF, 0, 1, 2 * ms}, hopSpec{selM, 2, 3, 3 * ms}),
			10*ms + 2*scion.TransitPenalty, true},
		{"both ends declaring", bothEnds, 14*ms + 2*scion.TransitPenalty, true},
		{"an undeclared edge",
			rawRoute(1, now, hopSpec{selF, 0, 1, 0}, hopSpec{selM, 2, 3, 3 * ms}), 0, false},
		{"an undeclared edge into the node",
			rawRoute(1, now, hopSpec{selF, 0, 1, 2 * ms}, hopSpec{selM, 2, 3, 0}), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, priced := priceOf(tc.c.PCB)
			if got != tc.want || priced != tc.priced {
				t.Errorf("priceOf = %v, %v; want %v, %v", got, priced, tc.want, tc.priced)
			}
		})
	}
}

// TestRankRoutes checks the rank: priced routes before unpriced ones, the
// lower price first — a transit charged its penalty — then the fewer
// entries, then the newer origination.
func TestRankRoutes(t *testing.T) {
	now := time.Now()
	routes := labeled{
		"direct": rawRoute(1, now, hopSpec{selF, 0, 1, 5 * ms}),
		"through M": rawRoute(2, now,
			hopSpec{selF, 0, 2, ms}, hopSpec{selM, 3, 4, ms}),
		"unpriced short": rawRoute(3, now, hopSpec{selF, 0, 5, 0}),
		"unpriced newer": rawRoute(4, now.Add(time.Second),
			hopSpec{selF, 0, 6, 0}, hopSpec{selN, 7, 8, 0}),
		"unpriced older": rawRoute(5, now,
			hopSpec{selF, 0, 9, 0}, hopSpec{selK, 10, 11, 0}),
	}
	var got []Candidate
	for _, r := range rankRoutes(routes.all()) {
		got = append(got, r.Candidate)
	}
	// The direct route's 10ms beats the 4ms through M, charged 10ms for M.
	want := []string{"direct", "through M", "unpriced short", "unpriced newer", "unpriced older"}
	if diff := cmp.Diff(want, routes.names(got)); diff != "" {
		t.Errorf("rank (-want +got):\n%s", diff)
	}
}

// TestPickSetCoversEveryOrigin checks the first picks: the founder's
// cheapest route leads though another origin's is cheaper, each origin's
// cheapest follows, and without a founder the origins go in rank order. An
// origin enters even where the backups and the interfaces would leave it
// out: over the node's one link from M, F's second route is the cheaper
// backup, and O's route adds no interface.
func TestPickSetCoversEveryOrigin(t *testing.T) {
	now := time.Now()
	routes := labeled{
		"founder":        rawRoute(1, now, hopSpec{selF, 0, 1, 9 * ms}),
		"founder dearer": rawRoute(2, now, hopSpec{selF, 0, 2, 20 * ms}),
		"other":          rawRoute(2, now, hopSpec{selO, 0, 3, ms}),
		"other dearer":   rawRoute(1, now, hopSpec{selO, 0, 4, 30 * ms}),
	}
	ranked := rankRoutes(routes.all())
	if diff := cmp.Diff([]string{"founder", "other"},
		routes.names(pickSet(ranked, selF, bus.Cluster{}))); diff != "" {
		t.Errorf("set with the founder (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"other", "founder"},
		routes.names(pickSet(ranked, 0, bus.Cluster{}))); diff != "" {
		t.Errorf("set without a founder (-want +got):\n%s", diff)
	}

	oneLink := labeled{
		"founder": rawRoute(9, now,
			hopSpec{selF, 0, 1, ms}, hopSpec{selM, 2, 3, ms}),
		"founder around F's link": rawRoute(9, now,
			hopSpec{selF, 0, 4, 2 * ms}, hopSpec{selM, 5, 3, ms}),
		"other": rawRoute(9, now,
			hopSpec{selO, 0, 6, 9 * ms}, hopSpec{selM, 7, 3, ms}),
	}
	if diff := cmp.Diff([]string{"founder", "other"},
		oneLink.names(pickSet(rankRoutes(oneLink.all()), selF, bus.Cluster{}))); diff != "" {
		t.Errorf("set over one link (-want +got):\n%s", diff)
	}
}

// TestPickSetAddsBackups checks the backups: while some link is crossed by
// every route picked, the cheapest route avoiding one such link joins, until
// no route avoids the links left in common. Three routes from F reach the
// node through K over one interface; the cheapest leads, the next avoids
// its link out of M, the last its link out of F, and K's link into the node
// stays common to all.
func TestPickSetAddsBackups(t *testing.T) {
	now := time.Now()
	routes := labeled{
		"cheapest": rawRoute(9, now,
			hopSpec{selF, 0, 1, ms}, hopSpec{selM, 2, 3, ms}, hopSpec{selK, 4, 5, ms}),
		"around M's link": rawRoute(9, now,
			hopSpec{selF, 0, 1, ms}, hopSpec{selM, 2, 11, ms}, hopSpec{selK, 12, 5, 2 * ms}),
		"around F's link": rawRoute(9, now,
			hopSpec{selF, 0, 6, ms}, hopSpec{selN, 7, 8, ms}, hopSpec{selK, 10, 5, 3 * ms}),
	}
	got := routes.names(pickSet(rankRoutes(routes.all()), selF, bus.Cluster{}))
	if diff := cmp.Diff([]string{"cheapest", "around M's link", "around F's link"}, got); diff != "" {
		t.Errorf("set (-want +got):\n%s", diff)
	}
	alone := labeled{"cheapest": routes["cheapest"]}
	if diff := cmp.Diff([]string{"cheapest"},
		alone.names(pickSet(rankRoutes(alone.all()), selF, bus.Cluster{}))); diff != "" {
		t.Errorf("set of a lone route (-want +got):\n%s", diff)
	}
}

// TestPickSetCoversEveryInterface checks the last picks: each interface with
// routes of which none was picked adds its cheapest, and an interface
// already covered adds none. F's direct route leads, M's route avoids its
// link as the backup, N's interface adds its cheapest route, and the dearer
// second routes over M's and N's interfaces stay out.
func TestPickSetCoversEveryInterface(t *testing.T) {
	now := time.Now()
	routes := labeled{
		"direct": rawRoute(1, now, hopSpec{selF, 0, 1, ms}),
		"via M": rawRoute(2, now,
			hopSpec{selF, 0, 2, ms}, hopSpec{selM, 3, 4, ms}),
		"via N": rawRoute(3, now,
			hopSpec{selF, 0, 1, ms}, hopSpec{selN, 5, 6, 2 * ms}),
		"via K and M": rawRoute(2, now,
			hopSpec{selF, 0, 10, ms}, hopSpec{selK, 11, 12, ms}, hopSpec{selM, 13, 4, ms}),
		"via K and N": rawRoute(3, now,
			hopSpec{selF, 0, 14, ms}, hopSpec{selK, 15, 16, ms}, hopSpec{selN, 17, 6, ms}),
	}
	got := routes.names(pickSet(rankRoutes(routes.all()), selF, bus.Cluster{}))
	if diff := cmp.Diff([]string{"direct", "via M", "via N"}, got); diff != "" {
		t.Errorf("set (-want +got):\n%s", diff)
	}
}

// TestPickSetCoversEveryLinkIntoTheCluster checks the picks for a cluster:
// each link into the cluster with routes of which none was picked adds its
// cheapest, whichever member the route reaches the node through. M is the
// node's fellow member. F's direct route leads and the route through M is
// its backup; the routes through M that entered the cluster from N and from
// K add one each, and the dearer second route from N, over the same link
// into the cluster, stays out. In no cluster, the routes through M add none.
func TestPickSetCoversEveryLinkIntoTheCluster(t *testing.T) {
	now := time.Now()
	routes := labeled{
		"direct": rawRoute(1, now, hopSpec{selF, 0, 1, ms}),
		"via M": rawRoute(2, now,
			hopSpec{selF, 0, 2, ms}, hopSpec{selM, 3, 4, ms}),
		"from N": rawRoute(2, now,
			hopSpec{selF, 0, 5, ms}, hopSpec{selN, 6, 7, ms}, hopSpec{selM, 8, 4, ms}),
		"from K": rawRoute(2, now,
			hopSpec{selF, 0, 9, ms}, hopSpec{selK, 10, 11, 2 * ms}, hopSpec{selM, 12, 4, ms}),
		"from N again": rawRoute(2, now,
			hopSpec{selF, 0, 13, ms}, hopSpec{selK, 14, 15, ms}, hopSpec{selN, 16, 7, ms},
			hopSpec{selM, 8, 4, ms}),
	}
	ranked := rankRoutes(routes.all())
	got := routes.names(pickSet(ranked, selF, bus.NewCluster(selM)))
	if diff := cmp.Diff([]string{"direct", "via M", "from N", "from K"}, got); diff != "" {
		t.Errorf("set in the cluster (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"direct", "via M"}, routes.names(pickSet(ranked, selF, bus.Cluster{}))); diff != "" {
		t.Errorf("set in no cluster (-want +got):\n%s", diff)
	}
}

// TestPickSetKeepsItsFirstPicks checks the bound: of more origins than a set
// holds, the set keeps the first maxSetSize picks, the cheapest origins.
func TestPickSetKeepsItsFirstPicks(t *testing.T) {
	now := time.Now()
	var cands []Candidate
	for i := range maxSetSize + 6 {
		origin := addr.MustIAFrom(30, 0xff0000001000+addr.AS(i))
		cands = append(cands, rawRoute(uint16(i+1), now,
			hopSpec{origin, 0, 1, time.Duration(i+1) * ms}))
	}
	set := pickSet(rankRoutes(cands), selF, bus.Cluster{})
	if len(set) != maxSetSize {
		t.Fatalf("set holds %d routes, want %d", len(set), maxSetSize)
	}
	for k, c := range set {
		if c.PCB != cands[k].PCB {
			t.Fatalf("pick %d = the route over interface %d, want the %d-th cheapest",
				k, c.Ingress, k+1)
		}
	}
	if got := pickSet(nil, selF, bus.Cluster{}); len(got) != 0 {
		t.Errorf("set of no routes = %d routes, want none", len(got))
	}
}
