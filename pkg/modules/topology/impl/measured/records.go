package measured

import (
	"fmt"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The changes the selection's records name, each the message its log line
// carries.
const (
	LinkPromoted        = "Link promoted"
	LinkRetired         = "Link retired"
	PromotionAnnounced  = "Promotion announced"
	PromotionWithdrawn  = "Promotion withdrawn"
	RetirementAnnounced = "Retirement announced"
	RetirementWithdrawn = "Retirement withdrawn"
	ClusterJoined       = "Cluster joined"
	ClusterLeft         = "Cluster left"
)

// verdict is what a decision found: why it changes the node's state, the
// line it cleared, and the estimates it weighed, each named.
type verdict struct {
	why     string
	line    time.Duration
	weighed []evidence.Weighed
}

// record appends the record of a change to the node's journal of changes,
// its subject the peer or the node it concerns; nothing without a journal.
func (s *selection) record(change, subject, from, to string, v verdict) {
	if s.cfg.Changes == nil {
		return
	}
	s.cfg.Changes.Append(evidence.Record{At: time.Now(), Change: change, Subject: subject, From: from, To: to,
		Why: v.why, Line: v.line, Weighed: v.weighed})
}

// linkName names a link in a record by its interface.
func linkName(ifID uint16) string {
	return fmt.Sprintf("interface %d", ifID)
}

// clusterLabel names a cluster in a record: its name, nothing for none.
func clusterLabel(cluster addr.IA) string {
	if cluster == 0 {
		return ""
	}
	return cluster.String()
}

// reachedVerdict returns the verdict of a candidate a rule promotes for
// reaching it at all: the direct side weighed alone.
func reachedVerdict(why string, sm sample) verdict {
	return verdict{why: why, weighed: []evidence.Weighed{{Name: "direct", Estimate: sm.reading}}}
}

// secondRouteVerdict returns the verdict of a candidate promoted as a second
// route for its tier: the room the ratio leaves above the tier's price, and
// the direct side and that price weighed.
func secondRouteVerdict(t *tier, sm sample) verdict {
	return verdict{
		why:  "a second route for its tier",
		line: ratioOf(t.price, SecondRouteRatio) - t.price,
		weighed: []evidence.Weighed{
			{Name: "direct", Estimate: sm.reading},
			{Name: "price", Estimate: readingOfRoute(t.priceRoute)},
		},
	}
}

// beatenVerdict returns the verdict of a member whose direct round trip
// beats its own price, the tier's when no route prices the member, as beats
// reads the two: on the readings, the gain the promotion ratio and the margin
// floor ask, the readings weighed; else confirmed, the band, the bounds
// weighed.
func beatenVerdict(t *tier, ia addr.IA, sm sample) verdict {
	price, low := t.prices[ia], t.lows[ia]
	priceRoute, lowRoute := t.priceRoutes[ia], t.lowRoutes[ia]
	if price == 0 {
		price, low = t.price, t.low
		priceRoute, lowRoute = t.priceRoute, t.lowRoute
	}
	if sm.direct < ratioOf(price, PromotionRatio) && price-sm.direct >= MarginFloor {
		return verdict{
			why:  "its direct link beats its own price on its readings",
			line: max(price-ratioOf(price, PromotionRatio), MarginFloor),
			weighed: []evidence.Weighed{
				{Name: "direct", Estimate: sm.reading},
				{Name: "price", Estimate: readingOfRoute(priceRoute)},
			},
		}
	}
	return verdict{
		why:  "its direct link beats its own price, its history confirming",
		line: scion.Band(sm.hi, low),
		weighed: []evidence.Weighed{
			{Name: "direct", Estimate: sm.bounds},
			{Name: "price", Estimate: boundsOfRoute(lowRoute)},
		},
	}
}

// evictedVerdict returns the verdict of a link the cap's eviction displaces
// for a candidate: the candidate's estimates as its own verdict weighed
// them, and, for an up link, its tier's price with and without it.
func evictedVerdict(e target, admitted verdict, victim *links.Link, ts []tier) verdict {
	v := verdict{
		why:     "displaced by the least-harm eviction for " + e.IA.String(),
		weighed: slices.Clone(admitted.weighed),
	}
	t := tierOf(ts, victim.NeighborIA)
	if t == nil {
		return v
	}
	if ex, ok := t.excluded[victim.NeighborIA]; ok && t.priceRoute != nil && ex.priceRoute != nil {
		v.weighed = append(v.weighed,
			evidence.Weighed{Name: "with", Estimate: readingOfRoute(t.priceRoute)},
			evidence.Weighed{Name: "without", Estimate: readingOfRoute(ex.priceRoute)})
	}
	return v
}

// uselessWeighed returns what a link's useless test confirmed its readings
// by: the bounds of its direct side, and at the tier's level those of the
// cheapest route crossing the link and of the survivors', those the probes
// give; the direct side's alone for a peer the window classed into no tier.
func uselessWeighed(t *tier, ia addr.IA, sm sample) []evidence.Weighed {
	weighed := []evidence.Weighed{{Name: "direct", Estimate: sm.bounds}}
	if t == nil {
		return weighed
	}
	ex := t.excluded[ia]
	if ex.lowRoute != nil {
		weighed = append(weighed, evidence.Weighed{Name: "crossing", Estimate: boundsOfRoute(ex.lowRoute)})
	}
	if ex.highRoute != nil {
		weighed = append(weighed, evidence.Weighed{Name: "survivors", Estimate: boundsOfRoute(ex.highRoute)})
	}
	return weighed
}

// readingOfRoute returns the estimate a route's reading comes from, at its
// price.
func readingOfRoute(c *scion.Candidate) evidence.Estimate {
	return c.ReadingEvidence.Plus(c.Charge())
}

// boundsOfRoute returns the estimate a route's bounds come from, at its
// price.
func boundsOfRoute(c *scion.Candidate) evidence.Estimate {
	return c.BoundsEvidence.Plus(c.Charge())
}
