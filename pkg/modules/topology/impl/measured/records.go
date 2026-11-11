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
	return verdict{why: why, weighed: []evidence.Weighed{{Name: "direct", Estimate: sm.bounds}}}
}

// secondRouteVerdict returns the verdict of a candidate promoted as a second
// route for its tier: the direct side and the tier's ceiling weighed.
func secondRouteVerdict(t *tier, sm sample) verdict {
	return verdict{
		why: "a second route for its tier",
		weighed: []evidence.Weighed{
			{Name: "direct", Estimate: sm.bounds},
			{Name: "ceiling", Estimate: secondRouteCeiling(t.estimate)},
		},
	}
}

// beatenVerdict returns the verdict of a member whose direct side beats its
// own price, the tier's when no route prices the member: the band, and the
// direct side and the price weighed.
func beatenVerdict(sm sample, price evidence.Estimate) verdict {
	return verdict{
		why:  "its direct link beats its own price",
		line: scion.Band(sm.bounds.Value, price.Value),
		weighed: []evidence.Weighed{
			{Name: "direct", Estimate: sm.bounds},
			{Name: "price", Estimate: price},
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
	if ex, ok := t.excluded[victim.NeighborIA]; ok && t.estimate.Answered > 0 && ex.survivors.Answered > 0 {
		v.weighed = append(v.weighed,
			evidence.Weighed{Name: "with", Estimate: t.estimate},
			evidence.Weighed{Name: "without", Estimate: ex.survivors})
	}
	return v
}

// uselessWeighed returns what a link's useless test weighed: the direct
// side, and at the tier's level the routes crossing the link and the
// survivors, those that price; the direct side's alone for a peer the window
// classed into no tier.
func uselessWeighed(t *tier, ia addr.IA, sm sample) []evidence.Weighed {
	weighed := []evidence.Weighed{{Name: "direct", Estimate: sm.bounds}}
	if t == nil {
		return weighed
	}
	ex := t.excluded[ia]
	if ex.crossing.Answered > 0 {
		weighed = append(weighed, evidence.Weighed{Name: "crossing", Estimate: ex.crossing})
	}
	if ex.survivors.Answered > 0 {
		weighed = append(weighed, evidence.Weighed{Name: "survivors", Estimate: ex.survivors})
	}
	return weighed
}

// naturalVerdict returns the verdict of a node the natural cluster holds:
// the cluster's separation floor and its separation weighed.
func naturalVerdict(v *coordView, c []addr.IA) verdict {
	diameter, separation, _ := spread(v, c)
	return verdict{
		why: "a natural cluster holds the node",
		weighed: []evidence.Weighed{
			{Name: "floor", Estimate: separationFloor(diameter)},
			{Name: "separation", Estimate: separation},
		},
	}
}

// brokenVerdict returns the verdict of a node whose unit breaks the budget
// for a pair across its edge, as buys weighs it: MarginFloor, the line the
// pair's direct round trip beats the round trip through the clusters by,
// and the direct round trip, the buy ceiling of the round trip through the
// clusters, and that round trip weighed.
func brokenVerdict(direct, through evidence.Estimate) verdict {
	return verdict{
		why:  "a pair across its unit's edge breaks the budget",
		line: MarginFloor,
		weighed: []evidence.Weighed{
			{Name: "direct", Estimate: direct},
			{Name: "ceiling", Estimate: buyCeiling(through)},
			{Name: "through", Estimate: through},
		},
	}
}
