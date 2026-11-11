// Package beaconingtest is the beacon policy module's contract suite: what
// every method keeps. An answer holds only candidates the ask handed, none
// twice, and one at least whenever the ask handed any, whoever the receiver
// and whether a TRC is pinned; the handed beacons stay as they were; and the
// loops may ask at once. Which candidates a method picks, and in what order,
// are its own tests'.
package beaconingtest

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"

	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/beaconing"
)

// NewPolicy builds the method under test for the node ia.
type NewPolicy func(ia addr.IA) beaconing.Policy

// The suite's ISD-ASes: the node under test and its neighbor, the founding
// core and another core, and the ASes between them and the node.
var (
	nodeIA     = addr.MustIAFrom(40, 0xff0000000001)
	neighborIA = addr.MustIAFrom(40, 0xff0000000002)
	founderIA  = addr.MustIAFrom(40, 0xff0000000003)
	otherIA    = addr.MustIAFrom(40, 0xff0000000004)
	transitM   = addr.MustIAFrom(40, 0xff0000000005)
	transitN   = addr.MustIAFrom(40, 0xff0000000006)
)

// Run runs the contract suite against the method newPolicy builds.
func Run(t *testing.T, newPolicy NewPolicy) {
	t.Run("answers with candidates handed", func(t *testing.T) {
		p := newPolicy(nodeIA)
		for name, cands := range asks() {
			for _, receiver := range []addr.IA{nodeIA, neighborIA} {
				for _, founder := range []addr.IA{founderIA, 0} {
					keys := routeKeys(cands)
					if err := check(cands, p.Select(receiver, founder, cands)); err != nil {
						t.Errorf("%s, to %v, founder %v: %v", name, receiver, founder, err)
					}
					if !slices.Equal(keys, routeKeys(cands)) {
						t.Errorf("%s, to %v, founder %v: the handed beacons changed",
							name, receiver, founder)
					}
				}
			}
		}
	})

	t.Run("answers the loops at once", func(t *testing.T) {
		p := newPolicy(nodeIA)
		var wg sync.WaitGroup
		for name, cands := range asks() {
			for _, receiver := range []addr.IA{nodeIA, neighborIA} {
				wg.Go(func() {
					if err := check(cands, p.Select(receiver, founderIA, cands)); err != nil {
						t.Errorf("%s, to %v: %v", name, receiver, err)
					}
				})
			}
		}
		wg.Wait()
	})
}

// check reports how an answer breaks the contract for the candidates
// handed: no answer though some were handed, a candidate not handed, or one
// answered twice.
func check(handed, answer []beaconing.Candidate) error {
	if len(handed) > 0 && len(answer) == 0 {
		return errors.New("answered none of the candidates handed")
	}
	seen := make(map[beaconing.Candidate]bool, len(answer))
	for _, a := range answer {
		if !slices.Contains(handed, a) {
			return fmt.Errorf("answered a candidate not handed, over interface %d", a.Ingress)
		}
		if seen[a] {
			return fmt.Errorf("answered a candidate twice, over interface %d", a.Ingress)
		}
		seen[a] = true
	}
	return nil
}

// routeKeys returns the route keys of the candidates' beacons, in order.
func routeKeys(cands []beaconing.Candidate) []string {
	keys := make([]string, len(cands))
	for i, c := range cands {
		keys[i] = c.PCB.RouteKey()
	}
	return keys
}

// hop is one entry of a route the suite builds: the AS, its interfaces in
// construction direction, and its egress link's declared one-way delay, none
// when zero.
type hop struct {
	ia              addr.IA
	ingress, egress uint16
	latency         time.Duration
}

// candidate builds an unsigned candidate over the hops, originated at ts and
// arrived over ingress.
func candidate(ingress uint16, ts time.Time, hops ...hop) beaconing.Candidate {
	pcb := &segment.PCB{Info: segment.Info{Timestamp: ts}}
	for _, h := range hops {
		e := segment.ASEntry{IA: h.ia, Hop: path.HopField{ConsIngress: h.ingress, ConsEgress: h.egress}}
		if h.latency != 0 {
			e.Latency = map[segment.LinkID]time.Duration{{IA: h.ia, IfID: h.egress}: h.latency}
		}
		pcb.Entries = append(pcb.Entries, e)
	}
	return beaconing.Candidate{Ingress: ingress, PCB: pcb}
}

// asks returns the candidates the suite hands, by name: none; one route; two
// origins over two interfaces; routes that share their links over one
// interface; routes that declare no delay; and one route from each of many
// origins.
func asks() map[string][]beaconing.Candidate {
	ts := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	ms := time.Millisecond
	var many []beaconing.Candidate
	for i := range 100 {
		origin := addr.MustIAFrom(40, 0xff0000001000+addr.AS(i))
		many = append(many, candidate(uint16(i%8+1), ts,
			hop{origin, 0, 1, time.Duration(i%7+1) * ms}))
	}
	return map[string][]beaconing.Candidate{
		"none":      nil,
		"one route": {candidate(1, ts, hop{founderIA, 0, 1, ms})},
		"two origins": {
			candidate(1, ts, hop{founderIA, 0, 1, 2 * ms}),
			candidate(2, ts, hop{otherIA, 0, 1, ms}),
			candidate(2, ts, hop{founderIA, 0, 2, ms}, hop{transitM, 3, 4, ms}),
		},
		"shared links": {
			candidate(1, ts, hop{founderIA, 0, 1, ms}, hop{transitM, 2, 3, ms}),
			candidate(1, ts, hop{founderIA, 0, 1, ms}, hop{transitM, 2, 5, 2 * ms}),
			candidate(1, ts, hop{founderIA, 0, 6, ms}, hop{transitN, 7, 3, 3 * ms}),
		},
		"no delays declared": {
			candidate(1, ts, hop{founderIA, 0, 1, 0}),
			candidate(2, ts.Add(time.Second), hop{otherIA, 0, 1, 0}, hop{transitM, 2, 3, 0}),
		},
		"many origins": many,
	}
}
