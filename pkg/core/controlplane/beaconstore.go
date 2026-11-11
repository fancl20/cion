package controlplane

import (
	"sort"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/beaconing"
)

// storePerInterface bounds the routes kept per ingress interface, the
// stalest leaving first.
const storePerInterface = 64

// beaconKey identifies a candidate by its ingress interface and its route:
// every origination of one route over one interface shares the key, each
// drawing a fresh segment ID and timestamp over the same links.
type beaconKey struct {
	ingress uint16
	route   string
}

// BeaconStore holds candidate PCBs in memory (draft Section 2.3.2): keyed by
// ingress interface and route, keeping each route's latest origination and
// when it arrived, expiring entries with their hops. A restarted node is
// rebuilt by the next period's beacons.
type BeaconStore struct {
	mtx     sync.Mutex
	beacons map[beaconKey]candidate
}

func NewBeaconStore() *BeaconStore {
	return &BeaconStore{beacons: make(map[beaconKey]candidate)}
}

type candidate struct {
	beaconing.Candidate
	timestamp time.Time
	arrived   time.Time
}

// Insert stores the beacon, replacing the entry with the same key — a
// re-origination of one route over one ingress — when the new origination is
// fresher, recording when it arrived, and keeping per-interface capacity
// bounded by evicting the stalest candidates.
func (s *BeaconStore) Insert(ingress uint16, pcb *segment.PCB) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	key := beaconKey{ingress: ingress, route: pcb.RouteKey()}
	if existing, ok := s.beacons[key]; ok && !pcb.Timestamp().After(existing.timestamp) {
		return
	}
	s.beacons[key] = candidate{
		Ingress: ingress, PCB: pcb,
		timestamp: pcb.Timestamp(),
		arrived:   time.Now(),
	}
	s.evictStale(ingress)
}

// evictStale drops expired candidates and, beyond the per-interface bound,
// the stalest ones. Callers hold the lock.
func (s *BeaconStore) evictStale(ingress uint16) {
	now := time.Now()
	var perIngress []beaconKey
	for key, cand := range s.beacons {
		if key.ingress != ingress {
			continue
		}
		if !cand.PCB.Expiration().After(now) {
			delete(s.beacons, key)
			continue
		}
		perIngress = append(perIngress, key)
	}
	if len(perIngress) <= storePerInterface {
		return
	}
	sort.Slice(perIngress, func(i, j int) bool {
		return s.beacons[perIngress[i]].timestamp.After(s.beacons[perIngress[j]].timestamp)
	})
	for _, key := range perIngress[storePerInterface:] {
		delete(s.beacons, key)
	}
}

// Qualifying returns the unexpired candidates keep admits whose latest
// origination arrived within the window, in no particular order. keep runs
// under the store's lock.
func (s *BeaconStore) Qualifying(
	window time.Duration, keep func(beaconing.Candidate) bool) []beaconing.Candidate {

	s.mtx.Lock()
	defer s.mtx.Unlock()
	now := time.Now()
	var out []beaconing.Candidate
	for _, cand := range s.beacons {
		if cand.PCB.Expiration().After(now) && now.Sub(cand.arrived) <= window &&
			keep(cand.Candidate) {
			out = append(out, cand.Candidate)
		}
	}
	return out
}

// Len returns the number of stored candidates.
func (s *BeaconStore) Len() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return len(s.beacons)
}
