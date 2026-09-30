package controlplane

import (
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/segment"
)

// storePerInterface bounds the candidate PCBs kept per ingress interface: the
// store is write-heavy and valid for one beaconing period at a time, so the
// freshest candidates are enough.
const storePerInterface = 64

// beaconKey identifies a candidate by its ingress interface, originating
// ISD-AS, and segment ID: the identity the rest of the system already reads
// from a segment, so two origins sharing an ingress and an ID are two
// candidates, not one slot the fresher takes.
type beaconKey struct {
	ingress uint16
	origin  addr.IA
	id      uint16
}

// BeaconStore holds candidate PCBs in memory (draft Section 2.3.2): keyed by
// ingress interface, originating ISD-AS, and segment ID, keeping the latest
// origination per key, expiring entries with their hops. A restarted node is
// rebuilt by the next period's beacons.
type BeaconStore struct {
	mtx     sync.Mutex
	beacons map[beaconKey]candidate
}

// Candidate is a stored beacon with the interface it arrived on.
type Candidate struct {
	// Ingress is the interface the beacon arrived on: the node's parent
	// side of that link.
	Ingress uint16
	// PCB is the candidate beacon.
	PCB *segment.PCB
}

func NewBeaconStore() *BeaconStore {
	return &BeaconStore{beacons: make(map[beaconKey]candidate)}
}

type candidate struct {
	Candidate
	timestamp time.Time
}

// Insert stores the beacon, replacing the entry with the same key — one
// origin's re-origination of one segment over one ingress — when the new
// origination is fresher, and keeping per-interface capacity bounded by
// evicting the stalest candidates. The origin is the beacon's first entry,
// the identity reception verified against the TRC's core list.
func (s *BeaconStore) Insert(ingress uint16, pcb *segment.PCB) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	key := beaconKey{ingress: ingress, origin: pcb.FirstIA(), id: pcb.ID()}
	if existing, ok := s.beacons[key]; ok && !pcb.Timestamp().After(existing.timestamp) {
		return
	}
	s.beacons[key] = candidate{
		Ingress: ingress, PCB: pcb,
		timestamp: pcb.Timestamp(),
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

// BestSet returns the fixed bounded set of freshest unexpired candidates — the
// store's per-key freshness ordering is the only selection rule (no policy
// engine).
func (s *BeaconStore) BestSet(n int) []Candidate {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	now := time.Now()
	cands := make([]candidate, 0, len(s.beacons))
	for _, cand := range s.beacons {
		if cand.PCB.Expiration().After(now) {
			cands = append(cands, cand)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].timestamp.Equal(cands[j].timestamp) {
			return cands[i].PCB.ID() > cands[j].PCB.ID()
		}
		return cands[i].timestamp.After(cands[j].timestamp)
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]Candidate, len(cands))
	for i, cand := range cands {
		out[i] = cand.Candidate
	}
	return out
}

// Len returns the number of stored candidates.
func (s *BeaconStore) Len() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return len(s.beacons)
}
