package controlplane

import (
	"sync"
	"time"
)

// LinkLatency is the node's latest per-link one-way delay samples: the
// selection loop's echo round trips halved, keyed by interface ID. The
// beaconer's entries declare them — the StaticInfoExtension the drafts
// define — so a sample one evaluation window measures rides the next
// beacons out, each AS attesting its own links alone. A link without a
// fresh sample declares nothing: recording zero drops the declaration, and
// a link that regains a sample declares again at the next entry the
// beacons carry.
type LinkLatency struct {
	mtx sync.Mutex
	m   map[uint16]time.Duration
}

// NewLinkLatency returns an empty sample table.
func NewLinkLatency() *LinkLatency {
	return &LinkLatency{m: make(map[uint16]time.Duration)}
}

// Record records the interface's one-way delay estimate; zero drops the
// interface's sample.
func (l *LinkLatency) Record(ifID uint16, oneWay time.Duration) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if oneWay == 0 {
		delete(l.m, ifID)
		return
	}
	l.m[ifID] = oneWay
}

// Sample returns the interface's latest one-way delay estimate; zero when
// the last window measured none.
func (l *LinkLatency) Sample(ifID uint16) time.Duration {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return l.m[ifID]
}
