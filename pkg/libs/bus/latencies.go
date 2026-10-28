package bus

import (
	"maps"
	"time"
)

// LinkLatencies is the node's latest one-way delay estimates of its links,
// by interface ID: each link's echo round trip halved, as one selection
// window measured them. A published LinkLatencies is never mutated. The zero
// LinkLatencies holds no estimate.
type LinkLatencies struct {
	m map[uint16]time.Duration
}

// NewLinkLatencies returns the estimates the map holds, copied, its zero
// delays left out.
func NewLinkLatencies(m map[uint16]time.Duration) LinkLatencies {
	l := LinkLatencies{m: maps.Clone(m)}
	maps.DeleteFunc(l.m, func(_ uint16, d time.Duration) bool { return d == 0 })
	return l
}

// Of returns the link's one-way delay estimate, zero when the latencies hold
// none.
func (l LinkLatencies) Of(ifID uint16) time.Duration {
	return l.m[ifID]
}
