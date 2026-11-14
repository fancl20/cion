package scion

import (
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// The ECN codepoints of the traffic class's low two bits.
const (
	ecnMask = 0x3
	ecnECT0 = 0x2
	ecnCE   = 0x3
)

// The destination rates' pace and steps.
const (
	// rateTick is how long each of a destination's ticks runs: a closed
	// tick's bytes join the base, and after a clean answer the tick climbs
	// a set rate once.
	rateTick = 100 * time.Millisecond
	// rateTicks is how many ticks make a second; rateBase is how many
	// seconds back a destination's base, the most it was sent in any
	// second, reaches.
	rateTicks = int(time.Second / rateTick)
	rateBase  = 10
	// rateGain is how far each answer moves a destination's average share of
	// marked answers toward its own, as DCTCP's gain moves its average.
	rateGain = 1.0 / 16
	// rateClimb raises a set rate at each tick closed after a clean answer,
	// up to twice the base, or to rateFloor where twice the base lies under
	// it.
	rateClimb = 1.0 / 256
	// rateFloor is the least a rate falls to, in bits per second.
	rateFloor = 64_000
	// rateHold is how far ahead a write's turn may lie; a write whose turn
	// lies further is dropped.
	rateHold = 100 * time.Millisecond
	// rateUnset is how long a set rate goes neither cut nor climbed before
	// it unsets: the marks stopped, or the traffic did.
	rateUnset = 30 * time.Second
	// arrivalBucket is how finely a destination's arrivals count, over the
	// hotSpan a path's marks read.
	arrivalBucket = hotSpan / 3
)

// ECN is the node's destination rates: one state, which every socket the
// node opens shares. For each destination node it counts what the sockets
// other than control ones send there, and keeps a rate, unset until an
// answer to one of the node's echoes there comes back marked, which paces
// those sockets' writes there. The writes and the answers move it; each
// first closes the destination's ticks that ended, as a library runs no
// loop. It also counts what each destination sends those sockets, and how
// much of it comes marked.
type ECN struct {
	mtx   sync.Mutex
	dests map[addr.IA]*destRate
}

// destRate is one destination's counts and rate.
type destRate struct {
	// arrivals counts what the destination sent, by arrivalBucket, oldest
	// first, within hotSpan.
	arrivals []arrivals
	// tickBytes is what the current tick sent, in bytes; bytes holds what
	// each of the last rateTicks closed ticks sent; peaks holds the most
	// bytes any second ending in each of the last rateBase seconds sent;
	// ticks counts the closed ticks; and tickEnd is when the current tick
	// ends.
	tickBytes uint64
	bytes     [rateTicks]uint64
	peaks     [rateBase]uint64
	ticks     int
	tickEnd   time.Time
	// rate is the rate in bits per second, zero while unset; alpha is the
	// average share of marked answers; climbing reports whether the last
	// answer came back clean; cut is when the rate was last cut, and moved
	// when it was last cut or climbed; free is when the writes so far fit
	// the rate by.
	rate     float64
	alpha    float64
	climbing bool
	cut      time.Time
	moved    time.Time
	free     time.Time
}

// arrivals is what a destination sent within the arrivalBucket starting at
// start: its datagrams, and those that came marked.
type arrivals struct {
	start           time.Time
	arrived, marked int
}

// NewECN returns the state of a node that has sent nothing.
func NewECN() *ECN {
	return &ECN{dests: make(map[addr.IA]*destRate)}
}

// Answer hands the node's ECN state the answer to one of the node's echoes
// to dst: whether its reply came back marked, and when the request was
// sent. A conn without the state drops it.
func (c *Conn) Answer(dst addr.IA, marked bool, sent time.Time) {
	if c.ecn != nil {
		c.ecn.answer(dst, marked, sent, time.Now())
	}
}

// admit takes a write of size bytes to dst at now, once dst's ticks that
// ended are closed, reporting false where a rate is set and the write's turn
// lies more than rateHold ahead: the write is dropped, never queued. A write
// it takes counts in dst's current tick.
func (e *ECN) admit(dst addr.IA, size int, now time.Time) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	d := e.dest(dst)
	d.advance(dst, now)
	if d.rate != 0 {
		turn := d.free
		if turn.Before(now) {
			turn = now
		}
		if turn.Sub(now) > rateHold {
			return false
		}
		d.free = turn.Add(time.Duration(float64(size*8) * float64(time.Second) / d.rate))
	}
	d.tickBytes += uint64(size)
	return true
}

// answer takes an answer to an echo to dst at now, once dst's ticks that
// ended are closed: whether its reply came back marked, and when the request
// was sent. Every answer moves the average share of marked answers by
// rateGain, from a start of zero, so a stray mark cuts little: the brake on a
// congested link takes a load's first strain. A marked answer to a request
// sent after the last cut cuts the rate to 1 - average/2 of the lesser of
// itself and the base, as DCTCP cuts its window and as TCP cuts from what it
// sent rather than from its window, or sets an unset rate to that share of
// the base; no rate falls under rateFloor, and none is set for a destination
// whose base lies under it, for its traffic is not what filled the queue. A
// clean answer has each tick closed after it climb a set rate.
func (e *ECN) answer(dst addr.IA, marked bool, sent, now time.Time) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	d := e.dest(dst)
	d.advance(dst, now)
	d.climbing = !marked
	if marked {
		d.alpha += rateGain * (1 - d.alpha)
	} else {
		d.alpha -= rateGain * d.alpha
	}
	if !marked || !sent.After(d.cut) {
		return
	}
	keep := 1 - d.alpha/2
	switch base := d.base(); {
	case d.rate != 0:
		d.rate = max(rateFloor, keep*min(d.rate, base))
	case base >= rateFloor:
		d.rate = max(rateFloor, keep*base)
		slog.Info("Pacing the traffic to a node as its echoes' replies return marked",
			"destination", dst, "rate", int64(d.rate))
	default:
		return
	}
	d.cut, d.moved = now, now
}

// arrived counts a datagram src sent the node's sockets at now, marked or
// not.
func (e *ECN) arrived(src addr.IA, marked bool, now time.Time) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	d := e.dest(src)
	d.trimArrivals(now)
	start := now.Truncate(arrivalBucket)
	if n := len(d.arrivals); n == 0 || !d.arrivals[n-1].start.Equal(start) {
		d.arrivals = append(d.arrivals, arrivals{start: start})
	}
	last := &d.arrivals[len(d.arrivals)-1]
	last.arrived++
	if marked {
		last.marked++
	}
}

// Arrivals returns how many datagrams dst sent the node's sockets other
// than control ones within hotSpan of now, and how many of them came marked.
func (e *ECN) Arrivals(dst addr.IA, now time.Time) (arrived, marked int) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	d := e.dests[dst]
	if d == nil {
		return 0, 0
	}
	d.trimArrivals(now)
	for _, a := range d.arrivals {
		arrived, marked = arrived+a.arrived, marked+a.marked
	}
	return arrived, marked
}

// dest returns dst's state, adding a fresh one, whose average share of
// marked answers starts at zero; the mutex must be held.
func (e *ECN) dest(dst addr.IA) *destRate {
	d := e.dests[dst]
	if d == nil {
		d = new(destRate)
		e.dests[dst] = d
	}
	return d
}

// advance closes each of the destination's ticks that ended by now, the
// first with the bytes the current tick counted and the rest empty, and
// unsets a rate neither cut nor climbed for rateUnset. The destination's
// first event starts its first tick.
func (d *destRate) advance(dst addr.IA, now time.Time) {
	switch {
	case d.tickEnd.IsZero():
		d.tickEnd = now.Add(rateTick)
	case !now.Before(d.tickEnd):
		ticks := int(now.Sub(d.tickEnd)/rateTick) + 1
		// Past the base's reach, an empty tick changes nothing: the base
		// stands at zero, and the cap at the floor no rate lies under.
		for i := range min(ticks, rateTicks*rateBase+1) {
			d.closeTick(d.tickEnd.Add(time.Duration(i) * rateTick))
		}
		d.tickEnd = d.tickEnd.Add(time.Duration(ticks) * rateTick)
	}
	if d.rate != 0 && now.Sub(d.moved) >= rateUnset {
		slog.Info("Stopped pacing the traffic to a node", "destination", dst, "rate", int64(d.rate))
		d.rate = 0
	}
}

// trimArrivals drops the destination's arrivals that counted from hotSpan
// or more before now.
func (d *destRate) trimArrivals(now time.Time) {
	i := 0
	for i < len(d.arrivals) && now.Sub(d.arrivals[i].start) >= hotSpan {
		i++
	}
	d.arrivals = slices.Delete(d.arrivals, 0, i)
}

// closeTick closes the tick that ended at end: its bytes join the last
// second and the peaks, and, after a clean answer, a set rate climbs by
// rateClimb, to at most twice the base, or rateFloor where twice the base
// lies under it.
func (d *destRate) closeTick(end time.Time) {
	d.bytes[d.ticks%rateTicks] = d.tickBytes
	d.tickBytes = 0
	var second uint64
	for _, b := range d.bytes {
		second += b
	}
	i := d.ticks / rateTicks % rateBase
	if d.ticks%rateTicks == 0 {
		d.peaks[i] = 0
	}
	d.peaks[i] = max(d.peaks[i], second)
	d.ticks++
	if d.rate == 0 || !d.climbing {
		return
	}
	if next := min(d.rate*(1+rateClimb), max(rateFloor, 2*d.base())); next > d.rate {
		d.rate, d.moved = next, end
	}
}

// base returns the most the destination was sent in any second of the last
// rateBase, in bits per second.
func (d *destRate) base() float64 {
	return float64(slices.Max(d.peaks[:])) * 8
}
