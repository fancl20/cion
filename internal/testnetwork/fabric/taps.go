package fabric

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"
)

// tap is one drawn impairment: the host pair it covers, the one-way time
// each direction's packets are held for, and the fraction of the pair's
// packets dropped.
type tap struct {
	a, b     netip.Addr
	oneWay   time.Duration
	fraction float64
}

// covers reports whether the packet's pair is the tap's, either direction.
func (t *tap) covers(src, dst netip.Addr) bool {
	return (src == t.a && dst == t.b) || (src == t.b && dst == t.a)
}

// drops reports whether one packet of the pair falls.
func (t *tap) drops() bool {
	if t.fraction >= 1 {
		return true
	}
	return t.fraction > 0 && rand.Float64() < t.fraction
}

// Delay draws a one-way delay for the pair, each direction's packets held
// the drawn time on the fabric's clock — the netem bands the stranded lab
// steered by pair. The returned lift removes the tap.
func (f *Fabric) Delay(a, b netip.Addr, oneWay time.Duration) func() {
	return f.draw(&tap{a: a, b: b, oneWay: oneWay})
}

// Loss draws a loss for the pair, the fraction of its packets dropped in
// both directions — wholly at one, the blackhole and the cut. The returned
// lift removes the tap.
func (f *Fabric) Loss(a, b netip.Addr, fraction float64) func() {
	return f.draw(&tap{a: a, b: b, fraction: fraction})
}

// Blackhole drops both directions of the pair while it stands; the returned
// lift restores them.
func (f *Fabric) Blackhole(a, b netip.Addr) func() {
	return f.Loss(a, b, 1)
}

// Cut drops the pair's packets; the returned lift restores them.
func (f *Fabric) Cut(a, b netip.Addr) func() {
	return f.Loss(a, b, 1)
}

// draw enters a tap into the fabric's set.
func (f *Fabric) draw(t *tap) func() {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.taps = append(f.taps, t)
	return func() {
		f.mtx.Lock()
		defer f.mtx.Unlock()
		f.taps = slices.DeleteFunc(f.taps, func(x *tap) bool { return x == t })
	}
}

// shape reads the taps covering the packet's pair, reporting whether the
// packet falls and how long the pair's taps hold it in sum.
func (f *Fabric) shape(src, dst netip.Addr) (drop bool, delay time.Duration) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, t := range f.taps {
		if !t.covers(src, dst) {
			continue
		}
		if t.drops() {
			drop = true
		}
		delay += t.oneWay
	}
	return drop, delay
}
