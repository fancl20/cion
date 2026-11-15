// Package congestiontest is the congestion module's contract suite: what
// every method keeps. A fresh policy brakes no link; a link whose echoes
// come back at their least is not braked, however much it writes; a link
// whose egress queue is empty marks nothing, whatever it owed before; a link
// that writes calls for echoes across it; a link's last echo is the latest
// reply to its echoes or request of the neighbor's; and the data plane's
// processors and senders, the loop that hands the policy its echoes'
// outcomes, the responder, and the BFD sessions may call the methods at once. When a method brakes a link, how far, how many
// replies it marks, and how often it calls for echoes are its own tests'.
package congestiontest

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/modules/congestion"
)

// NewPolicy builds the policy of the method under test, which calls echo for
// each echo it calls for to the next hop across a link.
type NewPolicy func(echo func(ifID uint16)) congestion.Policy

// link is one of the suite's links: its interface, its echoes' round trip
// while no queue stands, and the packets it writes each tick.
type link struct {
	ifID    uint16
	least   time.Duration
	packets int
}

// The suite's links: a near next hop, one across a country, and one across
// the world. They write a packet, a hundred, and ten thousand a tick.
var links = []link{
	{ifID: 1, least: 2 * time.Millisecond, packets: 1},
	{ifID: 2, least: 40 * time.Millisecond, packets: 100},
	{ifID: 3, least: 300 * time.Millisecond, packets: 10_000},
}

// The suite's clock: each link writes once a tick, for ticks ticks, in
// packets of packetSize bytes.
const (
	tick       = 100 * time.Millisecond
	ticks      = 100
	packetSize = 1500
)

// echoes counts the echoes a policy calls for across each link.
type echoes struct {
	mu     sync.Mutex
	called map[uint16]int
}

// newEchoes returns a count of echoes that has counted none.
func newEchoes() *echoes {
	return &echoes{called: make(map[uint16]int)}
}

// call counts an echo called for across the link.
func (e *echoes) call(ifID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.called[ifID]++
}

// take returns how many echoes were called for across the link since the
// last take.
func (e *echoes) take(ifID uint16) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.called[ifID]
	delete(e.called, ifID)
	return n
}

// Run runs the contract suite against the method newPolicy builds.
func Run(t *testing.T, newPolicy NewPolicy) {
	t.Run("a fresh policy brakes no link", func(t *testing.T) {
		p := newPolicy(newEchoes().call)
		for _, ifID := range []uint16{0, 1, 2, 3, 65535} {
			if rate := p.Rate(ifID); rate != 0 {
				t.Errorf("Rate(%d) = %v on a fresh policy, want 0", ifID, rate)
			}
		}
	})

	t.Run("echoes at their least brake no link", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newEchoes()
			p := newPolicy(e.call)
			start := time.Now()
			for range ticks {
				time.Sleep(tick)
				for _, l := range links {
					p.Wrote(l.ifID, l.packets, l.packets*packetSize, false)
					// Each echo called for comes back now, sent its round
					// trip ago.
					for range e.take(l.ifID) {
						p.Sampled(l.ifID, evidence.Sample{At: time.Now().Add(-l.least), RTT: l.least})
					}
					if rate := p.Rate(l.ifID); rate != 0 {
						t.Fatalf("Rate(%d) = %v %v on, its echoes at their "+
							"least; want 0", l.ifID, rate, time.Since(start))
					}
				}
			}
		})
	})

	t.Run("an empty queue marks nothing", func(t *testing.T) {
		for name, before := range map[string][]float64{
			"a fresh link":         nil,
			"after a full queue":   {1, 1, 1, 1},
			"after part of a mark": {0.9},
			"after a filling one":  {0.25, 0.5, 0.75, 1},
		} {
			p := newPolicy(newEchoes().call)
			for _, l := range links {
				for _, fill := range before {
					p.Mark(l.ifID, fill)
				}
				for i := range 10 {
					if p.Mark(l.ifID, 0) {
						t.Errorf("%s: link %d marked reply %d, its queue "+
							"empty", name, l.ifID, i)
					}
				}
			}
		}
	})

	t.Run("a link that writes calls for echoes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newEchoes()
			p := newPolicy(e.call)
			// Each link writes 500 packets over five seconds.
			for range 50 {
				time.Sleep(tick)
				for _, l := range links {
					p.Wrote(l.ifID, 10, 10*packetSize, false)
				}
			}
			for _, l := range links {
				if n := e.take(l.ifID); n == 0 {
					t.Errorf("link %d called for no echo across it, having "+
						"written 500 packets", l.ifID)
				}
			}
		})
	})

	t.Run("a link's last echo is the latest reply or request across it", func(t *testing.T) {
		p := newPolicy(newEchoes().call)
		t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		if got := p.Echoed(1); !got.IsZero() {
			t.Fatalf("Echoed(1) = %v on a fresh policy, want zero", got)
		}
		p.Sampled(1, evidence.Sample{At: t0, RTT: 20 * time.Millisecond})
		if got, want := p.Echoed(1), t0.Add(20*time.Millisecond); !got.Equal(want) {
			t.Fatalf("Echoed(1) = %v after a reply, want its arrival %v", got, want)
		}
		p.Requested(1, t0.Add(time.Second))
		if got, want := p.Echoed(1), t0.Add(time.Second); !got.Equal(want) {
			t.Fatalf("Echoed(1) = %v after a request, want its arrival %v", got, want)
		}
		p.Sampled(1, evidence.Sample{At: t0.Add(2 * time.Second), Lost: true})
		p.Sampled(1, evidence.Sample{At: t0, RTT: 30 * time.Millisecond})
		p.Requested(1, t0)
		if got, want := p.Echoed(1), t0.Add(time.Second); !got.Equal(want) {
			t.Errorf("Echoed(1) = %v after a lost echo and earlier arrivals, want still %v", got, want)
		}
		if got := p.Echoed(2); !got.IsZero() {
			t.Errorf("Echoed(2) = %v, its link carrying no echo, want zero", got)
		}
	})

	t.Run("the methods may be called at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy(newEchoes().call)
			var wg sync.WaitGroup
			for _, l := range links {
				// The echoes stand a second over their least through the
				// middle half, a fifth of them lost, then clear.
				wg.Go(func() {
					for i := range ticks {
						time.Sleep(tick)
						s := evidence.Sample{At: time.Now(), RTT: l.least}
						if i >= ticks/4 && i < ticks*3/4 {
							s.RTT += time.Second
							if i%5 == 0 {
								s.RTT, s.Lost = 0, true
							}
						}
						p.Sampled(l.ifID, s)
					}
				})
				wg.Go(func() {
					for range ticks {
						time.Sleep(tick)
						p.Wrote(l.ifID, l.packets, l.packets*packetSize, false)
					}
				})
				wg.Go(func() {
					for range ticks {
						time.Sleep(tick)
						p.Rate(l.ifID)
					}
				})
				wg.Go(func() {
					for i := range ticks {
						time.Sleep(tick)
						if fill := float64(i%5) / 4; p.Mark(l.ifID, fill) && fill == 0 {
							t.Errorf("link %d marked a reply, its queue empty", l.ifID)
						}
					}
				})
				wg.Go(func() {
					for range ticks {
						time.Sleep(tick)
						p.Requested(l.ifID, time.Now())
						p.Echoed(l.ifID)
					}
				})
			}
			wg.Wait()
		})
	})
}
