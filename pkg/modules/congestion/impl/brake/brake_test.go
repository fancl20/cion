package brake

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/modules/congestion"
	"github.com/fancl20/cion/pkg/modules/congestion/impl/congestiontest"
)

const ms = time.Millisecond

// lost stands, among a test's round trips, for an echo lost.
const lost time.Duration = -1

// The interfaces of the tests' links.
const (
	linkID  uint16 = 3
	otherID uint16 = 4
)

// approx equates rates within a billionth of each other: the error float
// arithmetic leaves in a cut or a climb.
var approx = cmpopts.EquateApprox(1e-9, 0)

// TestContract runs the congestion contract suite against the brake method.
func TestContract(t *testing.T) {
	congestiontest.Run(t, func(echo func(uint16)) congestion.Policy { return New(echo) })
}

// newPolicy returns a brake method whose echoes go nowhere.
func newPolicy() *Policy {
	return New(func(uint16) {})
}

// second is one second on a test's link: the bytes the link writes as the
// second begins, in packets of 1000 bytes, and whether its rate held data
// back as it wrote them; and the round trips of the echoes it sends at the
// second's middle, whose outcomes come back at once.
type second struct {
	bytes int
	held  bool
	rtts  []time.Duration
}

// seconds returns n seconds in which the link writes bytes, its rate holding
// data back or not, and sends echoes that take the round trips.
func seconds(n, bytes int, held bool, rtts ...time.Duration) []second {
	return slices.Repeat([]second{{bytes: bytes, held: held, rtts: rtts}}, n)
}

// echoes returns n echoes' round trips of rtt.
func echoes(n int, rtt time.Duration) []time.Duration {
	return slices.Repeat([]time.Duration{rtt}, n)
}

// play plays the seconds on the link, one after another, and returns the
// rate read as each ends, which steps the link. It first reads the rate,
// which starts a fresh link's clock as the first second begins.
func play(p *Policy, ifID uint16, ss ...second) []float64 {
	p.Rate(ifID)
	var rates []float64
	for _, s := range ss {
		if s.bytes > 0 {
			p.Wrote(ifID, s.bytes/1000, s.bytes, s.held)
		}
		time.Sleep(500 * ms)
		for _, rtt := range s.rtts {
			p.Sampled(ifID, sent(rtt))
		}
		time.Sleep(500 * ms)
		rates = append(rates, p.Rate(ifID))
	}
	return rates
}

// sent returns the outcome of an echo sent now: its round trip, or its loss.
func sent(rtt time.Duration) evidence.Sample {
	if rtt == lost {
		return evidence.Sample{At: time.Now(), Lost: true}
	}
	return evidence.Sample{At: time.Now(), RTT: rtt}
}

// settle settles the link at its least round trip of 40ms over four seconds:
// one whose echo comes back at the least, then three without an echo. The
// least's echo then lies over 4s back, out of the window of echoes a step
// reads, so the steps that follow read only the echoes that follow.
func settle(p *Policy, ifID uint16) {
	play(p, ifID, slices.Concat(seconds(1, 0, false, 40*ms), seconds(3, 0, false))...)
}

// settled is a scenario on a settled link: the seconds played after the
// settling, and the rates read as each ends.
type settled struct {
	name    string
	seconds []second
	want    []float64
}

// runSettled plays each scenario on a fresh policy's link once it settles,
// and checks the rates read.
func runSettled(t *testing.T, tests []settled) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPolicy()
				settle(p, linkID)
				got := play(p, linkID, tc.seconds...)
				if diff := cmp.Diff(tc.want, got, approx); diff != "" {
					t.Errorf("rates after each second (-want +got):\n%s", diff)
				}
			})
		})
	}
}

// TestWroteCallsForEchoes checks the grants, and the echoes they call for on
// links writing over 128 kbit/s. A link's first write grants it 4 packets. A
// write that uses a grant up makes the next, the overdraw not carried: 4
// packets until the link's first step, however many come at once, then the
// packets the link writes in 100ms at the packet rate its last step
// measured, over the whole time since the step before, between 4 and 128.
// It calls for one echo across the link once the mutex is released, however
// far it overdraws: the link's first at once, then, from the step that
// measures its bit rate, one per grant used up. Each link has its own
// grants, steps, and echoes.
func TestWroteCallsForEchoes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var p *Policy
		var called []uint16
		p = New(func(ifID uint16) {
			if !p.mu.TryLock() {
				t.Errorf("an echo across link %d called for under the mutex", ifID)
			} else {
				p.mu.Unlock()
			}
			called = append(called, ifID)
		})
		writes := []struct {
			// after is how long after the last write the write comes.
			after   time.Duration
			ifID    uint16
			packets int
			want    []uint16
		}{
			// The first write grants 4 packets and starts the link's clock.
			{0, linkID, 3, nil},
			// The first grant used up calls for the link's first echo and
			// makes another of 4, as does a burst of 100 packets, before the
			// link's first step; until that step measures its bit rate, the
			// link calls for no more echoes.
			{0, linkID, 1, []uint16{linkID}},
			{0, linkID, 100, nil},
			{0, linkID, 3, nil},
			// The other link's first write of 100 packets uses up its own
			// first grant of 4, making another 4, and calls for its own first
			// echo.
			{0, otherID, 100, []uint16{otherID}},
			{0, otherID, 3, nil},
			// The link writes 200 packets in its first second, the other
			// 107.
			{500 * ms, linkID, 93, nil},
			{0, otherID, 4, nil},
			// The link steps at 200 packets, 1.6 Mbit/s, a second, its grant
			// of 4 holding 1 more; then 200 packets a second come to 20 in
			// 100ms, each grant used up calling for an echo.
			{500 * ms, linkID, 3, nil},
			{0, linkID, 1, []uint16{linkID}},
			{0, linkID, 19, nil},
			{0, linkID, 1, []uint16{linkID}},
			// The other link steps at its own 107 packets, 856 kbit/s, a
			// second, its grant of 4 holding 3 more; then 107 packets a
			// second come to 10.7 in 100ms, granting 10.
			{0, otherID, 1, nil},
			{0, otherID, 3, []uint16{otherID}},
			{0, otherID, 9, nil},
			{0, otherID, 1, []uint16{otherID}},
			// The link writes 1500 packets in its second second.
			{500 * ms, linkID, 1476, []uint16{linkID}},
			// The link steps at 1500 packets, 12 Mbit/s, a second, its grant
			// of 20 holding 1 more; then 1500 packets a second come to 150
			// in 100ms: 128 at most.
			{500 * ms, linkID, 19, nil},
			{0, linkID, 1, []uint16{linkID}},
			{0, linkID, 127, nil},
			{0, linkID, 1, []uint16{linkID}},
			// The link steps four seconds later, at the 148 packets it wrote
			// over them, 37 a second, 296 kbit/s, its grant of 128 holding
			// 127 more; then 37 packets a second come to 3.7 in 100ms: 4 at
			// least.
			{4 * time.Second, linkID, 1, nil},
			{0, linkID, 127, []uint16{linkID}},
			{0, linkID, 3, nil},
			{0, linkID, 1, []uint16{linkID}},
		}
		var got, want [][]uint16
		for _, w := range writes {
			time.Sleep(w.after)
			called = nil
			p.Wrote(w.ifID, w.packets, 1000*w.packets, false)
			got = append(got, called)
			want = append(want, w.want)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("echoes each write called for (-want +got):\n%s", diff)
		}
	})
}

// writeFor has the link write 4 packets, of bytes all told, every 250ms for
// d: 16 packets a second, so each write uses up a grant of 4.
func writeFor(p *Policy, ifID uint16, d time.Duration, bytes int) {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(250 * ms) {
		p.Wrote(ifID, 4, bytes, false)
	}
}

// TestWroteCallsForEchoesUnderTheFloor checks the echoes of links each of
// whose writes uses up a grant. A free link whose last step measured under
// the floor of 128 kbit/s calls for its first echo at once, then for one
// only once 10s have passed since its last, however many grants it uses up;
// one whose last step measured the floor or more calls for one per grant,
// from that step to the next, whatever it writes between; and a braked link
// calls for one per grant whatever it writes.
func TestWroteCallsForEchoesUnderTheFloor(t *testing.T) {
	type phase struct {
		d     time.Duration
		bytes int
	}
	for _, tc := range []struct {
		name string
		// phases are how long the link writes, and the bytes of each write:
		// 4000 make 128 kbit/s.
		phases []phase
		// want is when, since the link's first write, it called for echoes.
		want []time.Duration
	}{
		{
			name:   "a free link under the floor",
			phases: []phase{{21 * time.Second, 1000}},
			// 32 kbit/s over 84 writes, each using up a grant: the first echo
			// at once, then one at the first write 10s or more after the
			// last, which comes exactly 10s after it.
			want: []time.Duration{0, 10 * time.Second, 20 * time.Second},
		},
		{
			name:   "a free link just under the floor",
			phases: []phase{{3 * time.Second, 3999}},
			// 127.968 kbit/s.
			want: []time.Duration{0},
		},
		{
			name:   "a free link at the floor",
			phases: []phase{{2 * time.Second, 4000}, {2 * time.Second, 1000}},
			// 128 kbit/s for two seconds, then 32: the first echo at once,
			// none more until the step at 1s measures 128 kbit/s, then one
			// per grant until the step at 3s measures 32 kbit/s.
			want: []time.Duration{0, 1000 * ms, 1250 * ms, 1500 * ms, 1750 * ms,
				2000 * ms, 2250 * ms, 2500 * ms, 2750 * ms},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var got []time.Duration
				p := New(func(uint16) { got = append(got, time.Since(start)) })
				for _, ph := range tc.phases {
					writeFor(p, linkID, ph.d, ph.bytes)
				}
				if diff := cmp.Diff(tc.want, got); diff != "" {
					t.Errorf("echoes called for, since the first write (-want +got):\n%s", diff)
				}
			})
		})
	}
	t.Run("a braked link", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			var got []time.Duration
			p := New(func(uint16) { got = append(got, time.Since(start)) })
			settle(p, linkID)
			// The link writes 800 kbit/s for a second, losing its echoes,
			// then 32 kbit/s.
			writeFor(p, linkID, 500*ms, 25_000)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			writeFor(p, linkID, 500*ms, 25_000)
			// 0.7 of 800 kbit/s.
			if rate := p.Rate(linkID); !cmp.Equal(rate, 560_000.0, approx) {
				t.Fatalf("Rate = %v, want 560000", rate)
			}
			writeFor(p, linkID, 2*time.Second, 1000)
			// The first echo at once, at 4s, after the settling; then, the
			// link braked, one per grant, though the step at 6s measures 32
			// kbit/s.
			want := []time.Duration{4 * time.Second, 5000 * ms, 5250 * ms, 5500 * ms, 5750 * ms,
				6000 * ms, 6250 * ms, 6500 * ms, 6750 * ms}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("echoes called for, since the test began (-want +got):\n%s", diff)
			}
		})
	})
}

// TestMarkFollowsTheFill checks the marks: a link marks as large a share of
// the replies that come back over it as its egress queue is full, a quarter
// full marking every fourth reply and full every one; an empty queue marks
// none and clears what the link owed.
func TestMarkFollowsTheFill(t *testing.T) {
	tests := []struct {
		name  string
		fills []float64
		want  []bool
	}{
		{"empty", []float64{0, 0, 0, 0}, []bool{false, false, false, false}},
		{"a quarter full", slices.Repeat([]float64{0.25}, 8),
			[]bool{false, false, false, true, false, false, false, true}},
		{"half full", slices.Repeat([]float64{0.5}, 4), []bool{false, true, false, true}},
		{"full", []float64{1, 1, 1, 1}, []bool{true, true, true, true}},
		{"filling", []float64{0.25, 0.5, 0.25, 1}, []bool{false, false, true, true}},
		{"emptied", []float64{0.75, 0, 0.25}, []bool{false, false, false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPolicy()
			var got []bool
			for _, fill := range tc.fills {
				got = append(got, p.Mark(linkID, fill))
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("marks for each reply (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMarkTakesNoLock checks that marks go on while the policy's mutex is
// held, as a link's step holds it, and that marks from many processors at
// once keep the share exact: a quarter full, every fourth packet.
func TestMarkTakesNoLock(t *testing.T) {
	p := newPolicy()
	p.mu.Lock()
	defer p.mu.Unlock()
	var marked atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				if p.Mark(linkID, 0.25) {
					marked.Add(1)
				}
			}
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the marks waited on the policy's mutex")
	}
	if got := marked.Load(); got != 2000 {
		t.Errorf("%d of 8000 packets a quarter full marked, want 2000", got)
	}
}

// BenchmarkMark measures a mark on the data plane's path, a packet that
// comes back over a link whose queue is half full, from every processor at
// once: alone, and beside a sender's writes and the echoes' outcomes, which
// take the policy's mutex.
func BenchmarkMark(b *testing.B) {
	for _, beside := range []bool{false, true} {
		b.Run(fmt.Sprintf("beside_writes=%t", beside), func(b *testing.B) {
			p := newPolicy()
			stop := make(chan struct{})
			var wg sync.WaitGroup
			if beside {
				wg.Go(func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						p.Wrote(linkID, 1, 1000, false)
						p.Sampled(linkID, evidence.Sample{At: time.Now(), RTT: 40 * ms})
					}
				})
			}
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					p.Mark(linkID, 0.5)
				}
			})
			b.StopTimer()
			close(stop)
			wg.Wait()
		})
	}
}

// TestRateCutsOnLoss checks the cut on loss of a settled link writing 800
// kbit/s: echoes since the last cut confidently answered under half the
// time, as three lost of three or two answered of eight are, cut the rate to
// 0.7 of what the link wrote since its last step, or of its rate where that
// is lower; fewer losses read nothing until more come; and no rate falls
// under 128 kbit/s.
func TestRateCutsOnLoss(t *testing.T) {
	runSettled(t, []settled{
		{
			name:    "three of three lost",
			seconds: seconds(1, 100_000, true, lost, lost, lost),
			// 0.7 of 800 kbit/s.
			want: []float64{560_000},
		},
		{
			name: "two of two lost, then a third",
			seconds: slices.Concat(
				seconds(1, 100_000, true, lost, lost), seconds(1, 100_000, true, lost)),
			// Two of two lost read nothing; three of three, 0.7 of the 800
			// kbit/s written since the last step.
			want: []float64{0, 560_000},
		},
		{
			name: "two of eight answered",
			seconds: seconds(1, 100_000, true,
				40*ms, lost, lost, lost, 40*ms, lost, lost, lost),
			// 0.7 of 800 kbit/s.
			want: []float64{560_000},
		},
		{
			name: "three of eight answered",
			seconds: seconds(1, 100_000, true,
				40*ms, lost, lost, 40*ms, lost, lost, 40*ms, lost),
			want: []float64{0},
		},
		{
			name: "seconds that stay lossy",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 50_000, true, lost, lost, lost),
				seconds(1, 100_000, true, lost, lost, lost)),
			// 0.7 of 800 kbit/s; of the 400 kbit/s written, under the rate;
			// then of the rate, under the 800 kbit/s written.
			want: []float64{560_000, 280_000, 196_000},
		},
		{
			name:    "the floor",
			seconds: seconds(2, 20_000, true, lost, lost, lost),
			// 0.7 of 160 kbit/s, then of the 128 kbit/s rate, falls under
			// the floor of 128 kbit/s.
			want: []float64{128_000, 128_000},
		},
	})
}

// TestRateCutsToTheDelivered checks the cut on a standing queue, for a
// settled link writing 800 kbit/s at its least of 40ms. Once the tenth
// percentile of the echoes since the last cut, their loss counted, has a
// lower bound, which takes 16 answered, standing the 15ms target or more
// over the least, the rate is cut to what the queue delivered: what the link
// wrote since its last step, or its rate where that is lower, over 1 plus
// how fast the round trips grew, in seconds a second. Less what drains the
// tenth percentile's excess over the target within a second, the cut keeps
// half of that at least, and 128 kbit/s at least.
func TestRateCutsToTheDelivered(t *testing.T) {
	runSettled(t, []settled{
		{
			name:    "a standing queue",
			seconds: seconds(1, 100_000, true, echoes(16, 180*ms)...),
			// The queue stands 140ms over the least: 800 kbit/s less 125ms/1s
			// of it, 700 kbit/s.
			want: []float64{700_000},
		},
		{
			name: "a queue at the target",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, true, echoes(16, 55*ms)...)),
			// 0.7 of 800 kbit/s; then 15ms over the least reads over and
			// drains nothing, cutting to the rate, under the 800 kbit/s
			// written.
			want: []float64{560_000, 560_000},
		},
		{
			name: "a queue under the target",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, true, echoes(16, 54*ms)...)),
			// 0.7 of 800 kbit/s; then 14ms over the least reads under,
			// climbing the rate to 9/8 of itself.
			want: []float64{560_000, 630_000},
		},
		{
			name: "a queue read at the tenth percentile",
			seconds: seconds(1, 100_000, true,
				slices.Concat([]time.Duration{180 * ms, 280 * ms}, echoes(14, 380*ms))...),
			// Of sixteen, the tenth percentile is the second shortest, 280ms,
			// 240ms over the least, its lower bound the shortest, 180ms, and
			// its upper the fourth: 800 kbit/s less 225ms/1s of it, 620
			// kbit/s.
			want: []float64{620_000},
		},
		{
			name: "fifteen echoes, then a sixteenth",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(15, 180*ms)...),
				seconds(1, 100_000, true, 180*ms)),
			// Fifteen give the tenth percentile no lower bound; sixteen cut
			// to 800 kbit/s less 125ms/1s of it, 700 kbit/s.
			want: []float64{0, 700_000},
		},
		{
			name: "a growing queue",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(8, 180*ms)...),
				seconds(1, 100_000, true, echoes(8, 430*ms)...)),
			// Round trips 250ms longer a second later grew 0.25s a second: the
			// queue delivered 800/1.25 = 640 kbit/s. The tenth percentile
			// stands 140ms over the least: 640 kbit/s less 125ms/1s of it, 560
			// kbit/s.
			want: []float64{0, 560_000},
		},
		{
			name: "a shrinking queue",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(8, 430*ms)...),
				seconds(1, 100_000, true, echoes(8, 180*ms)...)),
			// A shrinking queue delivered what the link wrote: 800 kbit/s less
			// 125ms/1s of it, 700 kbit/s.
			want: []float64{0, 700_000},
		},
		{
			name: "a growing queue, half its echoes lost",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(8, 180*ms)...),
				seconds(1, 100_000, true, slices.Concat(echoes(8, 430*ms), echoes(16, lost))...)),
			// The answered round trips grew 0.25s a second: the queue
			// delivered 800/1.25 = 640 kbit/s. Half lost, the tenth
			// percentile reads 180ms as 360ms, 320ms over the least: 640
			// kbit/s less 305ms/1s of it, 444.8 kbit/s.
			want: []float64{0, 444_800},
		},
		{
			name:    "a deep queue",
			seconds: seconds(1, 100_000, true, echoes(16, 1040*ms)...),
			// 800 kbit/s less 985ms/1s of it would leave 12 kbit/s: half of it,
			// 400 kbit/s.
			want: []float64{400_000},
		},
		{
			name: "half the echoes lost",
			seconds: seconds(1, 100_000, true,
				slices.Concat(echoes(16, 40*ms), echoes(16, lost))...),
			// Half lost, the answered 40ms read as 80ms, 40ms over the least:
			// 800 kbit/s less 25ms/1s of it, 780 kbit/s.
			want: []float64{780_000},
		},
		{
			name: "seconds that stay over",
			seconds: slices.Concat(seconds(2, 100_000, true, echoes(16, 180*ms)...),
				seconds(1, 50_000, true, echoes(16, 180*ms)...)),
			// 7/8 of 800 kbit/s; of the rate, under the 800 kbit/s written;
			// then of the 400 kbit/s written, under the rate.
			want: []float64{700_000, 612_500, 350_000},
		},
		{
			name:    "the floor",
			seconds: seconds(1, 20_000, true, echoes(16, 1040*ms)...),
			// The drain keeps half of 160 kbit/s, which falls under the floor
			// of 128 kbit/s.
			want: []float64{128_000},
		},
	})
}

// TestRateReadsJitterUnder checks that jitter brakes no link: echoes a
// quarter of which come back at the least of 40ms, the rest 160ms over it,
// put the tenth percentile at the least and read under, leaving a free link
// free and climbing a braked one by an eighth.
func TestRateReadsJitterUnder(t *testing.T) {
	jitter := slices.Concat(echoes(4, 40*ms), echoes(12, 200*ms))
	runSettled(t, []settled{
		{
			name:    "a free link",
			seconds: seconds(10, 100_000, false, jitter...),
			want:    make([]float64, 10),
		},
		{
			name: "a braked link",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(2, 100_000, true, jitter...)),
			// 0.7 of 800 kbit/s, then 9/8 of it twice.
			want: []float64{560_000, 630_000, 708_750},
		},
	})
}

// TestRateReadsAgainstTheLeast checks the least the echoes are read against:
// the least answered round trip of the 10s spans begun within the last
// minute. A link none of whose echoes was answered reads nothing, though all
// are lost; and a link whose least leaves the minute reads its echoes
// against the least of the spans left.
func TestRateReadsAgainstTheLeast(t *testing.T) {
	t.Run("no echo answered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			got := play(newPolicy(), linkID, slices.Concat(
				seconds(3, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, true, 40*ms, lost, lost, lost))...)
			// Once an echo is answered, the twelve lost of thirteen cut to 0.7
			// of 800 kbit/s.
			if diff := cmp.Diff([]float64{0, 0, 0, 560_000}, got, approx); diff != "" {
				t.Errorf("rates after each second (-want +got):\n%s", diff)
			}
		})
	})
	t.Run("the least leaves the minute", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// The bubble's clock starts at midnight, as a 10s span begins; the
			// link starts 5s into it.
			time.Sleep(5 * time.Second)
			// An echo at the least of 40ms, then sixteen a second 60ms over
			// it, from a link whose rate holds nothing back.
			rates := play(newPolicy(), linkID, slices.Concat(
				seconds(1, 100_000, false, 40*ms),
				seconds(57, 100_000, false, echoes(16, 100*ms)...))...)
			for i, rate := range rates {
				// The echoes read over from second 2, once 32 of them leave
				// the tenth percentile's lower bound past the least's one
				// echo, and cut the rate each second. The least's span leaves
				// the minute at the step that ends second 55, 61s after the
				// span began, and the echoes, read against their own least,
				// release the rate.
				if braked, want := rate != 0, i >= 2 && i <= 54; braked != want {
					t.Errorf("braked = %v after second %d, want %v", braked, i, want)
				}
			}
		})
	})
}

// TestRateCutsOncePerEvidence checks that each cut rests on echoes sent
// after the last: the echoes that cut the rate count at no later step, nor
// do any sent before the cut that come back after it, so a next step on one
// more echo as slow, or on those alone, reads neither and climbs the rate by
// a sixty-fourth; a step without an echo come since the last holds the
// rate; and fresh echoes over cut it again.
func TestRateCutsOncePerEvidence(t *testing.T) {
	runSettled(t, []settled{
		{
			name: "the echoes that cut",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(16, 180*ms)...),
				seconds(1, 100_000, true, 180*ms)),
			// 7/8 of 800 kbit/s; one more echo as slow, alone, reads
			// neither, climbing it to 65/64 of it.
			want: []float64{700_000, 710_937.5},
		},
		{
			name: "no echo since",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(2, 100_000, true), seconds(1, 100_000, true, lost, lost, lost)),
			// 0.7 of 800 kbit/s, held; then 0.7 of it, under the 800 kbit/s
			// written.
			want: []float64{560_000, 560_000, 560_000, 392_000},
		},
	})
	t.Run("echoes sent before the cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			got := play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
			p.Wrote(linkID, 100, 100_000, true)
			time.Sleep(500 * ms)
			// Three echoes sent 100ms before the cut come back lost.
			for range 3 {
				p.Sampled(linkID, evidence.Sample{At: time.Now().Add(-600 * ms), Lost: true})
			}
			time.Sleep(500 * ms)
			got = append(got, p.Rate(linkID))
			// 0.7 of 800 kbit/s, then 65/64 of it.
			if diff := cmp.Diff([]float64{560_000, 568_750}, got, approx); diff != "" {
				t.Errorf("rates after each second (-want +got):\n%s", diff)
			}
		})
	})
}

// TestRateReadsFourSecondsBack checks how far back a step reads echoes: to
// those sent 4s before it, and not a nanosecond further.
func TestRateReadsFourSecondsBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		// back is how long before the step two of the losses were sent.
		back time.Duration
		want float64
	}{
		// Three lost of three: 0.7 of 800 kbit/s.
		{"two losses 4s back", 4 * time.Second, 560_000},
		// One lost of one reads nothing.
		{"two losses 4s and a nanosecond back", 4*time.Second + 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPolicy()
				settle(p, linkID)
				// Two losses go out; the write, a second before the step,
				// steps the link on them alone, nothing written by then; a
				// third loss goes out after the write.
				time.Sleep(4500*ms - tc.back)
				p.Sampled(linkID, sent(lost))
				p.Sampled(linkID, sent(lost))
				time.Sleep(tc.back - time.Second)
				p.Wrote(linkID, 100, 100_000, true)
				time.Sleep(500 * ms)
				p.Sampled(linkID, sent(lost))
				time.Sleep(500 * ms)
				if got := p.Rate(linkID); !cmp.Equal(got, tc.want, approx) {
					t.Errorf("Rate = %v, want %v", got, tc.want)
				}
			})
		})
	}
}

// TestRateStepsOnceASecond checks when a link steps: at its first touch a
// second or more after its last step, on what it wrote over the whole time
// since and on the echoes that came since; a write or an echo that comes
// with the touch that steps the link counts toward its next step.
func TestRateStepsOnceASecond(t *testing.T) {
	t.Run("reads within a second of a step", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
			p.Wrote(linkID, 50, 50_000, true)
			time.Sleep(500 * ms)
			p.Wrote(linkID, 50, 50_000, true)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			got := []float64{p.Rate(linkID)}
			time.Sleep(500 * ms)
			got = append(got, p.Rate(linkID))
			// 0.7 of 800 kbit/s until a second after the step, then 0.7 of
			// it, under the 800 kbit/s the two writes came to.
			if diff := cmp.Diff([]float64{560_000, 392_000}, got, approx); diff != "" {
				t.Errorf("rates half a second and a second after a step (-want +got):\n%s", diff)
			}
		})
	})
	t.Run("a step two seconds after the last", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			p.Wrote(linkID, 100, 100_000, true)
			time.Sleep(500 * ms)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			time.Sleep(1500 * ms)
			// 0.7 of the 800 kbit written over two seconds, 400 kbit/s.
			if got, want := p.Rate(linkID), 280_000.0; !cmp.Equal(got, want, approx) {
				t.Errorf("Rate = %v, want %v", got, want)
			}
		})
	})
	t.Run("echoes that come with a step", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
			time.Sleep(time.Second)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			p.Wrote(linkID, 100, 100_000, true)
			got := []float64{p.Rate(linkID)}
			time.Sleep(time.Second)
			got = append(got, p.Rate(linkID))
			// The step the first loss makes finds no echo come since the
			// cut to 0.7 of 800 kbit/s, and holds it; the next cuts 0.7 of
			// it, under the 800 kbit/s written.
			if diff := cmp.Diff([]float64{560_000, 392_000}, got, approx); diff != "" {
				t.Errorf("rates after each step (-want +got):\n%s", diff)
			}
		})
	})
	t.Run("a write that comes with a step", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			time.Sleep(500 * ms)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			time.Sleep(500 * ms)
			p.Wrote(linkID, 100, 100_000, true)
			got := []float64{p.Rate(linkID)}
			time.Sleep(500 * ms)
			for range 3 {
				p.Sampled(linkID, sent(lost))
			}
			time.Sleep(500 * ms)
			got = append(got, p.Rate(linkID))
			// The step the write makes finds the losses and nothing written;
			// the next cuts to 0.7 of the 800 kbit/s written.
			if diff := cmp.Diff([]float64{0, 560_000}, got, approx); diff != "" {
				t.Errorf("rates after each step (-want +got):\n%s", diff)
			}
		})
	})
}

// TestRateClimbs checks the climb of a braked link whose rate held data back
// and whose fresh echoes do not read over: echoes within the target of the
// least climb the rate by an eighth, but by a sixty-fourth where it lies
// within an eighth under the ceiling, the rate its last cut came from: what
// the link wrote, or its rate where that was lower, on loss, and what the
// queue delivered of that on a standing queue. Echoes that read neither
// climb it by a sixty-fourth.
func TestRateClimbs(t *testing.T) {
	runSettled(t, []settled{
		{
			name: "after a loss cut",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(3, 100_000, true, 40*ms)),
			// 0.7 of 800 kbit/s, the ceiling. 560 and 630 kbit/s lie under
			// 7/8 of it, 700 kbit/s, and climb to 9/8 of themselves; 708.75
			// kbit/s lies within an eighth under it and climbs to 65/64.
			want: []float64{560_000, 630_000, 708_750, 719_824.21875},
		},
		{
			name: "after a second loss cut",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 50_000, true, lost, lost, lost),
				seconds(3, 100_000, true, 40*ms)),
			// 0.7 of 800 kbit/s; then of the 400 kbit/s written under the
			// rate, the ceiling. 280 and 315 kbit/s lie under 7/8 of it, 350
			// kbit/s, and climb to 9/8 of themselves; 354.375 kbit/s lies
			// within an eighth under it and climbs to 65/64.
			want: []float64{560_000, 280_000, 315_000, 354_375, 359_912.109375},
		},
		{
			name: "at 7/8 of the ceiling",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(16, 180*ms)...),
				seconds(1, 100_000, true, 40*ms)),
			// 7/8 of the 800 kbit/s delivered, the ceiling: not under 7/8 of
			// it, the rate climbs to 65/64 of itself.
			want: []float64{700_000, 710_937.5},
		},
		{
			name: "after a delay cut",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(8, 70*ms)...),
				seconds(1, 100_000, true, echoes(8, 320*ms)...),
				seconds(2, 100_000, true, 40*ms)),
			// Round trips grown 0.25s a second put the ceiling at the
			// 800/1.25 = 640 kbit/s delivered; the 30ms queue, 15ms over the
			// target, the rate at 1 - 15ms/1s of it, 630.4 kbit/s. Within an
			// eighth under the ceiling, it climbs to 65/64 of itself, 640.25
			// kbit/s, then, over it, to 9/8.
			want: []float64{0, 630_400, 640_250, 720_281.25},
		},
		{
			name: "after a second delay cut",
			seconds: slices.Concat(seconds(1, 100_000, true, echoes(16, 180*ms)...),
				seconds(1, 100_000, true, echoes(16, 70*ms)...),
				seconds(2, 100_000, true, 40*ms)),
			// 7/8 of 800 kbit/s; then, the 30ms queue standing 15ms over the
			// target, 1 - 15ms/1s of the rate, under the 800 kbit/s written
			// and now the ceiling: 689.5 kbit/s. Within an eighth under the
			// ceiling, it climbs to 65/64 of itself, 700.27 kbit/s, then,
			// over it, to 9/8.
			want: []float64{700_000, 689_500, 700_273.4375, 787_807.6171875},
		},
		{
			name: "on echoes that read neither",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(2, 100_000, true, 70*ms)),
			// 0.7 of 800 kbit/s. One or two echoes 30ms over the least give
			// the tenth percentile no lower bound and an upper one over the
			// target: 65/64 of the rate, twice, though it lies under 7/8 of
			// the ceiling.
			want: []float64{560_000, 568_750, 577_636.71875},
		},
	})
}

// TestRateReleases checks the release of a braked link: a step on fresh
// echoes that do not read over releases a rate that held no data back since
// the last step, one write held among several keeping it; echoes over cut
// it instead, and a step without a fresh echo holds it; and a link loses its
// rate at its first step five seconds or more after its last echo was sent.
func TestRateReleases(t *testing.T) {
	runSettled(t, []settled{
		{
			name: "nothing held",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(2, 100_000, false, 40*ms)),
			// 0.7 of 800 kbit/s, released.
			want: []float64{560_000, 0, 0},
		},
		{
			name: "nothing held, echoes that read neither",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, false, 70*ms)),
			// 0.7 of 800 kbit/s, released.
			want: []float64{560_000, 0},
		},
		{
			name: "nothing held, echoes over",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, false, lost, lost, lost)),
			// 0.7 of 800 kbit/s, then 0.7 of it, under the 800 kbit/s
			// written.
			want: []float64{560_000, 392_000},
		},
		{
			name: "nothing held, no echo",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 100_000, false), seconds(1, 100_000, false, 40*ms)),
			// 0.7 of 800 kbit/s, held, then released.
			want: []float64{560_000, 560_000, 0},
		},
		{
			name: "the echoes stop",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(5, 100_000, true)),
			// 0.7 of 800 kbit/s, held by the steps 1.5s to 4.5s after the
			// last echoes went out, and released by the one 5.5s after.
			want: []float64{560_000, 560_000, 560_000, 560_000, 560_000, 0},
		},
	})
	t.Run("one write of two held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newPolicy()
			settle(p, linkID)
			got := play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
			p.Wrote(linkID, 50, 50_000, true)
			p.Wrote(linkID, 50, 50_000, false)
			time.Sleep(500 * ms)
			p.Sampled(linkID, sent(40*ms))
			time.Sleep(500 * ms)
			got = append(got, p.Rate(linkID))
			// 0.7 of 800 kbit/s, then 9/8 of it.
			if diff := cmp.Diff([]float64{560_000, 630_000}, got, approx); diff != "" {
				t.Errorf("rates after each second (-want +got):\n%s", diff)
			}
		})
	})
	for _, tc := range []struct {
		name string
		// wait is how long after the cut the rate is read, the last echoes
		// having gone out half a second before the cut.
		wait time.Duration
		want float64
	}{
		// 0.7 of 800 kbit/s.
		{"a step just under five seconds after the last echo", 4500*ms - 1, 560_000},
		{"a step five seconds after the last echo", 4500 * ms, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPolicy()
				settle(p, linkID)
				play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
				time.Sleep(tc.wait)
				if got := p.Rate(linkID); !cmp.Equal(got, tc.want, approx) {
					t.Errorf("Rate = %v, want %v", got, tc.want)
				}
			})
		})
	}
}

// TestRateWithNothingWritten checks the links that wrote nothing since their
// last step: echoes over cut none of them, a free one staying free and a
// braked one holding its rate; and once a free link writes, they brake it.
func TestRateWithNothingWritten(t *testing.T) {
	runSettled(t, []settled{
		{
			name: "a free link",
			seconds: slices.Concat(seconds(2, 0, false, lost, lost, lost),
				seconds(1, 100_000, true, lost, lost, lost)),
			// Once it writes 800 kbit/s, 0.7 of it.
			want: []float64{0, 0, 560_000},
		},
		{
			name: "a braked link",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 0, false, lost, lost, lost),
				seconds(1, 100_000, true, lost, lost, lost)),
			// 0.7 of 800 kbit/s, held while the link writes nothing; then 0.7
			// of it, under the 800 kbit/s written.
			want: []float64{560_000, 560_000, 392_000},
		},
	})
}

// TestRateBrakesAFreeLinkUnderWhatItWrote checks that a free link is braked
// only to a rate under what it wrote since its last step, while a braked
// link is cut whatever it wrote. A cut keeps the floor of 128 kbit/s, so a
// free link writing at or under the floor stays free, on loss and on a
// standing queue, and brakes once it writes over it; and a queue at the
// target, which drains nothing, leaves a free link free.
func TestRateBrakesAFreeLinkUnderWhatItWrote(t *testing.T) {
	runSettled(t, []settled{
		{
			name: "loss",
			seconds: slices.Concat(seconds(1, 15_000, true, lost, lost, lost),
				seconds(1, 16_000, true, lost, lost, lost),
				seconds(1, 20_000, true, lost, lost, lost)),
			// Each cut, 0.7 of what the link wrote, keeps the floor of 128
			// kbit/s: no cut of 120 or 128 kbit/s written, which leaves the
			// link free; a cut of 160 kbit/s written, which brakes it.
			want: []float64{0, 0, 128_000},
		},
		{
			name: "a standing queue",
			seconds: slices.Concat(seconds(1, 15_000, true, echoes(16, 180*ms)...),
				seconds(1, 20_000, true, echoes(16, 180*ms)...)),
			// 7/8 of 120 kbit/s keeps the floor of 128 kbit/s, no cut of the
			// 120 kbit/s written; 7/8 of 160 kbit/s, 140 kbit/s, is a cut of
			// the 160 kbit/s written.
			want: []float64{0, 140_000},
		},
		{
			name:    "a queue at the target",
			seconds: seconds(1, 100_000, true, echoes(16, 55*ms)...),
			// 15ms over the least reads over but drains nothing, the cut
			// keeping all 800 kbit/s written.
			want: []float64{0},
		},
		{
			name: "a braked link",
			seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
				seconds(1, 12_500, true, lost, lost, lost)),
			// 0.7 of 800 kbit/s; then the floor of 128 kbit/s, over the 100
			// kbit/s written.
			want: []float64{560_000, 128_000},
		},
	})
}

// TestSampledKeepsTheSendOrder checks that a link keeps its echoes in the
// order they were sent: a loss sent before a cut, reported after losses sent
// since, leaves those to read, and they cut again.
func TestSampledKeepsTheSendOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPolicy()
		settle(p, linkID)
		play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
		p.Wrote(linkID, 100, 100_000, true)
		time.Sleep(500 * ms)
		for range 3 {
			p.Sampled(linkID, sent(lost))
		}
		// An echo sent 100ms before the cut comes back lost after them.
		p.Sampled(linkID, evidence.Sample{At: time.Now().Add(-600 * ms), Lost: true})
		time.Sleep(500 * ms)
		// 0.7 of the rate of 0.7 of 800 kbit/s, under the 800 kbit/s written.
		if got, want := p.Rate(linkID), 392_000.0; !cmp.Equal(got, want, approx) {
			t.Errorf("Rate = %v, want %v", got, want)
		}
	})
}

// TestSampledKeepsTheLatestEchoes checks that a link keeps its latest 256
// echoes: 200 lost, then 256 at the least, all sent since the cut, leave the
// 256 to read, which read under; counted, the loss would read the 40ms round
// trips as 71.25ms, over.
func TestSampledKeepsTheLatestEchoes(t *testing.T) {
	runSettled(t, []settled{{
		name: "200 lost, then 256 at the least",
		seconds: slices.Concat(seconds(1, 100_000, true, lost, lost, lost),
			seconds(1, 100_000, true, slices.Concat(echoes(200, lost), echoes(256, 40*ms))...)),
		// 0.7 of 800 kbit/s, then 9/8 of it.
		want: []float64{560_000, 630_000},
	}})
}

// unlocked is a log handler that reports a line logged while p's mutex is
// held.
type unlocked struct {
	slog.Handler
	p *Policy
	t *testing.T
}

// Handle reports the line if p's mutex is held, and hands it on.
func (h unlocked) Handle(ctx context.Context, r slog.Record) error {
	if !h.p.mu.TryLock() {
		h.t.Errorf("logged %q under the mutex", r.Message)
	} else {
		h.p.mu.Unlock()
	}
	return h.Handler.Handle(ctx, r)
}

// logs sends the default logger's lines, without their time, to the
// returned buffer for the rest of the test, reporting any logged while p's
// mutex is held.
func logs(t *testing.T, p *Policy) *bytes.Buffer {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var lines bytes.Buffer
	slog.SetDefault(slog.New(unlocked{p: p, t: t, Handler: slog.NewTextHandler(&lines,
		&slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		}})}))
	return &lines
}

// TestLogsEachBrakeOnce checks the log: a line as a link is braked, naming
// the interface, the share of echoes lost or the queue, and the rate set; a
// line as it is released, as its rate held nothing back or as its echoes
// stopped, naming the interface and the rate it had; and none as a braked
// link is cut again or climbs, or as a free link goes silent.
func TestLogsEachBrakeOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPolicy()
		lines := logs(t, p)
		settle(p, linkID)
		play(p, linkID, slices.Concat(
			// Braked to 0.7 of 800 kbit/s on six echoes lost of eight, cut
			// to 0.7 of that, climbed to 9/8 of that, then released.
			seconds(1, 100_000, true, 40*ms, lost, lost, lost, 40*ms, lost, lost, lost),
			seconds(1, 100_000, true, lost, lost, lost),
			seconds(1, 100_000, true, 40*ms),
			seconds(1, 100_000, false, 40*ms),
			// The echoes at the least leave the window.
			seconds(3, 0, false),
			// Braked to 7/8 of 800 kbit/s, then released, and silent.
			seconds(1, 100_000, true, echoes(16, 180*ms)...),
			seconds(7, 100_000, true),
		)...)
		want := []string{
			`level=INFO msg="Braking a link: its echoes stand over their least" interface=3 lost=0.75 rate=560000`,
			`level=INFO msg="Released a link's brake: its rate held nothing back" interface=3 rate=441000`,
			`level=INFO msg="Braking a link: its echoes stand over their least" interface=3 queue=140ms rate=700000`,
			`level=INFO msg="Released a link's brake: its echoes stopped" interface=3 rate=700000`,
		}
		got := strings.Split(strings.TrimSpace(lines.String()), "\n")
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("lines logged (-want +got):\n%s", diff)
		}
	})
}

// TestLogsOnceTheMutexIsReleased checks that a change to a link's brake is
// logged once the mutex is released, whichever call steps the link.
func TestLogsOnceTheMutexIsReleased(t *testing.T) {
	for _, tc := range []struct {
		name string
		step func(p *Policy)
	}{
		{"Wrote", func(p *Policy) { p.Wrote(linkID, 1, 1000, false) }},
		{"Rate", func(p *Policy) { p.Rate(linkID) }},
		{"Sampled", func(p *Policy) { p.Sampled(linkID, sent(40*ms)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPolicy()
				lines := logs(t, p)
				settle(p, linkID)
				play(p, linkID, seconds(1, 100_000, true, lost, lost, lost)...)
				// The call steps the link 5.5s after its last echo went out.
				time.Sleep(5 * time.Second)
				tc.step(p)
				want := []string{
					`level=INFO msg="Braking a link: its echoes stand over their least" interface=3 lost=1 rate=560000`,
					`level=INFO msg="Released a link's brake: its echoes stopped" interface=3 rate=560000`,
				}
				got := strings.Split(strings.TrimSpace(lines.String()), "\n")
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("lines logged (-want +got):\n%s", diff)
				}
			})
		})
	}
}

// TestKeepsLinksApart checks that a link's echoes, writes, rate, and marks
// are its own: echoes over their least on one link brake that link alone,
// against its own least, from what it wrote alone, and each link owes its
// own marks.
func TestKeepsLinksApart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPolicy()
		// The queued link settles at its least of 40ms, writing 800 kbit/s,
		// then sends sixteen echoes 140ms over it; the other, writing 1.6
		// Mbit/s, sends an echo a second at its least of 10ms.
		queued := slices.Concat(seconds(1, 100_000, true, 40*ms), seconds(3, 100_000, true),
			seconds(1, 100_000, true, echoes(16, 180*ms)...))
		p.Rate(linkID)
		p.Rate(otherID)
		for _, s := range queued {
			p.Wrote(linkID, s.bytes/1000, s.bytes, s.held)
			p.Wrote(otherID, 200, 200_000, true)
			time.Sleep(500 * ms)
			for _, rtt := range s.rtts {
				p.Sampled(linkID, sent(rtt))
			}
			p.Sampled(otherID, sent(10*ms))
			time.Sleep(500 * ms)
		}
		// The queued link's 800 kbit/s less 125ms/1s of it.
		rates := []float64{p.Rate(linkID), p.Rate(otherID), p.Rate(otherID + 1)}
		if diff := cmp.Diff([]float64{700_000, 0, 0}, rates, approx); diff != "" {
			t.Errorf("rates of the queued link, the other, and one never "+
				"measured (-want +got):\n%s", diff)
		}

		var marks []bool
		for range 2 {
			marks = append(marks, p.Mark(linkID, 0.5), p.Mark(otherID, 0.5))
		}
		if diff := cmp.Diff([]bool{false, false, true, true}, marks); diff != "" {
			t.Errorf("marks for replies over each link in turn, half full "+
				"(-want +got):\n%s", diff)
		}
	})
}
