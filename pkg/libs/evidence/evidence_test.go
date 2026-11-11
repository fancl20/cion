package evidence

import (
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

const ms = time.Millisecond

// median is the kind the tests read by default: the median at 0.95 over
// five minutes and the last twenty samples.
var median = Kind{Quantile: 0.5, Confidence: 0.95, Span: 5 * time.Minute, Count: 20}

// TestKindOf checks an estimate's reading: the window by span, its edge
// included, and by count; the quantile by nearest rank and its bounds, each
// divided by the delivery rate, the loss capped; and the samples answered,
// sent, and the newest answered.
func TestKindOf(t *testing.T) {
	now := time.Now()
	at := func(ago, rtt time.Duration) Sample { return Sample{At: now.Add(-ago), RTT: rtt} }
	lost := func(ago time.Duration) Sample { return Sample{At: now.Add(-ago), Lost: true} }
	past := median.Span + time.Nanosecond
	steady := func(n int, rtt time.Duration) []Sample {
		return slices.Repeat([]Sample{at(time.Second, rtt)}, n)
	}
	for _, tc := range []struct {
		name    string
		kind    Kind
		samples []Sample
		want    Estimate
	}{{
		name: "none",
		want: Estimate{},
	}, {
		name:    "lost alone",
		samples: []Sample{lost(0)},
		want:    Estimate{Sent: 1},
	}, {
		name:    "answered past the span",
		samples: []Sample{at(past, 10*ms), lost(0)},
		want:    Estimate{Sent: 1},
	}, {
		name:    "at the span's edge",
		samples: []Sample{at(past, 90*ms), at(median.Span, 20*ms), at(0, 10*ms)},
		want:    Estimate{Value: 10 * ms, Answered: 2, Sent: 2, Newest: now},
	}, {
		name:    "four, too few for a bound",
		samples: []Sample{at(4*ms, 10*ms), at(3*ms, 11*ms), at(2*ms, 12*ms), at(ms, 13*ms)},
		want:    Estimate{Value: 11 * ms, Answered: 4, Sent: 4, Newest: now.Add(-ms)},
	}, {
		name:    "five, the extremes bounding the median",
		samples: []Sample{at(5*ms, 14*ms), at(4*ms, 10*ms), at(3*ms, 11*ms), at(2*ms, 12*ms), at(ms, 13*ms)},
		want: Estimate{Value: 12 * ms, Lo: 10 * ms, Hi: 14 * ms, HasLo: true, HasHi: true, Answered: 5, Sent: 5,
			Newest: now.Add(-ms)},
	}, {
		name:    "the last twenty of more",
		samples: append(steady(5, 90*ms), steady(20, 10*ms)...),
		want: Estimate{Value: 10 * ms, Lo: 10 * ms, Hi: 10 * ms, HasLo: true, HasHi: true, Answered: 20, Sent: 20,
			Newest: now.Add(-time.Second)},
	}, {
		name: "every sample within the span without a count",
		kind: Kind{Quantile: 0.5, Confidence: 0.95, Span: 5 * time.Minute},
		samples: append(append(steady(15, 90*ms), steady(10, 10*ms)...),
			at(past, 10*ms)),
		want: Estimate{Value: 90 * ms, Lo: 10 * ms, Hi: 90 * ms, HasLo: true, HasHi: true, Answered: 25, Sent: 25,
			Newest: now.Add(-time.Second)},
	}, {
		name:    "a loss divides the value and the bounds",
		samples: append(steady(5, 15*ms), lost(0), lost(0), lost(0), lost(0), lost(0)),
		want: Estimate{Value: 30 * ms, Lo: 30 * ms, Hi: 30 * ms, HasLo: true, HasHi: true, Answered: 5, Sent: 10,
			Newest: now.Add(-time.Second)},
	}, {
		name:    "losses past the cap",
		samples: append([]Sample{at(0, 10*ms)}, slices.Repeat([]Sample{lost(0)}, 19)...),
		want:    Estimate{Value: 100 * ms, Answered: 1, Sent: 20, Newest: now},
	}, {
		name:    "zero round trips, bounded at zero",
		samples: steady(5, 0),
		want: Estimate{HasLo: true, HasHi: true, Answered: 5, Sent: 5,
			Newest: now.Add(-time.Second)},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.kind
			if kind == (Kind{}) {
				kind = median
			}
			tc.want.Kind = kind
			if diff := cmp.Diff(tc.want, kind.Of(tc.samples, now)); diff != "" {
				t.Errorf("Of (-want +got):\n%s", diff)
			}
		})
	}
}

// TestQuantileAndBounds checks the quantile by nearest rank and its bounds'
// ranks: a median's bounds stand from five round trips at 0.95, none from
// four; the 80th percentile's lower bound from two, its upper from fourteen.
func TestQuantileAndBounds(t *testing.T) {
	series := func(n int) []time.Duration {
		out := make([]time.Duration, n)
		for i := range out {
			out[i] = time.Duration(i+1) * ms
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		n      int
		q      float64
		value  time.Duration
		lo, hi int
	}{
		{"no round trip", 0, 0.5, 0, -1, -1},
		{"one", 1, 0.5, ms, -1, -1},
		{"a median of four", 4, 0.5, 2 * ms, -1, -1},
		{"a median of five", 5, 0.5, 3 * ms, 0, 4},
		{"a median of twenty", 20, 0.5, 10 * ms, 5, 14},
		{"an 80th percentile of one", 1, 0.8, ms, -1, -1},
		{"an 80th percentile of two", 2, 0.8, 2 * ms, 0, -1},
		{"an 80th percentile of ten", 10, 0.8, 8 * ms, 5, -1},
		{"an 80th percentile of fourteen", 14, 0.8, 12 * ms, 8, 13},
	} {
		lo, hi := BoundRanks(tc.n, tc.q, 0.95)
		if got := Quantile(series(tc.n), tc.q); got != tc.value || lo != tc.lo || hi != tc.hi {
			t.Errorf("%s: quantile %v, bound ranks %d, %d; want %v, %d, %d", tc.name, got, lo, hi, tc.value, tc.lo, tc.hi)
		}
	}
}

// TestAdd checks that a charge moves an estimate's value and each bound it
// has, and leaves an estimate without an answer as it was.
func TestAdd(t *testing.T) {
	e := Estimate{Kind: median, Value: 10 * ms, Hi: 20 * ms, HasHi: true, Answered: 3, Sent: 3}
	want := Estimate{Kind: median, Value: 14 * ms, Hi: 24 * ms, HasHi: true, Answered: 3, Sent: 3}
	if diff := cmp.Diff(want, e.Add(4*ms)); diff != "" {
		t.Errorf("Add (-want +got):\n%s", diff)
	}
	if got := (Estimate{Kind: median, Sent: 2}).Add(4 * ms); got.Value != 0 {
		t.Errorf("an estimate without an answer took the charge: %v", got.Value)
	}
}

// TestMul checks that a ratio scales an estimate's value and each bound it
// has, keeping its samples; leaves an estimate without an answer as it was;
// and panics at a ratio not above zero.
func TestMul(t *testing.T) {
	now := time.Now()
	e := Estimate{Kind: median, Value: 10 * ms, Lo: 9 * ms, Hi: 11 * ms, HasLo: true, HasHi: true,
		Answered: 3, Sent: 4, Newest: now}
	want := Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms, Hi: 22 * ms, HasLo: true, HasHi: true,
		Answered: 3, Sent: 4, Newest: now}
	if diff := cmp.Diff(want, e.Mul(2)); diff != "" {
		t.Errorf("twice (-want +got):\n%s", diff)
	}
	lo := Estimate{Kind: median, Value: 10 * ms, Lo: 9 * ms, HasLo: true, Answered: 2, Sent: 2}
	wantLo := Estimate{Kind: median, Value: 8 * ms, Lo: 7200 * time.Microsecond, HasLo: true,
		Answered: 2, Sent: 2}
	if diff := cmp.Diff(wantLo, lo.Mul(0.8)); diff != "" {
		t.Errorf("0.8 of an estimate with a lower bound alone (-want +got):\n%s", diff)
	}
	if got := (Estimate{Kind: median, Sent: 2}).Mul(2); got.Value != 0 || got.HasLo || got.HasHi {
		t.Errorf("an estimate without an answer took the ratio: %+v", got)
	}
	for _, r := range []float64{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("scaling by %v did not panic", r)
				}
			}()
			e.Mul(r)
		}()
	}
}

// TestMin checks the least of estimates: the least value, the least lower
// bound only where every estimate gives one, the least upper bound of those
// giving one, the samples across them, the newest answered of any; one
// without an answer takes no part, none answered leaves nothing, and
// estimates of different kinds panic.
func TestMin(t *testing.T) {
	now := time.Now()
	a := Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms, Hi: 30 * ms, HasLo: true, HasHi: true,
		Answered: 5, Sent: 6, Newest: now.Add(-time.Second)}
	b := Estimate{Kind: median, Value: 15 * ms, Lo: 12 * ms, Hi: 40 * ms, HasLo: true, HasHi: true,
		Answered: 7, Sent: 7, Newest: now}
	thin := Estimate{Kind: median, Value: 10 * ms, Answered: 2, Sent: 2, Newest: now.Add(-time.Minute)}
	silent := Estimate{Kind: median, Sent: 3}
	for _, tc := range []struct {
		name string
		es   []Estimate
		want Estimate
	}{
		{"none", nil, Estimate{}},
		{"one", []Estimate{a}, a},
		{"two bounded", []Estimate{a, b}, Estimate{Kind: median, Value: 15 * ms, Lo: 12 * ms, Hi: 30 * ms,
			HasLo: true, HasHi: true, Answered: 12, Sent: 13, Newest: now}},
		{"one without bounds", []Estimate{a, thin}, Estimate{Kind: median, Value: 10 * ms, Hi: 30 * ms,
			HasHi: true, Answered: 7, Sent: 8, Newest: now.Add(-time.Second)}},
		{"one unanswered", []Estimate{silent, a}, a},
		{"none answered", []Estimate{silent}, Estimate{}},
	} {
		if diff := cmp.Diff(tc.want, Min(tc.es...)); diff != "" {
			t.Errorf("%s: Min (-want +got):\n%s", tc.name, diff)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("the least of estimates of different kinds did not panic")
		}
	}()
	other := median
	other.Quantile = 0.8
	Min(a, Estimate{Kind: other, Value: ms, Answered: 1, Sent: 1})
}

// TestSub checks a difference of estimates: the values' difference, each
// bound against the other side's opposite bound where both stand, the
// samples of the side resting on fewer, the staler side's newest; a side
// without an answer leaves nothing, and estimates of different kinds panic.
func TestSub(t *testing.T) {
	now := time.Now()
	price := Estimate{Kind: median, Value: 40 * ms, Lo: 38 * ms, Hi: 44 * ms, HasLo: true, HasHi: true,
		Answered: 20, Sent: 20, Newest: now}
	direct := Estimate{Kind: median, Value: 10 * ms, Lo: 9 * ms, Hi: 12 * ms, HasLo: true, HasHi: true,
		Answered: 14, Sent: 15, Newest: now.Add(-time.Second)}
	thin := Estimate{Kind: median, Value: 10 * ms, Lo: 9 * ms, HasLo: true, Answered: 3, Sent: 3, Newest: now}
	for _, tc := range []struct {
		name string
		a, b Estimate
		want Estimate
	}{
		{"both bounded", price, direct, Estimate{Kind: median, Value: 30 * ms, Lo: 26 * ms, Hi: 35 * ms,
			HasLo: true, HasHi: true, Answered: 14, Sent: 15, Newest: now.Add(-time.Second)}},
		{"no upper bound to subtract", price, thin, Estimate{Kind: median, Value: 30 * ms, Hi: 35 * ms,
			HasHi: true, Answered: 3, Sent: 3, Newest: now}},
		{"a side unanswered", price, Estimate{Kind: median, Sent: 2}, Estimate{}},
	} {
		if diff := cmp.Diff(tc.want, tc.a.Sub(tc.b)); diff != "" {
			t.Errorf("%s: Sub (-want +got):\n%s", tc.name, diff)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("a difference of estimates of different kinds did not panic")
		}
	}()
	other := median
	other.Quantile = 0.8
	price.Sub(Estimate{Kind: other, Value: ms, Answered: 1, Sent: 1})
}

// TestMax checks the most of estimates: the most value, the most lower
// bound of those giving one, the most upper bound only with every one, the
// samples across them, and the newest; an unanswered estimate takes no part,
// and estimates of different kinds panic.
func TestMax(t *testing.T) {
	now := time.Now()
	a := Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms, Hi: 30 * ms, HasLo: true, HasHi: true,
		Answered: 5, Sent: 6, Newest: now.Add(-time.Second)}
	b := Estimate{Kind: median, Value: 15 * ms, Lo: 12 * ms, Hi: 40 * ms, HasLo: true, HasHi: true,
		Answered: 7, Sent: 7, Newest: now}
	thin := Estimate{Kind: median, Value: 25 * ms, Lo: 19 * ms, HasLo: true, Answered: 2, Sent: 2,
		Newest: now.Add(-time.Minute)}
	silent := Estimate{Kind: median, Sent: 3}
	for _, tc := range []struct {
		name string
		es   []Estimate
		want Estimate
	}{
		{"none", nil, Estimate{}},
		{"one", []Estimate{a}, a},
		{"two bounded", []Estimate{a, b}, Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms, Hi: 40 * ms,
			HasLo: true, HasHi: true, Answered: 12, Sent: 13, Newest: now}},
		{"one without an upper bound", []Estimate{a, thin}, Estimate{Kind: median, Value: 25 * ms,
			Lo: 19 * ms, HasLo: true, Answered: 7, Sent: 8, Newest: now.Add(-time.Second)}},
		{"one unanswered", []Estimate{silent, a}, a},
		{"none answered", []Estimate{silent}, Estimate{}},
	} {
		if diff := cmp.Diff(tc.want, Max(tc.es...)); diff != "" {
			t.Errorf("%s: Max (-want +got):\n%s", tc.name, diff)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("the most of estimates of different kinds did not panic")
		}
	}()
	other := median
	other.Quantile = 0.8
	Max(a, Estimate{Kind: other, Value: ms, Answered: 1, Sent: 1})
}

// TestSum checks a sum of estimates: the values' sum, the lower bounds' sum
// wherever one stands, a missing one counting zero, the upper bounds' sum
// only with every one, the samples of the estimate resting on fewest, the
// stalest newest; an unanswered estimate leaves nothing, and estimates of
// different kinds panic.
func TestSum(t *testing.T) {
	now := time.Now()
	a := Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms, Hi: 30 * ms, HasLo: true, HasHi: true,
		Answered: 5, Sent: 6, Newest: now.Add(-time.Second)}
	b := Estimate{Kind: median, Value: 15 * ms, Lo: 12 * ms, Hi: 40 * ms, HasLo: true, HasHi: true,
		Answered: 7, Sent: 7, Newest: now}
	thin := Estimate{Kind: median, Value: 10 * ms, Answered: 1, Sent: 2, Newest: now.Add(-time.Minute)}
	for _, tc := range []struct {
		name string
		es   []Estimate
		want Estimate
	}{
		{"none", nil, Estimate{}},
		{"one", []Estimate{a}, a},
		{"two bounded", []Estimate{a, b}, Estimate{Kind: median, Value: 35 * ms, Lo: 30 * ms, Hi: 70 * ms,
			HasLo: true, HasHi: true, Answered: 5, Sent: 6, Newest: now.Add(-time.Second)}},
		{"one without bounds", []Estimate{a, thin}, Estimate{Kind: median, Value: 30 * ms, Lo: 18 * ms,
			HasLo: true, Answered: 1, Sent: 2, Newest: now.Add(-time.Minute)}},
		{"none bounded", []Estimate{thin, thin}, Estimate{Kind: median, Value: 20 * ms, Answered: 1, Sent: 2,
			Newest: now.Add(-time.Minute)}},
		{"one unanswered", []Estimate{a, {Kind: median, Sent: 3}}, Estimate{}},
	} {
		if diff := cmp.Diff(tc.want, Sum(tc.es...)); diff != "" {
			t.Errorf("%s: Sum (-want +got):\n%s", tc.name, diff)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("the sum of estimates of different kinds did not panic")
		}
	}()
	other := median
	other.Quantile = 0.8
	Sum(a, Estimate{Kind: other, Value: ms, Answered: 1, Sent: 1})
}

// TestPublished checks a published estimate: the value and each bound
// given, a zero bound giving none, and one answered sample; a zero value
// states nothing.
func TestPublished(t *testing.T) {
	for _, tc := range []struct {
		name          string
		value, lo, hi time.Duration
		want          Estimate
	}{
		{"bounded", 20 * ms, 18 * ms, 25 * ms, Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms,
			Hi: 25 * ms, HasLo: true, HasHi: true, Answered: 1, Sent: 1}},
		{"bounded below", 20 * ms, 18 * ms, 0, Estimate{Kind: median, Value: 20 * ms, Lo: 18 * ms,
			HasLo: true, Answered: 1, Sent: 1}},
		{"unbounded", 20 * ms, 0, 0, Estimate{Kind: median, Value: 20 * ms, Answered: 1, Sent: 1}},
		{"no value", 0, 18 * ms, 25 * ms, Estimate{}},
	} {
		if diff := cmp.Diff(tc.want, Published(median, tc.value, tc.lo, tc.hi)); diff != "" {
			t.Errorf("%s: Published (-want +got):\n%s", tc.name, diff)
		}
	}
}

// TestBeats checks a comparison's verdicts at their edges, undecided where a
// bound is missing.
func TestBeats(t *testing.T) {
	bounded := func(lo, hi time.Duration) Estimate {
		return Estimate{Kind: median, Value: (lo + hi) / 2, Lo: lo, Hi: hi, HasLo: true, HasHi: true, Answered: 5,
			Sent: 5}
	}
	for _, tc := range []struct {
		name string
		a, b Estimate
		line time.Duration
		want Verdict
	}{
		{"apart by the line", bounded(10*ms, 20*ms), bounded(24*ms, 30*ms), 4 * ms, Better},
		{"bounded at zero", bounded(0, 0), bounded(4*ms, 4*ms), 4 * ms, Better},
		{"short of the line", bounded(10*ms, 20*ms), bounded(23*ms, 30*ms), 4 * ms, Undecided},
		{"overlapping", bounded(10*ms, 25*ms), bounded(20*ms, 30*ms), 0, Undecided},
		{"above by the line", bounded(23*ms, 40*ms), bounded(20*ms, 26*ms), 4 * ms, NotBetter},
		{"at the line from above", bounded(22*ms, 40*ms), bounded(20*ms, 26*ms), 4 * ms, Undecided},
		{"no upper bound", Estimate{Kind: median, Value: 10 * ms, Lo: 10 * ms, HasLo: true, Answered: 4, Sent: 4},
			bounded(30*ms, 40*ms), 0, Undecided},
		{"no lower bound", bounded(10*ms, 20*ms), Estimate{Kind: median, Value: 30 * ms, Answered: 1, Sent: 1},
			0, Undecided},
	} {
		if got := Beats(tc.a, tc.b, tc.line); got != tc.want {
			t.Errorf("%s: Beats = %v, want %v", tc.name, got, tc.want)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("weighing estimates of different kinds did not panic")
		}
	}()
	other := median
	other.Quantile = 0.8
	Beats(bounded(10*ms, 20*ms), Estimate{Kind: other}, 0)
}

// TestProportion checks a proportion of answers against a line at its
// edges: under one half at 0.95 once five samples in a row went unanswered,
// not at four; at five answers of twenty, not at six; at or over it from
// fifteen of twenty, not at fourteen; undecided for no sample.
func TestProportion(t *testing.T) {
	samples := func(answered, lost int) []Sample {
		var out []Sample
		for range answered {
			out = append(out, Sample{RTT: ms})
		}
		for range lost {
			out = append(out, Sample{Lost: true})
		}
		return out
	}
	for _, tc := range []struct {
		answered, lost int
		want           Verdict
	}{
		{0, 5, Better},
		{0, 4, Undecided},
		{5, 15, Better},
		{6, 14, Undecided},
		{14, 6, Undecided},
		{15, 5, NotBetter},
		{0, 0, Undecided},
	} {
		s := ProportionOf(samples(tc.answered, tc.lost), 0.95)
		if s.Answered != tc.answered || s.Sent != tc.answered+tc.lost {
			t.Errorf("%d answered, %d lost: proportion of %d of %d", tc.answered, tc.lost, s.Answered, s.Sent)
		}
		if got := s.Under(0.5); got != tc.want {
			t.Errorf("%d answered, %d lost: under one half = %v, want %v", tc.answered, tc.lost, got, tc.want)
		}
	}
}

// TestHold checks that a hold stands once it has held its duration with a
// sample of each side answered since it began, and starts over for another
// subject and after a release.
func TestHold(t *testing.T) {
	now := time.Now()
	seen := func(at time.Time) Estimate { return Estimate{Kind: median, Newest: at} }
	var h Hold
	if h.Stands("x", seen(now), seen(now), 5*time.Second, now) {
		t.Fatal("a new hold stood at once")
	}
	later := now.Add(5 * time.Second)
	if h.Stands("x", seen(now), seen(later), 5*time.Second, later) {
		t.Error("the hold stood without a fresh sample of the first side")
	}
	if h.Stands("x", seen(later), seen(later), 5*time.Second, now.Add(4*time.Second)) {
		t.Error("the hold stood before its duration")
	}
	if !h.Stands("x", seen(later), seen(later), 5*time.Second, later) {
		t.Error("the hold did not stand with its duration and a fresh sample of each side")
	}
	if h.Stands("y", seen(later), seen(later), 5*time.Second, later) {
		t.Error("another subject stood on the first one's hold")
	}
	h.Release()
	if h.Stands("y", seen(later.Add(time.Second)), seen(later.Add(time.Second)), 0, later.Add(time.Second)) {
		t.Error("a released hold stood at once")
	}
}
