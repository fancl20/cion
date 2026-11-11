// Package evidence weighs what a node measures for the decisions it takes on
// it: estimates that carry the samples they rest on, comparisons that decide
// on the estimates' bounds or answer undecided, holds, and the records of the
// changes the decisions make.
package evidence

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// lossCap bounds the loss an estimate counts, so that a lossy subject's
// estimate stays finite.
const lossCap = 0.9

// Sample is one measurement's outcome.
type Sample struct {
	// At is when the measurement was sent.
	At time.Time
	// RTT is its round trip, zero when it was lost.
	RTT time.Duration
	// Lost reports whether it went unanswered.
	Lost bool
}

// Kind is what an estimate states: a quantile of the round trips its window
// holds, each of its bounds at a one-sided confidence. The window holds the
// last Count samples sent within Span; a zero Count bounds it by Span alone.
type Kind struct {
	Quantile   float64
	Confidence float64
	Span       time.Duration
	Count      int
}

// Estimate is a kind read from samples at an instant: the quantile by
// nearest rank and its bounds, each divided by the delivery rate of the
// samples the window holds, the loss counted up to lossCap, beside the
// samples answered and sent and when the newest answered one was sent.
// HasLo and HasHi report the bounds the samples give; an estimate without an
// answered sample states nothing else.
type Estimate struct {
	Kind
	Value, Lo, Hi  time.Duration
	HasLo, HasHi   bool
	Answered, Sent int
	Newest         time.Time
}

// Of reads the kind's estimate from the samples, oldest first, at now.
func (k Kind) Of(samples []Sample, now time.Time) Estimate {
	if k.Count > 0 {
		samples = samples[max(0, len(samples)-k.Count):]
	}
	e := Estimate{Kind: k}
	var rtts []time.Duration
	for _, s := range samples {
		if now.Sub(s.At) > k.Span {
			continue
		}
		e.Sent++
		if !s.Lost {
			rtts = append(rtts, s.RTT)
			if s.At.After(e.Newest) {
				e.Newest = s.At
			}
		}
	}
	e.Answered = len(rtts)
	if e.Answered == 0 {
		return e
	}
	slices.Sort(rtts)
	delivery := 1 - min(float64(e.Sent-e.Answered)/float64(e.Sent), lossCap)
	scale := func(d time.Duration) time.Duration { return time.Duration(float64(d) / delivery) }
	e.Value = scale(Quantile(rtts, k.Quantile))
	lo, hi := BoundRanks(len(rtts), k.Quantile, k.Confidence)
	if e.HasLo = lo >= 0; e.HasLo {
		e.Lo = scale(rtts[lo])
	}
	if e.HasHi = hi >= 0; e.HasHi {
		e.Hi = scale(rtts[hi])
	}
	return e
}

// Add returns the estimate with d added to its value and to each bound it
// has: a charge a price carries beside the round trip.
func (e Estimate) Add(d time.Duration) Estimate {
	if e.Answered == 0 {
		return e
	}
	e.Value += d
	if e.HasLo {
		e.Lo += d
	}
	if e.HasHi {
		e.Hi += d
	}
	return e
}

// Mul returns the estimate with its value and each bound it has scaled by
// r: a multiple or a fraction of what it states, such as a ratio a decision
// weighs it at. A ratio not above zero is a caller's mistake.
func (e Estimate) Mul(r float64) Estimate {
	if r <= 0 {
		panic(fmt.Sprintf("evidence: an estimate scaled by %v", r))
	}
	scale := func(d time.Duration) time.Duration { return time.Duration(r * float64(d)) }
	e.Value = scale(e.Value)
	if e.HasLo {
		e.Lo = scale(e.Lo)
	}
	if e.HasHi {
		e.Hi = scale(e.Hi)
	}
	return e
}

// Min returns the estimate of the least of the subjects the estimates
// read: the least value; the least lower bound, which needs every
// estimate's, for the least of several lies above the least of their lower
// bounds only where each has one; the least upper bound of those giving one;
// the samples answered and sent across them; and the newest answered sample
// of any. An estimate without an answered sample states nothing and takes
// no part; none answered leaves the zero estimate. Estimates of different
// kinds are a caller's mistake.
func Min(es ...Estimate) Estimate {
	var out Estimate
	allLo := true
	for _, e := range es {
		if e.Answered == 0 {
			continue
		}
		if out.Answered == 0 {
			out = Estimate{Kind: e.Kind, Value: e.Value, Lo: e.Lo, Hi: e.Hi, HasHi: e.HasHi}
		} else if e.Kind != out.Kind {
			panic(fmt.Sprintf("evidence: the least of a %+v estimate and a %+v one", out.Kind, e.Kind))
		}
		out.Value = min(out.Value, e.Value)
		allLo = allLo && e.HasLo
		if e.HasLo {
			out.Lo = min(out.Lo, e.Lo)
		}
		if e.HasHi && (!out.HasHi || e.Hi < out.Hi) {
			out.Hi, out.HasHi = e.Hi, true
		}
		out.Answered += e.Answered
		out.Sent += e.Sent
		if e.Newest.After(out.Newest) {
			out.Newest = e.Newest
		}
	}
	if out.HasLo = out.Answered > 0 && allLo; !out.HasLo {
		out.Lo = 0
	}
	if !out.HasHi {
		out.Hi = 0
	}
	return out
}

// Sub returns the estimate of the difference between the subject e reads
// and the one o reads: the values' difference; the lower bound e's lower
// bound less o's upper, and the upper bound e's upper bound less o's lower,
// each where both stand; the samples answered and sent of the side resting
// on fewer; and the staler side's newest answered sample. A side without an
// answered sample leaves the zero estimate. Estimates of different kinds are
// a caller's mistake.
func (e Estimate) Sub(o Estimate) Estimate {
	if e.Answered == 0 || o.Answered == 0 {
		return Estimate{}
	}
	if e.Kind != o.Kind {
		panic(fmt.Sprintf("evidence: a %+v estimate less a %+v one", e.Kind, o.Kind))
	}
	d := Estimate{Kind: e.Kind, Value: e.Value - o.Value, Answered: min(e.Answered, o.Answered),
		Sent: min(e.Sent, o.Sent), Newest: e.Newest}
	if o.Newest.Before(d.Newest) {
		d.Newest = o.Newest
	}
	if d.HasLo = e.HasLo && o.HasHi; d.HasLo {
		d.Lo = e.Lo - o.Hi
	}
	if d.HasHi = e.HasHi && o.HasLo; d.HasHi {
		d.Hi = e.Hi - o.Lo
	}
	return d
}

// Max returns the estimate of the most of the subjects the estimates read:
// the most value; the most lower bound of those giving one; the most upper
// bound, which needs every estimate's, for the most of several lies below
// the most of their upper bounds only where each has one; the samples
// answered and sent across them; and the newest answered sample of any. An
// estimate without an answered sample states nothing and takes no part;
// none answered leaves the zero estimate. Estimates of different kinds are
// a caller's mistake.
func Max(es ...Estimate) Estimate {
	var out Estimate
	allHi := true
	for _, e := range es {
		if e.Answered == 0 {
			continue
		}
		if out.Answered == 0 {
			out = Estimate{Kind: e.Kind, Value: e.Value, Lo: e.Lo, HasLo: e.HasLo, Hi: e.Hi}
		} else if e.Kind != out.Kind {
			panic(fmt.Sprintf("evidence: the most of a %+v estimate and a %+v one", out.Kind, e.Kind))
		}
		out.Value = max(out.Value, e.Value)
		if e.HasLo && (!out.HasLo || e.Lo > out.Lo) {
			out.Lo, out.HasLo = e.Lo, true
		}
		allHi = allHi && e.HasHi
		if e.HasHi {
			out.Hi = max(out.Hi, e.Hi)
		}
		out.Answered += e.Answered
		out.Sent += e.Sent
		if e.Newest.After(out.Newest) {
			out.Newest = e.Newest
		}
	}
	if out.HasHi = out.Answered > 0 && allHi; !out.HasHi {
		out.Hi = 0
	}
	if !out.HasLo {
		out.Lo = 0
	}
	return out
}

// Sum returns the estimate of the sum of the round trips the estimates
// read: the values' sum; the lower bounds' sum wherever any estimate gives
// one, a missing one counting zero, for no round trip is shorter; the upper
// bounds' sum, which needs every estimate's; the samples answered and sent
// of the estimate resting on fewest; and the stalest estimate's newest
// answered sample. An estimate without an answered sample leaves the zero
// estimate, as does none. Estimates of different kinds are a caller's
// mistake.
func Sum(es ...Estimate) Estimate {
	if len(es) == 0 {
		return Estimate{}
	}
	out := Estimate{Kind: es[0].Kind, HasHi: true, Answered: es[0].Answered, Sent: es[0].Sent,
		Newest: es[0].Newest}
	for _, e := range es {
		if e.Answered == 0 {
			return Estimate{}
		}
		if e.Kind != out.Kind {
			panic(fmt.Sprintf("evidence: the sum of a %+v estimate and a %+v one", out.Kind, e.Kind))
		}
		out.Value += e.Value
		if e.HasLo {
			out.Lo, out.HasLo = out.Lo+e.Lo, true
		}
		if out.HasHi = out.HasHi && e.HasHi; out.HasHi {
			out.Hi += e.Hi
		}
		out.Answered = min(out.Answered, e.Answered)
		out.Sent = min(out.Sent, e.Sent)
		if e.Newest.Before(out.Newest) {
			out.Newest = e.Newest
		}
	}
	if !out.HasHi {
		out.Hi = 0
	}
	return out
}

// Published returns the estimate a published value and its bounds state,
// for a reader that holds the values and not the samples they rest on: the
// value, each bound given, a zero one giving none, and one answered sample,
// sent when the reader does not know, standing for the publisher's. A zero
// value states nothing.
func Published(k Kind, value, lo, hi time.Duration) Estimate {
	if value == 0 {
		return Estimate{}
	}
	return Estimate{Kind: k, Value: value, Lo: lo, Hi: hi, HasLo: lo > 0, HasHi: hi > 0, Answered: 1, Sent: 1}
}

// Proportion is the proportion of a window's samples answered: the samples
// answered and sent, and the one-sided confidence of its bounds, the
// binomial's exact bounds — the proportion under which the answers seen, or
// fewer, would come with no more than the odds the confidence leaves, and
// the one over which they, or more, would.
type Proportion struct {
	Answered, Sent int
	Confidence     float64
}

// ProportionOf returns the proportion of the samples answered, bounded at
// confidence c.
func ProportionOf(samples []Sample, c float64) Proportion {
	s := Proportion{Sent: len(samples), Confidence: c}
	for _, x := range samples {
		if !x.Lost {
			s.Answered++
		}
	}
	return s
}

// Under weighs whether the proportion lies under the line, a proportion
// strictly between zero and one: Better when its upper bound does, NotBetter
// when its lower bound reaches the line, Undecided otherwise and for a
// proportion of no sample.
func (s Proportion) Under(line float64) Verdict {
	if s.Sent == 0 {
		return Undecided
	}
	cdf := binomialCDF(s.Sent, line)
	switch {
	case cdf[s.Answered] < 1-s.Confidence:
		return Better
	case s.Answered > 0 && cdf[s.Answered-1] >= s.Confidence:
		return NotBetter
	default:
		return Undecided
	}
}

// Quantile returns the q-quantile of the sorted round trips by nearest rank:
// the first that at least a q share of them lie at or below. Zero for none.
func Quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[rank(len(sorted), q)]
}

// rank returns the index of the q-quantile by nearest rank among n sorted
// values. The tolerance keeps a product a float rounds above a whole rank,
// such as 0.8 times ten, on that rank.
func rank(n int, q float64) int {
	return min(n, max(1, int(math.Ceil(q*float64(n)-1e-9)))) - 1
}

// BoundRanks returns the indices, among n sorted round trips, of the bounds
// of their q-quantile, each with one-sided confidence c: lo, the round trip
// it lies at or above, and hi, the one it lies at or below. Each is the order
// statistic the count of round trips below the quantile, binomial over them,
// reaches with the confidence, so the bounds assume nothing of how the round
// trips spread. A bound too few round trips give is -1.
func BoundRanks(n int, q, c float64) (lo, hi int) {
	lo, hi = -1, -1
	below := binomialCDF(n, q)
	for u := 1; u <= n; u++ {
		if below[u-1] >= c {
			hi = u - 1
			break
		}
	}
	for l := n; l >= 1; l-- {
		if 1-below[l-1] >= c {
			lo = l - 1
			break
		}
	}
	return lo, hi
}

// binomialCDF returns P(B <= k) for k from 0 to n, B binomial over n trials
// of probability p.
func binomialCDF(n int, p float64) []float64 {
	logFactorial := func(k int) float64 {
		v, _ := math.Lgamma(float64(k + 1))
		return v
	}
	cdf := make([]float64, n+1)
	sum := 0.0
	for k := range cdf {
		sum += math.Exp(logFactorial(n) - logFactorial(k) - logFactorial(n-k) +
			float64(k)*math.Log(p) + float64(n-k)*math.Log(1-p))
		cdf[k] = sum
	}
	return cdf
}

// Verdict is what a comparison answers.
type Verdict uint8

const (
	// Undecided is a comparison whose bounds do not part by the line, or
	// that lacks a bound it needs.
	Undecided Verdict = iota
	// Better is a comparison confident that the one estimate beats the
	// other by the line.
	Better
	// NotBetter is a comparison confident that it does not.
	NotBetter
)

func (v Verdict) String() string {
	switch v {
	case Better:
		return "better"
	case NotBetter:
		return "not better"
	default:
		return "undecided"
	}
}

// Beats weighs whether a beats b by at least line: Better when a's upper
// bound and the line lie at or below b's lower bound, NotBetter when a's
// lower bound and the line lie above b's upper bound, Undecided otherwise
// and whenever a bound either test needs is missing. Estimates of different
// kinds are a caller's mistake.
func Beats(a, b Estimate, line time.Duration) Verdict {
	if a.Kind != b.Kind {
		panic(fmt.Sprintf("evidence: weighing a %+v estimate against a %+v one", a.Kind, b.Kind))
	}
	switch {
	case a.HasHi && b.HasLo && a.Hi+line <= b.Lo:
		return Better
	case a.HasLo && b.HasHi && a.Lo+line > b.Hi:
		return NotBetter
	default:
		return Undecided
	}
}

// Hold holds a verdict on a subject until it has stood for a duration, with
// a sample of each side answered since it first stood. Its zero value holds
// nothing.
type Hold struct {
	subject      string
	since        time.Time
	aSeen, bSeen time.Time
}

// Stands reports whether the hold on the subject stands at now: it has held
// for d, and each side's newest answered sample is newer than when the hold
// began. A subject the hold does not hold starts it over, standing not yet.
func (h *Hold) Stands(subject string, a, b Estimate, d time.Duration, now time.Time) bool {
	if h.subject != subject || h.since.IsZero() {
		*h = Hold{subject: subject, since: now, aSeen: a.Newest, bSeen: b.Newest}
		return false
	}
	return now.Sub(h.since) >= d && a.Newest.After(h.aSeen) && b.Newest.After(h.bSeen)
}

// Release ends the hold.
func (h *Hold) Release() {
	*h = Hold{}
}
