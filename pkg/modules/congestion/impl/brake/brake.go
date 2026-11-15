// Package brake is the brake method of the congestion module. It grants
// each link the packets it writes in 100ms at the packet rate its last step
// measured, between 4 and 128, and calls for an echo to the next hop across
// the link each time the link uses one up, though a free link whose last
// step measured under 128 kbit/s, which no cut brakes, calls for one every
// ten seconds at most, enough to keep its least fresh. It weighs the queue
// the link meets beyond the node from the echoes sent since its last cut
// against the least round trip of the last minute, deciding only where the
// echoes' evidence does. Once a second, a link whose recent echoes are
// confidently answered under half the time is braked to 0.7 of what it
// wrote, and one whose recent round trips confidently stand the 15ms target
// or more over the least to what the queue beyond it delivered, read from
// how fast the round trips grew, less what drains the queue's standing
// excess within a second; a link that wrote nothing since its last step is
// not cut, and a free link is braked only to a rate under what it wrote. A
// braked link climbs its rate by an eighth where its round trips confidently
// stand within the target, and by a sixty-fourth where they read neither or
// where the rate lies just under the one its last cut came at; it is
// released after a second in which its rate held no data back, or once its
// echoes stop for five seconds. A link marks as large a share of the packets
// that come back over it as its egress queue is full. The brake sends its
// echoes itself, each to the neighbor's responder over the one-hop path out
// of the link, which a resolution over that path names; an echo unanswered
// within a second counts as lost, and eight lost in a row to one neighbor
// have its host resolved again, the echoes keeping the host they have
// meanwhile. A link's last echo, either way, is the later of the last reply
// to its own echoes and the last request the neighbor sent across it.
package brake

import (
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/modules/congestion"
)

// The brake's echoes, readings, and steps.
const (
	// grantSpan is how much of a link's traffic a grant covers, at the
	// packet rate the link's last step measured, and minGrant and maxGrant
	// bound a grant, in packets: a link calls for an echo per grant it uses
	// up, though a free one whose last step measured under rateFloor calls
	// for one a leastSpan at most.
	grantSpan = 100 * time.Millisecond
	minGrant  = 4
	maxGrant  = 128
	// reach is how far back the least round trip a link's echoes are read
	// against reaches, kept as the least of each leastSpan: a step in the
	// link's base round trip reads as queue for a minute at most.
	reach     = time.Minute
	leastSpan = 10 * time.Second
	// keep is how many of its latest echoes a link keeps to read.
	keep = 256
	// target is the margin over their least a link's round trips are
	// weighed at: the target or more over the least reads over, and within
	// the target of it, under.
	target = 15 * time.Millisecond
	// lossLine is the share of a link's recent echoes answered under which,
	// with the reading's confidence, the link reads over.
	lossLine = 0.5
	// stepEvery is how often a link steps at most.
	stepEvery = time.Second
	// climb raises a braked link's rate at each step its echoes stand
	// within the target, and nearClimb within climb of the rate its last
	// cut came at, under it, where the queue last filled.
	climb     = 1.0 / 8
	nearClimb = climb / 8
	// lossCut is the share of what it wrote a link that loses its echoes is
	// braked to, CUBIC's and BBR's cut on loss; drainCut the least share a
	// standing queue's drain keeps of what the queue delivered.
	lossCut  = 0.7
	drainCut = 0.5
	// silence is how long a link goes without an echo sent before it loses
	// its rate: its echoes follow its traffic, so a silent link's traffic
	// left it, and a stale rate must not throttle the traffic when it
	// returns.
	silence = 5 * time.Second
	// rateFloor is the least rate a link is braked to, in bits per second: a
	// link calls for an echo per grant of minGrant packets or more, and a
	// delay reading takes sixteen echoes within four seconds, so a link
	// writing under sixteen packets a second, 128 kbit/s of 1000-byte
	// packets, cannot be read for delay.
	rateFloor = 128_000
)

// recent is how a link's echoes since its last cut are read at a step: the
// tenth percentile round trip of those sent within four seconds, each bound
// at 80% one-sided confidence. Its lower bound needs sixteen answered echoes
// and is one of their shortest round trips, so a queue every echo waits in
// reads over, and the jitter some echoes meet does not.
var recent = evidence.Kind{Quantile: 0.1, Confidence: 0.8, Span: 4 * time.Second}

// Policy is the brake method's policy, which a Brake runs beside its echoes.
// One mutex guards its links' echoes, either way, and brakes, and the methods
// that take it wait on nothing else: a link steps as Wrote, Rate, or Sampled
// touches it, and the echoes a write calls for, and the log line of the
// step's change to the link's brake, go out once the mutex is released. Mark,
// which the data plane calls for each packet that comes back over a braked
// link, takes no lock once its link has marked: what a link owes in marks is
// a count of its own, moved atomically. Its clock is time.Now; a sample's At
// is when its echo was sent.
type Policy struct {
	echo  func(ifID uint16)
	mu    sync.Mutex
	links map[uint16]*link
	// owed holds what each link owes in marks, in markUnits, by interface:
	// a map replaced whole under owedMu as a link first marks, and read
	// without a lock.
	owed   atomic.Pointer[map[uint16]*atomic.Int64]
	owedMu sync.Mutex
}

// markUnit is one whole mark in the units a link's owed marks count in.
const markUnit = 1 << 20

// link is one link's echoes and brake.
type link struct {
	// tokens is the packets left of the link's grant: zero until the link's
	// first write.
	tokens int
	// samples are the outcomes of the link's latest echoes, oldest sent
	// first, at most keep of them; fresh reports whether one came since the
	// last step.
	samples []evidence.Sample
	fresh   bool
	// minima holds the least answered round trip of each leastSpan, oldest
	// first, within reach.
	minima []minimum
	// bytes and packets count what the link wrote since its last step,
	// which was at stepAt: zero until the link's first touch starts its
	// clock; held reports whether its rate held data back since; pace and
	// written are the packet and bit rates its last step measured, in
	// packets and bits a second since the step before or the clock's
	// start: zero until its first step. echoAt is when the link last called
	// for an echo: zero until its first. cutAt is when the link's rate was
	// last cut: only the echoes sent after it read the rate it set.
	bytes, packets int
	held           bool
	pace, written  float64
	echoAt         time.Time
	stepAt         time.Time
	cutAt          time.Time
	// rate is what the link's egress queue drains at, in bits per second:
	// zero while the link is not braked; ceiling is the rate its last cut
	// came at.
	rate, ceiling float64
	// echoedAt is when an echo last crossed the link, either way: zero until
	// a reply to one of its echoes or a request of the neighbor's arrived.
	echoedAt time.Time
}

// minimum is the least answered round trip of the echoes sent in the
// leastSpan that starts at span.
type minimum struct {
	span time.Time
	rtt  time.Duration
}

// reading is what a link's echoes read at a step: silent, over, under, or
// none of these. An over reading carries the share of echoes lost, or the
// queue, how far the round trips stand over the least, and its growth, how
// fast the round trips grew, in seconds a second.
type reading struct {
	silent, over, under bool
	lost                float64
	queue               time.Duration
	growth              float64
}

// change is what a step changed of a link's brake, logged once the mutex
// is released: braked, with the reading that braked it and the rate it set,
// or released as its rate held nothing back or its echoes stopped.
type change struct {
	braked        bool
	r             reading
	rate          float64
	free, stopped bool
	ceased        float64
}

var _ congestion.Policy = (*Policy)(nil)

// New returns the brake method's policy, which has measured no link and
// calls echo for each echo it calls for to the next hop across a link.
func New(echo func(ifID uint16)) *Policy {
	return &Policy{echo: echo, links: make(map[uint16]*link)}
}

// Wrote counts what the link wrote, once it has stepped, toward its next
// step, with whether its rate held data back, and takes the packets from its
// grant; the link's first write grants it minGrant. A write that uses the
// grant up, however far it overdraws, makes the next and calls for an echo
// across the link, unless the link is free, its last step measured under
// rateFloor, and it called for one within leastSpan: no cut brakes such a
// link, and its echoes only keep its least fresh.
func (p *Policy) Wrote(ifID uint16, packets, bytes int, held bool) {
	now := time.Now()
	p.mu.Lock()
	l, c := p.touch(ifID, now)
	l.bytes += bytes
	l.packets += packets
	l.held = l.held || held
	if l.tokens == 0 {
		l.tokens = minGrant
	}
	l.tokens -= packets
	echo := false
	if l.tokens <= 0 {
		l.tokens = l.grant()
		echo = l.rate != 0 || l.written >= rateFloor || now.Sub(l.echoAt) >= leastSpan
		if echo {
			l.echoAt = now
		}
	}
	p.mu.Unlock()
	c.log(ifID)
	if echo {
		p.echo(ifID)
	}
}

// grant returns the link's next grant: the packets it writes in grantSpan
// at its pace, between minGrant and maxGrant.
func (l *link) grant() int {
	return min(maxGrant, max(minGrant, int(l.pace*grantSpan.Seconds())))
}

// Rate returns the link's rate once it has stepped.
func (p *Policy) Rate(ifID uint16) float64 {
	p.mu.Lock()
	l, c := p.touch(ifID, time.Now())
	rate := l.rate
	p.mu.Unlock()
	c.log(ifID)
	return rate
}

// Mark adds the fill to what the link owes in marks, and marks the packet
// where a whole mark is owed, so the share of packets marked follows the
// fill. An empty queue marks nothing and clears what the link owed.
func (p *Policy) Mark(ifID uint16, fill float64) bool {
	owed := p.owedBy(ifID)
	if fill <= 0 {
		owed.Store(0)
		return false
	}
	add := int64(fill * markUnit)
	for {
		was := owed.Load()
		next := was + add
		marked := next >= markUnit
		if marked {
			next -= markUnit
		}
		if owed.CompareAndSwap(was, next) {
			return marked
		}
	}
}

// owedBy returns the count of what the link owes in marks, adding the link
// owing nothing on its first mark.
func (p *Policy) owedBy(ifID uint16) *atomic.Int64 {
	if owed := p.owed.Load(); owed != nil {
		if count := (*owed)[ifID]; count != nil {
			return count
		}
	}
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	owed := make(map[uint16]*atomic.Int64)
	if prev := p.owed.Load(); prev != nil {
		if count := (*prev)[ifID]; count != nil {
			return count
		}
		maps.Copy(owed, *prev)
	}
	count := new(atomic.Int64)
	owed[ifID] = count
	p.owed.Store(&owed)
	return count
}

// Sampled takes the echo's outcome once the link has stepped, fresh for the
// link's next step, and an answered echo's reply as the link's last echo.
func (p *Policy) Sampled(ifID uint16, s evidence.Sample) {
	p.mu.Lock()
	l, c := p.touch(ifID, time.Now())
	l.add(s)
	if !s.Lost {
		l.echoed(s.At.Add(s.RTT))
	}
	p.mu.Unlock()
	c.log(ifID)
}

// Requested takes the neighbor's echo request as the link's last echo.
func (p *Policy) Requested(ifID uint16, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.linkOf(ifID).echoed(at)
}

// Echoed returns when an echo last crossed the link, either way.
func (p *Policy) Echoed(ifID uint16) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.links[ifID]; l != nil {
		return l.echoedAt
	}
	return time.Time{}
}

// echoed takes an echo that crossed the link at as its last, unless a later
// one did; the mutex must be held.
func (l *link) echoed(at time.Time) {
	if at.After(l.echoedAt) {
		l.echoedAt = at
	}
}

// touch returns ifID's link once it has stepped at now, and what the step
// changed of its brake; the mutex must be held.
func (p *Policy) touch(ifID uint16, now time.Time) (*link, change) {
	l := p.linkOf(ifID)
	return l, l.step(now)
}

// linkOf returns ifID's link, adding one that has measured nothing; the
// mutex must be held.
func (p *Policy) linkOf(ifID uint16) *link {
	l := p.links[ifID]
	if l == nil {
		l = new(link)
		p.links[ifID] = l
	}
	return l
}

// add adds the sample among the link's in the order their echoes were
// sent, dropping the oldest past keep, and an answered one's round trip to
// the least of its span.
func (l *link) add(s evidence.Sample) {
	i := len(l.samples)
	for i > 0 && l.samples[i-1].At.After(s.At) {
		i--
	}
	l.samples = slices.Insert(l.samples, i, s)
	if n := len(l.samples) - keep; n > 0 {
		l.samples = slices.Delete(l.samples, 0, n)
	}
	l.fresh = true
	if s.Lost {
		return
	}
	span := s.At.Truncate(leastSpan)
	j := len(l.minima)
	for j > 0 && l.minima[j-1].span.After(span) {
		j--
	}
	if j > 0 && l.minima[j-1].span.Equal(span) {
		l.minima[j-1].rtt = min(l.minima[j-1].rtt, s.RTT)
		return
	}
	l.minima = slices.Insert(l.minima, j, minimum{span: span, rtt: s.RTT})
}

// step steps the link at now once stepEvery passed since its last step,
// keeping the packet and bit rates it wrote since then as its pace and
// written; the link's first touch starts its clock. A silent link loses its
// rate, and is not braked; a link with no echo come since the last step
// holds its rate. Otherwise echoes that read over cut the rate from what the
// link wrote since its last step, or from its rate where that is lower: to
// lossCut of it on loss, and on a standing queue to what the queue delivered
// of it, less what drains the queue's excess over the target within
// stepEvery, keeping drainCut of it at least. No rate falls under rateFloor.
// A link that wrote nothing since its last step is not cut, and a free link
// is braked only to a rate under what it wrote: either keeps its rate. A
// rate that held no data back since the last step is released where the
// echoes do not read over; otherwise echoes that read under climb it by
// climb, by nearClimb within climb under the rate the last cut came at, and
// echoes that read neither by nearClimb.
func (l *link) step(now time.Time) change {
	if l.stepAt.IsZero() {
		l.stepAt = now
		return change{}
	}
	elapsed := now.Sub(l.stepAt)
	if elapsed < stepEvery {
		return change{}
	}
	r := l.read(now)
	written := 8 * float64(l.bytes) / elapsed.Seconds()
	l.pace, l.written = float64(l.packets)/elapsed.Seconds(), written
	var c change
	switch {
	case r.silent:
		if l.rate != 0 {
			c.stopped, c.ceased = true, l.rate
			l.rate = 0
		}
	case !l.fresh:
	case r.over && l.bytes > 0:
		from := written
		if l.rate != 0 {
			from = min(l.rate, written)
		}
		var rate, ceiling float64
		if r.lost > 0 {
			rate, ceiling = max(rateFloor, lossCut*from), from
		} else {
			delivered := from / (1 + max(0, r.growth))
			drain := float64(r.queue-target) / float64(stepEvery)
			rate, ceiling = max(rateFloor, delivered*max(drainCut, 1-drain)), delivered
		}
		if l.rate == 0 {
			if rate >= written {
				break
			}
			c.braked, c.r, c.rate = true, r, rate
		}
		l.rate, l.ceiling, l.cutAt = rate, ceiling, now
	case r.over:
	case l.rate != 0 && !l.held:
		c.free, c.ceased = true, l.rate
		l.rate = 0
	case l.rate != 0:
		if r.under && (l.rate < (1-climb)*l.ceiling || l.rate >= l.ceiling) {
			l.rate *= 1 + climb
		} else {
			l.rate *= 1 + nearClimb
		}
	}
	l.bytes, l.packets, l.held, l.stepAt, l.fresh = 0, 0, false, now, false
	return c
}

// read drops the minima of spans past the reach, and weighs the recent
// echoes sent since the last cut: silent without an echo sent for silence;
// nothing without an answer within the reach to read the least from. Echoes
// confidently answered under lossLine of the time read over on loss; and so
// does a tenth percentile, its loss counted, confidently the target or more
// over the least, on the queue it stands at over the least and the growth of
// the echoes' round trips. One confidently within the target reads under;
// anything else reads nothing.
func (l *link) read(now time.Time) reading {
	i := 0
	for i < len(l.minima) && now.Sub(l.minima[i].span) > reach {
		i++
	}
	l.minima = slices.Delete(l.minima, 0, i)
	n := len(l.samples)
	if n == 0 || now.Sub(l.samples[n-1].At) >= silence {
		return reading{silent: true}
	}
	if len(l.minima) == 0 {
		return reading{}
	}
	least := l.minima[0].rtt
	for _, m := range l.minima[1:] {
		least = min(least, m.rtt)
	}
	since := len(l.samples)
	for since > 0 && l.samples[since-1].At.After(l.cutAt) && now.Sub(l.samples[since-1].At) <= recent.Span {
		since--
	}
	window := l.samples[since:]
	if answered := evidence.ProportionOf(window, recent.Confidence); answered.Under(lossLine) == evidence.Better {
		return reading{over: true, lost: 1 - float64(answered.Answered)/float64(answered.Sent)}
	}
	current := recent.Of(window, now)
	base := evidence.Estimate{Kind: recent, Value: least, Lo: least, Hi: least, HasLo: true, HasHi: true,
		Answered: 1, Sent: 1}
	switch evidence.Beats(base, current, target) {
	case evidence.Better:
		return reading{over: true, queue: current.Value - least, growth: growth(window)}
	case evidence.NotBetter:
		return reading{under: true}
	}
	return reading{}
}

// log logs the change to ifID's brake, if any.
func (c change) log(ifID uint16) {
	const braking = "Braking a link: its echoes stand over their least"
	switch {
	case c.braked && c.r.lost > 0:
		slog.Info(braking, "interface", ifID, "lost", c.r.lost, "rate", int64(c.rate))
	case c.braked:
		slog.Info(braking, "interface", ifID, "queue", c.r.queue, "rate", int64(c.rate))
	case c.free:
		slog.Info("Released a link's brake: its rate held nothing back", "interface", ifID,
			"rate", int64(c.ceased))
	case c.stopped:
		slog.Info("Released a link's brake: its echoes stopped", "interface", ifID, "rate", int64(c.ceased))
	}
}

// growth returns how fast the answered echoes' round trips grew against when
// they were sent, in seconds a second, by least squares; zero for fewer than
// two.
func growth(samples []evidence.Sample) float64 {
	var n, sx, sy, sxx, sxy float64
	var first time.Time
	for _, s := range samples {
		if s.Lost {
			continue
		}
		if n == 0 {
			first = s.At
		}
		x, y := s.At.Sub(first).Seconds(), s.RTT.Seconds()
		n++
		sx, sy, sxx, sxy = sx+x, sy+y, sxx+x*x, sxy+x*y
	}
	if d := n*sxx - sx*sx; n >= 2 && d > 0 {
		return (n*sxy - sx*sy) / d
	}
	return 0
}
