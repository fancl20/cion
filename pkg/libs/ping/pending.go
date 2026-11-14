package ping

import (
	"cmp"
	"slices"
	"time"

	"github.com/fancl20/cion/pkg/libs/evidence"
)

// Pending holds a caller's echo requests awaiting their replies, each with
// the caller's value for it, and settles each by its reply, or as lost once
// it has waited its wait. One loop of the caller's calls it.
type Pending[T any] struct {
	wait    time.Duration
	seq     uint16
	sent    uint64
	waiting map[uint16]request[T]
}

// request is one request awaiting its reply: the caller's value for it, when
// it was sent, and its place in the order the requests were sent.
type request[T any] struct {
	value T
	at    time.Time
	order uint64
}

// Settled is one request settled: the caller's value for it, and its sample,
// at when the request was sent, with the round trip to its reply and whether
// the reply came back marked, or lost.
type Settled[T any] struct {
	Value  T
	Sample evidence.Sample
}

// NewPending returns a Pending whose requests each wait for their reply.
func NewPending[T any](wait time.Duration) *Pending[T] {
	return &Pending[T]{wait: wait, waiting: make(map[uint16]request[T])}
}

// Send sends one request by send, under the next sequence number, and has it
// await its reply, sent at at and carrying v, unless send fails.
func (p *Pending[T]) Send(at time.Time, v T, send func(seq uint16) error) error {
	p.seq++
	if err := send(p.seq); err != nil {
		return err
	}
	p.sent++
	p.waiting[p.seq] = request[T]{value: v, at: at, order: p.sent}
	return nil
}

// Answered settles the request the reply answers; false for a reply no
// request awaits, as one that came after its request's wait.
func (p *Pending[T]) Answered(r Reply) (Settled[T], bool) {
	req, ok := p.waiting[r.Seq]
	if !ok {
		return Settled[T]{}, false
	}
	delete(p.waiting, r.Seq)
	return Settled[T]{Value: req.value, Sample: evidence.Sample{
		At:     req.at,
		RTT:    r.At.Sub(req.at),
		Marked: r.Marked,
	}}, true
}

// Expire settles every request that has waited its wait by now as lost, in
// the order they were sent.
func (p *Pending[T]) Expire(now time.Time) []Settled[T] {
	var expired []request[T]
	for seq, req := range p.waiting {
		if now.Sub(req.at) >= p.wait {
			delete(p.waiting, seq)
			expired = append(expired, req)
		}
	}
	slices.SortFunc(expired, func(a, b request[T]) int { return cmp.Compare(a.order, b.order) })
	lost := make([]Settled[T], len(expired))
	for i, req := range expired {
		lost[i] = Settled[T]{Value: req.value, Sample: evidence.Sample{At: req.at, Lost: true}}
	}
	return lost
}

// Deadline returns when the wait of the request sent first among those
// awaiting their replies runs out; false while none awaits one.
func (p *Pending[T]) Deadline() (time.Time, bool) {
	var first time.Time
	found := false
	for _, req := range p.waiting {
		if !found || req.at.Before(first) {
			first, found = req.at, true
		}
	}
	return first.Add(p.wait), found
}
