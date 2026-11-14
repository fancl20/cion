package ping

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/fancl20/cion/pkg/libs/evidence"
)

// start is the tests' first send.
var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// sent sends requests carrying the values, each at its offset from start,
// returning their sequence numbers.
func sent[T any](t *testing.T, p *Pending[T], at []time.Duration, values ...T) []uint16 {
	t.Helper()
	var seqs []uint16
	for i, v := range values {
		if err := p.Send(start.Add(at[i]), v, func(seq uint16) error {
			seqs = append(seqs, seq)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return seqs
}

// TestPendingAnswered checks that a reply settles the request it answers,
// with the round trip from the request's sending to the reply's arrival and
// the reply's mark, once; a reply no request awaits settles nothing.
func TestPendingAnswered(t *testing.T) {
	p := NewPending[string](time.Second)
	seqs := sent(t, p, []time.Duration{0, 10 * time.Millisecond}, "a", "b")
	got, ok := p.Answered(Reply{Seq: seqs[1], Marked: true, At: start.Add(50 * time.Millisecond)})
	if !ok {
		t.Fatal("the reply to b settled nothing")
	}
	want := Settled[string]{Value: "b", Sample: evidence.Sample{
		At: start.Add(10 * time.Millisecond), RTT: 40 * time.Millisecond, Marked: true}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("settled (-want +got):\n%s", diff)
	}
	if _, ok := p.Answered(Reply{Seq: seqs[1], At: start.Add(60 * time.Millisecond)}); ok {
		t.Error("a second reply to b settled it again")
	}
	if _, ok := p.Answered(Reply{Seq: seqs[1] + 1, At: start.Add(60 * time.Millisecond)}); ok {
		t.Error("a reply to no request sent settled one")
	}
}

// TestPendingExpires checks that a request expires lost once it has waited
// its wait, not before, in the order the requests were sent, that a reply
// after its wait settles nothing, and that the deadline follows the first
// request awaiting its reply.
func TestPendingExpires(t *testing.T) {
	p := NewPending[int](time.Second)
	values := make([]int, 40)
	at := make([]time.Duration, len(values))
	for i := range values {
		values[i] = i
		if i >= 20 {
			at[i] = 500 * time.Millisecond
		}
	}
	seqs := sent(t, p, at, values...)
	if got, ok := p.Deadline(); !ok || !got.Equal(start.Add(time.Second)) {
		t.Errorf("deadline = %v, %t, want %v", got, ok, start.Add(time.Second))
	}
	if got := p.Expire(start.Add(time.Second - time.Nanosecond)); len(got) != 0 {
		t.Fatalf("expired within the wait: %v", got)
	}
	lost := func(from, to int) []Settled[int] {
		var want []Settled[int]
		for i := from; i < to; i++ {
			want = append(want, Settled[int]{Value: i, Sample: evidence.Sample{At: start.Add(at[i]), Lost: true}})
		}
		return want
	}
	if diff := cmp.Diff(lost(0, 20), p.Expire(start.Add(time.Second))); diff != "" {
		t.Errorf("expired at the wait (-want +got):\n%s", diff)
	}
	if _, ok := p.Answered(Reply{Seq: seqs[0], At: start.Add(time.Second)}); ok {
		t.Error("a reply after its request's wait settled it")
	}
	if got, ok := p.Deadline(); !ok || !got.Equal(start.Add(1500*time.Millisecond)) {
		t.Errorf("deadline = %v, %t, want %v", got, ok, start.Add(1500*time.Millisecond))
	}
	if diff := cmp.Diff(lost(20, 40), p.Expire(start.Add(time.Minute))); diff != "" {
		t.Errorf("expired at the second wait (-want +got):\n%s", diff)
	}
	if got, ok := p.Deadline(); ok {
		t.Errorf("deadline = %v with no request awaiting its reply", got)
	}
}

// TestPendingSendFails checks that a request whose send fails awaits no
// reply, and that the next request takes a sequence number of its own.
func TestPendingSendFails(t *testing.T) {
	p := NewPending[string](time.Second)
	refused := errors.New("refused")
	var failed uint16
	if err := p.Send(start, "a", func(seq uint16) error {
		failed = seq
		return refused
	}); !errors.Is(err, refused) {
		t.Fatalf("Send = %v, want the send's failure", err)
	}
	if _, ok := p.Deadline(); ok {
		t.Error("a request whose send failed awaits its reply")
	}
	if seqs := sent(t, p, []time.Duration{0}, "b"); seqs[0] == failed {
		t.Errorf("the next request took the failed one's sequence number %d", failed)
	}
}
