package bus

import (
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// TestInterfaceDownState checks the interface-down state: a signal holds its
// link until it lapses, a later signal extends the hold, the next signal
// leaves the lapsed ones out, and the destinations quoted after a count are
// the ones later signals quoted, the zero destination never among them.
func TestInterfaceDownState(t *testing.T) {
	t0 := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	hold := 10 * time.Second
	ia := func(as addr.AS) addr.IA { return addr.MustIAFrom(1, as) }
	link := func(as addr.AS, ifID uint16) segment.LinkID { return segment.LinkID{IA: ia(as), IfID: ifID} }
	quotedAfter := func(s InterfaceDownState, seq uint64) []addr.IA {
		ds := slices.Collect(s.QuotedAfter(seq))
		slices.SortFunc(ds, func(a, b addr.IA) int { return int(a.AS()) - int(b.AS()) })
		return ds
	}

	var zero InterfaceDownState
	if zero.Holds(link(1, 1), t0) || zero.Seq() != 0 || len(quotedAfter(zero, 0)) != 0 {
		t.Error("the zero state holds a signal")
	}

	first := zero.Signaled(link(1, 1), ia(10), t0, t0.Add(hold))
	if !first.Holds(link(1, 1), t0.Add(hold-time.Nanosecond)) {
		t.Error("a signal lapsed before its hold ended")
	}
	if first.Holds(link(1, 1), t0.Add(hold)) {
		t.Error("a signal held past its hold")
	}
	if first.Holds(link(1, 2), t0) {
		t.Error("a signal held a link it does not name")
	}
	if zero.Seq() != 0 || first.Seq() != 1 {
		t.Errorf("seqs = %d then %d, want 0 then 1: a published state is never mutated", zero.Seq(), first.Seq())
	}

	second := first.Signaled(link(2, 1), ia(20), t0.Add(5*time.Second), t0.Add(15*time.Second))
	third := second.Signaled(link(2, 1), addr.IA(0), t0.Add(8*time.Second), t0.Add(18*time.Second))
	if diff := cmp.Diff([]addr.IA{ia(10), ia(20)}, quotedAfter(third, 0)); diff != "" {
		t.Errorf("destinations quoted after 0 (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]addr.IA{ia(20)}, quotedAfter(third, first.Seq())); diff != "" {
		t.Errorf("destinations quoted after the first signal (-want +got):\n%s", diff)
	}
	if ds := quotedAfter(third, second.Seq()); len(ds) != 0 {
		t.Errorf("a signal quoting no destination quoted %v", ds)
	}
	if !third.Holds(link(2, 1), t0.Add(17*time.Second)) {
		t.Error("a later signal did not extend its link's hold")
	}

	// Past the first signal's hold, the next signal leaves it out.
	fourth := third.Signaled(link(3, 1), ia(30), t0.Add(12*time.Second), t0.Add(22*time.Second))
	if fourth.Holds(link(1, 1), t0) {
		t.Error("the next state kept a lapsed signal")
	}
	if diff := cmp.Diff([]addr.IA{ia(20), ia(30)}, quotedAfter(fourth, 0)); diff != "" {
		t.Errorf("destinations quoted after 0 once the first lapsed (-want +got):\n%s", diff)
	}
}
