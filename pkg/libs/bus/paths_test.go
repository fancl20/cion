package bus

import (
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// TestPathIDOf checks that a path's ID names its links in order: the same
// links give the same ID, and their reversal another.
func TestPathIDOf(t *testing.T) {
	a := segment.LinkID{IA: addr.MustIAFrom(1, 0xff0000000001), IfID: 1}
	b := segment.LinkID{IA: addr.MustIAFrom(1, 0xff0000000002), IfID: 7}
	if got, want := PathIDOf([]segment.LinkID{a, b}), PathID("1-ff00:0:1#1 1-ff00:0:2#7"); got != want {
		t.Errorf("PathIDOf = %q, want %q", got, want)
	}
	if PathIDOf([]segment.LinkID{a, b}) == PathIDOf([]segment.LinkID{b, a}) {
		t.Error("a path and its reversal share an ID")
	}
	if got := PathIDOf(nil); got != "" {
		t.Errorf("PathIDOf(nil) = %q, want empty", got)
	}
}

// TestPathRequestsRequested checks a requester's update: its entries for the
// destination replaced, its lapsed destinations dropped, no entries dropping
// the destination, and every other requester's entries left alone; and its
// replacement, which swaps every destination's entries at once.
func TestPathRequestsRequested(t *testing.T) {
	now := time.Now()
	d1, d2, d3 := addr.MustIAFrom(1, 1), addr.MustIAFrom(1, 2), addr.MustIAFrom(1, 3)
	entry := func(id PathID, dst addr.IA, picked time.Time) PathRequest {
		return PathRequest{ID: id, Dst: dst, Picked: picked}
	}
	ids := func(r PathRequests) []PathID {
		var out []PathID
		for e := range r.All() {
			out = append(out, e.ID)
		}
		slices.Sort(out)
		return out
	}

	var r PathRequests
	r = r.Requested("picks", d1, []PathRequest{entry("a", d1, now.Add(-20*time.Minute))}, now.Add(-time.Hour))
	r = r.Requested("picks", d2, []PathRequest{entry("b", d2, now), entry("c", d2, now)}, now.Add(-time.Hour))
	r = r.Requested("routes", d3, []PathRequest{entry("d", d3, now.Add(-time.Hour))}, now.Add(-2*time.Hour))
	if diff := cmp.Diff([]PathID{"a", "b", "c", "d"}, ids(r)); diff != "" {
		t.Fatalf("requests (-want +got):\n%s", diff)
	}

	// An update for d2 lapses d1's entry for the requester alone.
	next := r.Requested("picks", d2, []PathRequest{entry("e", d2, now)}, now.Add(-RequestLapse))
	if diff := cmp.Diff([]PathID{"d", "e"}, ids(next)); diff != "" {
		t.Errorf("after the update (-want +got):\n%s", diff)
	}
	// The update built a new state.
	if diff := cmp.Diff([]PathID{"a", "b", "c", "d"}, ids(r)); diff != "" {
		t.Errorf("the published state changed (-want +got):\n%s", diff)
	}
	// No entries drop the destination.
	if diff := cmp.Diff([]PathID{"d"}, ids(next.Requested("picks", d2, nil, now.Add(-RequestLapse)))); diff != "" {
		t.Errorf("after dropping d2 (-want +got):\n%s", diff)
	}

	// A replacement swaps the requester's entries whole, the destinations it
	// leaves out dropped, and another requester's kept.
	replaced := r.Replaced("picks", map[addr.IA][]PathRequest{
		d3: {entry("f", d3, now)},
		d1: nil,
	})
	if diff := cmp.Diff([]PathID{"d", "f"}, ids(replaced)); diff != "" {
		t.Errorf("after the replacement (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]PathID{"a", "b", "c", "d"}, ids(r)); diff != "" {
		t.Errorf("the replacement changed the published state (-want +got):\n%s", diff)
	}
}

// TestPathMeasurements checks that the measurements copy their map and
// serve its records.
func TestPathMeasurements(t *testing.T) {
	records := map[PathID]PathRecord{"a": {Dst: addr.MustIAFrom(1, 1), LostBursts: 2}}
	m := NewPathMeasurements(records)
	records["b"] = PathRecord{}
	if _, ok := m.Of("b"); ok {
		t.Error("the measurements share their map with the caller")
	}
	if r, ok := m.Of("a"); !ok || r.LostBursts != 2 {
		t.Errorf("Of(a) = %+v, %v, want the record", r, ok)
	}
	n := 0
	for range m.All() {
		n++
	}
	if n != 1 {
		t.Errorf("All yielded %d records, want 1", n)
	}
	if _, ok := (PathMeasurements{}).Of("a"); ok {
		t.Error("the zero measurements hold a record")
	}
}
