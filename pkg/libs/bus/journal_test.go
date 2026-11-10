package bus

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/google/go-cmp/cmp"
)

// TestJournalSince checks a journal's reads: entries numbered from zero, the
// oldest dropped past JournalKept and counted by a read from before them, a
// read from a number returning the entries from it on, and a read's entries
// unchanged by the appends after it.
func TestJournalSince(t *testing.T) {
	var j Journal[int]
	if got, dropped := j.Since(0); len(got) != 0 || dropped != 0 || j.Next() != 0 {
		t.Fatalf("an empty journal read %v, dropped %d, next %d", got, dropped, j.Next())
	}
	j.Append(0)
	first, _ := j.Since(0)
	for i := 1; i < JournalKept+10; i++ {
		j.Append(i)
	}
	if j.Next() != JournalKept+10 {
		t.Errorf("next after %d appends = %d", JournalKept+10, j.Next())
	}
	got, dropped := j.Since(4)
	if len(got) != JournalKept || dropped != 6 || got[0] != 10 || got[len(got)-1] != JournalKept+9 {
		t.Errorf("a read from 4 returned %d entries from %d to %d, dropped %d; want %d from 10 to %d, dropped 6",
			len(got), got[0], got[len(got)-1], dropped, JournalKept, JournalKept+9)
	}
	got, dropped = j.Since(JournalKept + 8)
	if diff := cmp.Diff([]int{JournalKept + 8, JournalKept + 9}, got); diff != "" || dropped != 0 {
		t.Errorf("a read near the end (-want +got):\n%s, dropped %d", diff, dropped)
	}
	if got, dropped := j.Since(j.Next()); len(got) != 0 || dropped != 0 {
		t.Errorf("a read from the next number returned %v, dropped %d", got, dropped)
	}
	if diff := cmp.Diff([]int{0}, first); diff != "" {
		t.Errorf("a read changed under the appends after it (-want +got):\n%s", diff)
	}
}

// TestJournalSubscribe checks a journal's subscription: nothing before the
// first append; the next number, once, for the appends a subscriber has not
// taken; the next number at once for a subscriber that starts after an
// append; and the channel's close once the context ends.
func TestJournalSubscribe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var j Journal[int]
		ctx, cancel := context.WithCancel(t.Context())
		early := j.Subscribe(ctx)
		if n, ok := taken(early); ok {
			t.Fatalf("a subscriber of an empty journal received %d", n)
		}
		j.Append(1)
		j.Append(2)
		if n, ok := taken(early); !ok || n != 2 {
			t.Errorf("after two appends the subscriber received %d (%t), want the next number, 2", n, ok)
		}
		if n, ok := taken(early); ok {
			t.Errorf("the subscriber received %d past the latest", n)
		}

		late := j.Subscribe(t.Context())
		if n, ok := taken(late); !ok || n != 2 {
			t.Errorf("a late subscriber received %d (%t), want the next number, 2, at once", n, ok)
		}

		cancel()
		synctest.Wait()
		if n, ok := <-early; ok {
			t.Errorf("a subscription received %d after its context ended, want it closed", n)
		}
	})
}
