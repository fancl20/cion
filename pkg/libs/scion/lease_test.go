package scion

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// leased reads the lease.
func leased(t *testing.T, l *Lease) Leased {
	t.Helper()
	got, err := l.Path()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestLeaseKeepsAndMoves checks what keeps and moves a lease: the first read
// leases the best path; a suspect leased path stays; an ejected one is left
// at once, but for another ejected one; a path within the band never takes
// over; a healthy path cheaper beyond the band takes over at the first
// evaluation LeaseSwitchHold after the first that found it so.
func TestLeaseKeepsAndMoves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the first read leased %q, want the best %q", got, f.viaMid.ID)
		}

		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: answered(time.Now(), 5*ms),
			&f.direct: answered(time.Now(), 50*ms),
		})
		time.Sleep(LeaseEvaluation)
		lease.Lost(f.viaMid.ID)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Errorf("a suspect leased path moved the lease to %q", got)
		}

		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: answered(time.Now(), 50*ms),
		})
		time.Sleep(LeaseEvaluation)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("an ejected leased path kept the lease on %q", got)
		}

		slow := answered(time.Now().Add(-time.Minute), 50*ms)
		slow.LastLoss, slow.LostBursts = time.Now(), 2
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: slow,
		})
		time.Sleep(LeaseEvaluation)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("with every path ejected the lease moved to %q", got)
		}

		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: answered(time.Now(), 45*ms),
			&f.direct: answered(time.Now(), 50*ms),
		})
		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatal("a path within the band took the lease")
			}
		}

		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: answered(time.Now(), 5*ms),
			&f.direct: answered(time.Now(), 50*ms),
		})
		for range LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatalf("the cheaper path took the lease before %v", LeaseSwitchHold)
			}
		}
		time.Sleep(LeaseEvaluation)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Errorf("the cheaper path led for %v, the lease still on %q", LeaseSwitchHold, got)
		}
	})
}

// TestLeaseIgnoresUnmeasuredChallengers checks that an unmeasured path whose
// declared cost beats the leased path's beyond the band never takes over.
func TestLeaseIgnoresUnmeasuredChallengers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: answered(time.Now(), 50*time.Millisecond),
		})
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("the first read leased %q, want the healthy %q", got, f.direct.ID)
		}
		f.measure(map[*Candidate]bus.PathRecord{&f.direct: answered(time.Now(), 50*time.Millisecond)})
		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatalf("the unmeasured path %q took the lease", got)
			}
		}
	})
}

// TestLeaseRefreshesTheLeasedPath checks that an evaluation refreshes the
// leased path to its freshest composition: a fresher origination of the
// leased route replaces the one leased.
func TestLeaseRefreshesTheLeasedPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRankFixture(t, time.Minute)
		direct := func(origin time.Time) *segment.PCB {
			return signedLine(t, origin,
				linkHop{ia: iaCore, eg: 11, latency: 40 * time.Millisecond},
				linkHop{ia: iaLeaf, in: 12})
		}
		p := f.provider(t, direct(time.Now().Add(-4*time.Minute)))
		lease := p.Lease(iaDest)
		first := leased(t, lease)
		if _, err := p.DB.Insert(context.Background(), &pathdb.Segment{
			Type: pathdb.SegmentTypeUp,
			PCB:  direct(time.Now().Add(-2 * time.Minute)),
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(LeaseEvaluation)
		got := leased(t, lease)
		if got.ID != first.ID || !PathExpiry(got.Path).After(PathExpiry(first.Path)) {
			t.Errorf("the lease holds %q lapsing at %v, want %q's fresher origination",
				got.ID, PathExpiry(got.Path), first.ID)
		}
	})
}

// TestLeaseLeavesExpiringPath checks that a leased path whose hop fields
// lapse within LeaseExpiryMargin is left for one that lapses later, and that
// with every path lapsing the bootstrap route stands in.
func TestLeaseLeavesExpiringPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRankFixture(t, time.Minute)
		// The direct route was originated an hour after the middle's, so its
		// hop fields lapse an hour later.
		direct := signedLine(t, time.Now().Add(time.Hour),
			linkHop{ia: iaCore, eg: 11, latency: 40 * time.Millisecond},
			linkHop{ia: iaLeaf, in: 12})
		p := f.provider(t, direct, f.upMid)
		route := linePCB(t, time.Now(), iaCore, iaLeaf).ReversePath()
		p.Bootstrap = func(addr.IA) *spath.Decoded { return route }
		lease := p.Lease(iaDest)
		first := leased(t, lease)

		time.Sleep(time.Until(PathExpiry(first.Path).Add(-LeaseExpiryMargin)) + time.Second)
		if got := leased(t, lease).ID; got == first.ID || got == "" {
			t.Errorf("a lapsing leased path kept the lease: %q", got)
		}

		time.Sleep(time.Hour)
		if got := leased(t, lease); got.ID != "" || got.Path != route {
			t.Errorf("with every path lapsing the lease holds %+v, want the bootstrap route", got)
		}
	})
}

// TestLeaseEvaluates checks the lease's reads: the reads within
// LeaseEvaluation share one evaluation; Path reads the lookups' held answers
// without waiting, and Await waits for the destination's lookup while
// nothing composes.
func TestLeaseEvaluates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRankFixture(t, time.Minute)
		p := f.provider(t, f.upDirect)
		var mtx sync.Mutex
		landed, waited, lookups := false, false, 0
		land := make(chan struct{})
		p.Lookup = func(ctx context.Context, dst addr.IA) []*pathdb.Segment {
			mtx.Lock()
			lookups++
			wait := !landed && ctx.Err() == nil
			waited = waited || wait
			mtx.Unlock()
			if wait {
				<-land
			}
			mtx.Lock()
			defer mtx.Unlock()
			if !landed {
				return nil
			}
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: f.down}}
		}
		state := func() (int, bool) {
			mtx.Lock()
			defer mtx.Unlock()
			return lookups, waited
		}
		// Nothing composes to the destination before its down segment lands.
		lease := p.Lease(iaDest)
		for range 3 {
			if _, err := lease.Path(); err == nil {
				t.Fatal("a lease composed before the lookup landed")
			}
		}
		if n, w := state(); n != 1 || w {
			t.Fatalf("lookups = %d, waited %v; want one lookup, not waited on", n, w)
		}

		done := make(chan error)
		go func() {
			_, err := lease.Await(context.Background())
			done <- err
		}()
		synctest.Wait()
		if _, w := state(); !w {
			t.Fatal("Await did not wait for the lookup")
		}
		mtx.Lock()
		landed = true
		mtx.Unlock()
		close(land)
		if err := <-done; err != nil {
			t.Errorf("Await = %v, want the path the lookup landed", err)
		}
	})
}

// TestLeaseRequests checks the entries an evaluation updates while the
// destination is in use: the leased path in use, picked at the last use,
// with its callers' confirmation and doubt, beside its standby; a read
// without use updates none, nor does one RequestLapse past the last use.
func TestLeaseRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		lease := f.p.Lease(iaDest)
		if _, err := lease.Peek(); err != nil {
			t.Fatal(err)
		}
		for r := range f.p.Requests.Latest().All() {
			t.Fatalf("a read without use requested %+v", r)
		}

		used := time.Now()
		id := leased(t, lease).ID
		lease.Delivered(id)
		time.Sleep(LeaseEvaluation)
		lease.Lost(f.direct.ID)
		if _, err := lease.Peek(); err != nil {
			t.Fatal(err)
		}
		entries := map[bus.PathID]bus.PathRequest{}
		for r := range f.p.Requests.Latest().All() {
			entries[r.ID] = r
		}
		inUse, standby := entries[id], entries[f.direct.ID]
		if len(entries) != 2 || inUse.Role != bus.PathInUse || standby.Role != bus.PathStandby {
			t.Fatalf("requests = %v, want the leased path in use and its standby", entries)
		}
		if !inUse.Picked.Equal(used) || !inUse.Confirmed.Equal(used) || !standby.Doubted.After(used) {
			t.Errorf("in use %+v, standby %+v; want picked and confirmed at the use, the standby doubted since",
				inUse, standby)
		}

		time.Sleep(bus.RequestLapse)
		lease.Delivered(id)
		if _, err := lease.Peek(); err != nil {
			t.Fatal(err)
		}
		for r := range f.p.Requests.Latest().All() {
			if r.ID == id && !r.Confirmed.Equal(used) {
				t.Errorf("an evaluation RequestLapse past the last use updated %+v", r)
			}
		}
	})
}

// TestLeaseDropped checks that every caller shares a destination's lease,
// that a lease read within RequestLapse outlives the sweep, and that one
// nothing read for RequestLapse is dropped.
func TestLeaseDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		lease := f.p.Lease(iaDest)
		if f.p.Lease(iaDest) != lease {
			t.Fatal("two calls returned two leases")
		}
		time.Sleep(bus.RequestLapse - time.Minute)
		if _, err := lease.Peek(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		if f.p.Lease(iaDest) != lease {
			t.Fatal("a lease read within RequestLapse was dropped")
		}
		time.Sleep(bus.RequestLapse)
		if f.p.Lease(iaDest) == lease {
			t.Error("a lease nothing read for RequestLapse outlived it")
		}
	})
}
