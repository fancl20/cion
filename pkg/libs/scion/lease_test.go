package scion

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// heartbeats returns a record of n probes of the round trip, a second apart,
// the last sent at at.
func heartbeats(at time.Time, n int, rtt time.Duration) bus.PathRecord {
	r := bus.PathRecord{LastAnswer: at}
	for i := n - 1; i >= 0; i-- {
		r.Samples = append(r.Samples, bus.PathSample{At: at.Add(-time.Duration(i) * time.Second), RTT: rtt})
	}
	return r
}

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
// over; a healthy path cheaper beyond the band takes over only once both
// prices' bounds stand and part by the band, and that verdict has stood for
// LeaseSwitchHold with a fresh probe of each path.
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
		for range 2 * 5 {
			slow.Samples = append(slow.Samples, bus.PathSample{At: time.Now(), Lost: true})
		}
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
			&f.viaMid: heartbeats(time.Now(), ReadingSamples-1, 5*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
		})
		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatal("a cheaper path too few probes bound took the lease")
			}
		}

		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: heartbeats(time.Now(), ReadingSamples, 5*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
		})
		for range LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatal("the cheaper path took the lease without a fresh probe of each path")
			}
		}
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: heartbeats(time.Now(), ReadingSamples, 5*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
		})
		time.Sleep(LeaseEvaluation)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Errorf("the cheaper path stood its hold, the lease still on %q", got)
		}
	})
}

// TestLeaseMovesForATransit checks the band's cap on long paths: a healthy
// path whose price beats the leased one's by a transit's price takes over,
// though within a fifth of it.
func TestLeaseMovesForATransit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: heartbeats(time.Now(), ReadingSamples, 100*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
		})
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the first read leased %q, want the middle's %q", got, f.viaMid.ID)
		}
		// 205ms through the middle prices at 205ms and two transits' charge,
		// 200ms direct at 200ms and one's.
		slow := func() {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: heartbeats(time.Now(), ReadingSamples, 205*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
			})
		}
		slow()
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		time.Sleep(LeaseSwitchHold)
		slow()
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Errorf("the lease holds %q, want the direct route, a transit's price cheaper", got)
		}
	})
}

// TestLeaseHoldsAgainstSpreadProbes checks that a path cheaper by its median
// but whose probes spread, its bounds straddling the leased path's price,
// never takes the lease, however long its probes keep coming.
func TestLeaseHoldsAgainstSpreadProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		spread := func(at time.Time) bus.PathRecord {
			r := bus.PathRecord{LastAnswer: at}
			for i, rtt := range []time.Duration{300 * ms, 10 * ms, 15 * ms, 20 * ms, 25 * ms} {
				r.Samples = append(r.Samples, bus.PathSample{At: at.Add(time.Duration(i-4) * time.Second), RTT: rtt})
			}
			return r
		}
		measure := func() {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: spread(time.Now()),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 60*ms),
			})
		}
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 60*ms),
		})
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("the first read leased %q, want the direct route %q", got, f.direct.ID)
		}
		for range 6 * LeaseSwitchHold / LeaseEvaluation {
			measure()
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatal("a path whose bounds straddle the leased path's price took the lease")
			}
		}
	})
}

// TestLeaseHoldEndsWithItsVerdict checks that a verdict that lapses ends
// the hold: a cheaper path whose bounds part from the leased path's starts
// it, a spread of its probes ends it, and once its bounds part again the
// hold starts over, however long ago the first began.
func TestLeaseHoldEndsWithItsVerdict(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		measure := func(mid bus.PathRecord) {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: mid,
				&f.direct: heartbeats(time.Now(), ReadingSamples, 60*ms),
			})
		}
		spread := func(at time.Time) bus.PathRecord {
			r := heartbeats(at, ReadingSamples, 10*ms)
			r.Samples[0].RTT = 300 * ms
			return r
		}
		measure(ejectedAt(time.Now()))
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("the first read leased %q, want the direct route %q", got, f.direct.ID)
		}
		measure(heartbeats(time.Now(), ReadingSamples, 10*ms))
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		measure(spread(time.Now()))
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		time.Sleep(LeaseSwitchHold)
		measure(heartbeats(time.Now(), ReadingSamples, 10*ms))
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatal("the cheaper path took the lease on a hold its lapsed verdict began")
		}
		time.Sleep(LeaseSwitchHold)
		measure(heartbeats(time.Now(), ReadingSamples, 10*ms))
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Errorf("the cheaper path stood its new hold, the lease still on %q", got)
		}
	})
}

// TestLeaseRecordsItsMoves checks the record each change of a lease's path
// appends to the journal of changes: the first read's, an ejection's, and a
// cheaper path's beside the band and both prices' estimates.
func TestLeaseRecordsItsMoves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		f.p.Changes = new(bus.Journal[bus.Change])
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: heartbeats(time.Now(), ReadingSamples, 100*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
		})
		lease := f.p.Lease(iaDest)
		leased(t, lease)
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
		})
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		recovered := func() {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: heartbeats(time.Now(), ReadingSamples, 10*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
			})
		}
		recovered()
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		time.Sleep(LeaseSwitchHold)
		recovered()
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the lease holds %q, want the recovered middle's %q", got, f.viaMid.ID)
		}

		changes, _ := f.p.Changes.Since(0)
		type move struct{ from, to, why string }
		var records []evidence.Record
		var got []move
		for _, c := range changes {
			r, ok := c.(evidence.Record)
			if !ok || r.Change != LeaseMoved || r.Subject != iaDest.String() {
				t.Errorf("change %+v is no record of the lease's move", c)
				continue
			}
			records = append(records, r)
			got = append(got, move{r.From, r.To, r.Why})
		}
		mid, direct := string(f.viaMid.ID), string(f.direct.ID)
		want := []move{{"", mid, whyFirst}, {mid, direct, whyEjected}, {direct, mid, whyCheaper}}
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(move{})); diff != "" {
			t.Fatalf("records (-want +got):\n%s", diff)
		}
		cheaper := records[2]
		from, to := cheaper.Weighed[0], cheaper.Weighed[1]
		// The direct route prices its 200ms beside a transit, the middle's its
		// 10ms beside two.
		ownPrice, midPrice := 200*ms+2*TransitPenalty, 10*ms+4*TransitPenalty
		if cheaper.Line != Band(midPrice, ownPrice) || from.Name != "from" || to.Name != "to" ||
			from.Value != ownPrice || from.Lo != ownPrice || to.Value != midPrice || to.Hi != midPrice ||
			to.Answered != ReadingSamples {
			t.Errorf("the cheaper path's record weighed %+v and %+v over %v", from, to, cheaper.Line)
		}
	})
}

// TestLeaseIdleTakesACheaperPath checks an idle lease: a healthy path cheaper
// beyond the band that one probe prices never takes a lease in use, but takes
// the lease at once at a read that finds it unused for bus.RequestLapse, and
// the move's record names both prices' estimates; a lease no caller ever
// used takes such a path at once too.
func TestLeaseIdleTakesACheaperPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		f.p.Changes = new(bus.Journal[bus.Change])
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: ejectedAt(time.Now()),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
		})
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("the first read leased %q, want the direct %q", got, f.direct.ID)
		}
		recovered := func(f measuredFixture) {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: answered(time.Now(), 10*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
			})
		}
		recovered(f)
		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatalf("a path one probe prices took the lease in use, now on %q", got)
			}
		}

		time.Sleep(bus.RequestLapse)
		recovered(f)
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the idle lease kept %q, want the cheaper %q at once", got, f.viaMid.ID)
		}
		changes, _ := f.p.Changes.Since(0)
		r, ok := changes[len(changes)-1].(evidence.Record)
		if !ok || r.Why != whyIdle || r.From != string(f.direct.ID) || r.To != string(f.viaMid.ID) || r.Line == 0 ||
			len(r.Weighed) != 2 || r.Weighed[0].Answered != ReadingSamples || r.Weighed[1].Answered != 1 {
			t.Errorf("the idle move recorded %+v", changes[len(changes)-1])
		}

		g := newMeasuredFixture(t, time.Minute)
		g.measure(map[*Candidate]bus.PathRecord{
			&g.viaMid: ejectedAt(time.Now()),
			&g.direct: heartbeats(time.Now(), ReadingSamples, 200*ms),
		})
		unused := g.p.Lease(iaDest)
		if got, err := unused.Peek(); err != nil || got.ID != g.direct.ID {
			t.Fatalf("the unused lease's first read leased %q (%v), want the direct %q", got.ID, err, g.direct.ID)
		}
		recovered(g)
		time.Sleep(LeaseEvaluation)
		if got, err := unused.Peek(); err != nil || got.ID != g.viaMid.ID {
			t.Errorf("a lease no caller used kept %q (%v), want the cheaper %q at once", got.ID, err, g.viaMid.ID)
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

// TestLeaseComparesPricesWithinTheSpan checks that a lease compares the
// prices of ReadingSpan: a path fast only in probes past the span never takes
// the lease, and a path left behind, slow only in probes past the span, takes
// it back once its probes within the span beat the leased path's beyond the
// band.
func TestLeaseComparesPricesWithinTheSpan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		probes := func(at time.Time, n int, rtt time.Duration) []bus.PathSample {
			return slices.Repeat([]bus.PathSample{{At: at, RTT: rtt}}, n)
		}
		record := func(samples ...[]bus.PathSample) bus.PathRecord {
			r := bus.PathRecord{Samples: slices.Concat(samples...)}
			r.LastAnswer = r.Samples[len(r.Samples)-1].At
			return r
		}

		now := time.Now()
		f.measure(map[*Candidate]bus.PathRecord{
			&f.direct: record(probes(now, bus.PathSamples, 50*ms)),
			&f.viaMid: record(probes(now, 1, 200*ms)),
		})
		lease := f.p.Lease(iaDest)
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Fatalf("the first read leased %q, want the direct route %q", got, f.direct.ID)
		}
		f.measure(map[*Candidate]bus.PathRecord{
			&f.direct: record(probes(now, bus.PathSamples, 50*ms)),
			&f.viaMid: record(probes(now.Add(-2*ReadingSpan), bus.PathSamples-1, 5*ms), probes(now, 1, 200*ms)),
		})
		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatal("a path fast only past the span took the lease")
			}
		}

		// Each phase measures twice, so that a fresh probe of each path
		// answers within the hold.
		slowDirect := func() {
			now := time.Now()
			f.measure(map[*Candidate]bus.PathRecord{
				&f.direct: record(probes(now, bus.PathSamples, 100*ms)),
				&f.viaMid: record(probes(now, bus.PathSamples, 10*ms)),
			})
		}
		slowDirect()
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		time.Sleep(LeaseSwitchHold)
		slowDirect()
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the lease holds %q, want the middle's %q", got, f.viaMid.ID)
		}
		fastAgain := func() {
			now := time.Now()
			f.measure(map[*Candidate]bus.PathRecord{
				&f.direct: record(probes(now.Add(-2*ReadingSpan), 15, 300*ms), probes(now, 5, 10*ms)),
				&f.viaMid: record(probes(now, bus.PathSamples, 40*ms)),
			})
		}
		fastAgain()
		time.Sleep(LeaseEvaluation)
		leased(t, lease)
		time.Sleep(LeaseSwitchHold)
		fastAgain()
		if got := leased(t, lease).ID; got != f.direct.ID {
			t.Errorf("a path slow only past the span stayed behind, the lease on %q", got)
		}
	})
}

// TestLeaseRefreshesTheLeasedPath checks that an evaluation refreshes the
// leased path to its freshest composition: a fresher origination of the
// leased route replaces the one leased, and the lease names its segment.
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
		fresher := direct(time.Now().Add(-2 * time.Minute))
		if _, err := p.DB.Insert(context.Background(), &pathdb.Segment{
			Type: pathdb.SegmentTypeUp,
			PCB:  fresher,
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(LeaseEvaluation)
		got := leased(t, lease)
		if got.ID != first.ID || !PathExpiry(got.Path).After(PathExpiry(first.Path)) {
			t.Errorf("the lease holds %q lapsing at %v, want %q's fresher origination",
				got.ID, PathExpiry(got.Path), first.ID)
		}
		if !slices.ContainsFunc(got.Segments, func(s *pathdb.Segment) bool { return s.PCB == fresher }) {
			t.Error("the lease does not name the fresher origination's segment")
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

// TestLeaseRequestsItsChallenger checks that a lease measures the path it
// would move to: an unmeasured path ranking above the leased one, sharing a
// link with it so that another path is the disjoint standby, is requested
// weighed beside that one.
func TestLeaseRequestsItsChallenger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		// A second branch through the middle, over a link to the core of
		// its own, shares the leaf's link to the middle with the first.
		second := signedLine(t, time.Now(),
			linkHop{ia: iaCore, eg: 26, latency: 6 * time.Millisecond},
			linkHop{ia: iaMid, in: 25, eg: 23, latency: 5 * time.Millisecond},
			linkHop{ia: iaLeaf, in: 24})
		p := f.provider(t, f.upDirect, f.upMid, second)
		p.Measurements = new(bus.Topic[bus.PathMeasurements])
		p.Requests = new(bus.Topic[bus.PathRequests])
		candidates, err := p.Enumerate(context.Background(), iaCore)
		if err != nil {
			t.Fatal(err)
		}
		branch := map[*segment.PCB]*Candidate{}
		for i := range candidates {
			branch[candidates[i].Segments[0].PCB] = &candidates[i]
		}
		direct, first, viaSecond := branch[f.upDirect], branch[f.upMid], branch[second]
		measure := func(records map[*Candidate]bus.PathRecord) {
			m := make(map[bus.PathID]bus.PathRecord, len(records))
			for c, r := range records {
				r.Links = c.Crossed
				m[c.ID] = r
			}
			p.Measurements.Publish(bus.NewPathMeasurements(m))
		}
		measure(map[*Candidate]bus.PathRecord{
			viaSecond: answered(time.Now(), 20*time.Millisecond),
			first:     ejectedAt(time.Now()),
		})
		lease := p.Lease(iaCore)
		if got := leased(t, lease).ID; got != viaSecond.ID {
			t.Fatalf("the lease took %q, want the second middle branch %q", got, viaSecond.ID)
		}

		// The second branch slows and the first's record is gone: the first
		// ranks above the leased path by its declared cost, unmeasured.
		measure(map[*Candidate]bus.PathRecord{viaSecond: answered(time.Now(), 80*time.Millisecond)})
		time.Sleep(LeaseEvaluation)
		if got := leased(t, lease).ID; got != viaSecond.ID {
			t.Fatalf("the unmeasured first branch took the lease to %q", got)
		}
		roles := map[bus.PathID]bus.PathRole{}
		for r := range p.Requests.Latest().All() {
			roles[r.ID] = r.Role
		}
		want := map[bus.PathID]bus.PathRole{
			viaSecond.ID: bus.PathInUse, direct.ID: bus.PathStandby, first.ID: bus.PathWeighed,
		}
		if diff := cmp.Diff(want, roles); diff != "" {
			t.Errorf("requests (-want +got):\n%s", diff)
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

// marked returns a record of n probes of the round trip, a second apart, the
// last sent at at, each answered marked.
func marked(at time.Time, n int, rtt time.Duration) bus.PathRecord {
	r := heartbeats(at, n, rtt)
	for i := range r.Samples {
		r.Samples[i].Marked = true
	}
	return r
}

// TestLeaseLeavesAHotPath checks a lease on a hot path: it stays while every
// path is hot; once a path that is not hot serves, it leaves for it within
// LeaseHotHold, slower though that path is; it takes no hot path back,
// however cheaper; and once the path cools, it returns to it by the band as
// it takes any cheaper path.
func TestLeaseLeavesAHotPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		lease := f.p.Lease(iaDest)
		f.measure(map[*Candidate]bus.PathRecord{
			&f.viaMid: heartbeats(time.Now(), ReadingSamples, 5*ms),
			&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
		})
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the first read leased %q, want the cheaper %q", got, f.viaMid.ID)
		}

		for range 2 * LeaseHotHold / LeaseEvaluation {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: marked(time.Now(), ReadingSamples, 5*ms),
				&f.direct: marked(time.Now(), ReadingSamples, 50*ms),
			})
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.viaMid.ID {
				t.Fatalf("with every path hot the lease moved to %q", got)
			}
		}

		left := false
		for range LeaseHotHold/LeaseEvaluation + 1 {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: marked(time.Now(), ReadingSamples, 5*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
			})
			time.Sleep(LeaseEvaluation)
			if leased(t, lease).ID == f.direct.ID {
				left = true
				break
			}
		}
		if !left {
			t.Fatalf("the lease stayed on the hot path %v past its hold", LeaseHotHold)
		}

		for range 3 * LeaseSwitchHold / LeaseEvaluation {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: marked(time.Now(), ReadingSamples, 5*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
			})
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.direct.ID {
				t.Fatalf("the cheaper hot path took the lease back to %q", got)
			}
		}

		returned := false
		for range 2*LeaseSwitchHold/LeaseEvaluation + 1 {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: heartbeats(time.Now(), ReadingSamples, 5*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
			})
			time.Sleep(LeaseEvaluation)
			if leased(t, lease).ID == f.viaMid.ID {
				returned = true
				break
			}
		}
		if !returned {
			t.Error("the cheaper path cooled, but the lease never returned to it")
		}
	})
}

// TestLeaseLeavesAPathItsArrivalsMark checks a lease whose destination's
// datagrams come back marked: the path it holds reads hot, so it leaves for
// the fastest healthy path that is not hot within LeaseHotHold, though its
// probes' answers come back unmarked; marks on fewer than half of them move
// nothing.
func TestLeaseLeavesAPathItsArrivalsMark(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := time.Millisecond
		f := newMeasuredFixture(t, time.Minute)
		var mu sync.Mutex
		arrived, marked := 0, 0
		f.p.Arrivals = func(addr.IA, time.Time) (int, int) {
			mu.Lock()
			defer mu.Unlock()
			return arrived, marked
		}
		set := func(a, m int) {
			mu.Lock()
			defer mu.Unlock()
			arrived, marked = a, m
		}
		lease := f.p.Lease(iaDest)
		measure := func() {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: heartbeats(time.Now(), ReadingSamples, 5*ms),
				&f.direct: heartbeats(time.Now(), ReadingSamples, 50*ms),
			})
		}
		measure()
		if got := leased(t, lease).ID; got != f.viaMid.ID {
			t.Fatalf("the first read leased %q, want the cheaper %q", got, f.viaMid.ID)
		}

		set(100, 40)
		for range 2 * LeaseHotHold / LeaseEvaluation {
			measure()
			time.Sleep(LeaseEvaluation)
			if got := leased(t, lease).ID; got != f.viaMid.ID {
				t.Fatalf("marks on fewer than half the arrivals moved the lease to %q", got)
			}
		}

		set(100, 80)
		left := false
		for range LeaseHotHold/LeaseEvaluation + 1 {
			measure()
			time.Sleep(LeaseEvaluation)
			if leased(t, lease).ID == f.direct.ID {
				left = true
				break
			}
		}
		if !left {
			t.Errorf("the lease stayed on the path its arrivals mark %v past its hold", LeaseHotHold)
		}
	})
}
