package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
)

// lookupFixture is a lookup service over a path database with one up
// segment, and a recording fetch.
type lookupFixture struct {
	db     pathdb.DB
	lookup *LookupService
	fetch  *recordingFetch
	now    time.Time
}

// fetchCall records one fetch: the peer it dialed and the question asked.
type fetchCall struct {
	peer *scion.Addr
	src  addr.IA
	dst  addr.IA
}

// recordingFetch records fetches and answers each with the canned segments
// of the core it asks, by type. A core in errFor fails its fetches with the
// error it maps to, and a fetch from a core in silent waits until the core's
// channel closes or the fetch's deadline passes — a core gone silent. peak
// is the most fetches ever in flight at once.
type recordingFetch struct {
	mtx     sync.Mutex
	calls   []fetchCall
	errFor  map[addr.IA]error
	silent  map[addr.IA]chan struct{}
	down    map[addr.IA][]*cppb.PathSegment
	core    map[addr.IA][]*cppb.PathSegment
	running int
	peak    int
}

func (f *recordingFetch) Fetch(
	ctx context.Context, peer *scion.Addr, src, dst addr.IA) (*cppb.SegmentsResponse, error) {

	f.mtx.Lock()
	f.calls = append(f.calls, fetchCall{peer: peer, src: src, dst: dst})
	f.running++
	f.peak = max(f.peak, f.running)
	silent := f.silent[peer.IA]
	f.mtx.Unlock()
	if silent != nil {
		select {
		case <-silent:
		case <-ctx.Done():
		}
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.running--
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.errFor[peer.IA]; err != nil {
		return nil, err
	}
	resp := &cppb.SegmentsResponse{Segments: map[int32]*cppb.SegmentsResponse_Segments{}}
	// The core answers only with segments that reach the requested
	// destination; the canned segments stand in for those reaching iaLineC
	// and the founding core.
	if dst.Equal(iaLineC) || dst.Equal(coreIATest) {
		resp.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)] =
			&cppb.SegmentsResponse_Segments{Segments: f.down[peer.IA]}
		resp.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_CORE)] =
			&cppb.SegmentsResponse_Segments{Segments: f.core[peer.IA]}
	}
	return resp, nil
}

// count returns how many fetches were made.
func (f *recordingFetch) count() int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return len(f.calls)
}

// asked returns the fetches made.
func (f *recordingFetch) asked() []fetchCall {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return slices.Clone(f.calls)
}

// fail makes the core's fetches fail with err; nil lets them answer.
func (f *recordingFetch) fail(core addr.IA, err error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.errFor[core] = err
}

// answerDown sets the core's canned down segments.
func (f *recordingFetch) answerDown(core addr.IA, segs ...*cppb.PathSegment) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.down[core] = segs
}

// silence makes the core silent and returns the release that lets it
// answer again, its fetches in flight included.
func (f *recordingFetch) silence(core addr.IA) func() {
	ch := make(chan struct{})
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.silent[core] = ch
	return func() {
		f.mtx.Lock()
		defer f.mtx.Unlock()
		delete(f.silent, core)
		close(ch)
	}
}

// newLookupFixture serves lookups over a path database holding one up segment
// from the core and a recording fetch answering for the core and the fellow
// core; edit adjusts the configuration before the service is built.
func newLookupFixture(t *testing.T, edit ...func(*LookupConfig)) *lookupFixture {
	t.Helper()
	db, err := pathdbbbolt.New(filepath.Join(t.TempDir(), "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	up := terminatedSegment(t, coreIATest, nodeIATest, 1, now)
	if _, err := db.Insert(context.Background(), up); err != nil {
		t.Fatal(err)
	}
	fetch := &recordingFetch{
		errFor: make(map[addr.IA]error),
		silent: make(map[addr.IA]chan struct{}),
		down: map[addr.IA][]*cppb.PathSegment{
			coreIATest:  {terminatedSegment(t, coreIATest, iaLineC, 2, now).PCB.PB},
			iaCore2Test: {terminatedSegment(t, iaCore2Test, iaLineC, 5, now).PCB.PB},
		},
		core: map[addr.IA][]*cppb.PathSegment{
			coreIATest:  {terminatedSegment(t, coreIATest, iaLineC, 3, now).PCB.PB},
			iaCore2Test: {terminatedSegment(t, iaCore2Test, iaLineC, 6, now).PCB.PB},
		},
	}
	cfg := LookupConfig{
		IA:    nodeIATest,
		DB:    db,
		Cores: func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest} },
		Fetch: fetch.Fetch,
	}
	for _, e := range edit {
		e(&cfg)
	}
	return &lookupFixture{db: db, lookup: NewLookupService(cfg), fetch: fetch, now: now}
}

// twoCores lists the fellow core after the founder as the TRC's cores.
func twoCores(cfg *LookupConfig) {
	cfg.Cores = func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest, iaCore2Test} }
}

// reachCore2 stores an up segment from the fellow core, which makes it
// reachable too: the core expansion's source set.
func (fx *lookupFixture) reachCore2(t *testing.T) {
	t.Helper()
	up := terminatedSegment(t, iaCore2Test, nodeIATest, 4, fx.now)
	if _, err := fx.db.Insert(context.Background(), up); err != nil {
		t.Fatal(err)
	}
}

// segIDs returns the segments' IDs, in order.
func segIDs(segs []*pathdb.Segment) []uint16 {
	ids := make([]uint16, 0, len(segs))
	for _, seg := range segs {
		ids = append(ids, seg.PCB.ID())
	}
	return ids
}

// terminatedSegment builds a signed [core, end] segment fixture.
func terminatedSegment(
	t *testing.T, core, end addr.IA, id uint16, now time.Time) *pathdb.Segment {

	t.Helper()
	f := newBeaconFixture(t)
	pcb, err := segment.PCBWithID(now, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), core, segment.EntryOptions{
		Next: end, EgressIfID: 1,
	}, macFactory(), f.engines[core]); err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), end, segment.EntryOptions{
		IngressIfID: 1,
	}, macFactory(), f.engines[end]); err != nil {
		t.Fatal(err)
	}
	seg, err := pathdb.NewSegment(pathdb.SegmentTypeUp, pcb.PB)
	if err != nil {
		t.Fatal(err)
	}
	return seg
}

// TestLookupSourceHandler checks the source-AS handler (Section 4.2.2): up
// segments from the local database, down segments fetched from the core with
// the source wildcard expanded to the core AS of the destination ISD.
func TestLookupSourceHandler(t *testing.T) {
	fx := newLookupFixture(t)

	// Up segments: served from the local database, no fetch.
	resp, err := fx.lookup.Segments(context.Background(),
		connect.NewRequest(&cppb.SegmentsRequest{
			SrcIsdAs: uint64(nodeIATest),
			DstIsdAs: uint64(coreIATest),
		}))
	if err != nil {
		t.Fatal(err)
	}
	ups := resp.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_UP)]
	if ups == nil || len(ups.Segments) != 1 {
		t.Fatalf("up segments = %v, want one from the local database", ups)
	}
	if got := len(fx.fetch.calls); got != 0 {
		t.Errorf("fetches = %d, want 0 for up segments", got)
	}

	// Down segments: fetched from the core with the core as the source.
	resp, err = fx.lookup.Segments(context.Background(),
		connect.NewRequest(&cppb.SegmentsRequest{
			SrcIsdAs: uint64(addr.MustIAFrom(iaLineC.ISD(), 0)),
			DstIsdAs: uint64(iaLineC),
		}))
	if err != nil {
		t.Fatal(err)
	}
	downs := resp.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)]
	if downs == nil || len(downs.Segments) != 1 {
		t.Fatalf("down segments = %v, want one fetched from the core", downs)
	}
	fx.fetch.mtx.Lock()
	if len(fx.fetch.calls) != 1 || !fx.fetch.calls[0].src.Equal(coreIATest) {
		t.Errorf("fetch calls = %v, want one expanded to the core", fx.fetch.calls)
	}
	fx.fetch.mtx.Unlock()
}

// TestLookupRefreshesBehind checks the answer's refresh: inside
// answerRefresh a lookup serves the core's answer without asking the core;
// past it, a lookup serves the answer at once and refreshes it behind the
// lookup, and the refresh's answer replaces it. The core stays silent until
// released, so a lookup that waited on the refresh would find the bubble's
// clock moved.
func TestLookupRefreshesBehind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		down := func() []uint16 { return segIDs(fx.lookup.Down(ctx, iaLineC)) }
		if got := down(); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments = %v, want the core's [2]", got)
		}
		time.Sleep(answerRefresh - time.Second)
		if got := down(); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments inside answerRefresh = %v, want the held [2]", got)
		}
		if got := fx.fetch.count(); got != 1 {
			t.Errorf("fetches inside answerRefresh = %d, want 1", got)
		}

		// The core's answer changes, and the held one grows past
		// answerRefresh.
		fx.fetch.answerDown(coreIATest, terminatedSegment(t, coreIATest, iaLineC, 9, time.Now()).PCB.PB)
		release := fx.fetch.silence(coreIATest)
		time.Sleep(time.Second)
		start := time.Now()
		if got := down(); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments past answerRefresh = %v, want the held [2]", got)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("lookup past answerRefresh waited %v, want the answer served at once", waited)
		}
		synctest.Wait()
		if got := fx.fetch.count(); got != 2 {
			t.Errorf("fetches past answerRefresh = %d, want 2 (the refresh behind the lookup)", got)
		}

		// The refresh lands; its answer replaces the held one.
		release()
		synctest.Wait()
		if got := down(); !slices.Equal(got, []uint16{9}) {
			t.Fatalf("down segments after the refresh = %v, want its [9]", got)
		}
		if got := fx.fetch.count(); got != 2 {
			t.Errorf("fetches after the refresh = %d, want 2", got)
		}
	})
}

// TestLookupHoldsAnswerUntilExpiry checks the answer's window: a core's
// answer serves, its refreshes failing, until the earliest expiration of its
// segments, and not from then on.
func TestLookupHoldsAnswerUntilExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		downs := fx.lookup.Down(ctx, iaLineC)
		if len(downs) != 1 {
			t.Fatalf("down segments = %d, want 1", len(downs))
		}
		expiry := downs[0].Expiration()
		fx.fetch.fail(coreIATest, errors.New("core unreachable"))

		time.Sleep(time.Until(expiry) - time.Nanosecond)
		if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments a nanosecond before the expiry = %v, want the held [2]", got)
		}
		synctest.Wait()
		time.Sleep(time.Nanosecond)
		if got := fx.lookup.Down(ctx, iaLineC); len(got) != 0 {
			t.Fatalf("down segments at the expiry = %d, want none", len(got))
		}
		if got := fx.fetch.count(); got != 2 {
			t.Errorf("fetches = %d, want 2 (the core set aside by the failed refresh)", got)
		}
	})
}

// TestLookupKeysByType checks the answers' key widened by the segment type:
// one core-and-destination pair asked under two types answers each kind from
// its own entry, never the other's.
func TestLookupKeysByType(t *testing.T) {
	fx := newLookupFixture(t)
	ctx := context.Background()
	ask := func(kind pathdb.SegmentType) []uint16 {
		return segIDs(slices.Concat(fx.lookup.ask(ctx, []addr.IA{coreIATest}, iaLineC, kind)...))
	}

	if got := ask(pathdb.SegmentTypeDown); !slices.Equal(got, []uint16{2}) {
		t.Fatalf("down segments = %v, want the canned down segment [2]", got)
	}
	if got := ask(pathdb.SegmentTypeCore); !slices.Equal(got, []uint16{3}) {
		t.Fatalf("core segments = %v, want the canned core segment [3]", got)
	}

	// Both kinds serve from their own entries: no further fetch.
	ask(pathdb.SegmentTypeDown)
	ask(pathdb.SegmentTypeCore)
	if got := fx.fetch.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 (each kind answered from its own entry)", got)
	}
}

// TestLookupRefreshesEachKindAlone checks the answers' windows per kind: a
// down answer past answerRefresh refreshes alone while the core answer,
// fetched later, serves from its own entry however many reads pass; the
// down refresh's answer replaces the down answer alone; and neither kind
// ever answers the other's question.
func TestLookupRefreshesEachKindAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		ask := func(kind pathdb.SegmentType) []uint16 {
			return segIDs(slices.Concat(fx.lookup.ask(ctx, []addr.IA{coreIATest}, iaLineC, kind)...))
		}

		ask(pathdb.SegmentTypeDown)
		time.Sleep(answerRefresh / 2)
		ask(pathdb.SegmentTypeCore)

		// The down answer grows past answerRefresh and refreshes behind the
		// read; the core answer, half as old, does not.
		fx.fetch.answerDown(coreIATest, terminatedSegment(t, coreIATest, iaLineC, 9, time.Now()).PCB.PB)
		time.Sleep(answerRefresh / 2)
		if got := ask(pathdb.SegmentTypeDown); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments past answerRefresh = %v, want the held [2]", got)
		}
		synctest.Wait()
		for range 5 {
			if got := ask(pathdb.SegmentTypeCore); !slices.Equal(got, []uint16{3}) {
				t.Fatalf("core segments = %v, want the held [3]", got)
			}
			if got := ask(pathdb.SegmentTypeDown); !slices.Equal(got, []uint16{9}) {
				t.Fatalf("down segments = %v, want the refresh's [9]", got)
			}
		}
		if got := fx.fetch.count(); got != 3 {
			t.Errorf("fetches = %d, want 3 (each kind once, then the down refresh)", got)
		}

		// Half a window on, the core answer refreshes alone.
		time.Sleep(answerRefresh / 2)
		ask(pathdb.SegmentTypeCore)
		ask(pathdb.SegmentTypeDown)
		synctest.Wait()
		if got := fx.fetch.count(); got != 4 {
			t.Errorf("fetches = %d, want 4 (then the core refresh)", got)
		}
	})
}

// TestLookupEmptyAnswerNotHeld checks the empty-answer seam: a fetch that
// answers nothing is not held — the registration it raced can land any
// moment, so the next request asks the core again and sees it.
func TestLookupEmptyAnswerNotHeld(t *testing.T) {
	fx := newLookupFixture(t)
	ctx := context.Background()

	// The core holds no down segment for the middle node yet.
	fx.fetch.mtx.Lock()
	canned := fx.fetch.down[coreIATest]
	fx.fetch.mtx.Unlock()
	fx.fetch.answerDown(coreIATest)
	for range 2 {
		if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 0 {
			t.Fatalf("down segments = %d, want none while the core holds none", len(segs))
		}
	}
	if got := fx.fetch.count(); got != 2 {
		t.Errorf("fetches after empty answers = %d, want 2 (an empty answer is not held)", got)
	}

	// The registration lands; the very next request sees it.
	fx.fetch.answerDown(coreIATest, canned...)
	if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
		t.Fatalf("down segments after the registration = %d, want 1", len(segs))
	}
}

// TestLookupEmptyRefreshRemovesAnswer checks an empty refresh: the core
// holds nothing for the destination now, so its last answer leaves, and the
// next lookup asks the core again.
func TestLookupEmptyRefreshRemovesAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		down := func() []uint16 { return segIDs(fx.lookup.Down(ctx, iaLineC)) }
		down()
		fx.fetch.mtx.Lock()
		canned := fx.fetch.down[coreIATest]
		fx.fetch.mtx.Unlock()

		// The core answers its refresh with nothing.
		fx.fetch.answerDown(coreIATest)
		time.Sleep(answerRefresh)
		if got := down(); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments past answerRefresh = %v, want the held [2]", got)
		}
		synctest.Wait()
		if got := down(); len(got) != 0 {
			t.Fatalf("down segments after the empty refresh = %v, want none", got)
		}
		if got := fx.fetch.count(); got != 3 {
			t.Errorf("fetches = %d, want 3 (the first, the empty refresh, the next lookup's)", got)
		}

		// The registration lands; the next lookup sees it.
		fx.fetch.answerDown(coreIATest, canned...)
		if got := down(); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments after the registration = %v, want [2]", got)
		}
	})
}

// TestLookupDownSkipsCoreDestinations checks the down lookup's core
// destination: a non-core asks the core nothing toward a core — no down
// segment ends there, and the handler answers a core destination with core
// segments alone — while a non-core destination is fetched as ever.
func TestLookupDownSkipsCoreDestinations(t *testing.T) {
	fx := newLookupFixture(t)
	ctx := context.Background()

	for range 2 {
		if segs := fx.lookup.Down(ctx, coreIATest); len(segs) != 0 {
			t.Fatalf("down segments toward the core = %d, want none", len(segs))
		}
	}
	fx.fetch.mtx.Lock()
	if got := len(fx.fetch.calls); got != 0 {
		t.Errorf("fetches toward the core = %d, want 0", got)
	}
	fx.fetch.mtx.Unlock()

	if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
		t.Fatalf("down segments toward a non-core = %d, want the fetched 1", len(segs))
	}
	fx.fetch.mtx.Lock()
	defer fx.fetch.mtx.Unlock()
	if len(fx.fetch.calls) != 1 || !fx.fetch.calls[0].dst.Equal(iaLineC) {
		t.Errorf("fetch calls = %v, want the one toward the non-core", fx.fetch.calls)
	}
}

// TestLookupFetchesAskTheCoreTheyName checks the fetch's per-core send: the
// down expansion asks each core of the destination ISD at that core's own
// address with itself as the source, the core expansion each reachable
// core, and a core that fails to answer answers nothing while the other
// core's segments are still served, the failing core asked again once its
// retry is due.
func TestLookupFetchesAskTheCoreTheyName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t, twoCores)
		fx.reachCore2(t)
		ctx := context.Background()

		// One core fails to answer; the other's answer is served regardless.
		fx.fetch.fail(iaCore2Test, errors.New("core unreachable"))
		if downs := fx.lookup.Down(ctx, iaLineC); len(downs) != 1 {
			t.Fatalf("down segments under one failed fetch = %d, want the other core's 1", len(downs))
		}
		synctest.Wait()
		fx.fetch.fail(iaCore2Test, nil)

		// The down expansion: one request per core of the destination ISD,
		// each at its own address and with itself as the source — the
		// handler's check that the source be this core matches everywhere
		// they land. The failed core is set aside: a lookup asks it again,
		// behind the other core's answer, once its retry is due.
		if downs := fx.lookup.Down(ctx, iaLineC); len(downs) != 1 {
			t.Fatalf("down segments with the failed core set aside = %d, want the other core's 1",
				len(downs))
		}
		time.Sleep(SendTimeout)
		fx.lookup.Down(ctx, iaLineC)
		synctest.Wait()
		if downs := fx.lookup.Down(ctx, iaLineC); len(downs) != 2 {
			t.Fatalf("down segments = %d, want both cores' after the retry", len(downs))
		}
		calls := fx.fetch.asked()
		if len(calls) != 3 {
			t.Fatalf("fetch calls = %d, want 3 (two of the failed core, one held)", len(calls))
		}
		asked := make(map[addr.IA]bool)
		for _, call := range calls {
			if !call.peer.IA.Equal(call.src) {
				t.Errorf("fetch to %v = source %v, want the asked core", call.peer.IA, call.src)
			}
			if !call.peer.IA.Equal(coreIATest) && !call.peer.IA.Equal(iaCore2Test) {
				t.Errorf("fetch to %v, want a core of the destination ISD", call.peer.IA)
			}
			if call.peer.Service != addr.SvcCS {
				t.Errorf("fetch to %v = service %#x, want the CS service",
					call.peer.IA, uint16(call.peer.Service))
			}
			asked[call.peer.IA] = true
		}
		if !asked[coreIATest] || !asked[iaCore2Test] {
			t.Fatalf("cores asked = %v, want each core of the destination ISD", asked)
		}

		// The core expansion: each reachable core asked the same way.
		fx.fetch.mtx.Lock()
		fx.fetch.calls = nil
		fx.fetch.mtx.Unlock()
		if _, err := fx.lookup.Segments(ctx, connect.NewRequest(&cppb.SegmentsRequest{
			DstIsdAs: uint64(coreIATest),
		})); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		reached := make(map[addr.IA]bool)
		for _, call := range fx.fetch.asked() {
			if !call.dst.Equal(coreIATest) {
				t.Errorf("core-expansion fetch = dst %v, want the core destination", call.dst)
			}
			if !call.peer.IA.Equal(call.src) {
				t.Errorf("fetch to %v = source %v, want the asked core", call.peer.IA, call.src)
			}
			reached[call.peer.IA] = true
		}
		if !reached[coreIATest] || !reached[iaCore2Test] {
			t.Fatalf("cores asked by the core expansion = %v, want each reachable core", reached)
		}
	})
}

// TestLookupFailedRefreshSetsCoreAside checks a failed refresh: the core's
// last answer keeps serving, and no refresh asks the core until its retry is
// due, the first within SendTimeout; an answer clears the set-aside, so the
// next failure sets the core aside for the first retry's delay again.
func TestLookupFailedRefreshSetsCoreAside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		failure := errors.New("core unreachable")
		lookup := func(want ...uint16) {
			t.Helper()
			if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, want) {
				t.Fatalf("down segments = %v, want %v", got, want)
			}
			synctest.Wait()
		}
		lookup(2)

		// The answer grows past answerRefresh, and its refresh fails: the
		// answer keeps serving, and the core is set aside.
		time.Sleep(answerRefresh)
		fx.fetch.fail(coreIATest, failure)
		lookup(2)
		lookup(2)
		if got := fx.fetch.count(); got != 2 {
			t.Fatalf("fetches after the failed refresh = %d, want 2 (the core set aside)", got)
		}

		// Its retry falls due within SendTimeout, and fails again.
		time.Sleep(SendTimeout)
		lookup(2)
		if got := fx.fetch.count(); got != 3 {
			t.Fatalf("fetches once the retry is due = %d, want 3", got)
		}

		// The core answers once its second retry is due; the answer replaces
		// the held one.
		fx.fetch.fail(coreIATest, nil)
		fx.fetch.answerDown(coreIATest, terminatedSegment(t, coreIATest, iaLineC, 9, time.Now()).PCB.PB)
		time.Sleep(2 * SendTimeout)
		lookup(2)
		lookup(9)
		if got := fx.fetch.count(); got != 4 {
			t.Fatalf("fetches once the second retry is due = %d, want 4", got)
		}

		// The answer cleared the set-aside: the next failure sets the core
		// aside for the first retry's delay, not the third's.
		time.Sleep(answerRefresh)
		fx.fetch.fail(coreIATest, failure)
		lookup(9)
		time.Sleep(SendTimeout)
		lookup(9)
		if got := fx.fetch.count(); got != 6 {
			t.Errorf("fetches a SendTimeout past the next failure = %d, want 6 (the set-aside cleared)", got)
		}
	})
}

// TestLookupFailuresTogetherCountOnce checks the core's schedule under
// refreshes that fail together: they count as one try, so the core's retry
// falls due within SendTimeout, as after a single failure.
func TestLookupFailuresTogetherCountOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		kinds := []pathdb.SegmentType{pathdb.SegmentTypeDown, pathdb.SegmentTypeCore}
		ask := func(kind pathdb.SegmentType) {
			fx.lookup.ask(ctx, []addr.IA{coreIATest}, iaLineC, kind)
		}
		for _, kind := range kinds {
			ask(kind)
		}

		// Both answers grow past answerRefresh; their refreshes run together
		// and fail together.
		time.Sleep(answerRefresh)
		release := fx.fetch.silence(coreIATest)
		for _, kind := range kinds {
			ask(kind)
		}
		fx.fetch.fail(coreIATest, errors.New("core unreachable"))
		release()
		synctest.Wait()
		if got := fx.fetch.count(); got != 4 {
			t.Fatalf("fetches = %d, want 4 (each kind, then its refresh)", got)
		}

		time.Sleep(SendTimeout)
		ask(pathdb.SegmentTypeDown)
		synctest.Wait()
		if got := fx.fetch.count(); got != 5 {
			t.Errorf("fetches a SendTimeout past the failures = %d, want 5 (the retry due)", got)
		}
	})
}

// TestLookupSkipsCoresSetAside checks a destination no core holds an answer
// for under a failing core: the lookup that asks it returns empty once the
// failure lands, and the lookups after it ask nothing and wait on nothing
// until the core's retry is due.
func TestLookupSkipsCoresSetAside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		fx.fetch.fail(coreIATest, errors.New("core unreachable"))
		if got := fx.lookup.Down(ctx, iaLineC); len(got) != 0 {
			t.Fatalf("down segments from a failing core = %d, want none", len(got))
		}
		start := time.Now()
		if got := fx.lookup.Down(ctx, iaLineC); len(got) != 0 {
			t.Fatalf("down segments with the core set aside = %d, want none", len(got))
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("lookup with the core set aside waited %v, want none", waited)
		}
		if got := fx.fetch.count(); got != 1 {
			t.Errorf("fetches with the core set aside = %d, want 1", got)
		}

		time.Sleep(SendTimeout)
		fx.fetch.fail(coreIATest, nil)
		if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments once the retry is due = %v, want the core's [2]", got)
		}
	})
}

// TestLookupNoRouteSetsNothingAside checks a fetch that finds no route to
// the core: it asked nothing, so the core is not set aside, and the next
// lookup asks again, answered as soon as a route carries it.
func TestLookupNoRouteSetsNothingAside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		fx.fetch.fail(coreIATest, connect.NewError(connect.CodeUnavailable,
			fmt.Errorf("%w %s", scion.ErrNoLink, coreIATest)))
		for range 2 {
			if got := fx.lookup.Down(ctx, iaLineC); len(got) != 0 {
				t.Fatalf("down segments with no route to the core = %d, want none", len(got))
			}
		}
		if got := fx.fetch.count(); got != 2 {
			t.Errorf("fetches with no route to the core = %d, want 2 (the core not set aside)", got)
		}

		// A route appears: the next lookup is answered.
		fx.fetch.fail(coreIATest, nil)
		if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments once a route exists = %v, want the core's [2]", got)
		}
	})
}

// TestLookupFirstAsksEveryCore checks the first lookup of a destination no
// core holds an answer for: it asks every core at once and returns with the
// first answer, waiting on no silent core listed before the answering one,
// and the silent core's answer lands for the next lookup.
func TestLookupFirstAsksEveryCore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t, twoCores)
		ctx := context.Background()
		release := fx.fetch.silence(coreIATest)
		start := time.Now()
		if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, []uint16{5}) {
			t.Fatalf("first down segments = %v, want the answering core's [5]", got)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("first lookup waited %v on the silent core, want none", waited)
		}
		synctest.Wait()
		asked := make(map[addr.IA]bool)
		for _, call := range fx.fetch.asked() {
			asked[call.peer.IA] = true
		}
		if !asked[coreIATest] || !asked[iaCore2Test] {
			t.Errorf("cores asked = %v, want both at once", asked)
		}

		// The silent core answers after the lookup returned; its answer
		// lands for the next.
		release()
		synctest.Wait()
		if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, []uint16{2, 5}) {
			t.Fatalf("down segments after the silent core answered = %v, want both cores' [2 5]", got)
		}
		if got := fx.fetch.count(); got != 2 {
			t.Errorf("fetches = %d, want 2 (each core once)", got)
		}
	})
}

// TestLookupDeadlineEndsFirst checks a first lookup whose caller's deadline
// ends before any core answers: it returns empty at the deadline, and the
// fetch it started lands for the next lookup.
func TestLookupDeadlineEndsFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		release := fx.fetch.silence(coreIATest)
		const deadline = time.Second
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		start := time.Now()
		if got := fx.lookup.Down(ctx, iaLineC); len(got) != 0 {
			t.Fatalf("down segments past the caller's deadline = %d, want none", len(got))
		}
		if waited := time.Since(start); waited != deadline {
			t.Errorf("lookup returned after %v, want at the caller's deadline, %v", waited, deadline)
		}

		// The core answers once the caller gave up; its answer lands for the
		// next lookup.
		release()
		synctest.Wait()
		if got := segIDs(fx.lookup.Down(context.Background(), iaLineC)); !slices.Equal(got, []uint16{2}) {
			t.Fatalf("down segments after the fetch landed = %v, want the core's [2]", got)
		}
		if got := fx.fetch.count(); got != 1 {
			t.Errorf("fetches = %d, want 1 (the first lookup's, landed)", got)
		}
	})
}

// TestLookupOneRefreshPerQuestion checks that a question runs one refresh at
// a time: concurrent first lookups join the one refresh in flight and return
// with its answer, and concurrent lookups serving an answer past
// answerRefresh start one refresh between them.
func TestLookupOneRefreshPerQuestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		var wg sync.WaitGroup
		got := make([][]uint16, 5)
		lookups := func() {
			for i := range got {
				wg.Go(func() { got[i] = segIDs(fx.lookup.Down(ctx, iaLineC)) })
			}
		}
		returned := func() {
			t.Helper()
			wg.Wait()
			for i, ids := range got {
				if !slices.Equal(ids, []uint16{2}) {
					t.Errorf("lookup %d = %v, want the core's [2]", i, ids)
				}
			}
		}

		release := fx.fetch.silence(coreIATest)
		lookups()
		synctest.Wait()
		if n := fx.fetch.count(); n != 1 {
			t.Errorf("fetches under concurrent first lookups = %d, want 1", n)
		}
		release()
		returned()

		time.Sleep(answerRefresh)
		release = fx.fetch.silence(coreIATest)
		lookups()
		returned()
		synctest.Wait()
		if n := fx.fetch.count(); n != 2 {
			t.Errorf("fetches under concurrent lookups past answerRefresh = %d, want 2", n)
		}
		release()
		synctest.Wait()
		fx.fetch.mtx.Lock()
		defer fx.fetch.mtx.Unlock()
		if fx.fetch.peak != 1 {
			t.Errorf("fetches in flight at once = %d, want 1", fx.fetch.peak)
		}
	})
}

// TestLookupAnswersInCoresOrder checks the answers' order: each core's
// answer returns in the order the TRC lists the cores, whichever landed
// first.
func TestLookupAnswersInCoresOrder(t *testing.T) {
	canned := map[addr.IA]uint16{coreIATest: 2, iaCore2Test: 5}
	for _, cores := range [][]addr.IA{{coreIATest, iaCore2Test}, {iaCore2Test, coreIATest}} {
		t.Run(fmt.Sprint(cores), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fx := newLookupFixture(t, func(cfg *LookupConfig) {
					cfg.Cores = func(isd addr.ISD) []addr.IA { return cores }
				})
				ctx := context.Background()
				// The core listed first answers last.
				release := fx.fetch.silence(cores[0])
				fx.lookup.Down(ctx, iaLineC)
				release()
				synctest.Wait()
				want := []uint16{canned[cores[0]], canned[cores[1]]}
				if got := segIDs(fx.lookup.Down(ctx, iaLineC)); !slices.Equal(got, want) {
					t.Errorf("down segments = %v, want %v in the cores' order", got, want)
				}
			})
		})
	}
}

// TestLookupSourceCoreSegments checks that the source handler's core
// segments follow the down lookup's rules: the first request returns with
// the first answer, waiting on no silent core; the silent core's answer
// lands for the next request, which serves each core's answer at once in
// the reachable cores' order; and past answerRefresh, a request serves the
// answers at once while their refreshes run behind it, a failed refresh
// keeping its core's last answer and setting the core aside.
func TestLookupSourceCoreSegments(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t, twoCores)
		fx.reachCore2(t)
		reachable := fx.lookup.reachableCores()
		if len(reachable) != 2 {
			t.Fatalf("reachable cores = %v, want both", reachable)
		}
		canned := map[addr.IA]uint16{coreIATest: 3, iaCore2Test: 6}
		ctx := context.Background()
		cores := func() []uint16 {
			t.Helper()
			resp, err := fx.lookup.Segments(ctx, connect.NewRequest(&cppb.SegmentsRequest{
				DstIsdAs: uint64(coreIATest),
			}))
			if err != nil {
				t.Fatal(err)
			}
			var ids []uint16
			for _, pb := range resp.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_CORE)].GetSegments() {
				seg, err := pathdb.NewSegment(pathdb.SegmentTypeCore, pb)
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, seg.PCB.ID())
			}
			return ids
		}

		// The first request returns with the answering core's segments.
		release := fx.fetch.silence(reachable[0])
		start := time.Now()
		if got, want := cores(), []uint16{canned[reachable[1]]}; !slices.Equal(got, want) {
			t.Fatalf("first core segments = %v, want the answering core's %v", got, want)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("first request waited %v on the silent core, want none", waited)
		}

		// The silent core answers; the next request serves both in order.
		release()
		synctest.Wait()
		want := []uint16{canned[reachable[0]], canned[reachable[1]]}
		if got := cores(); !slices.Equal(got, want) {
			t.Fatalf("core segments = %v, want %v in the reachable cores' order", got, want)
		}

		// Past answerRefresh, the request serves both at once, a silent
		// core's refresh running behind it; the other core's refresh fails,
		// and its answer keeps serving while the core is set aside.
		time.Sleep(answerRefresh)
		fx.fetch.fail(reachable[0], errors.New("core unreachable"))
		release = fx.fetch.silence(reachable[1])
		start = time.Now()
		if got := cores(); !slices.Equal(got, want) {
			t.Fatalf("core segments past answerRefresh = %v, want the held %v", got, want)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("request past answerRefresh waited %v, want the answers served at once", waited)
		}
		release()
		synctest.Wait()
		if got := cores(); !slices.Equal(got, want) {
			t.Fatalf("core segments after a failed refresh = %v, want the held %v", got, want)
		}
		synctest.Wait()
		if got := fx.fetch.count(); got != 4 {
			t.Errorf("fetches = %d, want 4 (each core once, then each refresh, the failed core set aside)",
				got)
		}
	})
}

// TestLookupAuthoritativeServesCoreHandler checks the widened selection's
// other side: the authoritative tier serves the core handler from its own
// database and refuses a request whose source names the founder — the check
// that keeps the per-core fetch honest.
func TestLookupAuthoritativeServesCoreHandler(t *testing.T) {
	fx := newLookupFixture(t, func(cfg *LookupConfig) {
		cfg.IsCore = true
		cfg.IA = iaCore2Test
	})
	ctx := context.Background()

	// A request whose source names the founder is refused empty.
	resp, err := fx.lookup.Segments(ctx, connect.NewRequest(&cppb.SegmentsRequest{
		SrcIsdAs: uint64(coreIATest),
		DstIsdAs: uint64(coreIATest),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Segments) != 0 {
		t.Errorf("segments = %v, want none for the founder's source", resp.Msg.Segments)
	}

	// The authoritative's own source is served from the local database.
	seg := terminatedSegment(t, iaCore2Test, nodeIATest, 8, time.Now())
	seg.Type = pathdb.SegmentTypeCore
	if _, err := fx.db.Insert(ctx, seg); err != nil {
		t.Fatal(err)
	}
	resp, err = fx.lookup.Segments(ctx, connect.NewRequest(&cppb.SegmentsRequest{
		SrcIsdAs: uint64(iaCore2Test),
		DstIsdAs: uint64(coreIATest),
	}))
	if err != nil {
		t.Fatal(err)
	}
	cores := resp.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_CORE)]
	if cores == nil || len(cores.Segments) != 1 {
		t.Fatalf("core segments = %v, want one from the local database", cores)
	}
}

// TestLookupCoreHandler checks the core's handler (Section 4.2.3): the
// source must be this core; core destinations are served from the core
// segments, everything else from the down segments.
func TestLookupCoreHandler(t *testing.T) {
	fx := newLookupFixture(t, func(cfg *LookupConfig) {
		cfg.IsCore = true
		cfg.IA = coreIATest
	})

	// A request whose source is not this core is refused empty.
	resp, err := fx.lookup.Segments(context.Background(),
		connect.NewRequest(&cppb.SegmentsRequest{
			SrcIsdAs: uint64(nodeIATest),
			DstIsdAs: uint64(iaLineC),
		}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Segments) != 0 {
		t.Errorf("segments = %v, want none for a foreign source", resp.Msg.Segments)
	}

	// A down request is served from the local database; the fixture's up
	// segment stands in for a stored down segment.
	down := terminatedSegment(t, coreIATest, nodeIATest, 7, time.Now())
	down.Type = pathdb.SegmentTypeDown
	if _, err := fx.db.Insert(context.Background(), down); err != nil {
		t.Fatal(err)
	}
	resp, err = fx.lookup.Segments(context.Background(),
		connect.NewRequest(&cppb.SegmentsRequest{
			SrcIsdAs: uint64(coreIATest),
			DstIsdAs: uint64(nodeIATest),
		}))
	if err != nil {
		t.Fatal(err)
	}
	downs := resp.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)]
	if downs == nil || len(downs.Segments) != 1 {
		t.Fatalf("down segments = %v, want one from the local database", downs)
	}
}

// TestPathProviderCompose checks the in-node provider: the route to the core
// is the reversed up segment, the route elsewhere composes the reversed up
// segment with a down segment.
func TestPathProviderCompose(t *testing.T) {
	fx := newLookupFixture(t)
	provider := &scion.PathProvider{
		IA:     nodeIATest,
		DB:     fx.db,
		Lookup: fx.lookup.Down,
		Cores:  func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest} },
	}

	ctx := context.Background()
	up, err := provider.Path(ctx, coreIATest)
	if err != nil {
		t.Fatal(err)
	}
	if up.InfoFields[0].ConsDir {
		t.Error("route to the core is not reversed")
	}
	if len(up.HopFields) != 2 {
		t.Fatalf("hops = %d, want 2", len(up.HopFields))
	}

	composed, err := provider.Path(ctx, iaLineC)
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.InfoFields) != 2 || len(composed.HopFields) != 4 {
		t.Fatalf("composed path = %d info fields, %d hops; want 2, 4",
			len(composed.InfoFields), len(composed.HopFields))
	}
	if composed.InfoFields[0].ConsDir || !composed.InfoFields[1].ConsDir {
		t.Error("composed path directions wrong: up reversed, down forward")
	}

	// No route to an unreachable destination.
	if _, err := provider.Path(ctx, iaLineD); err == nil {
		t.Error("path to an unreachable destination resolved")
	}
}

// TestPathProviderBootstrap checks the enrollment route fallback: before the
// TRC is pinned, the reversed unverified beacon — already extended with the
// node's own hop — serves the founder route.
func TestPathProviderBootstrap(t *testing.T) {
	fx := newLookupFixture(t)
	db, err := pathdbbbolt.New(filepath.Join(t.TempDir(), "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := newBeaconFixture(t)
	// The beaconer's bootstrap route: the [A] beacon plus the node's own
	// unsigned hop, reversed.
	route, err := lineBeacon(t, f, time.Now()).Clone()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.AppendRouteHop(nodeIATest, segment.EntryOptions{
		IngressIfID: 1,
	}, macFactory()); err != nil {
		t.Fatal(err)
	}
	provider := &scion.PathProvider{
		IA:     nodeIATest,
		DB:     db,
		Lookup: fx.lookup.Down,
		Bootstrap: func(core addr.IA) *spath.Decoded {
			if !core.Equal(coreIATest) {
				return nil
			}
			return route.ReversePath()
		},
		Cores: func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest} },
	}
	// No up segments in the database: the bootstrap route serves.
	path, err := provider.Path(context.Background(), coreIATest)
	if err != nil {
		t.Fatal(err)
	}
	if path.InfoFields[0].ConsDir || len(path.HopFields) != 2 {
		t.Error("bootstrap route is not the reversed beacon with the node's own hop")
	}
}
