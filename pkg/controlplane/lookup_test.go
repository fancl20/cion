package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// lookupFixture is a lookup service over a path database with one up and one
// down segment, and a recording fetch.
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

// recordingFetch records fetches and answers with canned segments of each
// type; a peer in errFor answers with a dial's failure — a core the node
// holds no route to.
type recordingFetch struct {
	mtx    sync.Mutex
	calls  []fetchCall
	errFor map[addr.IA]error
	down   []*cppb.PathSegment
	core   []*cppb.PathSegment
}

func (f *recordingFetch) Fetch(
	ctx context.Context, peer *scion.Addr, src, dst addr.IA) (*cppb.SegmentsResponse, error) {

	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.calls = append(f.calls, fetchCall{peer: peer, src: src, dst: dst})
	if err := f.errFor[peer.IA]; err != nil {
		return nil, err
	}
	resp := &cppb.SegmentsResponse{Segments: map[int32]*cppb.SegmentsResponse_Segments{}}
	// The core answers only with segments that reach the requested
	// destination; the canned segments reach iaLineC.
	if dst.Equal(iaLineC) {
		resp.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)] =
			&cppb.SegmentsResponse_Segments{Segments: f.down}
		resp.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_CORE)] =
			&cppb.SegmentsResponse_Segments{Segments: f.core}
	}
	return resp, nil
}

func newLookupFixture(t *testing.T) *lookupFixture {
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
		down: []*cppb.PathSegment{
			terminatedSegment(t, coreIATest, iaLineC, 2, now).PCB.PB,
		},
		core: []*cppb.PathSegment{
			terminatedSegment(t, coreIATest, iaLineC, 3, now).PCB.PB,
		},
	}
	lookup := NewLookupService()
	lookup.IA = nodeIATest
	lookup.DB = db
	lookup.Cores = func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest} }
	lookup.Fetch = fetch.Fetch
	return &lookupFixture{db: db, lookup: lookup, fetch: fetch, now: now}
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

// TestLookupCacheUntilExpiry checks the expiry-aware caching: a second
// request inside the TTL is served from the cache; once it passes, the core
// is asked again. The TTL's passage is a fake-time sleep in the bubble.
func TestLookupCacheUntilExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		for range 2 {
			if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
				t.Fatalf("down segments = %d, want 1", len(segs))
			}
		}
		fx.fetch.mtx.Lock()
		if got := len(fx.fetch.calls); got != 1 {
			t.Errorf("fetches inside TTL = %d, want 1", got)
		}
		fx.fetch.mtx.Unlock()

		time.Sleep(2 * lookupCacheTTL)
		if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
			t.Fatalf("down segments after TTL = %d, want 1", len(segs))
		}
		fx.fetch.mtx.Lock()
		if got := len(fx.fetch.calls); got != 2 {
			t.Errorf("fetches after TTL = %d, want 2", got)
		}
		fx.fetch.mtx.Unlock()
	})
}

// TestLookupCacheKeysByType checks the cache's key widened by the segment
// type: one core-and-destination pair fetched under two types answers each
// kind from its own entry, never the other's.
func TestLookupCacheKeysByType(t *testing.T) {
	fx := newLookupFixture(t)
	ctx := context.Background()

	downs := fx.lookup.fetchCached(ctx, coreIATest, iaLineC, pathdb.SegmentTypeDown)
	cores := fx.lookup.fetchCached(ctx, coreIATest, iaLineC, pathdb.SegmentTypeCore)
	if len(downs) != 1 || downs[0].PCB.ID() != 2 {
		t.Fatalf("down segments = %v, want the canned down segment", downs)
	}
	if len(cores) != 1 || cores[0].PCB.ID() != 3 {
		t.Fatalf("core segments = %v, want the canned core segment", cores)
	}
	fx.lookup.mtx.Lock()
	if got := len(fx.lookup.cache); got != 2 {
		t.Errorf("cache entries = %d, want one per type under the one pair", got)
	}
	fx.lookup.mtx.Unlock()

	// Both kinds serve from their own entries: no further fetch.
	fx.lookup.fetchCached(ctx, coreIATest, iaLineC, pathdb.SegmentTypeDown)
	fx.lookup.fetchCached(ctx, coreIATest, iaLineC, pathdb.SegmentTypeCore)
	fx.fetch.mtx.Lock()
	defer fx.fetch.mtx.Unlock()
	if got := len(fx.fetch.calls); got != 2 {
		t.Errorf("fetches = %d, want 2 (each kind answered from its own entry)", got)
	}
}

// TestLookupCacheForgets checks the cache's bound: an entry past its expiry
// leaves on the next write, an entry still within its expiry survives
// another's write however many pass, and neither kind ever answers the
// other's question. The TTL's passage is a fake-time sleep in the bubble.
func TestLookupCacheForgets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fx := newLookupFixture(t)
		ctx := context.Background()
		fetch := func(t pathdb.SegmentType) []*pathdb.Segment {
			return fx.lookup.fetchCached(ctx, coreIATest, iaLineC, t)
		}
		cacheLen := func() int {
			fx.lookup.mtx.Lock()
			defer fx.lookup.mtx.Unlock()
			return len(fx.lookup.cache)
		}

		fetch(pathdb.SegmentTypeDown)
		fetch(pathdb.SegmentTypeCore)
		if got := cacheLen(); got != 2 {
			t.Fatalf("cache entries = %d, want both kinds within their expiry", got)
		}

		// The TTL passes; the next write empties the map of the expired
		// entries and holds the one it wrote.
		time.Sleep(2 * lookupCacheTTL)
		if downs := fetch(pathdb.SegmentTypeDown); len(downs) != 1 || downs[0].PCB.ID() != 2 {
			t.Fatalf("down segments after the TTL = %v, want the canned segment re-fetched", downs)
		}
		if got := cacheLen(); got != 1 {
			t.Errorf("cache entries after the TTL = %d, want 1 (the expired kinds left on the write)", got)
		}

		// The live entry survives another kind's landing write, and however
		// many reads pass, both kinds answer from the cache alone.
		for range 5 {
			fetch(pathdb.SegmentTypeCore)
			if downs := fetch(pathdb.SegmentTypeDown); len(downs) != 1 || downs[0].PCB.ID() != 2 {
				t.Fatalf("down segments = %v, want the entry the write left standing", downs)
			}
		}
		if got := cacheLen(); got != 2 {
			t.Errorf("cache entries = %d, want 2 (a live entry survives another's writes)", got)
		}
		fx.fetch.mtx.Lock()
		if got := len(fx.fetch.calls); got != 4 {
			t.Errorf("fetches = %d, want 4 (one per kind per expiry)", got)
		}
		fx.fetch.mtx.Unlock()
	})
}

// TestLookupEmptyAnswerNotCached checks the empty-answer seam: a fetch that
// answers nothing is not cached — the registration it raced can land any
// moment, so the next request asks the core again and sees it.
func TestLookupEmptyAnswerNotCached(t *testing.T) {
	fx := newLookupFixture(t)
	ctx := context.Background()

	// The core holds no down segment for the middle node yet.
	fx.fetch.mtx.Lock()
	canned := fx.fetch.down
	fx.fetch.down = nil
	fx.fetch.mtx.Unlock()
	for range 2 {
		if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 0 {
			t.Fatalf("down segments = %d, want none while the core holds none", len(segs))
		}
	}
	fx.fetch.mtx.Lock()
	if got := len(fx.fetch.calls); got != 2 {
		t.Errorf("fetches after empty answers = %d, want 2 (an empty answer is not cached)", got)
	}
	fx.fetch.mtx.Unlock()

	// The registration lands; the very next request sees it.
	fx.fetch.mtx.Lock()
	fx.fetch.down = canned
	fx.fetch.mtx.Unlock()
	if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
		t.Fatalf("down segments after the registration = %d, want 1", len(segs))
	}
}

// TestLookupFetchesAskTheCoreTheyName checks the fetch's per-core send: the
// down expansion asks each core of the destination ISD at that core's own
// address with itself as the source, the core expansion each reachable
// core, and a core whose dial fails — no route to it — answers nothing while
// the other core's segments are still served, the failed ask left uncached.
func TestLookupFetchesAskTheCoreTheyName(t *testing.T) {
	fx := newLookupFixture(t)
	fx.lookup.Cores = func(isd addr.ISD) []addr.IA {
		return []addr.IA{coreIATest, iaCore2Test}
	}
	// A second origin's up segment makes the second core reachable too —
	// the core expansion's source set.
	up2 := terminatedSegment(t, iaCore2Test, nodeIATest, 4, fx.now)
	if _, err := fx.db.Insert(context.Background(), up2); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// One core's dial fails; the other's answer is served regardless.
	fx.fetch.mtx.Lock()
	fx.fetch.errFor[iaCore2Test] = errors.New("no route to the asked core")
	fx.fetch.mtx.Unlock()
	if downs := fx.lookup.Down(ctx, iaLineC); len(downs) != 1 {
		t.Fatalf("down segments under one failed dial = %d, want the other core's 1", len(downs))
	}
	fx.fetch.mtx.Lock()
	fx.fetch.errFor[iaCore2Test] = nil
	fx.fetch.mtx.Unlock()

	// The down expansion: one request per core of the destination ISD, each
	// at its own address and with itself as the source — the handler's
	// check that the source be this core matches everywhere they land. The
	// failed ask is not cached: the next request asks that core again.
	if downs := fx.lookup.Down(ctx, iaLineC); len(downs) != 2 {
		t.Fatalf("down segments = %d, want both cores' after the retry", len(downs))
	}
	fx.fetch.mtx.Lock()
	calls := append([]fetchCall(nil), fx.fetch.calls...)
	fx.fetch.mtx.Unlock()
	if len(calls) != 3 {
		t.Fatalf("fetch calls = %d, want 3 (two of the failed core, one cached)", len(calls))
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
	fx.fetch.mtx.Lock()
	calls = append([]fetchCall(nil), fx.fetch.calls...)
	fx.fetch.mtx.Unlock()
	reached := make(map[addr.IA]bool)
	for _, call := range calls {
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
}

// TestLookupAuthoritativeServesCoreHandler checks the widened selection's
// other side: the authoritative tier serves the core handler from its own
// database and refuses a request whose source names the founder — the check
// that keeps the per-core fetch honest.
func TestLookupAuthoritativeServesCoreHandler(t *testing.T) {
	fx := newLookupFixture(t)
	fx.lookup.IsCore = true
	fx.lookup.IA = iaCore2Test
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
	fx := newLookupFixture(t)
	fx.lookup.IsCore = true
	fx.lookup.IA = coreIATest

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
// node's own hop — serves the core route.
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
