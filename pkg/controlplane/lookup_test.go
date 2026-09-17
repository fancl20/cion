package controlplane

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
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

// recordingFetch records fetches and answers with canned segments.
type recordingFetch struct {
	mtx      sync.Mutex
	requests [][2]addr.IA
	down     []*cppb.PathSegment
}

func (f *recordingFetch) Fetch(
	ctx context.Context, peer *scion.Addr, src, dst addr.IA) (*cppb.SegmentsResponse, error) {

	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.requests = append(f.requests, [2]addr.IA{src, dst})
	resp := &cppb.SegmentsResponse{Segments: map[int32]*cppb.SegmentsResponse_Segments{}}
	// The core answers only with segments that reach the requested
	// destination; the canned segment reaches iaLineC.
	if dst.Equal(iaLineC) {
		resp.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)] =
			&cppb.SegmentsResponse_Segments{Segments: f.down}
	}
	return resp, nil
}

func newLookupFixture(t *testing.T) *lookupFixture {
	t.Helper()
	db, err := pathdbbbolt.New(filepath.Join(t.TempDir(), "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	now := time.Now()
	up := terminatedSegment(t, coreIATest, nodeIATest, 1, now)
	if _, err := db.Insert(context.Background(), up); err != nil {
		t.Fatal(err)
	}
	fetch := &recordingFetch{down: []*cppb.PathSegment{
		terminatedSegment(t, coreIATest, iaLineC, 2, now).PCB.PB,
	}}
	lookup := NewLookupService()
	lookup.IA = nodeIATest
	lookup.DB = db
	lookup.Cores = func(isd addr.ISD) []addr.IA { return []addr.IA{coreIATest} }
	lookup.Fetch = fetch.Fetch
	lookup.CoreRoute = func() *scion.Addr {
		return &scion.Addr{IA: coreIATest, Addr: fakeCoreEndpoint}
	}
	return &lookupFixture{db: db, lookup: lookup, fetch: fetch, now: now}
}

var fakeCoreEndpoint = netip.MustParseAddrPort("192.0.2.10:30044")

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
	if got := len(fx.fetch.requests); got != 0 {
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
	if len(fx.fetch.requests) != 1 || !fx.fetch.requests[0][0].Equal(coreIATest) {
		t.Errorf("fetch requests = %v, want one expanded to the core", fx.fetch.requests)
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
		for i := 0; i < 2; i++ {
			if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
				t.Fatalf("down segments = %d, want 1", len(segs))
			}
		}
		fx.fetch.mtx.Lock()
		if got := len(fx.fetch.requests); got != 1 {
			t.Errorf("fetches inside TTL = %d, want 1", got)
		}
		fx.fetch.mtx.Unlock()

		time.Sleep(2 * lookupCacheTTL)
		if segs := fx.lookup.Down(ctx, iaLineC); len(segs) != 1 {
			t.Fatalf("down segments after TTL = %d, want 1", len(segs))
		}
		fx.fetch.mtx.Lock()
		if got := len(fx.fetch.requests); got != 2 {
			t.Errorf("fetches after TTL = %d, want 2", got)
		}
		fx.fetch.mtx.Unlock()
	})
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
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
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
