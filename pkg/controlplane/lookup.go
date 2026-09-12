package controlplane

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"

	"github.com/fancl20/cion/pkg/pathdb"
)

// lookupCacheTTL caps how long fetched segments are served from the cache,
// so fresh registrations surface even though hop fields stay valid for hours.
const lookupCacheTTL = time.Minute

// LookupService implements the draft's segment-request handlers: the source-
// AS handler of a non-core (Section 5.2.2) — up segments from the local path
// database, core and down segments fetched from the core's control service
// with expiry-aware caching, source wildcards expanded per Table 4 — and the
// core handler (Section 5.2.3), which serves from the local database.
type LookupService struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// DB is the local path database.
	DB pathdb.DB
	// IsCore selects the core's handler behavior.
	IsCore bool
	// Cores enumerates the core ASes of an ISD named by the pinned TRC; nil
	// cores mean the TRC is not pinned.
	Cores func(isd addr.ISD) []addr.IA
	// Fetch requests segments from a core's control service.
	Fetch func(ctx context.Context, peer *Addr, src, dst addr.IA) (*cppb.SegmentsResponse, error)
	// CoreRoute resolves the core's endpoint to fetch through.
	CoreRoute func() *Addr

	mtx   sync.Mutex
	cache map[[2]addr.IA]cachedSegments
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// cachedSegments holds fetched segments until the earliest of their
// expirations, capped by the cache TTL.
type cachedSegments struct {
	segments []*pathdb.Segment
	expiry   time.Time
}

// NewLookupService returns a lookup service with an empty cache.
func NewLookupService() *LookupService {
	return &LookupService{cache: make(map[[2]addr.IA]cachedSegments)}
}

// Segments serves a segment request (draft Section 5).
func (s *LookupService) Segments(
	ctx context.Context,
	req *connect.Request[cppb.SegmentsRequest],
) (*connect.Response[cppb.SegmentsResponse], error) {

	src := addr.IA(req.Msg.SrcIsdAs)
	dst := addr.IA(req.Msg.DstIsdAs)
	if dst.IsZero() || dst.ISD() == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.New("segment request needs a destination ISD-AS", "src", src, "dst", dst))
	}
	resp := &cppb.SegmentsResponse{Segments: make(map[int32]*cppb.SegmentsResponse_Segments)}
	for _, segs := range s.lookup(ctx, src, dst) {
		t := int32(segs.Type)
		if _, ok := resp.Segments[t]; !ok {
			resp.Segments[t] = &cppb.SegmentsResponse_Segments{}
		}
		for _, seg := range segs.list {
			resp.Segments[t].Segments = append(resp.Segments[t].Segments, seg.PCB.PB)
		}
	}
	return connect.NewResponse(resp), nil
}

type typedSegments struct {
	Type pathdb.SegmentType
	list []*pathdb.Segment
}

// lookup resolves one request into typed segment lists.
func (s *LookupService) lookup(
	ctx context.Context,
	src, dst addr.IA,
) []typedSegments {

	if s.IsCore {
		return s.coreLookup(src, dst)
	}
	return s.sourceLookup(ctx, src, dst)
}

// coreLookup implements the core's handler (Section 5.2.3): the source must
// be this core; core and wildcard destinations are served from the core
// segments, everything else from the down segments.
func (s *LookupService) coreLookup(src, dst addr.IA) []typedSegments {
	if !src.IsZero() && !src.Equal(s.IA) {
		slog.Warn("Rejecting segment request whose source is not this core",
			"src", src, "isd_as", s.IA)
		return nil
	}
	if s.isCore(dst) {
		return []typedSegments{{Type: pathdb.SegmentTypeCore,
			list: s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeCore})}}
	}
	if dst.ISD() != s.IA.ISD() {
		return nil
	}
	return []typedSegments{{Type: pathdb.SegmentTypeDown,
		list: s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: dst})}}
}

// sourceLookup implements the non-core source-AS handler (Section 5.2.2).
func (s *LookupService) sourceLookup(ctx context.Context, src, dst addr.IA) []typedSegments {
	var out []typedSegments
	srcIsLocal := src.IsZero() || src.Equal(s.IA)
	dstIsCore := s.isCore(dst)

	if srcIsLocal && (dst.IsWildcard() || dstIsCore) {
		q := pathdb.Query{Type: pathdb.SegmentTypeUp}
		if !dst.IsWildcard() {
			q.SrcIA = dst
		}
		if ups := s.DBGet(q); len(ups) != 0 {
			out = append(out, typedSegments{Type: pathdb.SegmentTypeUp, list: ups})
		}
	}
	if (src.IsZero() || s.isCore(src)) && (dst.IsWildcard() || dstIsCore) {
		// Core segments: the source wildcard expands into one request per
		// reachable core AS of the source ISD (Table 4).
		for _, core := range s.reachableCores() {
			if segs := s.fetchCached(ctx, core, dst, pathdb.SegmentTypeCore); len(segs) != 0 {
				out = append(out, typedSegments{Type: pathdb.SegmentTypeCore, list: segs})
			}
		}
	}
	if !dst.IsWildcard() && !dstIsCore {
		// Down segments: the source wildcard expands into one request per
		// core AS of the destination ISD (Table 4).
		for _, core := range s.cores(dst.ISD()) {
			if segs := s.fetchCached(ctx, core, dst, pathdb.SegmentTypeDown); len(segs) != 0 {
				out = append(out, typedSegments{Type: pathdb.SegmentTypeDown, list: segs})
			}
		}
	}
	return out
}

// reachableCores returns the core ASes this node has up segments to.
func (s *LookupService) reachableCores() []addr.IA {
	ups := s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeUp})
	var cores []addr.IA
	seen := make(map[addr.IA]bool)
	for _, seg := range ups {
		if core := seg.FirstIA(); !seen[core] {
			seen[core] = true
			cores = append(cores, core)
		}
	}
	return cores
}

// Down returns the down segments serving dst, fetching and caching them from
// the core's control service as needed; the path provider composes them.
func (s *LookupService) Down(ctx context.Context, dst addr.IA) []*pathdb.Segment {
	if s.IsCore {
		return s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: dst})
	}
	var down []*pathdb.Segment
	for _, core := range s.cores(dst.ISD()) {
		down = append(down, s.fetchCached(ctx, core, dst, pathdb.SegmentTypeDown)...)
	}
	return down
}

// fetchCached returns segments of the given type from the cache, or fetches
// them from the core and caches them until their earliest expiration, capped
// by the cache TTL.
func (s *LookupService) fetchCached(
	ctx context.Context,
	core, dst addr.IA,
	t pathdb.SegmentType,
) []*pathdb.Segment {

	now := s.now()
	key := [2]addr.IA{core, dst}
	s.mtx.Lock()
	if cached, ok := s.cache[key]; ok && now.Before(cached.expiry) {
		s.mtx.Unlock()
		return cached.segments
	}
	s.mtx.Unlock()

	route := s.CoreRoute()
	if route == nil {
		return nil
	}
	resp, err := s.Fetch(ctx, route, core, dst)
	if err != nil {
		slog.Warn("Fetching segments from core", "core", core, "dst", dst, "err", err)
		return nil
	}
	raw, ok := resp.Segments[int32(t)]
	if !ok {
		raw = &cppb.SegmentsResponse_Segments{}
	}
	var segs []*pathdb.Segment
	expiry := now.Add(lookupCacheTTL)
	for _, pb := range raw.Segments {
		seg, err := pathdb.NewSegment(t, pb)
		if err != nil {
			slog.Warn("Parsing fetched segment", "err", err)
			continue
		}
		if seg.Expiration().Before(expiry) {
			expiry = seg.Expiration()
		}
		segs = append(segs, seg)
	}
	s.mtx.Lock()
	s.cache[key] = cachedSegments{segments: segs, expiry: expiry}
	s.mtx.Unlock()
	return segs
}

// DBGet reads the local database.
func (s *LookupService) DBGet(q pathdb.Query) []*pathdb.Segment {
	ctx := context.Background()
	segs, err := s.DB.Get(ctx, q)
	if err != nil {
		slog.Error("Querying path database", "query", q, "err", err)
		return nil
	}
	return segs
}

func (s *LookupService) cores(isd addr.ISD) []addr.IA {
	if s.Cores == nil {
		return nil
	}
	return s.Cores(isd)
}

// isCore reports whether the IA names a core AS of its ISD.
func (s *LookupService) isCore(ia addr.IA) bool {
	if ia.IsWildcard() {
		return false
	}
	for _, core := range s.cores(ia.ISD()) {
		if core.Equal(ia) {
			return true
		}
	}
	return false
}

func (s *LookupService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
