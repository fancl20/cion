package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"

	"github.com/fancl20/cion/pkg/libs/expiring"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// answerRefresh is how old a core's answer grows before a lookup serving it
// starts a refresh, so fresh registrations surface even though hop fields
// stay valid for hours.
const answerRefresh = time.Minute

// LookupConfig configures a LookupService.
type LookupConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// DB is the local path database.
	DB pathdb.DB
	// IsCore selects the core handler's behavior: the core tiers — founding
	// and authoritative alike — serve from the local database.
	IsCore bool
	// Cores enumerates the core ASes of an ISD named by the pinned TRC; nil
	// cores mean the TRC is not pinned.
	Cores func(isd addr.ISD) []addr.IA
	// Fetch requests segments from a core's control service; the peer names
	// the core the question is addressed to, and the source of the question
	// is that core.
	Fetch func(ctx context.Context, peer *scion.Addr, src, dst addr.IA) (*cppb.SegmentsResponse, error)
}

// LookupService implements the draft's segment-request handlers: the source-
// AS handler of a non-core (Section 4.2.2) — up segments from the local path
// database, core and down segments fetched from the cores' control services,
// source wildcards expanded per Table 4 — and the core handler (Section
// 4.2.3), which serves from the local database. The source handler keeps
// each core's last answer to a question and serves it at once, refreshing it
// behind the lookup; a core asked a refresh it fails to answer is set aside
// on the node's retry schedule while its last answer keeps serving.
type LookupService struct {
	cfg LookupConfig

	// mtx guards the fields below.
	mtx sync.Mutex
	// answers holds each core's last answer to a question until the
	// earliest expiration of its segments.
	answers *expiring.Map[lookupKey, answer]
	// refreshing holds the questions whose refresh is in flight.
	refreshing map[lookupKey]bool
	// aside schedules a retry for each core that failed to answer a
	// refresh, from SendTimeout doubling up to answerRefresh: no refresh
	// asks the core before its retry is due.
	aside loops.Attempts[addr.IA]
	// landed is closed, and replaced, whenever a refresh lands, waking the
	// lookups that wait for a first answer.
	landed chan struct{}
}

// lookupKey names a question asked of a core: the core asked, the
// destination asked about, and the segment type fetched — a core-segment
// fetch and a down-segment fetch for one destination are different
// questions and hold different answers.
type lookupKey struct {
	core    addr.IA
	dst     addr.IA
	segType pathdb.SegmentType
}

// answer is a core's answer to a question and when it was fetched.
type answer struct {
	segs    []*pathdb.Segment
	fetched time.Time
}

// NewLookupService returns a lookup service holding no answers.
func NewLookupService(cfg LookupConfig) *LookupService {
	return &LookupService{
		cfg:        cfg,
		answers:    expiring.New[lookupKey, answer](),
		refreshing: make(map[lookupKey]bool),
		aside:      loops.Attempts[addr.IA]{Backoff: loops.Backoff{Base: SendTimeout, Max: answerRefresh}},
		landed:     make(chan struct{}),
	}
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

	if s.cfg.IsCore {
		return s.coreLookup(src, dst)
	}
	return s.sourceLookup(ctx, src, dst)
}

// coreLookup implements the core's handler (Section 4.2.3): the source must
// be this core; core and wildcard destinations are served from the core
// segments, everything else from the down segments.
func (s *LookupService) coreLookup(src, dst addr.IA) []typedSegments {
	if !src.IsZero() && !src.Equal(s.cfg.IA) {
		slog.Warn("Rejecting segment request whose source is not this core",
			"src", src, "isd_as", s.cfg.IA)
		return nil
	}
	if s.isCore(dst) {
		return []typedSegments{{Type: pathdb.SegmentTypeCore,
			list: s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeCore})}}
	}
	if dst.ISD() != s.cfg.IA.ISD() {
		return nil
	}
	return []typedSegments{{Type: pathdb.SegmentTypeDown,
		list: s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: dst})}}
}

// sourceLookup implements the non-core source-AS handler (Section 4.2.2):
// up segments from the local database, and core and down segments as ask
// serves them, one list per core holding an answer.
func (s *LookupService) sourceLookup(ctx context.Context, src, dst addr.IA) []typedSegments {
	var out []typedSegments
	srcIsLocal := src.IsZero() || src.Equal(s.cfg.IA)
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
		for _, segs := range s.ask(ctx, s.reachableCores(), dst, pathdb.SegmentTypeCore) {
			out = append(out, typedSegments{Type: pathdb.SegmentTypeCore, list: segs})
		}
	}
	if !dst.IsWildcard() && !dstIsCore {
		// Down segments: the source wildcard expands into one request per
		// core AS of the destination ISD (Table 4).
		for _, segs := range s.ask(ctx, s.cores(dst.ISD()), dst, pathdb.SegmentTypeDown) {
			out = append(out, typedSegments{Type: pathdb.SegmentTypeDown, list: segs})
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

// Down returns the down segments serving dst, each core's answer as ask
// serves it, in the cores' order; the path provider composes them. A
// non-core asks nothing for a core destination: down segments end at the
// non-core ASes that register them, and the core's handler answers a core
// destination with core segments alone, so the fetch would come back empty —
// never held, asked again at every call.
func (s *LookupService) Down(ctx context.Context, dst addr.IA) []*pathdb.Segment {
	if s.cfg.IsCore {
		return s.DBGet(pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: dst})
	}
	cores := s.cores(dst.ISD())
	if slices.Contains(cores, dst) {
		return nil
	}
	return slices.Concat(s.ask(ctx, cores, dst, pathdb.SegmentTypeDown)...)
}

// ask returns the cores' answers to the question of dst's segments of type
// t, in the cores' order, one per core holding an answer. It serves the
// answers held at once and starts a refresh of each core's answer that is
// older than answerRefresh or not held, waiting for none. Only when no core
// holds an answer does it wait: until one lands, no refresh of the cores'
// answers is left in flight, or ctx ends.
func (s *LookupService) ask(
	ctx context.Context,
	cores []addr.IA,
	dst addr.IA,
	t pathdb.SegmentType,
) [][]*pathdb.Segment {

	keys := make([]lookupKey, len(cores))
	for i, core := range cores {
		keys[i] = lookupKey{core: core, dst: dst, segType: t}
	}
	inFlight := func(key lookupKey) bool { return s.refreshing[key] }
	s.mtx.Lock()
	defer s.mtx.Unlock()
	now := time.Now()
	for _, key := range keys {
		if a, ok := s.answers.Get(key); !ok || now.Sub(a.fetched) >= answerRefresh {
			s.refresh(key, now)
		}
	}
	for {
		var held [][]*pathdb.Segment
		for _, key := range keys {
			if a, ok := s.answers.Get(key); ok {
				held = append(held, a.segs)
			}
		}
		if len(held) != 0 || ctx.Err() != nil || !slices.ContainsFunc(keys, inFlight) {
			return held
		}
		landed := s.landed
		s.mtx.Unlock()
		select {
		case <-landed:
		case <-ctx.Done():
		}
		s.mtx.Lock()
	}
}

// refresh starts a refresh of the core's answer to the question, unless the
// core is set aside or the question's refresh is in flight. The caller holds
// s.mtx.
func (s *LookupService) refresh(key lookupKey, now time.Time) {
	if s.refreshing[key] || !s.aside.Due(key.core, now) {
		return
	}
	s.refreshing[key] = true
	go func() {
		segs, err := s.fetch(key)
		s.land(key, segs, err)
	}()
}

// fetch asks the core the question — the peer client's dial routing it, a
// core the node holds no route to failing the dial — and returns the
// answer's segments. SendTimeout alone bounds it: detached from the lookup
// that started it, the answer lands for the next lookup even after that
// one gave up.
func (s *LookupService) fetch(key lookupKey) ([]*pathdb.Segment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), SendTimeout)
	defer cancel()
	peer := &scion.Addr{IA: key.core, Service: addr.SvcCS}
	resp, err := s.cfg.Fetch(ctx, peer, key.core, key.dst)
	if err != nil {
		slog.Warn("Fetching segments from core", "core", key.core, "dst", key.dst, "err", err)
		return nil, err
	}
	var segs []*pathdb.Segment
	for _, pb := range resp.Segments[int32(key.segType)].GetSegments() {
		seg, err := pathdb.NewSegment(key.segType, pb)
		if err != nil {
			slog.Warn("Parsing fetched segment", "err", err)
			continue
		}
		segs = append(segs, seg)
	}
	return segs, nil
}

// land lands a refresh of the core's answer to the question and wakes the
// lookups waiting for one. An answer replaces the core's last and clears
// the core's set-aside; a failure keeps the last answer and sets the core
// aside, unless the fetch found no route to the core: it asked nothing, and
// the next lookup asks again, which a route then carries.
func (s *LookupService) land(key lookupKey, segs []*pathdb.Segment, err error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s.refreshing, key)
	close(s.landed)
	s.landed = make(chan struct{})
	now := time.Now()
	if err != nil {
		// Refreshes that fail together count as one try: a core already
		// set aside keeps its schedule.
		if !errors.Is(err, scion.ErrNoLink) && s.aside.Due(key.core, now) {
			s.aside.Tried(key.core, now)
		}
		return
	}
	s.aside.Forget(key.core)
	// The answer is held until the earliest expiration of its segments. One
	// holding none expires at once: a registration the fetch raced lands
	// any moment, and the next lookup asks again to see it.
	expiry := now
	for i, seg := range segs {
		if i == 0 || seg.Expiration().Before(expiry) {
			expiry = seg.Expiration()
		}
	}
	s.answers.Set(key, answer{segs: segs, fetched: now}, expiry)
}

// DBGet reads the local database. A read failure logs and answers empty: the
// read also serves dial paths, where a store closed under a write in flight
// is the shutdown racing the send, not corruption.
func (s *LookupService) DBGet(q pathdb.Query) []*pathdb.Segment {
	ctx := context.Background()
	segs, err := s.cfg.DB.Get(ctx, q)
	if err != nil {
		slog.Error("Querying path database", "query", q, "err", err)
		return nil
	}
	return segs
}

func (s *LookupService) cores(isd addr.ISD) []addr.IA {
	if s.cfg.Cores == nil {
		return nil
	}
	return s.cfg.Cores(isd)
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
