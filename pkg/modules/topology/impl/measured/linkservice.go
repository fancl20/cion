package measured

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/peeria"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// LinkMinInterval is the link service's rate cap: the least pause between
// admissions of one peer.
const LinkMinInterval = time.Second

// LinkService implements the in-band establishment: a node that composed
// paths already reach asks over the control endpoint's authenticated
// channel, the peer's chain identifying it. The acceptor applies its
// admission policy, allocates its own interface ID and link address, records
// the entry as established, and replies with them. Served by the measured
// provider, mounted behind the peer middleware.
type LinkService struct {
	// Store is the neighbor table.
	Store links.DB
	// MaxLinks caps the live link count.
	MaxLinks int
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// MinInterval is the least pause between admissions of one peer; zero
	// uses the default.
	MinInterval time.Duration
	// Changed is called after each store mutation.
	Changed func()

	limiterOnce sync.Once
	limiter     sourceLimiter[addr.IA]
	// mtx serializes the handlers' lookup-and-mutate runs over the store.
	mtx sync.Mutex
}

// rateLimiter returns the admission rate limiter, built on first use so a
// struct literal configuration works.
func (s *LinkService) rateLimiter() *sourceLimiter[addr.IA] {
	s.limiterOnce.Do(func() {
		interval := s.MinInterval
		if interval == 0 {
			interval = LinkMinInterval
		}
		s.limiter = newSourceLimiter[addr.IA](interval)
	})
	return &s.limiter
}

var _ nodev1connect.LinkServiceHandler = (*LinkService)(nil)

// Request admits the caller's link and answers the acceptor's side of it.
// The requester is named by its verified certificate chain; a channel that
// verified no chain serves no identity and the request is refused.
func (s *LinkService) Request(
	ctx context.Context,
	req *connect.Request[nodev1.LinkRequest],
) (*connect.Response[nodev1.LinkReply], error) {

	if req.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("no link request"))
	}
	peer := peeria.AuthenticatedIA(ctx)
	if peer.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("no authenticated ISD-AS; the channel verified no chain"))
	}
	if !s.rateLimiter().admit(peer) {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("peer %s exceeds the admission rate", peer))
	}
	linkAddr, err := netip.ParseAddrPort(req.Msg.LocalAddr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("parsing the requester's link address: %w", err))
	}
	if req.Msg.IfId > 0xffff {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("interface ID out of range"))
	}

	// The rendezvous acceptor and the selection's establishment record
	// entries too; the store refuses a neighbor's second live entry and a
	// second live entry on one local address, and a request that loses
	// either race looks again: it refreshes the winner's entry, or records
	// its own on a fresh address.
	s.mtx.Lock()
	defer s.mtx.Unlock()
	entry, err := s.record(ctx, peer, linkAddr, uint16(req.Msg.IfId))
	if errors.Is(err, links.ErrDuplicateNeighbor) || errors.Is(err, links.ErrDuplicateLocal) {
		entry, err = s.record(ctx, peer, linkAddr, uint16(req.Msg.IfId))
	}
	if err != nil {
		return nil, err
	}
	s.changed()
	slog.Info("Link established", "neighbor", peer, "local", entry.Local,
		"remote", entry.Remote, "interface", entry.IfID)
	return connect.NewResponse(&nodev1.LinkReply{
		LocalAddr: entry.Local.String(),
		IfId:      uint32(entry.IfID),
	}), nil
}

// record lands the peer's entry as established: a peer the table lacks is
// admitted under the cap with a fresh link address and interface ID.
func (s *LinkService) record(
	ctx context.Context, peer addr.IA, linkAddr netip.AddrPort, remoteIfID uint16,
) (*links.Link, error) {

	entry, err := s.Store.ByNeighbor(ctx, peer)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if entry == nil {
		entries, err := s.Store.All(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("reading the link store: %w", err))
		}
		if live := liveLinks(entries); live >= s.MaxLinks {
			return nil, connect.NewError(connect.CodeResourceExhausted,
				fmt.Errorf("link cap reached (%d)", live))
		}
		local, err := AllocateLinkAddr(s.LinkHost, entries)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		entry = &links.Link{
			NeighborIA: peer,
			Local:      local,
			Remote:     linkAddr,
			RemoteIfID: remoteIfID,
			State:      links.StateEstablished,
		}
		if err := s.Store.Insert(ctx, entry); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	} else {
		// A peer already in the table re-answers with its recorded side; a
		// re-establishment refreshes the requester's addresses without a new
		// interface ID — the cap never blocks a returning neighbor.
		entry.Remote = linkAddr
		entry.RemoteIfID = remoteIfID
		entry.State = links.StateEstablished
		if err := s.Store.Update(ctx, entry); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return entry, nil
}

// liveLinks counts the live entries, the ones the service's cap bounds.
func liveLinks(entries []*links.Link) int {
	live := 0
	for _, l := range entries {
		if l.Live() {
			live++
		}
	}
	return live
}

func (s *LinkService) changed() {
	if s.Changed != nil {
		s.Changed()
	}
}
