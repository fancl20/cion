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

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
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
// the entry as established, and replies with them. The request is the
// confirm: possession establishes, and a request the entry's own link
// observed re-aims the entry's locator at the observation. Served by the
// measured provider, mounted behind the peer middleware.
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
	// Sockets is the socket source the allocated addresses probe through;
	// the zero value is the kernel's.
	Sockets underlay.Sockets
	// Observed returns a serving link's last observed underlay source by
	// interface ID — the data plane's witness of where the peer's packets
	// come from, the record the request's agreement rule reads. Nil serves
	// none and no locator moves.
	Observed func(ifID uint16) netip.AddrPort

	limiterOnce sync.Once
	limiter     *ratelimit.Keyed[addr.IA]
	// mtx serializes the handlers' lookup-and-mutate runs over the store.
	mtx sync.Mutex
}

// rateLimiter returns the admission rate limiter, built on first use so a
// struct literal configuration works.
func (s *LinkService) rateLimiter() *ratelimit.Keyed[addr.IA] {
	s.limiterOnce.Do(func() {
		interval := s.MinInterval
		if interval == 0 {
			interval = LinkMinInterval
		}
		s.limiter = ratelimit.NewKeyed[addr.IA](interval)
	})
	return s.limiter
}

var _ nodev1connect.LinkServiceHandler = (*LinkService)(nil)

// Request admits the caller's link and answers the acceptor's side of it.
// The requester is named by its verified certificate chain; a channel that
// verified no chain serves no identity and the request is refused. The
// request establishes — a candidate it lands on establishes, a live entry's
// identity and the peer's interface ID refresh — and a request whose
// arrival the entry's own link observed takes that observation as the
// entry's locator.
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
	if !s.rateLimiter().Admit(peer) {
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
	// The request's arrival link, the interface the channel names the
	// request's connection by: nonzero exactly when the request rode a
	// one-hop path — the direct hop of the link it confirms.
	arrival := uint16(0)
	if remote := scionrpc.RemoteAddr(ctx); remote != nil {
		arrival = remote.IfID
	}

	// The rendezvous acceptor and the selection's establishment record
	// entries too; the store refuses a neighbor's second live entry and a
	// second live entry on one local address, and a request that loses
	// either race looks again: it refreshes the winner's entry, or records
	// its own on a fresh address.
	s.mtx.Lock()
	defer s.mtx.Unlock()
	entry, err := s.record(ctx, peer, linkAddr, uint16(req.Msg.IfId), arrival)
	if errors.Is(err, links.ErrDuplicateNeighbor) || errors.Is(err, links.ErrDuplicateLocal) {
		entry, err = s.record(ctx, peer, linkAddr, uint16(req.Msg.IfId), arrival)
	}
	if err != nil {
		return nil, err
	}
	slog.Info("Link established", "neighbor", peer, "local", entry.Local,
		"remote", entry.Remote, "interface", entry.IfID)
	return connect.NewResponse(&nodev1.LinkReply{
		LocalAddr: entry.Local.String(),
		IfId:      uint32(entry.IfID),
	}), nil
}

// record lands the peer's entry as established: a peer the table lacks is
// admitted under the cap with a fresh link address and interface ID, its
// locator the link the request arrived on observed when it arrived over a
// direct hop, else the request's claim. A peer the table holds keeps its
// recorded locator unless the request rode the entry's own link — the
// agreement of the request's arrival and the link's latest observation — in
// which case the entry takes that observation as its locator. The identity
// and the peer's interface ID refresh whatever the path the request rode: a
// confirm over a composed path proves the identity without moving anything.
func (s *LinkService) record(
	ctx context.Context,
	peer addr.IA,
	linkAddr netip.AddrPort,
	remoteIfID uint16,
	arrival uint16,
) (*links.Link, error) {

	observed := s.arrivalSource(arrival)
	entry, err := s.Store.ByNeighbor(ctx, peer)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if entry == nil {
		// A request that arrived over a direct hop names its own locator:
		// the link it rode is a link to the requester, and that link's last
		// observed source is the requester's link socket as the underlay
		// spells it.
		if observed.IsValid() {
			linkAddr = observed
		}
		entries, err := s.Store.All(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("reading the link store: %w", err))
		}
		if live := liveLinks(entries); live >= s.MaxLinks {
			return nil, connect.NewError(connect.CodeResourceExhausted,
				fmt.Errorf("link cap reached (%d)", live))
		}
		local, err := AllocateLinkAddr(s.Sockets, s.LinkHost, entries)
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
		// re-establishment refreshes the requester's interface ID without a
		// new one — the cap never blocks a returning neighbor — and the
		// locator moves only when the request rode this entry's own link.
		entry.RemoteIfID = remoteIfID
		entry.State = links.StateEstablished
		if arrival == entry.IfID && observed.IsValid() {
			entry.Remote = observed
		}
		if err := s.Store.Update(ctx, entry); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return entry, nil
}

// arrivalSource returns the last observed underlay source of the link the
// request arrived on — the request's own arrival the latest witness — and
// the zero AddrPort when no link holds the interface or no source serves
// reads. A zero interface, the composed path's mark, observes nothing.
func (s *LinkService) arrivalSource(arrival uint16) netip.AddrPort {
	if arrival == 0 || s.Observed == nil {
		return netip.AddrPort{}
	}
	return s.Observed(arrival)
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
