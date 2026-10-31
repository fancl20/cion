package measured

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
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
// observed re-aims the entry's locator at the observation. Each end tells
// the other how it sees the other on the link and whether the other's
// rendezvous port answered there. Served by the measured provider, mounted
// behind the peer middleware.
type LinkService struct {
	// Store is the neighbor table.
	Store links.DB
	// MaxLinks caps the live link count.
	MaxLinks int
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// MinInterval is the least pause between admissions of one peer's
	// requests of one kind — link requests, probe punches, and link
	// punches; zero uses each kind's default.
	MinInterval time.Duration
	// Sockets is the socket source the allocated addresses probe through;
	// the zero value is the kernel's.
	Sockets underlay.Sockets
	// Links is the node's link state topic. Each serving link's observed
	// source, the data plane's witness of where the peer's packets come
	// from, is the record the request's agreement rule reads, and a link's
	// punch takes over a caller's standing entry only while the entry's
	// verdict is down. A nil topic observes nothing, so no locator moves, and
	// reports every link up.
	Links *bus.Topic[bus.LinkState]
	// Reflector returns the rendezvous address of a neighbor in the
	// directory the ID names, whose acceptor answers the binding requests a
	// punch learns its socket's reflexive address by, and fails when none
	// answers. Nil punches nothing.
	Reflector func(ctx context.Context, id bus.DirectoryID) (netip.AddrPort, error)
	// Punching reports whether the node's own link punch toward the peer is
	// in flight; nil reports none.
	Punching func(peer addr.IA) bool
	// Echo sends a binding request to a rendezvous address and reports
	// whether it answered: the check of the requester's rendezvous port at
	// the host the node sees it at.
	Echo func(ctx context.Context, target netip.AddrPort) bool
	// Seen records what a request reports of the node on the link it
	// confirms: the host the requester sees the node at, and whether the
	// node's rendezvous port answered the requester's echo there.
	Seen func(ifID uint16, observed netip.AddrPort, answered bool)

	limiterOnce sync.Once
	limiter     *ratelimit.Keyed[addr.IA]
	punchOnce   sync.Once
	punches     *ratelimit.Keyed[punchKey]
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
// entry's locator. The node records what the request reports of it, and the
// reply tells the requester the entry's locator — how the node sees it —
// and whether the requester's rendezvous port answered there.
func (s *LinkService) Request(
	ctx context.Context,
	req *nodev1.LinkRequest,
) (*nodev1.LinkReply, error) {

	if req == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "no link request")
	}
	peer := peeria.AuthenticatedIA(ctx)
	if peer.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS; the channel verified no chain")
	}
	if !s.rateLimiter().Admit(peer) {
		return nil, connect.Errorf(connect.CodeResourceExhausted,
			"peer %s exceeds the admission rate", peer)
	}
	linkAddr, err := netip.ParseAddrPort(req.LocalAddr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"parsing the requester's link address").WithCause(err)
	}
	if req.IfId > 0xffff {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"interface ID out of range")
	}
	mine, err := netip.ParseAddrPort(req.Observed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"parsing the requester's observation").WithCause(err)
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
	entry, err := s.record(ctx, peer, linkAddr, uint16(req.IfId), arrival)
	if errors.Is(err, links.ErrDuplicateNeighbor) || errors.Is(err, links.ErrDuplicateLocal) {
		entry, err = s.record(ctx, peer, linkAddr, uint16(req.IfId), arrival)
	}
	s.mtx.Unlock()
	if err != nil {
		return nil, err
	}
	slog.Info("Link established", "neighbor", peer, "local", entry.Local,
		"remote", entry.Remote, "interface", entry.IfID)
	s.Seen(entry.IfID, mine, req.RendezvousAnswered)
	// The echo runs outside the lock: an unanswered one spends its whole
	// timeout.
	return &nodev1.LinkReply{
		LocalAddr:          entry.Local.String(),
		IfId:               uint32(entry.IfID),
		Observed:           entry.Remote.String(),
		RendezvousAnswered: s.Echo(ctx, netip.AddrPortFrom(entry.Remote.Addr(), RendezvousPort)),
	}, nil
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
		return nil, connect.NewError(connect.CodeInternal,
			"reading the neighbor table").WithCause(err)
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
				"reading the link store").WithCause(err)
		}
		if live := liveLinks(entries); live >= s.MaxLinks {
			return nil, connect.Errorf(connect.CodeResourceExhausted,
				"link cap reached (%d)", live)
		}
		local, err := AllocateLinkAddr(s.Sockets, s.LinkHost, entries)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				"allocating the link address").WithCause(err)
		}
		entry = &links.Link{
			NeighborIA: peer,
			Local:      local,
			Remote:     linkAddr,
			RemoteIfID: remoteIfID,
			State:      links.StateEstablished,
		}
		if err := s.Store.Insert(ctx, entry); err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				"recording the entry").WithCause(err)
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
			return nil, connect.NewError(connect.CodeInternal,
				"recording the entry").WithCause(err)
		}
	}
	return entry, nil
}

// arrivalSource returns the last observed underlay source of the link the
// request arrived on — the request's own arrival the latest witness — and
// the zero AddrPort when the link state holds none for the interface. A
// zero interface, the composed path's mark, observes nothing.
func (s *LinkService) arrivalSource(arrival uint16) netip.AddrPort {
	if arrival == 0 {
		return netip.AddrPort{}
	}
	return s.Links.Latest().Observed(arrival)
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
