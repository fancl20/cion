package measured

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

var (
	linkIA  = addr.MustIAFrom(20, 0xfd0000000031)
	linkIA2 = addr.MustIAFrom(20, 0xfd0000000032)
)

// newLinkService builds a link service over a memory store.
func newLinkService(t *testing.T, mutate func(*LinkService)) *LinkService {
	t.Helper()
	svc := &LinkService{
		Store:       memory.New(),
		MaxLinks:    8,
		LinkHost:    netip.MustParseAddr("127.0.0.1"),
		MinInterval: time.Second,
	}
	if mutate != nil {
		mutate(svc)
	}
	if svc.Store == nil {
		svc.Store = memory.New()
	}
	return svc
}

// linkRequest calls the handler as the authenticated peer — the identity the
// middleware peers into the context.
func linkRequest(
	ctx context.Context, svc *LinkService, peer addr.IA, local string, ifID uint32,
) (*nodev1.LinkReply, error) {

	sctx := context.WithValue(ctx, peeria.AuthenticatedIAContextKey(), peer)
	reply, err := svc.Request(sctx, &nodev1.LinkRequest{
		LocalAddr: local,
		IfId:      ifID,
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// linkEntry returns the peer's recorded entry.
func linkEntry(t *testing.T, svc *LinkService, peer addr.IA) *links.Link {
	t.Helper()
	entry, err := svc.Store.ByNeighbor(context.Background(), peer)
	if err != nil || entry == nil {
		t.Fatalf("no entry for %s (%v)", peer, err)
	}
	return entry
}

// staleStore is a memory link store whose next neighbor lookup misses once
// armed: the view of a writer that looked the neighbor up just before
// another writer recorded it.
type staleStore struct {
	*memory.DB
	armed atomic.Bool
}

func (s *staleStore) ByNeighbor(ctx context.Context, ia addr.IA) (*links.Link, error) {
	if s.armed.CompareAndSwap(true, false) {
		return nil, nil
	}
	return s.DB.ByNeighbor(ctx, ia)
}

// TestLinkServiceLosesRecordRace checks a request that loses the race to
// record its peer: the rendezvous acceptor records the peer between the
// service's lookup and its insert, the store refuses the second live entry,
// and the request refreshes the recorded one, answering with its side.
func TestLinkServiceLosesRecordRace(t *testing.T) {
	store := &staleStore{DB: memory.New()}
	svc := newLinkService(t, func(s *LinkService) { s.Store = store })
	minted := liveLink(linkIA, 40001)
	minted.State = links.StateCandidate
	if err := store.Insert(context.Background(), minted); err != nil {
		t.Fatal(err)
	}
	store.armed.Store(true)
	reply, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 9)
	if err != nil {
		t.Fatal(err)
	}
	if got := netip.MustParseAddrPort(reply.LocalAddr); got != minted.Local ||
		reply.IfId != uint32(minted.IfID) {
		t.Errorf("reply = %v/%d, want the recorded entry's %v/%d",
			got, reply.IfId, minted.Local, minted.IfID)
	}
	want := []links.State{links.StateEstablished}
	if got := statesOf(t, store.DB, linkIA); !slices.Equal(got, want) {
		t.Errorf("the peer's entries = %v, want the recorded one alone, established", got)
	}
	if entry := linkEntry(t, svc, linkIA); entry.IfID != minted.IfID || entry.RemoteIfID != 9 {
		t.Errorf("the peer's entry = %+v, want the recorded one with the request's side", entry)
	}
}

// squattedStore is a memory link store whose next insert of an entry with
// a local address finds the address taken once armed: the view of a writer
// that drew a port another writer recorded between the draw and the insert.
// The squatter is a seeded entry, live with no remote, so only the local
// rule refuses the writer.
type squattedStore struct {
	*memory.DB
	armed    atomic.Bool
	squatter *links.Link
}

func (s *squattedStore) Insert(ctx context.Context, l *links.Link) error {
	if l.Local.IsValid() && s.armed.CompareAndSwap(true, false) {
		s.squatter = &links.Link{Local: l.Local, State: links.StateCandidate}
		if err := s.DB.Insert(ctx, s.squatter); err != nil {
			return err
		}
	}
	return s.DB.Insert(ctx, l)
}

// lostPortRace checks the outcome of a writer's lost race for the port it
// drew: the squatter's entry stands on the address, and the neighbor's
// entry, the one the writer answered with, lies on another.
func lostPortRace(t *testing.T, store *squattedStore, ia addr.IA, answered netip.AddrPort) {
	t.Helper()
	if store.squatter == nil {
		t.Fatal("the writer inserted no entry on a drawn address")
	}
	entries, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var squatter, entry *links.Link
	for _, l := range entries {
		switch {
		case l.IfID == store.squatter.IfID:
			squatter = l
		case l.Live() && l.NeighborIA.Equal(ia):
			entry = l
		}
	}
	if squatter == nil || !squatter.Live() || squatter.Local != store.squatter.Local {
		t.Errorf("the squatter's entry = %+v, want it live on %v", squatter, store.squatter.Local)
	}
	if entry == nil {
		t.Fatalf("no live entry of %s", ia)
	}
	if !entry.Local.IsValid() || entry.Local == store.squatter.Local {
		t.Errorf("the entry of %s lies on %v, want another address than the squatter's",
			ia, entry.Local)
	}
	if answered != entry.Local {
		t.Errorf("the writer answered %v, want its entry's %v", answered, entry.Local)
	}
}

// TestLinkServiceLosesPortRace checks a request that loses the race for
// the port it drew: another writer records an entry on that address
// between the service's draw and its insert, the store refuses a second
// live entry on it, and the request records its own entry on a fresh
// address.
func TestLinkServiceLosesPortRace(t *testing.T) {
	store := &squattedStore{DB: memory.New()}
	svc := newLinkService(t, func(s *LinkService) { s.Store = store })
	store.armed.Store(true)
	reply, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 9)
	if err != nil {
		t.Fatal(err)
	}
	lostPortRace(t, store, linkIA, netip.MustParseAddrPort(reply.LocalAddr))
}

// TestLinkServiceAdmits checks the in-band establishment: the authenticated
// peer's link is recorded as established with both sides' addresses, the
// reply carrying the acceptor's. The rate cap reads the clock, so the test
// runs in a bubble: the pause past the interval is a fake-time sleep,
// instant and never a real-time race.
func TestLinkServiceAdmits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The rate cap is loose here: the re-request below is a refresh, not a
		// burst.
		svc := newLinkService(t, func(s *LinkService) { s.MinInterval = time.Millisecond })
		reply, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 9)
		if err != nil {
			t.Fatal(err)
		}
		entry := linkEntry(t, svc, linkIA)
		if entry.State != links.StateEstablished {
			t.Errorf("state = %v, want established", entry.State)
		}
		if entry.Remote != netip.MustParseAddrPort("127.0.0.1:4242") || entry.RemoteIfID != 9 {
			t.Errorf("requester side = %v/%d, want the request's", entry.Remote, entry.RemoteIfID)
		}
		if got := netip.MustParseAddrPort(reply.LocalAddr); got != entry.Local {
			t.Errorf("reply address = %v, want the entry's %v", got, entry.Local)
		}
		if reply.IfId != uint32(entry.IfID) {
			t.Errorf("reply interface ID = %d, want the entry's %d", reply.IfId, entry.IfID)
		}

		// A re-request refreshes the requester's addresses without a new
		// interface ID.
		time.Sleep(2 * time.Millisecond)
		reply2, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4243", 10)
		if err != nil {
			t.Fatal(err)
		}
		if reply2.IfId != reply.IfId {
			t.Error("a re-establishment allocated a second interface ID")
		}
		if entry := linkEntry(t, svc, linkIA); entry.RemoteIfID != 10 {
			t.Errorf("the re-request did not refresh the remote interface ID: %v", entry)
		}
	})
}

// TestLinkServiceRefusals checks the admission policy: a channel that
// verified no chain serves no identity, and so does a request past the link
// cap refuse — while a returning neighbor never is.
func TestLinkServiceRefusals(t *testing.T) {
	// No authenticated peer.
	svc := newLinkService(t, nil)
	if _, err := linkRequest(context.Background(), svc, addr.IA(0), "127.0.0.1:4242", 1); err == nil {
		t.Error("a request without an authenticated ISD-AS was admitted")
	}

	// The link cap.
	svc = newLinkService(t, func(s *LinkService) {
		s.MaxLinks = 1
	})
	if err := svc.Store.Insert(context.Background(), &links.Link{
		NeighborIA: linkIA2,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateEstablished,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 1); err == nil {
		t.Error("a request past the link cap was admitted")
	}
	// A returning neighbor is never blocked by the cap.
	if _, err := linkRequest(context.Background(), svc, linkIA2, "127.0.0.1:4243", 2); err != nil {
		t.Errorf("a returning neighbor was refused at the cap: %v", err)
	}

	// A malformed address and an out-of-range interface ID.
	svc = newLinkService(t, nil)
	if _, err := linkRequest(context.Background(), svc, linkIA, "not-an-address", 1); err == nil {
		t.Error("a request with a malformed address was admitted")
	}
	if _, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 1<<20); err == nil {
		t.Error("a request with an out-of-range interface ID was admitted")
	}
}

// TestLinkServiceRateCap checks the peer rate cap: a burst of requests from
// one peer is admitted once per interval.
func TestLinkServiceRateCap(t *testing.T) {
	svc := newLinkService(t, nil)
	if _, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 1); err == nil {
		t.Error("a burst of requests from one peer was admitted twice inside the interval")
	}
}

// arriving dials the handler as a peer whose request arrived on the given
// interface — the one-hop arrival's mark, the interface the channel names
// the connection by.
func arriving(
	ctx context.Context, svc *LinkService, peer addr.IA, local string, ifID uint32,
	arrival uint16,
) (*nodev1.LinkReply, error) {

	sctx := context.WithValue(ctx, peeria.AuthenticatedIAContextKey(), peer)
	sctx = context.WithValue(sctx, http3.RemoteAddrContextKey,
		&scion.Addr{IA: peer, IfID: arrival})
	reply, err := svc.Request(sctx, &nodev1.LinkRequest{
		LocalAddr: local,
		IfId:      ifID,
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// TestLinkServiceConfirmInstallsObservation checks the confirm's agreement
// rule: a request that arrived on the entry's own link — the one-hop arrival
// the channel names — takes that link's last observed source as the entry's
// locator and establishes the candidate it landed on; a request whose
// arrival the entry does not name — a composed path's zero mark, another
// link's interface — refreshes the identity and the peer's interface ID
// without moving the locator; and a peer the table lacks records the
// observation of the link its request rode.
func TestLinkServiceConfirmInstallsObservation(t *testing.T) {
	observed := netip.MustParseAddrPort("192.0.2.9:54321")
	// observing builds a service whose interface 7 observed the address.
	observing := func() *LinkService {
		return newLinkService(t, func(s *LinkService) {
			s.MinInterval = time.Millisecond
			s.Observed = func(ifID uint16) netip.AddrPort {
				if ifID == 7 {
					return observed
				}
				return netip.AddrPort{}
			}
		})
	}

	t.Run("the entry's own link", func(t *testing.T) {
		svc := observing()
		candidate := liveLink(linkIA, 40001)
		candidate.State = links.StateCandidate
		// The entry's interface is the one the arrival names: the link the
		// request rode and the entry's are one.
		candidate.IfID = 7
		if err := svc.Store.Insert(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if _, err := arriving(context.Background(), svc, linkIA,
			"127.0.0.1:4242", 9, 7); err != nil {
			t.Fatal(err)
		}
		entry := linkEntry(t, svc, linkIA)
		if entry.State != links.StateEstablished {
			t.Errorf("the candidate the confirm landed on is %v, want established", entry.State)
		}
		if entry.Remote != observed {
			t.Errorf("entry remote = %v, want the link's observation %v", entry.Remote, observed)
		}
		if entry.RemoteIfID != 9 {
			t.Errorf("entry remote interface = %d, want the request's 9", entry.RemoteIfID)
		}
	})

	t.Run("another link's arrival", func(t *testing.T) {
		svc := observing()
		held := liveLink(linkIA, 40001)
		if err := svc.Store.Insert(context.Background(), held); err != nil {
			t.Fatal(err)
		}
		if held.IfID == 7 {
			t.Fatal("the fixture drew the observing interface; the test needs another")
		}
		// The arrival names the interface the data plane keyed on, which the
		// entry does not hold: the observation installs nothing.
		if _, err := arriving(context.Background(), svc, linkIA,
			"127.0.0.1:4242", 9, 7); err != nil {
			t.Fatal(err)
		}
		entry := linkEntry(t, svc, linkIA)
		if entry.Remote != held.Remote {
			t.Errorf("entry remote = %v, want the recorded %v untouched", entry.Remote, held.Remote)
		}
		if entry.RemoteIfID != 9 {
			t.Errorf("entry remote interface = %d, want the identity refreshed to 9",
				entry.RemoteIfID)
		}
	})

	t.Run("a composed path", func(t *testing.T) {
		svc := observing()
		held := liveLink(linkIA, 40001)
		if err := svc.Store.Insert(context.Background(), held); err != nil {
			t.Fatal(err)
		}
		if _, err := arriving(context.Background(), svc, linkIA,
			"127.0.0.1:4243", 11, 0); err != nil {
			t.Fatal(err)
		}
		entry := linkEntry(t, svc, linkIA)
		if entry.Remote != held.Remote {
			t.Errorf("entry remote = %v, want the recorded %v untouched", entry.Remote, held.Remote)
		}
		if entry.RemoteIfID != 11 {
			t.Errorf("entry remote interface = %d, want 11", entry.RemoteIfID)
		}
	})

	t.Run("a peer the table lacks", func(t *testing.T) {
		svc := observing()
		if _, err := arriving(context.Background(), svc, linkIA2,
			"127.0.0.1:4242", 4, 7); err != nil {
			t.Fatal(err)
		}
		entry := linkEntry(t, svc, linkIA2)
		if entry.State != links.StateEstablished {
			t.Errorf("state = %v, want established", entry.State)
		}
		if entry.Remote != observed {
			t.Errorf("entry remote = %v, want the arrival link's observation %v",
				entry.Remote, observed)
		}
	})
}
