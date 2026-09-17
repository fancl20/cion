package topology

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
	"github.com/fancl20/cion/pkg/peeria"
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
	resp, err := svc.Request(sctx, connect.NewRequest(&nodev1.LinkRequest{
		LocalAddr: local,
		IfId:      ifID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
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
// verified no chain serves no identity, an unlisted ISD-AS is refused, and
// so is a request past the link cap — while a returning neighbor never is.
func TestLinkServiceRefusals(t *testing.T) {
	// No authenticated peer.
	svc := newLinkService(t, nil)
	if _, err := linkRequest(context.Background(), svc, addr.IA(0), "127.0.0.1:4242", 1); err == nil {
		t.Error("a request without an authenticated ISD-AS was admitted")
	}

	// Unlisted ISD-AS.
	svc = newLinkService(t, func(s *LinkService) {
		s.AllowAS = map[addr.IA]bool{linkIA2: true}
	})
	if _, err := linkRequest(context.Background(), svc, linkIA, "127.0.0.1:4242", 1); err == nil {
		t.Error("a request from an unlisted ISD-AS was admitted")
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
