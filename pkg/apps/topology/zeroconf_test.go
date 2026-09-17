package topology

import (
	"context"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
	"github.com/fancl20/cion/pkg/scion"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// zeroconfDraw is a first start's provisional draw: a private-range ISD-AS
// whose ISD the provider completes.
var zeroconfDraw = addr.MustIAFrom(20, 0xfd0000000051)

// TestZeroconfCompletesByEcho checks the measured completion: a first
// start's provisional ISD draw is completed from a bootstrap neighbor's
// rendezvous reply — the AS drawn kept, the ISD the network's — with the
// bootstrap remembered so the seed lands retargeted.
func TestZeroconfCompletesByEcho(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z := NewZeroconf(ZeroconfConfig{
		Neighbors:   []string{f.addr.String()},
		ControlHost: netip.MustParseAddr("127.0.0.1"),
	})
	ia, err := z.CompleteIdentity(context.Background(), zeroconfDraw)
	if err != nil {
		t.Fatal(err)
	}
	if ia.ISD() != rendezvousIA.ISD() {
		t.Errorf("completed ISD = %d, want the answering neighbor's %d",
			ia.ISD(), rendezvousIA.ISD())
	}
	if ia.AS() != zeroconfDraw.AS() {
		t.Errorf("completed AS = %x, want the drawn %x", ia.AS(), zeroconfDraw.AS())
	}
	if z.bootstrap == nil || z.bootstrap.target != f.addr {
		t.Error("the bootstrap's reply was not kept for the seed")
	}

	// The seed lands the bootstrap's neighbor retargeted: the reply's
	// addresses carry, the entry a candidate.
	store := memory.New()
	z.Wire(Pieces{IA: ia, Store: store})
	if err := z.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry, err := store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no seeded entry (%v)", err)
	}
	if entry.State != links.StateCandidate || entry.Remote != z.bootstrap.reply.LinkAddr {
		t.Errorf("seeded entry = %+v, want the retargeted candidate", entry)
	}
}

// TestZeroconfCoreDrawIsFinal checks the founding core's completion: its
// draw is its network's name already, so the identity returns unchanged and
// no dial is made — a dead rendezvous would fail it.
func TestZeroconfCoreDrawIsFinal(t *testing.T) {
	z := NewZeroconf(ZeroconfConfig{
		Core:      true,
		Neighbors: []string{"127.0.0.1:1"}, // nothing answers there
	})
	ia, err := z.CompleteIdentity(context.Background(), zeroconfDraw)
	if err != nil {
		t.Fatal(err)
	}
	if ia != zeroconfDraw {
		t.Errorf("the core's completed identity = %v, want the draw %v", ia, zeroconfDraw)
	}
}

// TestZeroconfFirstStartNeedsNeighbor checks the measured provider's half of
// the first-start neighbor requirement: a non-core with no --neighbor and an
// empty store refuses to start, one with a neighbor does not.
func TestZeroconfFirstStartNeedsNeighbor(t *testing.T) {
	z := NewZeroconf(ZeroconfConfig{})
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err == nil {
		t.Error("a non-core's first start without a --neighbor completed")
	}
	z = NewZeroconf(ZeroconfConfig{Neighbors: []string{"127.0.0.1:1"}})
	z.Wire(Pieces{Store: memory.New()})
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err == nil {
		t.Error("a first start whose bootstrap neighbor never answered completed")
	}
	// The same empty store seeds cleanly once a neighbor is named and
	// answered — the requirement is the neighbor, not the store.
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z = NewZeroconf(ZeroconfConfig{Neighbors: []string{f.addr.String()}})
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err != nil {
		t.Fatal(err)
	}
	z.Wire(Pieces{Store: memory.New()})
	if err := z.Seed(context.Background()); err != nil {
		t.Fatalf("seeding with a bootstrap neighbor: %v", err)
	}
}

// TestZeroconfMounts checks the mounts: the measured provider mounts the
// in-band link service on every node and the node directory's service
// beside it on the core, at the patterns the handlers name.
func TestZeroconfMounts(t *testing.T) {
	// Each join takes its own loopback host so the two rendezvous ports
	// do not clash; the connections are absent, the mounts being the test's
	// subject.
	joined := func(t *testing.T, host string, core bool) []string {
		t.Helper()
		z := NewZeroconf(ZeroconfConfig{
			Core:        core,
			ControlHost: netip.MustParseAddr(host),
			NewConn:     func() (*scion.Conn, error) { return nil, nil },
			CoreRoute:   func() *scion.Addr { return nil },
		})
		z.Wire(Pieces{Store: memory.New()})
		// Mounts binds the rendezvous port; releasing it lets a rerun of the
		// test in the same process bind it again.
		t.Cleanup(func() { z.Close() }) //nolint:errcheck
		mounts, err := z.Mounts()
		if err != nil {
			t.Fatal(err)
		}
		patterns := make([]string, 0, len(mounts))
		for _, m := range mounts {
			patterns = append(patterns, m.Pattern)
		}
		return patterns
	}
	linkPath := "/" + nodev1connect.LinkServiceName + "/"
	directoryPath := "/" + nodev1connect.DirectoryServiceName + "/"
	if got := joined(t, "127.0.0.1", false); len(got) != 1 || got[0] != linkPath {
		t.Errorf("a non-core's mounts = %v, want the link service's alone", got)
	}
	got := joined(t, "127.0.0.2", true)
	if len(got) != 2 || got[0] != linkPath || got[1] != directoryPath {
		t.Errorf("the core's mounts = %v, want the link and directory services'", got)
	}
}
