package testnetwork

import (
	"context"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// TestPathLayerServesTwoCores is the path seam's integration proof: a
// founder and an authoritative core joined per 0037, with a node under each
// and a third node under the founder. Both cores originate, and each core's
// path database holds a core segment of the other; the node under the
// authoritative holds up segments of both origins over its one ingress — the
// collision 0034 keyed the beacon store against, arrived on the real path —
// and registers its down segments with both cores; the third node's lookups
// fetch down segments from each core and compose paths to either child; the
// node first started under the authoritative alone enrolls and pins the
// successor, its retries riding the alternation of the bootstrap slot to the
// founder's fresher beacon.
func TestPathLayerServesTwoCores(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB := hostSlot(t), hostSlot(t)

	// The founding core.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// The authoritative core, joined per 0037: the core flag beside the
	// founder's rendezvous address.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	ctx := context.Background()

	// The join completes before any child starts: the successor TRC names
	// both cores, so the origin checks pass from the first beacon.
	successor := cppki.TRCID{ISD: a.app.IA().ISD(), Base: 1, Serial: 2}
	pinned := func(n *assemblyNode) bool {
		trc, err := n.app.TrustDB().SignedTRC(ctx, successor)
		return err == nil && !trc.IsZero()
	}
	Poll(t, "the founder pinned the successor", func() bool { return pinned(a) })
	Poll(t, "the authoritative pinned the successor", func() bool { return pinned(b) })

	// A node under each core, and a third node under the founder whose
	// lookups exercise the far core.
	c := nodeUnder(t, wpki, a)
	d := nodeUnder(t, wpki, b)
	e := nodeUnder(t, wpki, a)

	// Both cores originate on their core link: each terminates the other's
	// beacon into a core segment of the other.
	Poll(t, "a core segment of the authoritative at the founder", func() bool {
		return holdsSegmentFrom(t, a, pathdb.SegmentTypeCore, b.app.IA())
	})
	Poll(t, "a core segment of the founder at the authoritative", func() bool {
		return holdsSegmentFrom(t, b, pathdb.SegmentTypeCore, a.app.IA())
	})

	// The node under the authoritative enrolls — its retries riding the
	// alternation of the bootstrap slot to the founder's fresher beacon, for
	// the authoritative issues nothing — and pins the successor that names
	// its neighbor a core.
	Poll(t, "the node under the authoritative enrolled", func() bool {
		return holdsAssemblyChain(t, d, d.app.IA())
	})
	Poll(t, "the node under the authoritative pinned the successor", func() bool {
		return pinned(d)
	})

	// It holds up segments of both origins over its one ingress — the
	// founder's beacons propagated down by the authoritative beside the
	// authoritative's originated ones, two origins on one link the
	// origin-keyed store keeps apart. The selection provider may grow the
	// node more links later; the shared ingress the segments record is the
	// collision's own fact.
	Poll(t, "up segments of both origins over one ingress under the authoritative", func() bool {
		return holdsSharedIngressUps(t, d, a.app.IA(), b.app.IA())
	})

	// Its down segments register with both cores: each origin's segments at
	// that core's own control service.
	Poll(t, "down segments of the authoritative's child at the founder", func() bool {
		return holdsDownSegmentsOf(t, a, d.app.IA())
	})
	Poll(t, "down segments of the authoritative's child at the authoritative", func() bool {
		return holdsDownSegmentsOf(t, b, d.app.IA())
	})

	// The third node's lookups fetch down segments from each core — every
	// segment the receiving core holds originates at itself, so an answer
	// of each origin proves both cores answered — and compose paths to
	// either child.
	children := []struct {
		node *assemblyNode
		name string
	}{{c, "the founder's child"}, {d, "the authoritative's child"}}
	for _, child := range children {
		Poll(t, child.name+"'s down segments fetched from each core", func() bool {
			downs := e.app.Lookup().Down(ctx, child.node.app.IA())
			fromFounder, fromAuth := false, false
			for _, seg := range downs {
				if seg.FirstIA().Equal(a.app.IA()) {
					fromFounder = true
				}
				if seg.FirstIA().Equal(b.app.IA()) {
					fromAuth = true
				}
			}
			return fromFounder && fromAuth
		})
		Poll(t, "a path from the third node to "+child.name, func() bool {
			_, err := e.app.Provider().Path(ctx, child.node.app.IA())
			return err == nil
		})
	}
}

// nodeUnder boots a plain node standing under the core alone, its only
// neighbor the core's rendezvous.
func nodeUnder(t *testing.T, wpki *WebPKI, core *assemblyNode) *assemblyNode {
	t.Helper()
	ip := hostSlot(t)
	return bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ip)
		cfg.Control = FreeUDPAddrOn(t, ip)
		cfg.Neighbors = []string{core.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
}

// holdsSegmentFrom reports whether the node's path database holds a segment
// of the type originating at the given core.
func holdsSegmentFrom(
	t *testing.T, n *assemblyNode, typ pathdb.SegmentType, core addr.IA) bool {

	t.Helper()
	segs, err := n.app.PathDB().Get(context.Background(), pathdb.Query{Type: typ})
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range segs {
		if seg.FirstIA().Equal(core) {
			return true
		}
	}
	return false
}

// holdsSharedIngressUps reports whether the node's path database holds up
// segments of both origins whose terminating entries record one shared
// ingress interface — both origins' beacons arrived over one link.
func holdsSharedIngressUps(t *testing.T, n *assemblyNode, one, other addr.IA) bool {
	t.Helper()
	segs, err := n.app.PathDB().Get(context.Background(), pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	ingresses := make(map[addr.IA]map[uint16]bool)
	for _, seg := range segs {
		origin := seg.FirstIA()
		if !origin.Equal(one) && !origin.Equal(other) {
			continue
		}
		last := seg.PCB.Entries[len(seg.PCB.Entries)-1]
		if ingresses[origin] == nil {
			ingresses[origin] = make(map[uint16]bool)
		}
		ingresses[origin][last.Hop.ConsIngress] = true
	}
	if len(ingresses[one]) == 0 || len(ingresses[other]) == 0 {
		return false
	}
	for ifID := range ingresses[one] {
		if ingresses[other][ifID] {
			return true
		}
	}
	return false
}

// holdsDownSegmentsOf reports whether the node's path database holds down
// segments reaching the destination.
func holdsDownSegmentsOf(t *testing.T, n *assemblyNode, dst addr.IA) bool {
	t.Helper()
	segs, err := n.app.PathDB().Get(context.Background(),
		pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: dst})
	if err != nil {
		t.Fatal(err)
	}
	return len(segs) > 0
}
