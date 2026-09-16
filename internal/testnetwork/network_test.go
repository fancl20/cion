package testnetwork

import (
	"context"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/trust"
)

// TestLineTopology is the integration test of proposal 0004: a three-node
// line topology — the core A, the middle B, and C below with no A–C link —
// where beacons propagate A→B→C with signatures verified at each hop, C
// enrolls through the reversed beacon over B, C registers a down segment at
// A through B, and the provider resolves an end-to-end path from C to A.
func TestLineTopology(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA := addrIP(2)
	ipB := addrIP(3)
	ipC := addrIP(4)
	extA, extB1 := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	extB2, extC := FreeUDPAddrOn(t, ipB), FreeUDPAddrOn(t, ipC)

	a := StartNode(t, NodeConfig{IA: coreIA, Host: ipA, Links: []Link{
		{Local: extA, Remote: extB1, Neighbor: nodeIA},
	}, Core: true, WPKI: wpki})
	b := StartNode(t, NodeConfig{IA: nodeIA, Host: ipB, Links: []Link{
		{Local: extB1, Remote: extA, Neighbor: coreIA},
		{Local: extB2, Remote: extC, Neighbor: lineCIA},
	}, WPKI: wpki})
	c := StartNode(t, NodeConfig{IA: lineCIA, Host: ipC, Links: []Link{
		{Local: extC, Remote: extB2, Neighbor: nodeIA},
	}, WPKI: wpki})
	ctx := context.Background()

	// Beacons propagate A→B→C with signatures verified at each hop: the
	// beacon store only ever holds verified PCBs.
	Poll(t, "beacons at C", func() bool { return c.StoreBcn.Len() > 0 })
	Poll(t, "beacons at B", func() bool { return b.StoreBcn.Len() > 0 })

	// C enrolls through the reversed beacon over B: no direct A–C link
	// exists, so the enrollment fetch rides the bootstrap route.
	Poll(t, "C enrolled through B", func() bool {
		chains, err := c.TrustDB.Chains(ctx, trust.ChainQuery{IA: lineCIA})
		return err == nil && len(chains) > 0
	})
	trc, err := c.TrustDB.SignedTRC(ctx, cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	if trc.IsZero() {
		t.Fatal("C did not pin the TRC")
	}

	// C registers a down segment at A through B: A's path database holds the
	// segment to C.
	Poll(t, "down segment at A", func() bool {
		segs, err := a.PathDB.Get(ctx, pathdb.Query{
			Type: pathdb.SegmentTypeDown, DstIA: lineCIA})
		return err == nil && len(segs) > 0
	})

	// The provider resolves an end-to-end path from C to A: the reversed up
	// segment [A, B, C].
	Poll(t, "path from C to A", func() bool {
		path, err := c.Provider.Path(ctx, coreIA)
		return err == nil && path != nil && len(path.HopFields) == 3
	})
	path, err := c.Provider.Path(ctx, coreIA)
	if err != nil {
		t.Fatal(err)
	}
	if path.InfoFields[0].ConsDir {
		t.Error("route to the core is not reversed")
	}

	// B keeps its own up segment, and its provider reaches the core over it.
	Poll(t, "B up segment", func() bool {
		segs, err := b.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
		return err == nil && len(segs) > 0
	})

	// The up segments C terminates carry the full line's signatures; verify
	// one end to end through C's engine.
	ups, err := c.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil || len(ups) == 0 {
		t.Fatalf("no up segments at C: %v", err)
	}
	for i := range ups[0].PCB.Entries {
		if _, err := c.Engine.Verify(ctx,
			ups[0].PCB.Entries[i].Signed, ups[0].PCB.AssociatedData(i)...); err != nil {
			t.Fatalf("up segment entry %d does not verify: %v", i, err)
		}
	}
	if !ups[0].FirstIA().Equal(coreIA) || !ups[0].LastIA().Equal(lineCIA) {
		t.Errorf("up segment = %v..%v, want the full line",
			ups[0].FirstIA(), ups[0].LastIA())
	}
}

// TestRestartedNodeServesUpSegments checks that a restarted node serves up
// segments from the persistent path database before the next beaconing
// period.
func TestRestartedNodeServesUpSegments(t *testing.T) {
	wpki := NewWebPKI(t)
	// Loopback addresses of its own, so the still-running endpoints of
	// earlier tests keep their fixed ports.
	ipA := addrIP(5)
	ipB1 := addrIP(6)
	ipB2 := addrIP(7)
	dir := t.TempDir()
	extA, extB1 := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB1)

	StartNode(t, NodeConfig{IA: coreIA, Host: ipA, Links: []Link{
		{Local: extA, Remote: extB1, Neighbor: nodeIA},
	}, Core: true, WPKI: wpki})
	b := StartNode(t, NodeConfig{IA: nodeIA, Host: ipB1, StateDir: dir, Links: []Link{
		{Local: extB1, Remote: extA, Neighbor: coreIA},
	}, WPKI: wpki})
	ctx := context.Background()

	Poll(t, "B up segment", func() bool {
		segs, err := b.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
		return err == nil && len(segs) > 0
	})

	// Stop B's loops and release its databases; a restarted node — the same
	// state directory, a fresh underlay presence — serves the up segments
	// before the next beaconing period.
	b.cancel()
	if err := b.PeerClt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.PathDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.TrustDB.Close(); err != nil {
		t.Fatal(err)
	}
	// The link store's lock released with the cancellation; wait for it so
	// the restarted node opens a settled database.
	Poll(t, "the link store to release", func() bool {
		_, err := b.Store.All(context.Background())
		return err != nil
	})
	extB2 := FreeUDPAddrOn(t, ipB2)
	b2 := StartNode(t, NodeConfig{IA: nodeIA, Host: ipB2, StateDir: dir, Links: []Link{
		{Local: extB2, Remote: extA, Neighbor: coreIA},
	}, WPKI: wpki})
	segs, err := b2.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("restarted node serves no up segments before the next beaconing period")
	}
	path, err := b2.Provider.Path(ctx, coreIA)
	if err != nil {
		t.Fatalf("restarted node cannot route to the core: %v", err)
	}
	if len(path.HopFields) != 2 {
		t.Errorf("route to the core = %d hops, want 2", len(path.HopFields))
	}
}

// The test topologies' ISD-ASes, matching pkg/controlplane's.
var (
	coreIA  = addr.MustIAFrom(20, 0xff0000000001)
	nodeIA  = addr.MustIAFrom(20, 0xff0000000002)
	lineCIA = addr.MustIAFrom(20, 0xff0000000003)
)

// addrIP returns the n-th 127.0.0.x loopback address.
func addrIP(last byte) netip.Addr {
	return netip.AddrFrom4([4]byte{127, 0, 0, last})
}
