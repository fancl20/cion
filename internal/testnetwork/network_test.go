package testnetwork

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// startLine brings up the harness's three-node line — the founding core A,
// the middle B, and C below — on the given loopback hosts, its two seeded
// links the placement every line episode builds on.
func startLine(t *testing.T, wpki *WebPKI, ipA, ipB, ipC netip.Addr) (*Node, *Node, *Node) {
	t.Helper()
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
	return a, b, c
}

// TestLineTopology is the line topology's integration test: a three-node
// line — the core A, the middle B, and C below with no A–C link —
// where beacons propagate A→B→C with signatures verified at each hop, C
// enrolls through the reversed beacon over B, C registers a down segment at
// A through B, and the provider resolves an end-to-end path from C to A.
func TestLineTopology(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	a, b, c := startLine(t, wpki, hostSlot(t), hostSlot(t), hostSlot(t))
	ctx := context.Background()

	// Beacons propagate A→B→C with signatures verified at each hop: the
	// beacon store only ever holds verified PCBs.
	Poll(t, "beacons at C", func() bool { return c.StoreBcn.Len() > 0 })
	Poll(t, "beacons at B", func() bool { return b.StoreBcn.Len() > 0 })

	// C enrolls through the reversed beacon over B: no direct A–C link
	// exists, so the enrollment fetch rides the bootstrap route.
	Poll(t, "C enrolled through B", func() bool {
		chains, err := c.TrustDB.Chains(ctx, trustdb.ChainQuery{IA: lineCIA})
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
	// one end to end through C's engine, each entry bound to the identity
	// it claims.
	ups, err := c.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil || len(ups) == 0 {
		t.Fatalf("no up segments at C: %v", err)
	}
	for i := range ups[0].PCB.Entries {
		if _, err := c.Engine.VerifyBound(ctx, ups[0].PCB.Entries[i].IA,
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
	t.Parallel()
	wpki := NewWebPKI(t)
	// B's restart takes a fresh host: the first B's endpoint socket lives
	// to the test's cleanup, its fixed port held against the reboot.
	ipA, ipB1, ipB2 := hostSlot(t), hostSlot(t), hostSlot(t)
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

// TestHostSlotPool is the pool's own proof: the draws name pairwise
// distinct hosts, none inside the reserved /24 below the pool, and the
// pool's end refuses at the draw instead of wrapping.
func TestHostSlotPool(t *testing.T) {
	t.Parallel()
	reserved := netip.MustParsePrefix("127.0.0.0/24")

	// Live draws from the shared counter, each a host no earlier draw named.
	drawn := make(map[netip.Addr]bool, 32)
	for range 32 {
		ip := hostSlot(t)
		if reserved.Contains(ip) {
			t.Errorf("the draw %s names a host inside the reserved %s", ip, reserved)
		}
		if drawn[ip] {
			t.Errorf("the draw %s repeats a host the pool already handed out", ip)
		}
		drawn[ip] = true
	}

	// The whole pool, one host per draw: the first above the boundary, the
	// last below the space's end, every one distinct, none reserved.
	if first, ok := poolHost(1); !ok || first != netip.MustParseAddr("127.0.1.1") {
		t.Errorf("the pool's first host = %v (%v), want 127.0.1.1", first, ok)
	}
	seen := make(map[netip.Addr]bool, poolSize)
	for n := 1; n <= poolSize; n++ {
		ip, ok := poolHost(n)
		if !ok {
			t.Fatalf("draw %d of the pool's %d refused", n, poolSize)
		}
		if reserved.Contains(ip) {
			t.Fatalf("draw %d names %s inside the reserved %s", n, ip, reserved)
		}
		if seen[ip] {
			t.Fatalf("draw %d repeats the host of an earlier draw", n)
		}
		seen[ip] = true
	}
	if last, ok := poolHost(poolSize); !ok || last != netip.MustParseAddr("127.0.255.254") {
		t.Errorf("the pool's last host = %v (%v), want 127.0.255.254", last, ok)
	}
	// The end refuses: a wrapped hand-out would name a host the counter
	// already issued — the first draw past the end truncates to 127.0.0.1,
	// inside the reserved /24 itself.
	if _, ok := poolHost(poolSize + 1); ok {
		t.Error("a draw past the pool's end returned a host, want the refusal")
	}
}

// The test topologies' ISD-ASes, matching pkg/controlplane's.
var (
	coreIA  = addr.MustIAFrom(20, 0xff0000000001)
	nodeIA  = addr.MustIAFrom(20, 0xff0000000002)
	lineCIA = addr.MustIAFrom(20, 0xff0000000003)
)

// poolSize is the pool's size: the 127.0.X.Y loopback space above the
// reserved /24, X from 1, Y skipping the all-zero and all-one bytes that
// read as network and broadcast.
const poolSize = 255 * 254

// hostDraws counts the pool's draws; the counter never resets and never
// wraps, so a host is never reissued within a process. A node's sockets can
// outlive its test — the failed-boot proof's endpoint socket, which
// releases with the process rather than the failed setup, the standing
// example — so a repeated run must draw fresh hosts rather than find its
// fixed ports held for the wrong reason.
var hostDraws atomic.Uint32

// hostSlot draws the next loopback host of the pool the package's labs
// share, so two labs overlap freely, a repeated run draws fresh hosts, and
// no two draws name one host. The pool starts at 127.0.1.1, above
// 127.0.0.0/24 — that /24 belongs to the other packages' fixed loopback
// mounts, and go test runs the packages' processes in parallel — and a draw
// past the pool's end refuses instead of wrapping.
func hostSlot(t *testing.T) netip.Addr {
	t.Helper()
	ip, ok := poolHost(int(hostDraws.Add(1)))
	if !ok {
		t.Fatalf("the pool of %d loopback hosts is drawn dry", poolSize)
	}
	return ip
}

// poolHost returns the n-th draw's host of the pool, n counted from one,
// and whether the pool holds it.
func poolHost(n int) (netip.Addr, bool) {
	if n > poolSize {
		return netip.Addr{}, false
	}
	n--
	return netip.AddrFrom4([4]byte{127, 0, byte(n/254 + 1), byte(n%254 + 1)}), true
}
