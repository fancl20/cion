package testnetwork

import (
	"context"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// TestLineTopology is the line topology's integration test: a three-node
// line — the core A, the middle B, and C below with no A–C link —
// where beacons propagate A→B→C with signatures verified at each hop, C
// enrolls through the reversed beacon over B, C registers a down segment at
// A through B, and the provider resolves an end-to-end path from C to A.
// Fresher originations then replace their route's segment in every path
// database, and the enumerations between B and C — whose meetings leave a
// part idle — compose one candidate each.
func TestLineTopology(t *testing.T) {
	t.Parallel()
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA},
		links: [][2]addr.IA{{coreIA, nodeIA}, {nodeIA, lineCIA}},
	})
	a, b, c := nodes[coreIA], nodes[nodeIA], nodes[lineCIA]
	ctx := t.Context()

	// Beacons propagate A→B→C with signatures verified at each hop: a path
	// database holds only verified segments, and B and C each keep the up
	// segments they terminate.
	Poll(t, "up segments at C", func() bool { return holdsUpSegments(ctx, c.Node) })
	Poll(t, "up segments at B", func() bool { return holdsUpSegments(ctx, b.Node) })

	// C enrolls through the reversed beacon over B: no direct A–C link
	// exists, so the enrollment fetch rides the bootstrap route.
	Poll(t, "C enrolled through B", func() bool {
		chains, err := c.app.TrustDB().Chains(ctx, trustdb.ChainQuery{IA: lineCIA})
		return err == nil && len(chains) > 0
	})
	trc, err := c.app.TrustDB().SignedTRC(ctx,
		cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	if trc.IsZero() {
		t.Fatal("C did not pin the TRC")
	}

	// C registers a down segment at A through B: A's path database holds the
	// segment to C.
	Poll(t, "down segment at A", func() bool {
		segs, err := a.app.PathDB().Get(ctx, pathdb.Query{
			Type: pathdb.SegmentTypeDown, DstIA: lineCIA})
		return err == nil && len(segs) > 0
	})

	// The provider resolves an end-to-end path from C to A: the reversed up
	// segment [A, B, C].
	Poll(t, "path from C to A", func() bool {
		path, err := c.app.Provider().Path(ctx, coreIA)
		return err == nil && path != nil && len(path.HopFields) == 3
	})
	path, err := c.app.Provider().Path(ctx, coreIA)
	if err != nil {
		t.Fatal(err)
	}
	if path.InfoFields[0].ConsDir {
		t.Error("route to the core is not reversed")
	}

	// The up segments C terminates carry the full line's signatures; verify
	// one end to end through C's engine, each entry bound to the identity
	// it claims.
	ups, err := c.app.PathDB().Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil || len(ups) == 0 {
		t.Fatalf("no up segments at C: %v", err)
	}
	for i := range ups[0].PCB.Entries {
		if _, err := c.app.Engine().VerifyBound(ctx, ups[0].PCB.Entries[i].IA, nil,
			ups[0].PCB.Entries[i].Signed, ups[0].PCB.AssociatedData(i)...); err != nil {
			t.Fatalf("up segment entry %d does not verify: %v", i, err)
		}
	}
	if !ups[0].FirstIA().Equal(coreIA) || !ups[0].LastIA().Equal(lineCIA) {
		t.Errorf("up segment = %v..%v, want the full line",
			ups[0].FirstIA(), ups[0].LastIA())
	}

	// Once C terminates a fresher origination, every path database still
	// holds one segment per route: the line has one route to each node.
	first := ups[0].PCB.Timestamp()
	Poll(t, "a fresher origination at C", func() bool {
		segs, err := c.app.PathDB().Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
		if err != nil {
			return false
		}
		for _, seg := range segs {
			if seg.PCB.Timestamp().After(first) {
				return true
			}
		}
		return false
	})
	for _, h := range []struct {
		name string
		node *staticNode
		q    pathdb.Query
	}{
		{"B's up segments", b, pathdb.Query{Type: pathdb.SegmentTypeUp}},
		{"C's up segments", c, pathdb.Query{Type: pathdb.SegmentTypeUp}},
		{"A's down segments to B", a, pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: nodeIA}},
		{"A's down segments to C", a, pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: lineCIA}},
	} {
		held := 0
		Poll(t, h.name, func() bool {
			segs, err := h.node.app.PathDB().Get(ctx, h.q)
			held = len(segs)
			return err == nil && held > 0
		})
		if held != 1 {
			t.Errorf("%s = %d, want the route's one", h.name, held)
		}
	}
	// B meets C's down segment at B itself, and C meets B's down segment at
	// B, the destination: either way one part idles, and the one route
	// composes one candidate.
	for _, e := range []struct {
		name string
		from *staticNode
		to   addr.IA
	}{{"from B to C", b, lineCIA}, {"from C to B", c, nodeIA}} {
		composed := 0
		Poll(t, "candidates "+e.name, func() bool {
			candidates, err := e.from.app.Provider().Enumerate(ctx, e.to)
			composed = len(candidates)
			return err == nil && composed > 0
		})
		if composed != 1 {
			t.Errorf("candidates %s = %d, want the route's one", e.name, composed)
		}
	}
}

// TestRestartedNodeServesUpSegments checks that a restarted node serves up
// segments from the persistent path database before the next beaconing
// period.
func TestRestartedNodeServesUpSegments(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	nodes := bootTopology(t, wpki, staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA},
		links: [][2]addr.IA{{coreIA, nodeIA}},
	})
	b := nodes[nodeIA]
	ctx := t.Context()

	Poll(t, "B up segment", func() bool { return holdsUpSegments(ctx, b.Node) })

	// B stops, every socket and store released when its Close returns, and
	// boots again on the same state, host, and link set — the restart a
	// process supervisor performs — serving the up segments before the next
	// beaconing period.
	b.stop(t)
	b = bootStaticNode(t, wpki, b.host, false, b.stateDir, b.linkSet, nil)
	segs, err := b.app.PathDB().Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("restarted node serves no up segments before the next beaconing period")
	}
	path, err := b.app.Provider().Path(ctx, coreIA)
	if err != nil {
		t.Fatalf("restarted node cannot route to the core: %v", err)
	}
	if len(path.HopFields) != 2 {
		t.Errorf("route to the core = %d hops, want 2", len(path.HopFields))
	}
}

// holdsUpSegments reports whether the node's path database holds an up
// segment.
func holdsUpSegments(ctx context.Context, n *Node) bool {
	segs, err := n.app.PathDB().Get(ctx,
		pathdb.Query{Type: pathdb.SegmentTypeUp})
	return err == nil && len(segs) > 0
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
		ip := HostSlot(t)
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

// The test topologies' ISD-ASes, matching pkg/core/controlplane's.
var (
	coreIA  = addr.MustIAFrom(20, 0xff0000000001)
	nodeIA  = addr.MustIAFrom(20, 0xff0000000002)
	lineCIA = addr.MustIAFrom(20, 0xff0000000003)
)
