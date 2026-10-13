package testnetwork

import (
	"context"
	"hash"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// TestFabricatingNeighbor is the fabrication lab: an enrolled
// node — B, the middle of the line — signs an entry claiming the core's
// name and propagates the beacon to C over the same channel the honest
// beacons ride. The binding refuses it at C's reception with both
// identities named; no store ever holds a segment the fabrication
// contributed to — the honest flow around it undisturbed, and every
// segment every store holds still verifying bound to the identity each of
// its entries claims.
func TestFabricatingNeighbor(t *testing.T) {
	t.Parallel()
	// The line's links pin the interfaces the fabricated entries name: A's
	// toward B, and B's toward A and toward C.
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA},
		links: [][2]addr.IA{{coreIA, nodeIA}, {nodeIA, lineCIA}},
		pins: map[[2]addr.IA]uint16{
			{coreIA, nodeIA}: 1, {nodeIA, coreIA}: 1, {nodeIA, lineCIA}: 2,
		},
	})
	a, b, c := nodes[coreIA], nodes[nodeIA], nodes[lineCIA]
	ctx := t.Context()

	// The honest line stands: B enrolled, C terminates verified up segments
	// to the core, and the core holds the down segments to C.
	Poll(t, "B enrolled", func() bool { return holdsChain(ctx, b.assemblyNode) })
	Poll(t, "C's up segments bound-verify", func() bool {
		return boundVerifies(ctx, c.assemblyNode, pathdb.SegmentTypeUp)
	})
	Poll(t, "A's down segments bound-verify", func() bool {
		return boundVerifies(ctx, a.assemblyNode, pathdb.SegmentTypeDown)
	})

	// The fabrication: an entry claiming the core's name, signed by B's own
	// key — a signature valid against B's TRC-anchored chain, a claim it
	// has no right to make — followed by B's honest entry naming the
	// neighbor the arrival link expects, so every check but the binding
	// passes.
	key := b.forwardingKey(t)
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(key)
		return mac
	}
	fab, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, coreIA, segment.EntryOptions{
		Next:       nodeIA,
		EgressIfID: 1,
	}, macFactory, b.app.Engine()); err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, nodeIA, segment.EntryOptions{
		Next:        lineCIA,
		IngressIfID: 1,
		EgressIfID:  2,
	}, macFactory, b.app.Engine()); err != nil {
		t.Fatal(err)
	}

	err = b.app.PeerClient().Beacon(ctx, &scion.Addr{IA: lineCIA, Service: addr.SvcCS}, fab.PB)
	if err == nil || !strings.Contains(err.Error(), coreIA.String()) ||
		!strings.Contains(err.Error(), nodeIA.String()) {

		t.Fatalf("the fabricated beacon's refusal = %v, want the binding's both identities", err)
	}

	// No store holds the fabrication: let the beaconing and registration
	// rounds run — every opportunity the honest machinery has to propagate
	// or register what it stored — and every segment every store holds
	// still verifies bound.
	time.Sleep(3 * Registration)
	if !boundVerifies(ctx, c.assemblyNode, pathdb.SegmentTypeUp) {
		t.Error("C's up segments hold an entry another identity signed")
	}
	if !boundVerifies(ctx, a.assemblyNode, pathdb.SegmentTypeDown) {
		t.Error("the core's down segments hold an entry another identity signed")
	}

	// The honest flow is undisturbed: C still resolves its path to the core
	// over the verified segments alone.
	path, err := c.app.Provider().Path(ctx, coreIA)
	if err != nil || path == nil {
		t.Fatalf("C's path to the core after the fabrication: %v", err)
	}
}

// boundVerifies reports whether the node's path database holds segments of
// the type and every entry of every one of them verifies bound to the
// identity it claims.
func boundVerifies(ctx context.Context, n *assemblyNode, typ pathdb.SegmentType) bool {
	segs, err := n.app.PathDB().Get(ctx, pathdb.Query{Type: typ})
	if err != nil || len(segs) == 0 {
		return false
	}
	for _, seg := range segs {
		for i := range seg.PCB.Entries {
			if _, err := n.app.Engine().VerifyBound(ctx, seg.PCB.Entries[i].IA,
				seg.PCB.Entries[i].Signed, seg.PCB.AssociatedData(i)...); err != nil {
				return false
			}
		}
	}
	return true
}
