package testnetwork

import (
	"context"
	"hash"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
	"github.com/fancl20/cion/pkg/trust"
)

// TestFabricatingNeighbor is proposal 0015's fabrication lab: an enrolled
// node — B, the middle of the line — signs an entry claiming the core's
// name and propagates the beacon to C over the same channel the honest
// beacons ride. The binding refuses it at C's reception with both
// identities named; no store ever holds a segment the fabrication
// contributed to — the honest flow around it undisturbed, and every
// segment every store holds still verifying bound to the identity each of
// its entries claims.
func TestFabricatingNeighbor(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := addrIP(0x41), addrIP(0x42), addrIP(0x43)
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

	// The honest line stands: B enrolled, C terminates verified up segments
	// to the core, and the core holds the down segments to C.
	Poll(t, "B enrolled", func() bool {
		return holdsChainOf(b, nodeIA)
	})
	Poll(t, "C's up segments bound-verify", func() bool {
		return boundVerifies(c, pathdb.SegmentTypeUp)
	})
	Poll(t, "A's down segments bound-verify", func() bool {
		return boundVerifies(a, pathdb.SegmentTypeDown)
	})

	// The fabrication: an entry claiming the core's name, signed by B's own
	// key — a signature valid against B's TRC-anchored chain, a claim it
	// has no right to make — followed by B's honest entry naming the
	// neighbor the arrival link expects, so every check but the binding
	// passes.
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(b.MACKey)
		return mac
	}
	fab, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, coreIA, segment.EntryOptions{
		Next:       nodeIA,
		EgressIfID: 1,
	}, macFactory, b.Engine); err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, nodeIA, segment.EntryOptions{
		Next:        lineCIA,
		IngressIfID: 1,
		EgressIfID:  2,
	}, macFactory, b.Engine); err != nil {
		t.Fatal(err)
	}

	err = b.PeerClt.Beacon(ctx, &scion.Addr{IA: lineCIA, Service: addr.SvcCS}, fab.PB)
	if err == nil || !strings.Contains(err.Error(), coreIA.String()) ||
		!strings.Contains(err.Error(), nodeIA.String()) {

		t.Fatalf("the fabricated beacon's refusal = %v, want the binding's both identities", err)
	}

	// No store holds the fabrication: let the beaconing and registration
	// rounds run — every opportunity the honest machinery has to propagate
	// or register what it stored — and every segment every store holds
	// still verifies bound.
	time.Sleep(3 * Registration)
	if !boundVerifies(c, pathdb.SegmentTypeUp) {
		t.Error("C's up segments hold an entry another identity signed")
	}
	if !boundVerifies(a, pathdb.SegmentTypeDown) {
		t.Error("the core's down segments hold an entry another identity signed")
	}

	// The honest flow is undisturbed: C still resolves its path to the core
	// over the verified segments alone.
	path, err := c.Provider.Path(ctx, coreIA)
	if err != nil || path == nil {
		t.Fatalf("C's path to the core after the fabrication: %v", err)
	}
}

// holdsChainOf reports whether the node's trust database holds a valid
// chain for the given ISD-AS.
func holdsChainOf(n *Node, ia addr.IA) bool {
	now := time.Now()
	chains, err := n.TrustDB.Chains(context.Background(), trust.ChainQuery{
		IA:       ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	return err == nil && len(chains) > 0
}

// boundVerifies reports whether the node's path database holds segments of
// the type and every entry of every one of them verifies bound to the
// identity it claims.
func boundVerifies(n *Node, typ pathdb.SegmentType) bool {
	segs, err := n.PathDB.Get(context.Background(), pathdb.Query{Type: typ})
	if err != nil || len(segs) == 0 {
		return false
	}
	for _, seg := range segs {
		for i := range seg.PCB.Entries {
			if _, err := n.Engine.VerifyBound(context.Background(), seg.PCB.Entries[i].IA,
				seg.PCB.Entries[i].Signed, seg.PCB.AssociatedData(i)...); err != nil {
				return false
			}
		}
	}
	return true
}
