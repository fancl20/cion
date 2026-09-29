package testnetwork

import (
	"context"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// The origin-collision lab's ISD-ASes beside the package's own: a second core
// the founding core's genesis TRC names beside itself, the child both cores'
// beacons enter, and the node below that child.
var (
	core2IA  = addr.MustIAFrom(20, 0xff0000000005)
	sharedIA = addr.MustIAFrom(20, 0xff0000000006)
	lowIA    = addr.MustIAFrom(20, 0xff0000000007)
)

// bestSetScan is the beacon store's per-interface bound: the widest set one
// ingress holds, and so the whole of a one-link node's candidates.
const bestSetScan = 64

// TestTwoOriginsShareOneSegmentID is the origin-keyed beacon store's lab: a
// diamond — the founding core and a fellow core its genesis TRC names beside
// it, both linked into one shared child, and a node below — where the two
// cores' beacons, pinned to one segment ID at origination, reach the bottom
// node over the same link. Both register as up segments there and both
// compose paths; under the ingress-and-ID key alone, whichever beacon was
// fresher held the one slot and the other origin's route never existed.
func TestTwoOriginsShareOneSegmentID(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA1, ipA2, ipS, ipL := hostSlot(t), hostSlot(t), hostSlot(t), hostSlot(t)
	a1S, sA1 := FreeUDPAddrOn(t, ipA1), FreeUDPAddrOn(t, ipS)
	a2S, sA2 := FreeUDPAddrOn(t, ipA2), FreeUDPAddrOn(t, ipS)
	a1A2, a2A1 := FreeUDPAddrOn(t, ipA1), FreeUDPAddrOn(t, ipA2)
	sL, lS := FreeUDPAddrOn(t, ipS), FreeUDPAddrOn(t, ipL)

	// The founding core names the fellow core in the genesis TRC, so every
	// node that pins it accepts the fellow core's beacons as core-originated.
	// The fellow core runs the non-core assembly — it enrolls against the
	// founder over their link like any joiner, and the lab stands in for its
	// origination loop below.
	a1 := StartNode(t, NodeConfig{IA: coreIA, Host: ipA1, Links: []Link{
		{Local: a1S, Remote: sA1, Neighbor: sharedIA},
		{Local: a1A2, Remote: a2A1, Neighbor: core2IA},
	}, Core: true, WPKI: wpki, GenesisCores: []addr.IA{core2IA}})
	a2 := StartNode(t, NodeConfig{IA: core2IA, Host: ipA2, Links: []Link{
		{Local: a2A1, Remote: a1A2, Neighbor: coreIA},
		{Local: a2S, Remote: sA2, Neighbor: sharedIA},
	}, WPKI: wpki})
	shared := StartNode(t, NodeConfig{IA: sharedIA, Host: ipS, Links: []Link{
		{Local: sA1, Remote: a1S, Neighbor: coreIA},
		{Local: sA2, Remote: a2S, Neighbor: core2IA},
		{Local: sL, Remote: lS, Neighbor: lowIA},
	}, WPKI: wpki})
	l := StartNode(t, NodeConfig{IA: lowIA, Host: ipL, Links: []Link{
		{Local: lS, Remote: sL, Neighbor: sharedIA},
	}, WPKI: wpki})
	ctx := context.Background()

	// The fellow core's engine signs once its chain is anchored in the joint
	// TRC.
	Poll(t, "the fellow core enrolled", func() bool { return holdsChainOf(a2, core2IA) })

	const sharedID = uint16(0x0340)
	// originateFrom delivers the beacon the core would originate — its own
	// entry first, the segment ID pinned at origination — to the shared child
	// over their own link, the delivery the drafts' beacon service receives.
	originateFrom := func(n *Node) error {
		pcb, err := segment.PCBWithID(time.Now(), sharedID)
		if err != nil {
			return err
		}
		if err := pcb.AppendEntry(ctx, n.IA, segment.EntryOptions{
			Next:       sharedIA,
			EgressIfID: interfaceTo(t, n.Links(), sharedIA),
		}, macFactoryOf(n), n.Engine); err != nil {
			return err
		}
		return n.PeerClt.Beacon(ctx, &scion.Addr{IA: sharedIA, Service: addr.SvcCS}, pcb.PB)
	}
	deliverBoth := func() {
		if err := originateFrom(a1); err != nil {
			t.Fatal(err)
		}
		if err := originateFrom(a2); err != nil {
			t.Fatal(err)
		}
	}

	// The shared child holds both origins' candidates — over its two own
	// links, where no key ever collided — before anything flows below it.
	Poll(t, "both origins' candidates at the shared child", func() bool {
		deliverBoth()
		origins := candidateOrigins(shared, sharedID)
		return origins[coreIA] && origins[core2IA]
	})

	// Both origins' candidates reach the bottom node over the one link, and
	// both register there as up segments — the two rows the path database's
	// own three-part key always told apart.
	Poll(t, "both origins' candidates at the bottom node", func() bool {
		deliverBoth()
		origins := candidateOrigins(l, sharedID)
		return origins[coreIA] && origins[core2IA]
	})
	Poll(t, "up segments of both origins at the bottom node", func() bool {
		deliverBoth()
		origins, err := upSegmentOrigins(ctx, l, sharedID)
		return err == nil && origins[coreIA] && origins[core2IA]
	})

	// Both compose paths: the provider resolves a route to each core over
	// its own reversed up segment.
	for _, core := range []addr.IA{coreIA, core2IA} {
		path, err := l.Provider.Path(ctx, core)
		if err != nil {
			t.Fatalf("path from the bottom node to %v: %v", core, err)
		}
		if len(path.HopFields) != 3 {
			t.Errorf("path to %v = %d hops, want the three-hop reversed segment",
				core, len(path.HopFields))
		}
	}

	// Every up segment the lab produced verifies bound to the identity each
	// of its entries claims — the pinned origins included.
	if !boundVerifies(l, pathdb.SegmentTypeUp) {
		t.Error("the bottom node's up segments hold an entry another identity signed")
	}
}

// candidateOrigins returns the origins of the node's stored candidates
// carrying the segment ID.
func candidateOrigins(n *Node, id uint16) map[addr.IA]bool {
	origins := make(map[addr.IA]bool)
	for _, cand := range n.StoreBcn.BestSet(bestSetScan) {
		if cand.PCB.ID() == id {
			origins[cand.PCB.FirstIA()] = true
		}
	}
	return origins
}

// upSegmentOrigins returns the origins of the node's registered up segments
// carrying the segment ID.
func upSegmentOrigins(
	ctx context.Context, n *Node, id uint16) (map[addr.IA]bool, error) {

	segs, err := n.PathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		return nil, err
	}
	origins := make(map[addr.IA]bool)
	for _, seg := range segs {
		if seg.PCB.ID() == id {
			origins[seg.FirstIA()] = true
		}
	}
	return origins, nil
}

// macFactoryOf builds the node's forwarding-key MAC hashers, as its data
// plane does.
func macFactoryOf(n *Node) func() hash.Hash {
	return func() hash.Hash {
		mac, _ := scrypto.InitMac(n.MACKey)
		return mac
	}
}

// interfaceTo returns the node's interface ID toward the neighbor.
func interfaceTo(t *testing.T, links map[uint16]addr.IA, neighbor addr.IA) uint16 {
	t.Helper()
	for ifID, ia := range links {
		if ia.Equal(neighbor) {
			return ifID
		}
	}
	t.Fatalf("no interface toward %v", neighbor)
	return 0
}
