package testnetwork

import (
	"context"
	"hash"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// TestPingForkTopology is the end-to-end proof of the path library's first
// application: a responder on one node and a pinger on another of a fork
// topology — the core A between the leaves B and C. The leaf's requests ride
// the composed up/down path B←A→C and its replies ride the reversed arrival
// path — the first multi-segment carriage by the data plane — and the core's
// requests ride the down segment alone.
func TestPingForkTopology(t *testing.T) {
	wpki := NewWebPKI(t)
	// Loopback addresses of this test's own; earlier tests' endpoints keep
	// theirs.
	ipA := addrIP(8)
	ipB := addrIP(9)
	ipC := addrIP(10)
	extA1, extB := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	extA2, extC := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipC)

	a := StartNode(t, NodeConfig{IA: coreIA, Host: ipA, Links: []Link{
		{Local: extA1, Remote: extB, Neighbor: nodeIA},
		{Local: extA2, Remote: extC, Neighbor: lineCIA},
	}, Core: true, WPKI: wpki})
	b := StartNode(t, NodeConfig{IA: nodeIA, Host: ipB, Links: []Link{
		{Local: extB, Remote: extA1, Neighbor: coreIA},
	}, WPKI: wpki})
	c := StartNode(t, NodeConfig{IA: lineCIA, Host: ipC, Links: []Link{
		{Local: extC, Remote: extA2, Neighbor: coreIA},
	}, WPKI: wpki})
	ctx := context.Background()

	StartPingResponder(t, a)
	StartPingResponder(t, b)
	StartPingResponder(t, c)

	// Beacons propagate, C enrolls, and the provider resolves the composed
	// path C→A→B from C.
	Poll(t, "path from C to B", func() bool {
		_, err := c.Provider.Path(ctx, nodeIA)
		return err == nil
	})
	report, err := ping.Run(ctx, ping.Config{
		Conn:     c.NewConn(t, 0),
		Provider: c.Provider,
		Dst:      nodeIA,
		DstHost:  b.ControlIP,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Received != 3 || report.Loss() != 0 {
		t.Fatalf("received %d of %d replies, want 3 of 3",
			report.Received, report.Sent)
	}
	for _, reply := range report.Replies {
		if reply.RTT <= 0 {
			t.Errorf("seq %d RTT = %v, want positive", reply.Seq, reply.RTT)
		}
		// Reversed up [C, A] composed before the down [A, B]: four hops in
		// two segments, there and back.
		if reply.Hops != 4 {
			t.Errorf("seq %d arrival path = %d hops, want the composed 4",
				reply.Seq, reply.Hops)
		}
		if reply.Segments != 2 {
			t.Errorf("seq %d arrival path = %d segments, want 2",
				reply.Seq, reply.Segments)
		}
	}

	// The core pings down its other leaf: its own down segment is the
	// complete route.
	report, err = ping.Run(ctx, ping.Config{
		Conn:     a.NewConn(t, 0),
		Provider: a.Provider,
		Dst:      lineCIA,
		DstHost:  c.ControlIP,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Received != 3 {
		t.Fatalf("received %d of %d replies from the core, want 3 of 3",
			report.Received, report.Sent)
	}
	for _, reply := range report.Replies {
		if reply.Hops != 2 || reply.Segments != 1 {
			t.Errorf("seq %d arrival path = %d hops / %d segments, want the down segment's 2/1",
				reply.Seq, reply.Hops, reply.Segments)
		}
	}
}

// TestPingReresolvesExpiredPath checks the mid-run expiry: a pinger whose
// resolved path has expired re-resolves and the run continues — here from a
// stale up segment to a fresh one, with the replies proving the fresh path
// carried them.
func TestPingReresolvesExpiredPath(t *testing.T) {
	iaP := addr.MustIAFrom(20, 0xff0000000021)
	iaR := addr.MustIAFrom(20, 0xff0000000022)
	ipP, ipR := addrIP(0x11), addrIP(0x12)
	extP, extR := FreeUDPAddrOn(t, ipP), FreeUDPAddrOn(t, ipR)

	p := StartNode(t, NodeConfig{IA: iaP, Host: ipP, Links: []Link{
		{Local: extP, Remote: extR, Neighbor: iaR},
	}, WPKI: NewWebPKI(t)})
	r := StartNode(t, NodeConfig{IA: iaR, Host: ipR, Links: []Link{
		{Local: extR, Remote: extP, Neighbor: iaP},
	}, WPKI: NewWebPKI(t)})
	StartPingResponder(t, r)

	// The pinger resolves through a provider of crafted up segments: the
	// first resolution sees a stale segment — expired twenty-five hours
	// after its beacon — and every later one a fresh segment routing over
	// the real link.
	db := &flipPathDB{
		stale: upSegment(t, r.MACKey, p.MACKey, time.Now().Add(-25*time.Hour), iaR, iaP),
		fresh: upSegment(t, r.MACKey, p.MACKey, time.Now(), iaR, iaP),
	}
	provider := &scion.PathProvider{IA: iaP, DB: db}
	report, err := ping.Run(context.Background(), ping.Config{
		Conn:     p.NewConn(t, 0),
		Provider: provider,
		Dst:      iaR,
		DstHost:  r.ControlIP,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Reresolves != 1 {
		t.Errorf("re-resolutions = %d, want 1 (the expired initial path)", report.Reresolves)
	}
	if report.Received != 3 || report.Loss() != 0 {
		t.Fatalf("received %d of %d replies over the fresh path",
			report.Received, report.Sent)
	}
	for _, reply := range report.Replies {
		if reply.Hops != 2 {
			t.Errorf("seq %d arrival path = %d hops, want the segment's 2",
				reply.Seq, reply.Hops)
		}
	}
}

// upSegment builds the unsigned route form of a two-AS up segment from core
// to leaf over the test link, each hop MACed with its own AS's forwarding
// key the way beaconing does.
func upSegment(
	t *testing.T, coreKey, leafKey []byte, now time.Time, core, leaf addr.IA,
) *pathdb.Segment {

	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x333)
	if err != nil {
		t.Fatal(err)
	}
	macFactory := func(key []byte) func() hash.Hash {
		return func() hash.Hash {
			mac, _ := scrypto.InitMac(key)
			return mac
		}
	}
	if _, err := pcb.AppendRouteHop(core, segment.EntryOptions{EgressIfID: 1},
		macFactory(coreKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(leaf, segment.EntryOptions{IngressIfID: 1},
		macFactory(leafKey)); err != nil {
		t.Fatal(err)
	}
	return &pathdb.Segment{Type: pathdb.SegmentTypeUp, PCB: pcb}
}

// flipPathDB serves the stale segment once, the fresh one thereafter.
type flipPathDB struct {
	stale, fresh *pathdb.Segment
	served       bool
}

func (d *flipPathDB) Insert(context.Context, *pathdb.Segment) (bool, error) {
	return false, nil
}

func (d *flipPathDB) Get(_ context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	if q.Type != pathdb.SegmentTypeUp {
		return nil, nil
	}
	seg := d.fresh
	if !d.served {
		seg = d.stale
		d.served = true
	}
	if !q.SrcIA.IsZero() && !q.SrcIA.Equal(seg.FirstIA()) {
		return nil, nil
	}
	return []*pathdb.Segment{seg}, nil
}

func (d *flipPathDB) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }
func (d *flipPathDB) Close() error                                          { return nil }

// TestPingUnreachable checks that a destination no path resolves for is an
// error, not a hang.
func TestPingUnreachable(t *testing.T) {
	iaP := addr.MustIAFrom(20, 0xff0000000031)
	iaR := addr.MustIAFrom(20, 0xff0000000032)
	ipP, ipR := addrIP(0x13), addrIP(0x14)
	extP, extR := FreeUDPAddrOn(t, ipP), FreeUDPAddrOn(t, ipR)

	p := StartNode(t, NodeConfig{IA: iaP, Host: ipP, Links: []Link{
		{Local: extP, Remote: extR, Neighbor: iaR},
	}, WPKI: NewWebPKI(t)})
	StartNode(t, NodeConfig{IA: iaR, Host: ipR, Links: []Link{
		{Local: extR, Remote: extP, Neighbor: iaP},
	}, WPKI: NewWebPKI(t)})

	stranger := addr.MustIAFrom(20, 0xff0000000077)
	done := make(chan error, 1)
	go func() {
		_, err := ping.Run(context.Background(), ping.Config{
			Conn:     p.NewConn(t, 0),
			Provider: p.Provider,
			Dst:      stranger,
			DstHost:  netip.MustParseAddr("127.0.0.99"),
			Count:    1,
			Interval: time.Second,
			Wait:     time.Second,
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("pinging an unreachable ISD-AS succeeded, want error")
		}
	case <-time.After(TestTimeout):
		t.Fatal("pinging an unreachable ISD-AS hangs")
	}
}

// TestPingLossSummary checks the loss accounting: a destination whose
// responder is down loses every request, and the run still completes with
// the summary.
func TestPingLossSummary(t *testing.T) {
	iaP := addr.MustIAFrom(20, 0xff0000000041)
	iaR := addr.MustIAFrom(20, 0xff0000000042)
	ipP, ipR := addrIP(0x15), addrIP(0x16)
	extP, extR := FreeUDPAddrOn(t, ipP), FreeUDPAddrOn(t, ipR)

	// The provider resolves over a crafted up segment, so the requests are
	// delivered; no responder answers them.
	p := StartNode(t, NodeConfig{IA: iaP, Host: ipP, Links: []Link{
		{Local: extP, Remote: extR, Neighbor: iaR},
	}, WPKI: NewWebPKI(t)})
	r := StartNode(t, NodeConfig{IA: iaR, Host: ipR, Links: []Link{
		{Local: extR, Remote: extP, Neighbor: iaP},
	}, WPKI: NewWebPKI(t)})
	provider := &scion.PathProvider{
		IA: iaP,
		DB: &staticPathDB{seg: upSegment(t, r.MACKey, p.MACKey, time.Now(), iaR, iaP)},
	}
	report, err := ping.Run(context.Background(), ping.Config{
		Conn:     p.NewConn(t, 0),
		Provider: provider,
		Dst:      iaR,
		DstHost:  r.ControlIP,
		Count:    2,
		Interval: 100 * time.Millisecond,
		Wait:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Sent != 2 || report.Received != 0 || report.Loss() != 2 {
		t.Fatalf("sent %d, received %d, lost %d; want 2/0/2",
			report.Sent, report.Received, report.Loss())
	}
}

// staticPathDB serves one segment for every query.
type staticPathDB struct{ seg *pathdb.Segment }

func (d *staticPathDB) Insert(context.Context, *pathdb.Segment) (bool, error) {
	return false, nil
}

func (d *staticPathDB) Get(_ context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	if q.Type != pathdb.SegmentTypeUnspecified && q.Type != d.seg.Type {
		return nil, nil
	}
	return []*pathdb.Segment{d.seg}, nil
}

func (d *staticPathDB) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }
func (d *staticPathDB) Close() error                                          { return nil }
