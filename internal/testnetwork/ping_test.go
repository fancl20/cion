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
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// TestPingForkTopology is the end-to-end proof of the path library's first
// application: a pinger on one node of a fork topology — the core A between
// the leaves B and C — and the responder every node runs. The leaf's
// requests ride the composed up/down path B←A→C and its replies ride the
// reversed arrival path — the first multi-segment carriage by the data
// plane — and the core's requests ride the down segment alone.
func TestPingForkTopology(t *testing.T) {
	t.Parallel()
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA},
		links: [][2]addr.IA{{coreIA, nodeIA}, {coreIA, lineCIA}},
	})
	a, b, c := nodes[coreIA], nodes[nodeIA], nodes[lineCIA]
	ctx := t.Context()

	// Beacons propagate, C enrolls, and the provider resolves the composed
	// path C→A→B from C — the fork's three-node join pipeline, budgeted at
	// the restart lab's patience: on a loaded runner it outgrows the plain
	// test timeout while still progressing.
	PollFor(t, RestartTimeout, "path from C to B", func() bool {
		_, err := c.app.Provider().Path(ctx, nodeIA)
		return err == nil
	})
	report, err := ping.Run(ctx, ping.Config{
		Conn:     c.conn(t),
		Provider: c.app.Provider(),
		Dst:      nodeIA,
		DstHost:  b.host,
		Count:    3,
		Interval: 100 * time.Millisecond,
		// The reply wait tolerates a loaded runner's stall: a late reply
		// still proves the composed carriage the run wants, lost only when
		// nothing answers.
		Wait: 5 * time.Second,
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
	// complete route — its resolution waited for first, the run not
	// retrying one.
	PollFor(t, RestartTimeout, "path from A to C", func() bool {
		path, err := a.app.Provider().Path(ctx, lineCIA)
		return err == nil && len(path.HopFields) == 2
	})
	report, err = ping.Run(ctx, ping.Config{
		Conn:     a.conn(t),
		Provider: a.app.Provider(),
		Dst:      lineCIA,
		DstHost:  c.host,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     5 * time.Second,
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

// TestPingLineMiddleNode is the line episode: on A(core)—B—C
// the middle node B is pinged from below — C→B, the composition that
// revisits the destination — and pings below itself — B→C — with the
// reported hops exactly the two ASes and the core absent from the road.
// Replies ride the reversed arrival paths, and the line's existing
// episodes pass unchanged.
func TestPingLineMiddleNode(t *testing.T) {
	t.Parallel()
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA},
		links: [][2]addr.IA{{coreIA, nodeIA}, {nodeIA, lineCIA}},
	})
	a, b, c := nodes[coreIA], nodes[nodeIA], nodes[lineCIA]
	ctx := t.Context()

	// C's up segment [A, B, C] and B's registered down segment [A, B] meet
	// at B: the truncated reversed up segment alone is the route. The join
	// pipeline runs through enrollment and registration, budgeted at the
	// restart lab's patience like the fork's. B's and the core's own
	// episodes wait for their side of the pipeline — C's down segment
	// registered at the core — before pinging, the resolution a ping run
	// does not retry.
	PollFor(t, RestartTimeout, "path from C to B", func() bool {
		path, err := c.app.Provider().Path(ctx, nodeIA)
		return err == nil && len(path.HopFields) == 2
	})
	PollFor(t, RestartTimeout, "path from B to C", func() bool {
		path, err := b.app.Provider().Path(ctx, lineCIA)
		return err == nil && len(path.HopFields) == 2
	})
	PollFor(t, RestartTimeout, "path from A to C", func() bool {
		path, err := a.app.Provider().Path(ctx, lineCIA)
		return err == nil && len(path.HopFields) == 3
	})

	run := func(p *staticNode, dst addr.IA, host netip.Addr, wantHops, wantSegs int) {
		t.Helper()
		report, err := ping.Run(ctx, ping.Config{
			Conn:     p.conn(t),
			Provider: p.app.Provider(),
			Dst:      dst,
			DstHost:  host,
			Count:    3,
			Interval: 100 * time.Millisecond,
			Wait:     5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.Received != 3 || report.Loss() != 0 {
			t.Fatalf("received %d of %d replies to %v, want 3 of 3",
				report.Received, report.Sent, dst)
		}
		for _, reply := range report.Replies {
			if reply.Hops != wantHops || reply.Segments != wantSegs {
				t.Errorf("seq %d arrival path from %v = %d hops / %d segments, want %d/%d",
					reply.Seq, dst, reply.Hops, reply.Segments, wantHops, wantSegs)
			}
		}
	}
	// The middle node reached from below and reaching below: the meeting at
	// B truncates both sides, one segment each way.
	run(c, nodeIA, b.host, 2, 1)
	run(b, lineCIA, c.host, 2, 1)
	// The line's existing episodes pass unchanged.
	run(c, coreIA, a.host, 3, 1)
	run(a, lineCIA, c.host, 3, 1)
}

// TestPingSiblingNodes is the sibling episode: on the fork with
// a parent — A(core)—B, B—C, B—D — the siblings C and D ping each other and
// the reported hops meet at their parent B, the core absent from the road.
func TestPingSiblingNodes(t *testing.T) {
	t.Parallel()
	iaD := addr.MustIAFrom(20, 0xff0000000004)
	// The core and the parent run unattended: the episode reads only the
	// siblings' ends.
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA, iaD},
		links: [][2]addr.IA{{coreIA, nodeIA}, {nodeIA, lineCIA}, {nodeIA, iaD}},
	})
	c, d := nodes[lineCIA], nodes[iaD]
	ctx := t.Context()

	// C's up segment [A, B, C] and D's registered down segment [A, B, D]
	// meet at B: [C, B] composed before [B, D], four hops in two segments.
	PollFor(t, RestartTimeout, "path from C to D", func() bool {
		path, err := c.app.Provider().Path(ctx, iaD)
		return err == nil && len(path.HopFields) == 4
	})
	report, err := ping.Run(ctx, ping.Config{
		Conn:     c.conn(t),
		Provider: c.app.Provider(),
		Dst:      iaD,
		DstHost:  d.host,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Received != 3 || report.Loss() != 0 {
		t.Fatalf("received %d of %d replies, want 3 of 3", report.Received, report.Sent)
	}
	for _, reply := range report.Replies {
		if reply.Hops != 4 || reply.Segments != 2 {
			t.Errorf("seq %d arrival path = %d hops / %d segments, want the sibling join's 4/2",
				reply.Seq, reply.Hops, reply.Segments)
		}
	}
}

// TestPingReresolvesExpiredPath checks the mid-run expiry: a pinger whose
// resolved path has expired re-resolves and the run continues — here from a
// stale up segment to a fresh one, with the replies proving the fresh path
// carried them.
func TestPingReresolvesExpiredPath(t *testing.T) {
	t.Parallel()
	iaP := addr.MustIAFrom(20, 0xff0000000021)
	iaR := addr.MustIAFrom(20, 0xff0000000022)
	p, r := bootPair(t, iaP, iaR)
	keyP, keyR := p.forwardingKey(t), r.forwardingKey(t)

	// The pinger resolves through a provider of crafted up segments: the
	// first resolution sees a stale segment — expired twenty-five hours
	// after its beacon — and every later one a fresh segment routing over
	// the real link.
	fresh := upSegment(t, keyR, keyP, time.Now(), iaR, iaP)
	db := &flipPathDB{
		stale: upSegment(t, keyR, keyP, time.Now().Add(-25*time.Hour), iaR, iaP),
		fresh: fresh,
	}
	warmUp(t, p, r, fresh)
	report, err := ping.Run(t.Context(), ping.Config{
		Conn:     p.conn(t),
		Provider: &scion.PathProvider{IA: iaP, DB: db},
		Dst:      iaR,
		DstHost:  r.host,
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

// bootPair boots the crafted-path labs' two non-core nodes, P and R, on the
// static builder with no core: their one link pins interface 1 at both
// ends, the interface upSegment's hop fields name.
func bootPair(t *testing.T, iaP, iaR addr.IA) (p, r *staticNode) {
	t.Helper()
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		nodes: []addr.IA{iaP, iaR},
		links: [][2]addr.IA{{iaP, iaR}},
		pins:  map[[2]addr.IA]uint16{{iaP, iaR}: 1, {iaR, iaP}: 1},
	})
	return nodes[iaP], nodes[iaR]
}

// warmUp waits until R's responder answers an echo P sends over the
// crafted segment: until the link's BFD session comes up, P's data plane
// refuses the egress, and each node's generation swap at boot may drop a
// request.
func warmUp(t *testing.T, p, r *staticNode, seg *pathdb.Segment) {
	t.Helper()
	provider := &scion.PathProvider{IA: p.app.IA(), DB: &staticPathDB{seg: seg}}
	Poll(t, "R answers P's echo over the crafted segment", func() bool {
		return pingOver(t.Context(), p.assemblyNode, provider, r.app.IA(), r.host)
	})
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
	t.Parallel()
	iaP := addr.MustIAFrom(20, 0xff0000000031)
	iaR := addr.MustIAFrom(20, 0xff0000000032)
	p, _ := bootPair(t, iaP, iaR)

	stranger := addr.MustIAFrom(20, 0xff0000000077)
	conn := p.conn(t)
	done := make(chan error, 1)
	go func() {
		_, err := ping.Run(t.Context(), ping.Config{
			Conn:     conn,
			Provider: p.app.Provider(),
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

// TestPingLossSummary checks the loss accounting: a destination host no
// responder listens on loses every request, and the run still completes
// with the summary.
func TestPingLossSummary(t *testing.T) {
	t.Parallel()
	iaP := addr.MustIAFrom(20, 0xff0000000041)
	iaR := addr.MustIAFrom(20, 0xff0000000042)
	p, r := bootPair(t, iaP, iaR)

	// The provider resolves over a crafted up segment, so the requests are
	// delivered — R's responder answers the warm-up over it — and they aim
	// at a host of R's AS where no socket listens: the pool's next loopback
	// address, which no node binds.
	seg := upSegment(t, r.forwardingKey(t), p.forwardingKey(t), time.Now(), iaR, iaP)
	warmUp(t, p, r, seg)
	report, err := ping.Run(t.Context(), ping.Config{
		Conn:     p.conn(t),
		Provider: &scion.PathProvider{IA: iaP, DB: &staticPathDB{seg: seg}},
		Dst:      iaR,
		DstHost:  hostSlot(t),
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
