package scion

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/segment"
)

// ifDownClock is the cache's injectable clock.
type ifDownClock struct{ now time.Time }

func (c *ifDownClock) Now() time.Time { return c.now }

// newTestCache returns a cache on the injected clock, holding signals for
// the node-lifetime TTL.
func newTestCache() (*InterfaceDownCache, *ifDownClock) {
	clk := &ifDownClock{now: time.Now()}
	c := NewInterfaceDownCache()
	c.now = clk.Now
	return c, clk
}

// TestIfDownCacheHoldsAndLapses checks the retention: an entry lives
// exactly the TTL and ages out entirely — a signal storm changes no
// persistent state.
func TestIfDownCacheHoldsAndLapses(t *testing.T) {
	c, clk := newTestCache()
	c.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID, Dst: iaLeaf})
	if !c.Holds(iaMid, testIfID) {
		t.Fatal("a fresh signal is not held")
	}
	clk.now = clk.now.Add(IfDownCacheTTL + time.Second)
	if c.Holds(iaMid, testIfID) {
		t.Error("the signal outlived its TTL")
	}
	if c.HoldsAny() {
		t.Error("a lapsed cache still holds an entry")
	}
}

// TestIfDownCacheDeliversToSubscriber checks the receiver: every recognized
// signal reaches the registered subscriber with its quoted destination —
// the WireGuard bind's drop key.
func TestIfDownCacheDeliversToSubscriber(t *testing.T) {
	c, _ := newTestCache()
	var got []InterfaceDownSignal
	c.OnSignal(func(sig InterfaceDownSignal) { got = append(got, sig) })
	c.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID, Dst: iaLeaf})
	if len(got) != 1 || !got[0].Dst.Equal(iaLeaf) {
		t.Fatalf("delivered %v, want the one signal with its destination", got)
	}
}

// scmpHosts addresses the two ends of a crafted exchange.
var (
	scmpSrcHost = addr.HostIP(netip.MustParseAddr("127.0.0.2"))
	scmpDstHost = addr.HostIP(netip.MustParseAddr("127.0.0.3"))
)

// interfaceDownPacket builds the message the slow path sends: an SCMP
// External Interface Down quoting the given original packet.
func interfaceDownPacket(
	t *testing.T,
	srcIA, dstIA addr.IA,
	signaled addr.IA,
	ifID uint16,
	quoted []byte,
) []byte {

	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4SCMP,
		PathType: empty.PathType,
		Path:     &empty.Path{},
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}
	if err := scn.SetSrcAddr(scmpSrcHost); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(scmpDstHost); err != nil {
		t.Fatal(err)
	}
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(
		slayers.SCMPTypeExternalInterfaceDown, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	msg := &slayers.SCMPExternalInterfaceDown{IA: signaled, IfID: uint64(ifID)}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, scn, scmp, msg, gopacket.Payload(quoted))
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// quotedEchoRequest builds the packet a signal quotes: a plain SCMP echo
// request from the leaf toward the far side.
func quotedEchoRequest(t *testing.T, srcIA, dstIA addr.IA) []byte {
	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4SCMP,
		PathType: empty.PathType,
		Path:     &empty.Path{},
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}
	if err := scn.SetSrcAddr(scmpSrcHost); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(scmpDstHost); err != nil {
		t.Fatal(err)
	}
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(
		slayers.SCMPTypeEchoRequest, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	echo := &slayers.SCMPEcho{Identifier: 40441, SeqNumber: 1}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, scn, scmp, echo)
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// TestParseInterfaceDownPacket checks the recognition: a type-5 error names
// the signaled ISD-AS and interface, and the quote names whose cached path
// just failed; every other packet is not one — a forged signal from any
// speaker on a path is worth no more than one cache entry.
func TestParseInterfaceDownPacket(t *testing.T) {
	quoted := quotedEchoRequest(t, iaLeaf, iaMid)
	raw := interfaceDownPacket(t, iaMid, iaLeaf, iaMid, testIfID, quoted)

	sig, ok := parseInterfaceDownPacket(raw)
	if !ok {
		t.Fatal("the interface-down message was not recognized")
	}
	if !sig.IA.Equal(iaMid) || sig.IfID != testIfID {
		t.Errorf("signaled = %v/%d, want %v/%d", sig.IA, sig.IfID, iaMid, testIfID)
	}
	if !sig.Dst.Equal(iaMid) {
		t.Errorf("quoted destination = %v, want %v", sig.Dst, iaMid)
	}
	if sig.DstHost != scmpDstHost.IP() {
		t.Errorf("quoted destination host = %v, want %v", sig.DstHost, scmpDstHost.IP())
	}

	// An echo request is not a signal; neither is a truncated one.
	if _, ok := parseInterfaceDownPacket(quoted); ok {
		t.Error("an echo request was recognized as a signal")
	}
	if _, ok := parseInterfaceDownPacket(raw[:len(raw)/2]); ok {
		t.Error("a truncated message was recognized")
	}
}

// crossingSegment builds an up segment whose entries traverse the given
// interface — the crossing the cache skips.
func crossingSegment(
	t *testing.T,
	egressIA addr.IA,
	ifID uint16,
	now time.Time,
) *pathdb.Segment {

	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x222)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(egressIA, segment.EntryOptions{
		EgressIfID: ifID,
	}, testMACHasher); err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(iaLeaf, segment.EntryOptions{
		IngressIfID: ifID,
	}, testMACHasher); err != nil {
		t.Fatal(err)
	}
	return &pathdb.Segment{Type: pathdb.SegmentTypeUp, PCB: pcb}
}

func upSegment(t *testing.T, now time.Time, ias ...addr.IA) *pathdb.Segment {
	return &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  linePCB(t, now, ias...),
	}
}

// TestCompositionSkipsCrossingPaths checks the sender's reaction: a
// signaled interface's crossing composition is skipped while the entry
// lives — the freshest clean segment serves instead, and a crossing path
// stays a last resort when nothing else exists.
func TestCompositionSkipsCrossingPaths(t *testing.T) {
	cache, clk := newTestCache()
	now := time.Now()
	// The crossing segment is the freshest; the clean one a moment older.
	crossing := crossingSegment(t, iaMid, testIfID, now)
	clean := upSegment(t, now.Add(-time.Second), iaMid, iaLeaf)
	p := &PathProvider{
		IA:            iaLeaf,
		DB:            &fakePathDB{segs: []*pathdb.Segment{crossing, clean}},
		InterfaceDown: cache,
	}

	path, err := p.LocalPath(iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != len(crossing.PCB.Entries) {
		t.Fatalf("resolved %d hops, want the freshest %d",
			len(path.HopFields), len(crossing.PCB.Entries))
	}

	// Signal the interface the crossing segment traverses; the composition
	// avoids it.
	cache.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID})
	path, err = p.LocalPath(iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != len(clean.PCB.Entries) {
		t.Fatalf("resolved %d hops over the crossing segment, want the clean one's %d",
			len(path.HopFields), len(clean.PCB.Entries))
	}

	// A lone crossing path stays a last resort: it is the only route, and
	// lowering preference is all the drafts ask of a source.
	lone := &PathProvider{
		IA:            iaLeaf,
		DB:            &fakePathDB{segs: []*pathdb.Segment{crossing}},
		InterfaceDown: cache,
	}
	if _, err := lone.LocalPath(iaMid); err != nil {
		t.Fatalf("the lone crossing path was dropped: %v", err)
	}

	// The entry lapses and the freshest crossing segment serves again.
	clk.now = clk.now.Add(IfDownCacheTTL + time.Second)
	path, err = p.LocalPath(iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != len(crossing.PCB.Entries) {
		t.Fatalf("resolved %d hops after the lapse, want the freshest crossing %d",
			len(path.HopFields), len(crossing.PCB.Entries))
	}
}

// TestCompositionSkipsCrossingDownSegment checks the composed route's other
// half: a down segment crossing a signaled interface is skipped in favor of
// a clean one, the crossing kept only as the last resort.
func TestCompositionSkipsCrossingDownSegment(t *testing.T) {
	cache, _ := newTestCache()
	now := time.Now()
	up := upSegment(t, now, iaMid, iaLeaf)
	crossingDown := crossingSegment(t, iaMid, testIfID, now)
	crossingDown.Type = pathdb.SegmentTypeDown
	cleanDown := upSegment(t, now.Add(-time.Second), iaMid, iaLeaf)
	cleanDown.Type = pathdb.SegmentTypeDown
	p := &PathProvider{
		IA: iaLeaf,
		DB: &fakePathDB{segs: []*pathdb.Segment{up}},
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{crossingDown, cleanDown}
		},
		InterfaceDown: cache,
	}
	cache.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID})
	path, err := p.Path(context.Background(), iaLeaf)
	if err != nil {
		t.Fatal(err)
	}
	// The clean composition: the up segment's two hops plus the clean down's.
	if want := len(up.PCB.Entries) + len(cleanDown.PCB.Entries); len(path.HopFields) != want {
		t.Fatalf("composed %d hops, want the clean %d", len(path.HopFields), want)
	}

	// With the crossing segment alone, the composition keeps it as the last
	// resort.
	p.Lookup = func(context.Context, addr.IA) []*pathdb.Segment {
		return []*pathdb.Segment{crossingDown}
	}
	if _, err := p.Path(context.Background(), iaLeaf); err != nil {
		t.Fatalf("the lone crossing composition was dropped: %v", err)
	}
}
