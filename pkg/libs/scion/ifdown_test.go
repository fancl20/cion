package scion

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"

	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// newTestCache returns a cache at the package's own signal TTL.
func newTestCache() *InterfaceDownCache {
	return NewInterfaceDownCache()
}

// TestIfDownCacheHoldsAndLapses checks the retention: an entry lives exactly
// the TTL, to the nanosecond. The TTL's passage is a fake-time sleep in the
// bubble.
func TestIfDownCacheHoldsAndLapses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestCache()
		c.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID, Dst: iaLeaf})
		if !c.Holds(iaMid, testIfID) {
			t.Fatal("a fresh signal is not held")
		}
		time.Sleep(IfDownCacheTTL - time.Nanosecond)
		if !c.Holds(iaMid, testIfID) {
			t.Fatal("the signal lapsed before its TTL")
		}
		time.Sleep(time.Nanosecond)
		if c.Holds(iaMid, testIfID) {
			t.Error("the signal outlived its TTL")
		}
	})
}

// TestIfDownCacheDeliversToSubscriber checks the receiver: every recognized
// signal reaches the registered subscriber with its quoted destination —
// the WireGuard bind's drop key.
func TestIfDownCacheDeliversToSubscriber(t *testing.T) {
	c := newTestCache()
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

// echoPacket builds a packet a signal quotes: a plain SCMP echo message of
// the given type, identifier, and sequence from the source toward the
// destination.
func echoPacket(
	t *testing.T,
	srcIA, dstIA addr.IA,
	typ slayers.SCMPType,
	id, seq uint16,
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
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(typ, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	echo := &slayers.SCMPEcho{Identifier: id, SeqNumber: seq}
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
// just failed and the echo request it carried; every other packet is not
// one — a forged signal from any speaker on a path is worth no more than
// one cache entry.
func TestParseInterfaceDownPacket(t *testing.T) {
	quoted := echoPacket(t, iaLeaf, iaMid, slayers.SCMPTypeEchoRequest, 40441, 1)
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
	if sig.Echo == nil || sig.Echo.Reply || sig.Echo.Identifier != 40441 || sig.Echo.Seq != 1 {
		t.Errorf("quoted echo = %+v, want the request 40441/1", sig.Echo)
	}

	// A quoted reply carries no request, and neither does a quote cut short
	// before the request's sequence.
	reply := echoPacket(t, iaMid, iaLeaf, slayers.SCMPTypeEchoReply, 40441, 1)
	for name, quote := range map[string][]byte{
		"reply":     reply,
		"truncated": quoted[:len(quoted)-2],
	} {
		sig, ok := parseInterfaceDownPacket(
			interfaceDownPacket(t, iaMid, iaLeaf, iaMid, testIfID, quote))
		if !ok || sig.Echo != nil {
			t.Errorf("the %s quote = %+v (recognized %v), want a signal with no request",
				name, sig.Echo, ok)
		}
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
// interface — the crossing the cache skips — ending at the given terminator.
func crossingSegment(
	t *testing.T,
	egressIA, endIA addr.IA,
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
	if _, err := pcb.AppendRouteHop(endIA, segment.EntryOptions{
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
// stays a last resort when nothing else exists. The entry's lapse is a
// fake-time sleep in the bubble.
func TestCompositionSkipsCrossingPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newTestCache()
		now := time.Now()
		// The crossing segment is the freshest; the clean one a moment older.
		crossing := crossingSegment(t, iaMid, iaLeaf, testIfID, now)
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
		time.Sleep(IfDownCacheTTL + time.Second)
		path, err = p.LocalPath(iaMid)
		if err != nil {
			t.Fatal(err)
		}
		if len(path.HopFields) != len(crossing.PCB.Entries) {
			t.Fatalf("resolved %d hops after the lapse, want the freshest crossing %d",
				len(path.HopFields), len(crossing.PCB.Entries))
		}
	})
}

// TestCompositionSkipsCrossingDownSegment checks the composed route's other
// half: a down segment crossing a signaled interface is skipped in favor of
// a clean one, the crossing kept only as the last resort.
func TestCompositionSkipsCrossingDownSegment(t *testing.T) {
	cache := newTestCache()
	now := time.Now()
	up := upSegment(t, now, iaMid, iaLeaf)
	crossingDown := crossingSegment(t, iaMid, iaDest, testIfID, now)
	crossingDown.Type = pathdb.SegmentTypeDown
	cleanDown := upSegment(t, now.Add(-time.Second), iaMid, iaDest)
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
	path, err := p.Path(context.Background(), iaDest)
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
	if _, err := p.Path(context.Background(), iaDest); err != nil {
		t.Fatalf("the lone crossing composition was dropped: %v", err)
	}
}
