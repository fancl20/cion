package scion

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// signal updates the topic with a signal naming the interface, arrived now.
func signal(topic *bus.Topic[bus.InterfaceDownState], ia addr.IA, ifID uint16) {
	now := time.Now()
	topic.Update(func(s bus.InterfaceDownState) bus.InterfaceDownState {
		return s.Signaled(segment.LinkID{IA: ia, IfID: ifID}, now)
	})
}

// TestConnPublishesInterfaceDown checks the publisher: a conn that
// recognizes a signal updates the topic with the signaled link at the
// signal's arrival; one without the topic recognizes the signal all the
// same. The clock is the bubble's.
func TestConnPublishesInterfaceDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		quoted := echoPacket(t, iaLeaf, iaDest, slayers.SCMPTypeEchoRequest, 40441, 1)
		raw := interfaceDownPacket(t, iaMid, iaLeaf, iaMid, testIfID, quoted)
		topic := new(bus.Topic[bus.InterfaceDownState])
		c := &Conn{ifDown: topic}
		arrival := time.Now()
		if _, ok := c.recordInterfaceDown(raw); !ok {
			t.Fatal("the signal was not recognized")
		}
		link := segment.LinkID{IA: iaMid, IfID: testIfID}
		if at, ok := topic.Latest().Arrived(link, arrival); !ok || !at.Equal(arrival) {
			t.Errorf("the signaled link's arrival = %v (standing %v), want %v", at, ok, arrival)
		}
		if _, ok := (&Conn{}).recordInterfaceDown(raw); !ok {
			t.Error("a conn without the topic did not recognize the signal")
		}
	})
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
// the signaled ISD-AS and interface, and the quote names the echo request it
// carried; every other packet is not one — a forged signal from any speaker
// on a path is worth no more than one signal.
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
// interface — the crossing a signal doubts — ending at the given
// terminator.
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

// TestPicksAvoidSignaledPaths checks the sender's reaction to a signal: the
// paths through the signaled interface read suspect, so a clean path serves
// instead, past the ten seconds a signal once held; a lone signaled path
// stays the last resort; and the signaled path serves again once the signal
// lapses. Time passes as fake-time sleeps in the bubble, the segments
// refreshed after each.
func TestPicksAvoidSignaledPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		down := new(bus.Topic[bus.InterfaceDownState])
		signaled := segment.LinkID{IA: iaMid, IfID: testIfID}
		// segments returns the freshest segment, through the signaled
		// interface, and a clean one a moment older over another.
		segments := func() (through, clean *pathdb.Segment) {
			now := time.Now()
			return crossingSegment(t, iaMid, iaLeaf, testIfID, now),
				crossingSegment(t, iaMid, iaLeaf, testIfID+1, now.Add(-time.Second))
		}
		p := &PathProvider{IA: iaLeaf, InterfaceDown: down}
		// crosses reports whether the pick over the segments crosses the
		// signaled interface.
		crosses := func(segs ...*pathdb.Segment) bool {
			t.Helper()
			p.DB = &fakePathDB{segs: segs}
			c, err := p.local(iaMid)
			if err != nil {
				t.Fatal(err)
			}
			return slices.Contains(c.Crossed, signaled)
		}

		if !crosses(segments()) {
			t.Fatal("the pick avoids the freshest path before any signal")
		}
		signal(down, iaMid, testIfID)
		time.Sleep(time.Minute)
		through, clean := segments()
		if crosses(through, clean) {
			t.Error("the pick crosses the signaled interface a minute after the signal")
		}
		if !crosses(through) {
			t.Error("the lone signaled path does not serve as the last resort")
		}

		time.Sleep(bus.RequestLapse - time.Minute)
		if !crosses(segments()) {
			t.Error("the pick avoids the freshest path once the signal lapsed")
		}
	})
}

// TestPicksAvoidSignaledDownSegment checks the composed route's other half:
// a route over a down segment through a signaled interface reads suspect,
// and one over a clean down segment serves instead, the signaled one kept as
// the last resort.
func TestPicksAvoidSignaledDownSegment(t *testing.T) {
	down := new(bus.Topic[bus.InterfaceDownState])
	now := time.Now()
	signaled := segment.LinkID{IA: iaMid, IfID: testIfID + 1}
	up := upSegment(t, now, iaMid, iaLeaf)
	throughDown := crossingSegment(t, iaMid, iaDest, signaled.IfID, now)
	throughDown.Type = pathdb.SegmentTypeDown
	cleanDown := crossingSegment(t, iaMid, iaDest, testIfID+2, now.Add(-time.Second))
	cleanDown.Type = pathdb.SegmentTypeDown
	p := &PathProvider{
		IA: iaLeaf,
		DB: &fakePathDB{segs: []*pathdb.Segment{up}},
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{throughDown, cleanDown}
		},
		InterfaceDown: down,
	}
	signal(down, signaled.IA, signaled.IfID)
	c, err := p.Choose(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(c.Crossed, signaled) {
		t.Errorf("the pick %s crosses the signaled interface, want the clean down segment's route", c.ID)
	}

	// With the signaled down segment alone, its route serves as the last
	// resort.
	p.Lookup = func(context.Context, addr.IA) []*pathdb.Segment {
		return []*pathdb.Segment{throughDown}
	}
	if _, err := p.Choose(context.Background(), iaDest); err != nil {
		t.Fatalf("the lone signaled route was dropped: %v", err)
	}
}
