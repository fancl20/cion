package dataplane

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/evidence"
)

// markingPolicy is a congestion policy that marks every echo reply it is
// asked of, or none, and keeps the links and egress fills it was asked with;
// it paces nothing.
type markingPolicy struct {
	mark  bool
	asked []askedMark
}

// askedMark is one echo reply the data plane asked the policy to mark: the
// link it came back over and the fill of that link's egress queue.
type askedMark struct {
	ifID uint16
	fill float64
}

func (f *markingPolicy) Wrote(uint16, int, int, bool)    {}
func (f *markingPolicy) Rate(uint16) float64             { return 0 }
func (f *markingPolicy) Sampled(uint16, evidence.Sample) {}

func (f *markingPolicy) Mark(ifID uint16, fill float64) bool {
	f.asked = append(f.asked, askedMark{ifID, fill})
	return f.mark
}

// echoSpec is an echo request or reply the tests drive through the bench
// node: its type, its source and destination, the path it rides, and the
// link it enters by.
type echoSpec struct {
	typ      slayers.SCMPType
	src, dst addr.IA
	path     func(testing.TB, []byte, uint32) *scion.Decoded
	ingress  func(*benchNode) Link
}

// The echoes the tests drive through the bench node: a reply in transit from
// interface 2 to 1, one to the node over interface 1, one from the node over
// interface 1, and a request in transit from interface 1 to 2.
var (
	replyTransit   = echoSpec{slayers.SCMPTypeEchoReply, benchDstAS, benchSrcAS, revDirPath, benchIf2}
	replyToNode    = echoSpec{slayers.SCMPTypeEchoReply, benchSrcAS, benchLocal, inboundPath, benchIf1}
	replyFromNode  = echoSpec{slayers.SCMPTypeEchoReply, benchLocal, benchSrcAS, outboundPath, benchInternal}
	requestTransit = echoSpec{slayers.SCMPTypeEchoRequest, benchSrcAS, benchDstAS, transitPath, benchIf1}
)

// benchInternal, benchIf1, and benchIf2 return the bench node's links.
func benchInternal(n *benchNode) Link { return n.internal }
func benchIf1(n *benchNode) Link      { return n.if1 }
func benchIf2(n *benchNode) Link      { return n.if2 }

// echoPacket returns the spec's packet with the traffic class tc and every
// flow ID bit set, so a rewrite of the bits beside the ECN ones shows.
func echoPacket(t *testing.T, n *benchNode, s echoSpec, tc uint8) []byte {
	t.Helper()
	scn := &slayers.SCION{
		TrafficClass: tc,
		FlowID:       0xfffff,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		Path:         s.path(t, n.key, util.TimeToSecs(time.Now())),
		SrcIA:        s.src,
		DstIA:        s.dst,
	}
	if err := scn.SetSrcAddr(benchHost); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(benchHost); err != nil {
		t.Fatal(err)
	}
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(s.typ, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		scn, scmp, &slayers.SCMPEcho{Identifier: 40123, SeqNumber: 7})
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// TestArrivalsMarkedByTheirLinksQueue checks the marks: an ECN-capable
// packet that came in over an external link, in transit or to the node,
// asks the policy with that link and its egress queue's fill while that
// queue holds data, and carries CE when the policy marks it, the bits beside
// the ECN ones untouched; a packet the node sends, one not ECN-capable or
// marked already, and one over a link whose queue is empty ask nothing;
// without a policy nothing is marked.
func TestArrivalsMarkedByTheirLinksQueue(t *testing.T) {
	tests := []struct {
		name      string
		echo      echoSpec
		policy    *markingPolicy
		empty     bool
		ecn, want byte
		asked     uint16
	}{
		{"reply in transit, marked", replyTransit, &markingPolicy{mark: true}, false, ecnECT0, ecnCE, 2},
		{"reply in transit, ECT(1)", replyTransit, &markingPolicy{mark: true}, false, ecnECT1, ecnCE, 2},
		{"reply in transit, unmarked", replyTransit, &markingPolicy{}, false, ecnECT0, ecnECT0, 2},
		{"reply to the node, marked", replyToNode, &markingPolicy{mark: true}, false, ecnECT0, ecnCE, 1},
		{"request in transit, marked", requestTransit, &markingPolicy{mark: true}, false, ecnECT0, ecnCE, 1},
		{"reply from the node", replyFromNode, &markingPolicy{mark: true}, false, ecnECT0, ecnECT0, 0},
		{"reply not ECN-capable", replyTransit, &markingPolicy{mark: true}, false, 0, 0, 0},
		{"reply marked already", replyTransit, &markingPolicy{mark: true}, false, ecnCE, ecnCE, 0},
		{"reply over an empty queue", replyTransit, &markingPolicy{mark: true}, true, ecnECT0, ecnECT0, 0},
		{"without a policy", replyTransit, nil, false, ecnECT0, ecnECT0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := newBenchNode(t, benchRunConfig)
			if tc.policy != nil {
				n.d.RunConfig.Congestion = tc.policy
			}
			if el, ok := tc.echo.ingress(n).(*externalLink); ok && !tc.empty {
				el.egressQ <- &Packet{}
			}
			proc := newPacketProcessor(n.d)
			// A DSCP whose low bits sit beside the ECN ones.
			const dscp = 0x2d << 2
			pool := newTestPool(1, minHeadroom)
			p := fillBenchPacket(pool.Get(), echoPacket(t, n, tc.echo, dscp|tc.ecn>>4), tc.echo.ingress(n))
			proc.now = time.Now()
			if disp := proc.processPkt(p); disp != pForward {
				t.Fatalf("disposition = %d, want %d", disp, pForward)
			}
			raw := p.RawPacket
			if got := raw[1] & ecnMask; got != tc.want {
				t.Errorf("ECN bits = %#x, want %#x", got, tc.want)
			}
			if raw[0]&0x0f != dscp>>4 || raw[1]&^ecnMask != (dscp<<4)&0xc0|0x0f {
				t.Errorf("header bytes %#x %#x moved beside the ECN bits", raw[0], raw[1])
			}
			if tc.policy == nil {
				return
			}
			var want []askedMark
			if tc.asked != 0 {
				want = []askedMark{{tc.asked, n.d.interfaces[tc.asked].EgressFill()}}
			}
			if diff := cmp.Diff(want, tc.policy.asked, cmp.AllowUnexported(askedMark{})); diff != "" {
				t.Errorf("marks asked (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFullEgressQueueDropsItsOldest checks a full egress queue: it drops its
// oldest packet to take a new one, which leaves after the rest, and an empty
// queue drops nothing.
func TestFullEgressQueueDropsItsOldest(t *testing.T) {
	q := make(chan *Packet, 2)
	packet := func(tag byte) *Packet { return &Packet{RawPacket: []byte{tag}} }
	for _, tag := range []byte{'a', 'b'} {
		if dropped, ok := enqueueOverOldest(q, packet(tag)); dropped != nil || !ok {
			t.Fatalf("queueing %q: dropped %v, taken %v; want nothing dropped and taken", tag, dropped, ok)
		}
	}
	dropped, ok := enqueueOverOldest(q, packet('c'))
	if !ok || dropped == nil || dropped.RawPacket[0] != 'a' {
		t.Fatalf("queueing past the bound: dropped %v, taken %v; want the oldest dropped and taken", dropped, ok)
	}
	var left []byte
	for range 2 {
		left = append(left, (<-q).RawPacket[0])
	}
	if string(left) != "bc" {
		t.Errorf("the queue then holds %q, want %q", left, "bc")
	}
}
