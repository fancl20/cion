package dataplane

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// The benchmark topology: a transit node in AS 1-ff00:0:1, the source AS's
// router behind interface 1, the destination AS's behind interface 2. Every
// router shares the forwarding key, as if the control plane had distributed
// it.
var (
	benchKey   = []byte("0123456789abcdef")
	benchLocal = addr.MustIAFrom(1, 0xff0000000001)
	benchSrcAS = addr.MustIAFrom(1, 0xff0000000002)
	benchDstAS = addr.MustIAFrom(1, 0xff0000000003)
	benchHost  = addr.HostIP(netip.MustParseAddr("127.0.0.1"))
)

const (
	// benchHopExpTime is the hop fields' expiry exponent: the maximum
	// validity window, so a template built once serves a whole benchmark run.
	benchHopExpTime = 63

	// benchExpiredAge is how far in the past the expired-path template's
	// segment is dated: beyond the maximum validity window the hop expiry
	// check accepts, so the validation cannot lapse mid-benchmark.
	benchExpiredAge = 25 * time.Hour

	// benchFlow is the flow ID every template carries unless a benchmark
	// varies it; benchPad is the UDP payload padding of the default
	// templates.
	benchFlow uint32 = 0x1111
	benchPad  int    = 64

	// benchFlowCount is the many-flow load: enough distinct flows that the
	// dispatch hash spreads them across the pipeline matrix's largest
	// processor set. The step keeps the patched IDs apart within the common
	// header's 20 flow bits.
	benchFlowCount = 64
	benchFlowStep  = 7919

	// benchEgressQSize funds the pipeline benchmark's in-flight window (see
	// BenchmarkForwardPipeline): every queue a packet in flight can rest in
	// holds at least a batch, and the egress queues hold this much.
	benchEgressQSize = 1024

	// benchMaxProcs is the processor count the dispatch-side component
	// benchmarks hash against: the largest of the pipeline matrix.
	benchMaxProcs = 4
)

// idleSession is the BFD session of a benchmark link: arrivals are counted,
// nothing else. The liveness dispatch benchmark needs a session to hand its
// control packets to, without the protocol state behind it.
type idleSession struct {
	arrivals atomic.Uint64
}

func (s *idleSession) ReceiveMessage(*layers.BFD) { s.arrivals.Add(1) }
func (s *idleSession) IsUp() bool                 { return true }
func (s *idleSession) SetRawWriter(RawWriter)     {}

// benchRunConfig is the micro-benchmarks' plane shape: one processor of each
// kind, since they drive the processors directly, over the production socket
// buffers.
var benchRunConfig = RunConfig{
	NumProcessors:         1,
	NumSlowPathProcessors: 1,
	BatchSize:             64,
	ReceiveBufferSize:     1 << 20,
	SendBufferSize:        1 << 20,
}

// benchNode is the transit topology the benchmarks drive: one data plane
// with the internal link and two external links, interface IDs 1 and 2, over
// the UDP provider. The external links' far ends are sockets the harness
// owns — the pipeline benchmark sends into one and counts at the other —
// while the micro-benchmarks use only the links and the processors built on
// the plane. The caller configures the global meter provider before
// building; the node's metrics bind to whatever is installed.
type benchNode struct {
	d        *DataPlane
	provider *UDPProvider
	key      []byte
	internal Link
	if1      Link // external, interface 1; far end: the source AS's router
	if2      Link // external, interface 2; far end: the destination AS's router
	// The far ends of the external links, bound by the harness.
	srcEnd *net.UDPConn
	dstEnd *net.UDPConn
	// if1Addr is link 1's local socket: the address a sender writes into.
	if1Addr netip.AddrPort
}

func newBenchNode(tb testing.TB, rc RunConfig) *benchNode {
	tb.Helper()

	metrics, err := NewMetrics()
	if err != nil {
		tb.Fatal(err)
	}
	provider := NewUDPProvider(rc.BatchSize, rc.ReceiveBufferSize, rc.SendBufferSize)
	srcEnd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	dstEnd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	// The far ends' buffers must cover the in-flight window a full batch
	// charges — a datagram's kernel cost is its payload plus per-skb
	// overhead — or the kernel itself drops the burst the window allows,
	// a loss no counter in the plane names.
	if rc.ReceiveBufferSize != 0 {
		_ = srcEnd.SetReadBuffer(rc.ReceiveBufferSize)
		_ = dstEnd.SetReadBuffer(rc.ReceiveBufferSize)
	}
	internal, err := provider.NewInternalLink(
		freeUDPAddr(tb), benchEgressQSize, metrics.NewInterfaceMetrics(0, benchLocal, 0),
	)
	if err != nil {
		tb.Fatal(err)
	}
	if1, err := provider.NewExternalLink(
		benchEgressQSize, &idleSession{}, freeUDPAddr(tb), srcEnd.LocalAddr().String(),
		1, metrics.NewInterfaceMetrics(1, benchLocal, benchSrcAS),
	)
	if err != nil {
		tb.Fatal(err)
	}
	if2, err := provider.NewExternalLink(
		benchEgressQSize, nil, freeUDPAddr(tb), dstEnd.LocalAddr().String(),
		2, metrics.NewInterfaceMetrics(2, benchLocal, benchDstAS),
	)
	if err != nil {
		tb.Fatal(err)
	}
	d, err := NewDataPlane(benchLocal, benchHost, benchKey, provider,
		[]Link{internal, if1, if2})
	if err != nil {
		tb.Fatal(err)
	}
	d.RunConfig = rc

	n := &benchNode{
		d:        d,
		provider: provider,
		key:      benchKey,
		internal: internal,
		if1:      if1,
		if2:      if2,
		srcEnd:   srcEnd,
		dstEnd:   dstEnd,
	}
	for _, c := range provider.allConnections {
		if l, ok := c.link.(*connectedLink); ok && l.ifID == 1 {
			n.if1Addr = c.conn.conn.LocalAddr().(*net.UDPAddr).AddrPort()
		}
	}
	tb.Cleanup(func() {
		provider.Stop()
		_ = srcEnd.Close()
		_ = dstEnd.Close()
	})
	return n
}

// fillBenchPacket copies a template into a pooled packet and points it at
// its ingress link — what the receive path would have handed the processor.
func fillBenchPacket(p *Packet, tmpl []byte, ingress Link) *Packet {
	p.RawPacket = p.RawPacket[:len(tmpl)]
	copy(p.RawPacket, tmpl)
	p.Link = ingress
	return p
}

// varyFlow returns a copy of the template with the given flow ID patched
// into its common header — the one field the dispatch hash reads, and free
// to change: nothing on the forwarding path covers it.
func varyFlow(tmpl []byte, flow uint32) []byte {
	out := make([]byte, len(tmpl))
	copy(out, tmpl)
	out[1] = out[1]&0xF0 | byte(flow>>16)
	out[2] = byte(flow >> 8)
	out[3] = byte(flow)
	return out
}

// benchMAC computes a hop field MAC the way the key holder would.
func benchMAC(tb testing.TB, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	tb.Helper()
	mac, err := scrypto.InitMac(key)
	if err != nil {
		tb.Fatal(err)
	}
	return path.MAC(mac, info, hf, nil)
}

// transitPath returns the canonical forwarding shape: a two-hop path in
// construction direction whose current hop is the transit node's own —
// entering interface 1, leaving interface 2.
func transitPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	ours := path.HopField{ConsIngress: 1, ConsEgress: 2, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, info, ours)
	arrived := info
	arrived.UpdateSegID(ours.Mac)
	theirs := path.HopField{ConsIngress: 21, ConsEgress: 0, ExpTime: benchHopExpTime}
	theirs.Mac = benchMAC(tb, key, arrived, theirs)
	return &scion.Decoded{
		InfoFields: []path.InfoField{info},
		HopFields:  []path.HopField{ours, theirs},
		NumINF:     1,
		NumHops:    2,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{2, 0, 0}},
	}
}

// xoverPath returns the two-segment shape that crosses over at the transit
// node: segment 0 ends at the node's ingress hop on interface 1, segment 1
// starts at its egress hop on interface 2. The stored SegIDs are the ones an
// arriving packet carries — segment 0's already advanced by the upstream
// egress router, segment 1's untouched.
func xoverPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info0 := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	src := path.HopField{ConsIngress: 0, ConsEgress: 11, ExpTime: benchHopExpTime}
	src.Mac = benchMAC(tb, key, info0, src)
	arrived0 := info0
	arrived0.UpdateSegID(src.Mac)
	ours0 := path.HopField{ConsIngress: 1, ConsEgress: 0, ExpTime: benchHopExpTime}
	ours0.Mac = benchMAC(tb, key, arrived0, ours0)

	info1 := path.InfoField{SegID: 0x222, ConsDir: true, Timestamp: ts}
	ours1 := path.HopField{ConsIngress: 0, ConsEgress: 2, ExpTime: benchHopExpTime}
	ours1.Mac = benchMAC(tb, key, info1, ours1)
	arrived1 := info1
	arrived1.UpdateSegID(ours1.Mac)
	dst := path.HopField{ConsIngress: 21, ConsEgress: 0, ExpTime: benchHopExpTime}
	dst.Mac = benchMAC(tb, key, arrived1, dst)

	return &scion.Decoded{
		InfoFields: []path.InfoField{arrived0, info1},
		HopFields:  []path.HopField{src, ours0, ours1, dst},
		NumINF:     2,
		NumHops:    4,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{2, 2, 0}, CurrINF: 0, CurrHF: 1},
	}
}

// revDirPath returns the same transit traversed against construction
// direction: entering interface 2, leaving interface 1. It is the forward
// shape's reverse — hop order reversed, construction flag flipped — dated
// from the far end and carrying the SegID the forward traversal left there,
// so the node's own MAC check walks the chain backwards from it.
func revDirPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	src := path.HopField{ConsIngress: 0, ConsEgress: 11, ExpTime: benchHopExpTime}
	src.Mac = benchMAC(tb, key, info, src)
	afterSrc := info
	afterSrc.UpdateSegID(src.Mac)
	ours := path.HopField{ConsIngress: 1, ConsEgress: 2, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, afterSrc, ours)
	afterOurs := afterSrc
	afterOurs.UpdateSegID(ours.Mac)
	dst := path.HopField{ConsIngress: 21, ConsEgress: 0, ExpTime: benchHopExpTime}
	dst.Mac = benchMAC(tb, key, afterOurs, dst)

	forward := &scion.Decoded{
		InfoFields: []path.InfoField{afterOurs},
		HopFields:  []path.HopField{src, ours, dst},
		NumINF:     1,
		NumHops:    3,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{3, 0, 0}, CurrHF: 1},
	}
	rev, err := forward.Reverse()
	if err != nil {
		tb.Fatal(err)
	}
	return rev.(*scion.Decoded)
}

// inboundPath returns the delivered-to-local-AS shape: the last hop ends
// here, its SegID already advanced by the source AS's egress router.
func inboundPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	src := path.HopField{ConsIngress: 0, ConsEgress: 1, ExpTime: benchHopExpTime}
	src.Mac = benchMAC(tb, key, info, src)
	arrived := info
	arrived.UpdateSegID(src.Mac)
	ours := path.HopField{ConsIngress: 1, ConsEgress: 0, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, arrived, ours)
	return &scion.Decoded{
		InfoFields: []path.InfoField{arrived},
		HopFields:  []path.HopField{src, ours},
		NumINF:     1,
		NumHops:    2,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{2, 0, 0}, CurrHF: 1},
	}
}

// outboundPath returns the locally-originated shape: entering via the
// internal link with the transit node's egress hop on interface 1 current.
func outboundPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	ours := path.HopField{ConsIngress: 0, ConsEgress: 1, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, info, ours)
	arrived := info
	arrived.UpdateSegID(ours.Mac)
	theirs := path.HopField{ConsIngress: 11, ConsEgress: 0, ExpTime: benchHopExpTime}
	theirs.Mac = benchMAC(tb, key, arrived, theirs)
	return &scion.Decoded{
		InfoFields: []path.InfoField{info},
		HopFields:  []path.HopField{ours, theirs},
		NumINF:     1,
		NumHops:    2,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{2, 0, 0}},
	}
}

// serializeUDP returns src-to-dst traffic over the given path: a SCION
// header carrying the flow ID, a UDP header on the benchmark ports, and pad
// zero bytes of payload. UDP is the L4 the fast path's destination
// resolution reads the delivery port from.
func serializeUDP(
	tb testing.TB, src, dst addr.IA, p *scion.Decoded, flow uint32, pad int,
) []byte {
	tb.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4UDP,
		PathType: scion.PathType,
		Path:     p,
		FlowID:   flow,
		SrcIA:    src,
		DstIA:    dst,
	}
	if err := scn.SetSrcAddr(benchHost); err != nil {
		tb.Fatal(err)
	}
	if err := scn.SetDstAddr(benchHost); err != nil {
		tb.Fatal(err)
	}
	udp := &slayers.UDP{SrcPort: 40000, DstPort: 40001}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, udp, gopacket.Payload(make([]byte, pad)))
	if err != nil {
		tb.Fatal(err)
	}
	return buffer.Bytes()
}

// expiredTransitPath returns the full transit path — the source AS's egress
// hop included — with the transit node's hop current. The source's hop is
// what the reversed reply path routes the answer back over; the plain
// two-hop shape the fast-path benchmarks use carries no hop to return to.
func expiredTransitPath(tb testing.TB, key []byte, ts uint32) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: ts}
	src := path.HopField{ConsIngress: 0, ConsEgress: 11, ExpTime: benchHopExpTime}
	src.Mac = benchMAC(tb, key, info, src)
	afterSrc := info
	afterSrc.UpdateSegID(src.Mac)
	ours := path.HopField{ConsIngress: 1, ConsEgress: 2, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, afterSrc, ours)
	afterOurs := afterSrc
	afterOurs.UpdateSegID(ours.Mac)
	theirs := path.HopField{ConsIngress: 21, ConsEgress: 0, ExpTime: benchHopExpTime}
	theirs.Mac = benchMAC(tb, key, afterOurs, theirs)
	return &scion.Decoded{
		InfoFields: []path.InfoField{afterSrc},
		HopFields:  []path.HopField{src, ours, theirs},
		NumINF:     1,
		NumHops:    3,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{3, 0, 0}, CurrHF: 1},
	}
}

// expiredTransitPacket returns the packet the slow-path benchmark answers:
// the full transit shape dated past every validity window, so hop expiry
// validation routes it to the slow path.
func expiredTransitPacket(tb testing.TB, key []byte) []byte {
	tb.Helper()
	return serializeUDP(tb, benchSrcAS, benchDstAS,
		expiredTransitPath(tb, key, util.TimeToSecs(time.Now().Add(-benchExpiredAge))),
		benchFlow, benchPad)
}

// bfdPacket returns one SCION-framed BFD control packet — the frame the
// control plane's liveness sessions send and the data plane's BFD branch
// parses on arrival.
func bfdPacket(tb testing.TB, key []byte) []byte {
	tb.Helper()
	info := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())}
	hop := path.HopField{ConsIngress: 0, ConsEgress: 1, ExpTime: benchHopExpTime}
	hop.Mac = benchMAC(tb, key, info, hop)
	scn := &slayers.SCION{
		NextHdr:  slayers.L4BFD,
		PathType: onehop.PathType,
		Path:     &onehop.Path{Info: info, FirstHop: hop},
		SrcIA:    benchSrcAS,
		DstIA:    benchLocal,
	}
	if err := scn.SetSrcAddr(benchHost); err != nil {
		tb.Fatal(err)
	}
	if err := scn.SetDstAddr(benchHost); err != nil {
		tb.Fatal(err)
	}
	bfd := &layers.BFD{
		Version:               1,
		State:                 layers.BFDStateUp,
		DetectMultiplier:      3,
		MyDiscriminator:       0x1234567,
		YourDiscriminator:     0x7654321,
		DesiredMinTxInterval:  layers.BFDTimeInterval(time.Second.Microseconds()),
		RequiredMinRxInterval: layers.BFDTimeInterval(time.Second.Microseconds()),
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, bfd); err != nil {
		tb.Fatal(err)
	}
	return buffer.Bytes()
}

// benchCases enumerates the benchmark traffic through the real processPkt:
// one entry per reachable traffic class and path shape. The build function's
// pad argument sizes the UDP payload; ingress returns the link the packet
// enters by; the remaining fields are what processPkt must produce — the
// generator correctness test asserts them, and the fast-path benchmark
// carries them into its own invariants.
var benchCases = []struct {
	name        string
	build       func(testing.TB, *benchNode, int) []byte
	ingress     func(*benchNode) Link
	disposition disposition
	egress      uint16
	traffic     trafficType
}{
	{
		name: "br_transit/plain",
		build: func(tb testing.TB, n *benchNode, pad int) []byte {
			return serializeUDP(tb, benchSrcAS, benchDstAS,
				transitPath(tb, n.key, util.TimeToSecs(time.Now())), benchFlow, pad)
		},
		ingress:     func(n *benchNode) Link { return n.if1 },
		disposition: pForward,
		egress:      2,
		traffic:     ttBrTransit,
	},
	{
		name: "br_transit/xover",
		build: func(tb testing.TB, n *benchNode, pad int) []byte {
			return serializeUDP(tb, benchSrcAS, benchDstAS,
				xoverPath(tb, n.key, util.TimeToSecs(time.Now())), benchFlow, pad)
		},
		ingress:     func(n *benchNode) Link { return n.if1 },
		disposition: pForward,
		egress:      2,
		traffic:     ttBrTransit,
	},
	{
		name: "br_transit/revdir",
		build: func(tb testing.TB, n *benchNode, pad int) []byte {
			return serializeUDP(tb, benchDstAS, benchSrcAS,
				revDirPath(tb, n.key, util.TimeToSecs(time.Now())), benchFlow, pad)
		},
		ingress:     func(n *benchNode) Link { return n.if2 },
		disposition: pForward,
		egress:      1,
		traffic:     ttBrTransit,
	},
	{
		name: "in/deliver",
		build: func(tb testing.TB, n *benchNode, pad int) []byte {
			return serializeUDP(tb, benchSrcAS, benchLocal,
				inboundPath(tb, n.key, util.TimeToSecs(time.Now())), benchFlow, pad)
		},
		ingress:     func(n *benchNode) Link { return n.if1 },
		disposition: pForward,
		egress:      0,
		traffic:     ttIn,
	},
	{
		name: "out/forward",
		build: func(tb testing.TB, n *benchNode, pad int) []byte {
			return serializeUDP(tb, benchLocal, benchSrcAS,
				outboundPath(tb, n.key, util.TimeToSecs(time.Now())), benchFlow, pad)
		},
		ingress:     func(n *benchNode) Link { return n.internal },
		disposition: pForward,
		egress:      1,
		traffic:     ttOut,
	},
}

// TestBenchmarkGenerators runs every benchmark packet generator through
// processPkt once and asserts where each packet lands: disposition, egress
// interface, traffic type. A benchmark timing a discarded or misrouted
// packet measures nothing, and the generators are the one place this suite
// can lie quietly.
func TestBenchmarkGenerators(t *testing.T) {
	for _, tc := range benchCases {
		t.Run(tc.name, func(t *testing.T) {
			n := newBenchNode(t, benchRunConfig)
			pool := newTestPool(64, minHeadroom)
			proc := newPacketProcessor(n.d)

			p := fillBenchPacket(pool.Get(), tc.build(t, n, benchPad), tc.ingress(n))
			defer pool.Put(p)
			if got := proc.processPkt(p); got != tc.disposition {
				t.Fatalf("disposition = %d, want %d", got, tc.disposition)
			}
			if p.egress != tc.egress {
				t.Errorf("egress = %d, want %d", p.egress, tc.egress)
			}
			if p.trafficType != tc.traffic {
				t.Errorf("traffic type = %v, want %v", p.trafficType, tc.traffic)
			}
			if tc.traffic == ttIn && (*net.UDPAddr)(p.RemoteAddr) == nil {
				t.Error("inbound packet carries no resolved destination")
			}
		})
	}

	t.Run("bfd/dispatch", func(t *testing.T) {
		n := newBenchNode(t, benchRunConfig)
		pool := newTestPool(64, minHeadroom)
		proc := newPacketProcessor(n.d)

		p := fillBenchPacket(pool.Get(), bfdPacket(t, n.key), n.if1)
		defer pool.Put(p)
		if got := proc.processPkt(p); got != pDone {
			t.Fatalf("disposition = %d, want %d", got, pDone)
		}
		if got := n.if1.BFDSession().(*idleSession).arrivals.Load(); got != 1 {
			t.Errorf("session arrivals = %d, want 1", got)
		}
	})

	t.Run("scmp/expired", func(t *testing.T) {
		n := newBenchNode(t, benchRunConfig)
		pool := newTestPool(64, minHeadroom)
		fast := newPacketProcessor(n.d)
		slow := newSlowPathProcessor(n.d)

		p := fillBenchPacket(pool.Get(), expiredTransitPacket(t, n.key), n.if1)
		defer pool.Put(p)
		if got := fast.processPkt(p); got != pSlowPath {
			t.Fatalf("disposition = %d, want %d", got, pSlowPath)
		}
		if err := slow.processPacket(p); err != nil {
			t.Fatalf("answering the expired path: %v", err)
		}
		if p.trafficType != ttOther {
			t.Errorf("answered traffic type = %v, want %v", p.trafficType, ttOther)
		}
	})
}
