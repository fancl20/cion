package dataplane

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"golang.org/x/net/ipv4"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// controlTC is the traffic class the node's control-plane sockets mark.
const controlTC = underlay.ControlDSCP << 2

// withTrafficClass returns a copy of the packet with the traffic class set in
// its common header.
func withTrafficClass(raw []byte, tc uint8) []byte {
	out := slices.Clone(raw)
	out[0] = out[0]&0xF0 | tc>>4
	out[1] = out[1]&0x0F | tc<<4
	return out
}

// withNextHdr returns a copy of the packet with the common header's next
// header set.
func withNextHdr(raw []byte, nextHdr slayers.L4ProtocolType) []byte {
	out := slices.Clone(raw)
	out[nextHdrOffset] = byte(nextHdr)
	return out
}

// TestClassOf checks the class the common header gives an arrival.
func TestClassOf(t *testing.T) {
	udp := scionLikeDatagram(nil)
	tests := []struct {
		name     string
		raw      []byte
		internal bool
		want     class
	}{
		{"SCMP from an external link", withNextHdr(udp, slayers.L4SCMP), false, classControl},
		{"SCMP from the internal link", withNextHdr(udp, slayers.L4SCMP), true, classControl},
		{"BFD from an external link", withNextHdr(udp, slayers.L4BFD), false, classLink},
		{"the control DSCP from the internal link", withTrafficClass(udp, controlTC), true,
			classControl},
		{"the control DSCP and ECN bits from the internal link",
			withTrafficClass(udp, controlTC|0x3), true, classControl},
		{"the control DSCP from an external link", withTrafficClass(udp, controlTC), false,
			classData},
		{"another DSCP from the internal link", withTrafficClass(udp, 46<<2), true, classData},
		{"unmarked UDP from the internal link", udp, true, classData},
		{"shorter than the common header",
			withNextHdr(udp, slayers.L4SCMP)[:commonHdrLen-1], false, classData},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classOf(tc.raw, tc.internal); got != tc.want {
				t.Errorf("classOf() = %d, want %d", got, tc.want)
			}
		})
	}
}

// bfdOver returns a SCION-framed BFD control packet over the given path.
func bfdOver(t *testing.T, pathType path.Type, p path.Path) []byte {
	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4BFD,
		PathType: pathType,
		Path:     p,
		SrcIA:    benchSrcAS,
		DstIA:    benchLocal,
	}
	if err := scn.SetSrcAddr(benchHost); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(benchHost); err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// TestBFDReader checks what the receive loop hands a link's session: a BFD
// message over a one-hop or an empty path, and nothing over another path,
// from a truncated packet, or to a link without a session.
func TestBFDReader(t *testing.T) {
	ts := util.TimeToSecs(time.Now())
	oneHop := bfdPacket(t, benchKey)
	tests := []struct {
		name    string
		raw     []byte
		session bool
		want    bool
	}{
		{"one-hop path", oneHop, true, true},
		{"empty path", bfdOver(t, empty.PathType, empty.Path{}), true, true},
		{"SCION path", bfdOver(t, scion.PathType, transitPath(t, benchKey, ts)), true, false},
		{"truncated", oneHop[:len(oneHop)-4], true, false},
		{"no session", oneHop, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &idleSession{}
			var session Session
			if tc.session {
				session = s
			}
			if got := newBFDReader().read(tc.raw, session); got != tc.want {
				t.Errorf("read() = %v, want %v", got, tc.want)
			}
			var want uint64
			if tc.want {
				want = 1
			}
			if got := s.arrivals.Load(); got != want {
				t.Errorf("session arrivals = %d, want %d", got, want)
			}
		})
	}
}

// fullQueue returns a queue of one packet that already holds one.
func fullQueue(pool PacketPool) chan *Packet {
	q := make(chan *Packet, 1)
	q <- pool.Get()
	return q
}

// TestBFDSkipsEveryQueue checks that a BFD arrival reaches its link's session
// while the data processor queues and the control queue are full.
func TestBFDSkipsEveryQueue(t *testing.T) {
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(8, minHeadroom)
	el := n.if1.(*externalLink)
	el.start(context.Background(), []chan *Packet{fullQueue(pool)}, fullQueue(pool), pool)

	p := fillBenchPacket(pool.Get(), bfdPacket(t, n.key), n.if1)
	el.receive(len(p.RawPacket), &net.UDPAddr{}, p)
	if got := el.bfdSession.(*idleSession).arrivals.Load(); got != 1 {
		t.Fatalf("session arrivals = %d, want 1", got)
	}
	if got := len(pool.pool); got != 6 {
		t.Errorf("pool holds %d packets, want 6: the BFD arrival's buffer returned", got)
	}
}

// busyDrops returns the busy-processor drops recorded against the interface
// for packets of the template's size.
func busyDrops(t *testing.T, sums map[metricKey]int64, ifID string, tmpl []byte) int64 {
	t.Helper()
	return sums[metricKey{"dataplane.dropped_packets_total", ifID,
		ClassOfSize(len(tmpl)).String(), "busy_processor"}]
}

// TestControlSkipsBusyProcessors checks that SCMP on an external link and
// the control DSCP on the internal link land on the control queue while the
// data processor queues are full, and that a data arrival, the control DSCP
// on an external link included, drops as busy.
func TestControlSkipsBusyProcessors(t *testing.T) {
	ts := util.TimeToSecs(time.Now())
	tests := []struct {
		name    string
		link    func(*benchNode) Link
		ifID    string
		build   func(*testing.T, *benchNode) []byte
		control bool
	}{
		{
			name: "SCMP on an external link",
			link: func(n *benchNode) Link { return n.if1 },
			ifID: "1",
			build: func(t *testing.T, n *benchNode) []byte {
				return scmpPacket(t, benchSrcAS, benchDstAS, transitPath(t, n.key, ts),
					slayers.SCMPTypeEchoRequest, 1)
			},
			control: true,
		},
		{
			name: "the control DSCP on the internal link",
			link: func(n *benchNode) Link { return n.internal },
			ifID: "0",
			build: func(t *testing.T, n *benchNode) []byte {
				return withTrafficClass(serializeUDP(t, benchLocal, benchSrcAS,
					outboundPath(t, n.key, ts), benchFlow, benchPad), controlTC)
			},
			control: true,
		},
		{
			name: "data on an external link",
			link: func(n *benchNode) Link { return n.if1 },
			ifID: "1",
			build: func(t *testing.T, n *benchNode) []byte {
				return serializeUDP(t, benchSrcAS, benchDstAS, transitPath(t, n.key, ts),
					benchFlow, benchPad)
			},
		},
		{
			name: "the control DSCP on an external link",
			link: func(n *benchNode) Link { return n.if1 },
			ifID: "1",
			build: func(t *testing.T, n *benchNode) []byte {
				return withTrafficClass(serializeUDP(t, benchSrcAS, benchDstAS,
					transitPath(t, n.key, ts), benchFlow, benchPad), controlTC)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := newTestReader(t)
			n := newBenchNode(t, benchRunConfig)
			pool := newTestPool(8, minHeadroom)
			procQ := fullQueue(pool)
			controlQ := make(chan *Packet, 1)
			link := tc.link(n).(udpLink)
			link.start(context.Background(), []chan *Packet{procQ}, controlQ, pool)

			tmpl := tc.build(t, n)
			p := fillBenchPacket(pool.Get(), tmpl, link)
			link.receive(len(p.RawPacket), &net.UDPAddr{}, p)

			drops := busyDrops(t, collectSums(t, reader), tc.ifID, tmpl)
			if !tc.control {
				if len(controlQ) != 0 || drops != 1 {
					t.Fatalf("control queue holds %d, busy drops = %d; want 0 and 1",
						len(controlQ), drops)
				}
				return
			}
			if drops != 0 {
				t.Fatalf("busy drops = %d, want 0", drops)
			}
			select {
			case got := <-controlQ:
				if got != p || !got.control {
					t.Fatalf("control queue holds %p (control %v), want the arrival %p in "+
						"the control class", got, got.control, p)
				}
			default:
				t.Fatal("the control queue holds nothing")
			}
		})
	}
}

// TestControlFloodLeavesDataRoom checks that a full control queue drops a
// control arrival and leaves a data arrival its processor queue.
func TestControlFloodLeavesDataRoom(t *testing.T) {
	reader := newTestReader(t)
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(8, minHeadroom)
	procQ := make(chan *Packet, 1)
	el := n.if1.(*externalLink)
	el.start(context.Background(), []chan *Packet{procQ}, fullQueue(pool), pool)

	ts := util.TimeToSecs(time.Now())
	scmp := scmpPacket(t, benchSrcAS, benchDstAS, transitPath(t, n.key, ts),
		slayers.SCMPTypeEchoRequest, 1)
	p := fillBenchPacket(pool.Get(), scmp, n.if1)
	el.receive(len(p.RawPacket), &net.UDPAddr{}, p)
	if got := busyDrops(t, collectSums(t, reader), "1", scmp); got != 1 {
		t.Fatalf("busy drops = %d, want 1: the control arrival", got)
	}

	data := serializeUDP(t, benchSrcAS, benchDstAS, transitPath(t, n.key, ts), benchFlow, benchPad)
	p = fillBenchPacket(pool.Get(), data, n.if1)
	el.receive(len(p.RawPacket), &net.UDPAddr{}, p)
	if got := len(procQ); got != 1 {
		t.Fatalf("processor queue holds %d, want the data arrival", got)
	}
}

// recordingConn is an underlay socket whose writes record each batch's
// packets, by the first byte each carries, and report them all written.
type recordingConn struct {
	underlay.UDPConn
	batches chan []byte
}

func (c *recordingConn) WriteBatch(msgs []ipv4.Message) (int, error) {
	batch := make([]byte, len(msgs))
	for i, m := range msgs {
		batch[i] = m.Buffers[0][0]
	}
	c.batches <- batch
	return len(msgs), nil
}

// TestSenderTakesControlFirst checks a link's batches: control first, at
// most its share of the batch while data waits, and either class alone
// filling a batch.
func TestSenderTakesControlFirst(t *testing.T) {
	const batchSize = 8
	tests := []struct {
		name          string
		control, data int
	}{
		{"both queues full", 2 * batchSize, 2 * batchSize},
		{"control alone", 2 * batchSize, 0},
		{"data alone", 0, 2 * batchSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := newBenchNode(t, benchRunConfig)
			pool := newTestPool(4*batchSize, minHeadroom)
			el := n.if2.(*externalLink)
			conn := &recordingConn{batches: make(chan []byte, 4*batchSize)}
			u := &udpConnection{
				conn:         conn,
				name:         "test",
				link:         el,
				queue:        make(chan *Packet, 2*batchSize),
				controlQueue: make(chan *Packet, 2*batchSize),
				stopSend:     make(chan struct{}),
				metrics:      el.metrics,
			}
			queue := func(q chan *Packet, count int, tag byte, control bool) {
				for range count {
					p := pool.Get()
					p.RawPacket = append(p.RawPacket[:0], tag)
					p.control = control
					q <- p
				}
			}
			queue(u.controlQueue, tc.control, 'c', true)
			queue(u.queue, tc.data, 'd', false)

			u.running.Store(true)
			done := make(chan struct{})
			go func() {
				defer close(done)
				u.send(context.Background(), batchSize, pool)
			}()
			var first []byte
			select {
			case first = <-conn.batches:
			case <-time.After(testTimeout):
				t.Fatal("the sender wrote no batch")
			}
			close(u.stopSend)
			<-done

			if len(first) != batchSize {
				t.Fatalf("first batch = %q, want %d packets", first, batchSize)
			}
			control := 0
			for i, tag := range first {
				if tag != 'c' {
					continue
				}
				control++
				// The packet the sender blocked for may be of either class;
				// every later control packet precedes the data.
				if i > 0 && slices.Contains(first[1:i], 'd') {
					t.Errorf("first batch = %q: control after data", first)
				}
			}
			switch {
			case tc.data == 0 && control != batchSize:
				t.Errorf("first batch = %q, want control alone", first)
			case tc.control == 0 && control != 0:
				t.Errorf("first batch = %q, want data alone", first)
			case tc.control > 0 && tc.data > 0 &&
				(control < batchSize/controlShare || control > batchSize/controlShare+1):
				t.Errorf("first batch = %q: %d control, want its share of %d, or one more "+
					"for the packet the sender blocked for", first, control,
					batchSize/controlShare)
			}
		})
	}
}

// TestControlSurvivesFullDataQueue checks that a link whose data egress
// queue is full refuses a data packet, takes a control packet, and writes it
// in the next batch.
func TestControlSurvivesFullDataQueue(t *testing.T) {
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = far.Close() }()
	provider := NewUDPProvider(8, 0, 0, underlay.Kernel, nil)
	link, err := provider.NewExternalLink(1, nil, nil, freeUDPAddr(t), far.LocalAddr().String(),
		1, newTestMetrics(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Stop()
	// The pool covers the receive loop's batch beside the packets queued.
	pool := newTestPool(32, minHeadroom)
	packet := func(tag byte, control bool) *Packet {
		p := pool.Get()
		p.RawPacket = append(p.RawPacket[:0], tag)
		p.control = control
		return p
	}

	if !link.Send(packet('d', false)) {
		t.Fatal("the empty data queue refused a packet")
	}
	if p := packet('d', false); link.Send(p) {
		t.Fatal("the full data queue took a packet")
	} else {
		pool.Put(p)
	}
	if !link.Send(packet('c', true)) {
		t.Fatal("the control queue refused a packet while the data queue was full")
	}

	provider.Start(context.Background(), pool, []chan *Packet{make(chan *Packet, 1)},
		make(chan *Packet, 1))
	if err := far.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 16)
	for range 2 {
		n, _, err := far.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("reading the link's writes: %v (got %q)", err, got)
		}
		got = append(got, buf[:n]...)
	}
	if !slices.Contains(got, 'c') {
		t.Fatalf("the link wrote %q, want the control packet among them", got)
	}
}

// TestSlowPathAnswersAsControl checks that the interface-down answer to a
// packet for a down link queues on the ingress link's control queue.
func TestSlowPathAnswersAsControl(t *testing.T) {
	n := newBenchNode(t, benchRunConfig)
	n.if2.(*externalLink).bfdSession = downSession{}
	pool := newTestPool(8, minHeadroom)
	// The full transit shape, dated now, carries the source's hop the answer
	// returns over.
	tmpl := serializeUDP(t, benchSrcAS, benchDstAS,
		expiredTransitPath(t, n.key, util.TimeToSecs(time.Now())), benchFlow, benchPad)
	p := fillBenchPacket(pool.Get(), tmpl, n.if1)
	if got := newPacketProcessor(n.d).processPkt(p); got != pSlowPath {
		t.Fatalf("disposition = %d, want %d", got, pSlowPath)
	}

	var ingress *udpConnection
	for _, c := range n.provider.allConnections {
		if l, ok := c.link.(*externalLink); ok && l.ifID == 1 {
			ingress = c
		}
	}
	slowQ := make(chan *Packet, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	n.d.setRunning()
	wg.Go(func() { n.d.runSlowPathProcessor(ctx, 0, slowQ) })
	defer func() {
		cancel()
		wg.Wait()
	}()

	slowQ <- p
	select {
	case got := <-ingress.controlQueue:
		if got != p || !got.control {
			t.Fatalf("control queue holds %p (control %v), want the answer %p in the "+
				"control class", got, got.control, p)
		}
	case <-time.After(testTimeout):
		t.Fatal("no answer queued on the ingress link's control queue")
	}
	if got := len(ingress.queue); got != 0 {
		t.Errorf("the ingress link's data queue holds %d packets, want none", got)
	}
}
