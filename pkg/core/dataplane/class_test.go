package dataplane

import (
	"context"
	"maps"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"golang.org/x/net/ipv4"

	"github.com/fancl20/cion/pkg/libs/evidence"
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

// pacingPolicy is a congestion policy that paces every link at one rate,
// marks nothing, and keeps what each link wrote.
type pacingPolicy struct {
	bps float64

	mu    sync.Mutex
	wrote map[uint16]wrote
}

// wrote is what one link wrote: its packets and their bytes, and whether
// its rate held data back as it wrote any.
type wrote struct {
	packets, bytes int
	held           bool
}

// newPacingPolicy returns a policy pacing every link at bps, none for zero.
func newPacingPolicy(bps float64) *pacingPolicy {
	return &pacingPolicy{bps: bps, wrote: make(map[uint16]wrote)}
}

func (p *pacingPolicy) Sampled(uint16, evidence.Sample) {}
func (p *pacingPolicy) Requested(uint16, time.Time)     {}
func (p *pacingPolicy) Echoed(uint16) time.Time         { return time.Time{} }
func (p *pacingPolicy) Rate(uint16) float64             { return p.bps }
func (p *pacingPolicy) Mark(uint16, float64) bool       { return false }

func (p *pacingPolicy) Wrote(ifID uint16, packets, bytes int, held bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.wrote[ifID]
	p.wrote[ifID] = wrote{w.packets + packets, w.bytes + bytes, w.held || held}
}

// written returns what each link wrote so far.
func (p *pacingPolicy) written() map[uint16]wrote {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.wrote)
}

// timedConn is an underlay socket whose writes record when each batch went,
// with the first byte of each of its packets, and report them all written.
type timedConn struct {
	underlay.UDPConn
	mu     sync.Mutex
	writes []timedWrite
}

// timedWrite is one batch a timedConn wrote: when, and its packets' tags.
type timedWrite struct {
	at   time.Time
	tags string
}

func (c *timedConn) WriteBatch(msgs []ipv4.Message) (int, error) {
	tags := make([]byte, len(msgs))
	for i, m := range msgs {
		tags[i] = m.Buffers[0][0]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, timedWrite{time.Now(), string(tags)})
	return len(msgs), nil
}

// TestPacedSenderHoldsDataToItsRate checks a paced link's sender, on virtual
// time: with two control packets and five data packets queued, each of 1000
// bytes, at 400 kbit/s, which sends the five within the paced sojourn, the
// control packets go at once and count against the rate, while the data
// waits in its queue and goes a packet's time at the rate apart, the last
// one 120ms on, less the pacing's slack; the policy hears of all seven
// packets, and that the rate held data back. Without a rate, everything
// goes at once, held back by nothing.
func TestPacedSenderHoldsDataToItsRate(t *testing.T) {
	const (
		batchSize = 8
		size      = 1000
		control   = 2
		data      = 5
	)
	for _, tc := range []struct {
		name string
		bps  float64
		last time.Duration
	}{
		{"paced", size * 8 * 50, (control+data-1)*20*time.Millisecond - pacingSlack},
		{"unpaced", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pool := newTestPool(4*batchSize, minHeadroom)
				el := &externalLink{}
				el.locator.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
				conn := &timedConn{}
				policy := newPacingPolicy(tc.bps)
				u := &udpConnection{
					conn:         conn,
					name:         "test",
					link:         el,
					policy:       policy,
					ifID:         2,
					queue:        make(chan *Packet, 2*batchSize),
					controlQueue: make(chan *Packet, 2*batchSize),
					stopSend:     make(chan struct{}),
					metrics:      newTestMetrics(t, 2),
				}
				queue := func(q chan *Packet, count int, tag byte, isControl bool) {
					for range count {
						p := pool.Get()
						p.RawPacket = append(p.RawPacket[:0], make([]byte, size)...)
						p.RawPacket[0] = tag
						p.control = isControl
						q <- p
					}
				}
				queue(u.controlQueue, control, 'c', true)
				queue(u.queue, data, 'd', false)

				start := time.Now()
				u.running.Store(true)
				done := make(chan struct{})
				go func() {
					defer close(done)
					u.send(context.Background(), batchSize, pool)
				}()
				time.Sleep(50 * time.Millisecond)
				if held := len(u.queue); tc.bps != 0 && held == 0 {
					t.Error("the paced link's data queue holds nothing 50ms on, want its data waiting")
				}
				time.Sleep(time.Second)
				close(u.stopSend)
				<-done

				var dataAt []time.Duration
				for _, w := range conn.writes {
					for _, tag := range []byte(w.tags) {
						switch tag {
						case 'c':
							if w.at != start {
								t.Errorf("a control packet went %v on, want at once", w.at.Sub(start))
							}
						case 'd':
							dataAt = append(dataAt, w.at.Sub(start))
						}
					}
				}
				if len(dataAt) != data {
					t.Fatalf("%d data packets went, want %d", len(dataAt), data)
				}
				if got := dataAt[data-1]; got != tc.last {
					t.Errorf("the last data packet went %v on, want %v", got, tc.last)
				}
				for i := 2; tc.bps != 0 && i < data; i++ {
					if gap := dataAt[i] - dataAt[i-1]; gap != 20*time.Millisecond {
						t.Errorf("data packets %d and %d went %v apart, want 20ms", i-1, i, gap)
					}
				}
				want := map[uint16]wrote{2: {control + data, (control + data) * size, tc.bps != 0}}
				if diff := cmp.Diff(want, policy.written(), cmp.AllowUnexported(wrote{})); diff != "" {
					t.Errorf("writes handed to the policy (-want +got):\n%s", diff)
				}
			})
		})
	}
}

// TestControlSurvivesFullDataQueue checks that a link whose data egress
// queue is full drops its oldest data packet for a new one, takes a control
// packet, and writes both in the next batch, the oldest not at all.
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

	// The pool a running link returns its drops to.
	link.(*externalLink).pool = pool
	if !link.Send(packet('o', false)) {
		t.Fatal("the empty data queue refused a packet")
	}
	if !link.Send(packet('d', false)) {
		t.Fatal("the full data queue refused a packet, want its oldest dropped for it")
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
	if !slices.Contains(got, 'c') || !slices.Contains(got, 'd') || slices.Contains(got, 'o') {
		t.Fatalf("the link wrote %q, want the control packet and the newest data packet", got)
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

// TestPacerHolds checks when a paced queue holds data back: once it dropped
// some past its bound, or holds more than half of what the bound lets it,
// the bound at most the queue's room; never without a rate.
func TestPacerHolds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bps     float64
		queued  int
		trimmed int
		want    bool
	}{
		// 400 kbit/s keeps five 1000-byte packets in the sojourn.
		{"half the bound or less", 400_000, 2, 0, false},
		{"more than half the bound", 400_000, 3, 0, true},
		{"trimmed", 400_000, 0, 1, true},
		// 80 kbit/s keeps one: any packet waiting is more than half.
		{"a one-packet bound", 80_000, 1, 0, true},
		{"empty", 80_000, 0, 0, false},
		// 1 Gbit/s would keep 12,500, past the queue's room of 64.
		{"half the room or less", 1e9, 32, 0, false},
		{"more than half the room", 1e9, 33, 0, true},
		{"no rate", 0, 8, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pacer{bps: tc.bps, size: 1000, room: 64}
			if got := p.holds(tc.queued, tc.trimmed); got != tc.want {
				t.Errorf("holds(%d, %d) = %v, want %v", tc.queued, tc.trimmed, got, tc.want)
			}
		})
	}
}

// TestPacerTrimsPastTheSojourn checks the paced queue's bound: of five
// queued data packets of 1000 bytes, the pacer keeps what its rate sends in
// the paced sojourn, at most the queue's room, the newest, and drops the
// oldest; without a rate, or before it took a packet, it drops nothing.
func TestPacerTrimsPastTheSojourn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bps     float64
		size    int
		room    int
		dropped string
		left    string
	}{
		{"one packet's time", 80_000, 1000, 8, "abcd", "e"},
		{"three packets' time", 240_000, 1000, 8, "ab", "cde"},
		{"the room", 1e9, 1000, 3, "ab", "cde"},
		{"no rate", 0, 1000, 8, "", "abcde"},
		{"nothing taken yet", 80_000, 0, 8, "", "abcde"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := make(chan *Packet, 8)
			for _, tag := range []byte("abcde") {
				q <- &Packet{RawPacket: []byte{tag}}
			}
			p := pacer{bps: tc.bps, size: tc.size, room: tc.room}
			var dropped []byte
			p.trim(q, func(pkt *Packet) { dropped = append(dropped, pkt.RawPacket[0]) })
			var left []byte
			for len(q) > 0 {
				left = append(left, (<-q).RawPacket[0])
			}
			if string(dropped) != tc.dropped || string(left) != tc.left {
				t.Errorf("dropped %q and left %q, want %q and %q", dropped, left, tc.dropped, tc.left)
			}
		})
	}
}
