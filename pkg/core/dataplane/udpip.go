// Copyright 2024 SCION Association
// Copyright 2025 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modified for CION from udpip.go and fnv1acheap.go in
// github.com/scionproto/scion@v0.15.1/router/underlayproviders/udpip.

package dataplane

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"

	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/congestion"
)

var (
	errResolveOnExternalLink = errors.New("cannot resolve on external link")
	errInvalidServiceAddress = errors.New("invalid service address")
	errAlreadyInternalLink   = errors.New("internal link already exists")
	errDuplicateInterface    = errors.New("duplicate interface ID")
)

// pathTypeOffset is the SCION header's path-type byte, the mark that tells
// an external link's egress a packet is the node's own one-hop conversation
// with the peer rather than transit.
const pathTypeOffset = 8

// UDPProvider implements UnderlayProvider over UDP/IP. External links get an
// exclusive unconnected socket keyed by interface ID; the internal link uses
// a single unconnected socket of its own. Every socket binds through the
// socket source the constructor takes, so a whole node can boot on one
// network.
type UDPProvider struct {
	mu                 sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize          int
	allLinks           map[uint16]udpLink
	allConnections     []*udpConnection
	svc                *Services[netip.AddrPort]
	internalConnection *udpConnection
	internalHashSeed   uint32
	receiveBufferSize  int
	sendBufferSize     int
	sockets            underlay.Sockets
	onObserved         func()
	// policy paces the data the provider's external links write and takes
	// what they write, nil for none.
	policy congestion.Policy
}

// udpLink is the extension of Link implemented by all the links of this
// provider.
type udpLink interface {
	Link
	start(ctx context.Context, procQs []chan *Packet, controlQ chan *Packet, pool PacketPool)
	stop()
	receive(size int, srcAddr *net.UDPAddr, p *Packet)
	// egressAddr returns the underlay destination one packet queued on the
	// link's connection carries: the packet's own for a link that resolves
	// per packet — the internal link's hosts — and the link's live locator
	// for an external one, whose packets carry none.
	egressAddr(p *Packet) *net.UDPAddr
}

// NewUDPProvider returns a new provider for exclusive use by the caller,
// binding its sockets through the source. onObserved runs whenever an
// external link's observed source moves, on the link's receive path, so it
// must not block; nil runs nothing.
func NewUDPProvider(
	batchSize int, receiveBufferSize int, sendBufferSize int, sockets underlay.Sockets,
	onObserved func(),
) *UDPProvider {

	return &UDPProvider{
		batchSize:         batchSize,
		allLinks:          make(map[uint16]udpLink),
		svc:               NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
		sockets:           sockets,
		onObserved:        onObserved,
	}
}

// PaceBy has the external links the provider makes from now on drain their
// data egress queues at the policy's rates and hand it what they write; the
// policy may outlive the provider.
func (u *UDPProvider) PaceBy(policy congestion.Policy) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.policy = policy
}

// listen binds one of the provider's sockets through the socket source,
// sized as the provider's buffers. The provider pins the listen address's
// own family — the selection its link sockets always performed — by naming
// it as the hint where the caller names none.
func (u *UDPProvider) listen(
	localAddr *net.UDPAddr, remoteHint netip.AddrPort,
) (underlay.UDPConn, error) {

	if !remoteHint.IsValid() {
		if ap := localAddr.AddrPort(); ap.IsValid() {
			remoteHint = netip.AddrPortFrom(ap.Addr(), 0)
		}
	}
	c, err := u.sockets.NewUDP(localAddr, remoteHint)
	if err != nil {
		return nil, err
	}
	if u.receiveBufferSize != 0 {
		// Not all platforms support this; best effort only.
		_ = c.SetReadBuffer(u.receiveBufferSize)
	}
	if u.sendBufferSize != 0 {
		_ = c.SetWriteBuffer(u.sendBufferSize)
	}
	return c, nil
}

func (u *UDPProvider) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

func (u *UDPProvider) Headroom() int {
	// This underlay does not add any header of its own: the UDP socket API
	// manages the header independently.
	return 0
}

// AddSvc adds the address for the given service.
func (u *UDPProvider) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	// We pre-resolve the addresses, which is trivial for this underlay.
	a := netip.AddrPortFrom(host.IP(), port)
	if !a.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.AddSvc(svc, a)
	return nil
}

// DelSvc deletes the address for the given service.
func (u *UDPProvider) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	a := netip.AddrPortFrom(host.IP(), port)
	if !a.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.DelSvc(svc, a)
	return nil
}

// Start puts the provider in the running state. The queues to be used by the
// receiver tasks, the data processors' and the control class's, are supplied
// at this point because they must be sized according to the number of
// connections that will be started.
func (u *UDPProvider) Start(
	ctx context.Context,
	pool PacketPool,
	procQs []chan *Packet,
	controlQ chan *Packet,
) {
	u.mu.Lock()
	connSnapshot := slices.Clone(u.allConnections)
	linkSnapshot := make([]udpLink, 0, len(u.allLinks))
	for _, l := range u.allLinks {
		linkSnapshot = append(linkSnapshot, l)
	}
	u.mu.Unlock()

	// Links MUST be started before connections. Given that this is an internal
	// matter, we don't pay the price of checking at use time.
	for _, l := range linkSnapshot {
		l.start(ctx, procQs, controlQ, pool)
	}
	for _, c := range connSnapshot {
		c.start(ctx, u.batchSize, pool)
	}
}

func (u *UDPProvider) Stop() {
	u.mu.Lock()
	connSnapshot := slices.Clone(u.allConnections)
	linkSnapshot := make([]udpLink, 0, len(u.allLinks))
	for _, l := range u.allLinks {
		linkSnapshot = append(linkSnapshot, l)
	}
	u.mu.Unlock()

	for _, c := range connSnapshot {
		c.stop()
	}
	for _, l := range linkSnapshot {
		l.stop()
	}
}

// NewExternalLink returns an external link over the UDP/IP underlay: an
// unconnected socket bound to the entry's local address and aimed at the
// entry's recorded remote — the link's initial locator, live state the
// serving generation re-aims in place. The link continues the interface's
// observation record, nil starting one of its own. Two links may aim at one
// address; the store's write-time rules are the duplicate check that stands.
func (u *UDPProvider) NewExternalLink(
	qSize int,
	bfd Session,
	observed *Observation,
	local string,
	remote string,
	ifID uint16,
	metrics *InterfaceMetrics,
) (Link, error) {
	remoteAddr, err := underlay.ResolveAddrPort(remote)
	if err != nil {
		return nil, fmt.Errorf("resolving remote address: %w", err)
	}
	localAddr, err := underlay.ResolveLocalAddr(local)
	if err != nil {
		return nil, fmt.Errorf("resolving local address: %w", err)
	}
	if observed == nil {
		observed = new(Observation)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// A duplicate interface ID would denote a serious configuration error:
	// the store allocates one interface ID per live entry.
	if l := u.allLinks[ifID]; l != nil {
		return nil, fmt.Errorf("%w: %d", errDuplicateInterface, ifID)
	}
	return u.newExternalLink(qSize, bfd, observed, localAddr, remoteAddr, ifID, metrics)
}

func (u *UDPProvider) newExternalLink(
	qSize int,
	bfd Session,
	observed *Observation,
	localAddr *net.UDPAddr,
	remoteAddr netip.AddrPort,
	ifID uint16,
	metrics *InterfaceMetrics,
) (Link, error) {
	c, err := u.listen(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}
	queue := make(chan *Packet, qSize)
	controlQueue := make(chan *Packet, controlQueueSize)
	el := &externalLink{
		name:           remoteAddr.String(),
		egressQ:        queue,
		egressControlQ: controlQueue,
		metrics:        metrics,
		bfdSession:     bfd,
		bfdReader:      newBFDReader(),
		raw:            c,
		seed:           makeHashSeed(),
		ifID:           ifID,
		observed:       observed,
		onObserved:     u.onObserved,
	}
	el.locator.Store(udpAddrPointer(remoteAddr))
	if bfd != nil {
		// The link hands the session its writer for prebuilt packets: a send
		// beneath the egress queues and the validation above them. Every
		// generation re-attaches its own writer this way, the session's state
		// and timers untouched across the swap.
		bfd.SetRawWriter(el)
	}
	uc := &udpConnection{
		conn:         c,
		name:         el.name,
		link:         el,
		policy:       u.policy,
		ifID:         ifID,
		queue:        queue,
		controlQueue: controlQueue,
		stopSend:     make(chan struct{}),
		metrics:      metrics, // send() needs them.
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		bound:        &el.bound,
	}
	u.allConnections = append(u.allConnections, uc)
	u.allLinks[ifID] = el
	return el, nil
}

// Aim re-aims the interface's external link at a new locator in place — one
// field of live state, not a generational replacement: the link's transit and
// its BFD session's answers follow from the next packet on. A missing or
// internal interface aims nothing.
func (u *UDPProvider) Aim(ifID uint16, remote netip.AddrPort) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if l, ok := u.allLinks[ifID].(*externalLink); ok {
		l.locator.Store(udpAddrPointer(remote))
	}
}

// Observation is one interface's record of the underlay source its peer's
// packets arrive from — the data plane's witness of where the peer is, the
// record the authenticated link request's agreement rule reads and the
// address the link's answers pay back. The links that serve one flow in
// successive generations can continue one record, so it outlives the
// generation that wrote it. The zero value has observed nothing.
type Observation struct {
	source atomic.Pointer[net.UDPAddr]
}

// Load returns the source of the interface's last arrival, the zero
// AddrPort while none arrived.
func (o *Observation) Load() netip.AddrPort {
	if addr := o.source.Load(); addr != nil {
		return addr.AddrPort()
	}
	return netip.AddrPort{}
}

// udpAddrPointer builds the destination form of an address; the copy is the
// caller's, safe to share across the sends that read it.
func udpAddrPointer(ap netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: ap.Addr().AsSlice(), Zone: ap.Addr().Zone(), Port: int(ap.Port())}
}

// NewInternalLink returns an internal link over the UDP/IP underlay. At most
// one internal link is supported.
func (u *UDPProvider) NewInternalLink(
	local string, qSize int, metrics *InterfaceMetrics,
) (Link, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.internalConnection != nil {
		return nil, errAlreadyInternalLink
	}
	localAddr, err := underlay.ResolveLocalAddr(local)
	if err != nil {
		return nil, fmt.Errorf("resolving local address: %w", err)
	}
	c, err := u.listen(localAddr, netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	u.internalHashSeed = makeHashSeed()
	queue := make(chan *Packet, qSize)
	controlQueue := make(chan *Packet, controlQueueSize)
	il := &internalLink{
		egressQ:        queue,
		egressControlQ: controlQueue,
		metrics:        metrics,
		svc:            u.svc,
		seed:           u.internalHashSeed,
	}
	uc := &udpConnection{
		conn:         c,
		name:         "internal",
		link:         il,
		queue:        queue,
		controlQueue: controlQueue,
		stopSend:     make(chan struct{}),
		metrics:      metrics, // send() needs them.
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}
	u.allLinks[0] = il
	u.internalConnection = uc
	u.allConnections = append(u.allConnections, uc)
	return il, nil
}

// udpConnection is essentially a batch socket with two sending queues, the
// control class's and data's, and a demultiplexer. The rest is about logs and
// metrics.
type udpConnection struct {
	conn         underlay.UDPConn
	name         string  // for logs. It's more informative than ifID.
	link         udpLink // Link with exclusive use of the connection.
	queue        chan *Packet
	controlQueue chan *Packet
	stopSend     chan struct{} // Closed by stop; unblocks the sender without closing the queues.
	metrics      *InterfaceMetrics
	receiverDone chan struct{}
	senderDone   chan struct{}
	running      atomic.Bool
	stopped      atomic.Bool // Set by stop; a stopped connection cannot start.
	// policy paces the connection's data and takes what it writes, as the
	// link of interface ifID; nil for none. bound, where set, takes the
	// packets the paced queue holds at most, zero while unpaced.
	policy congestion.Policy
	ifID   uint16
	bound  *atomic.Int64
}

// start puts the connection in the running state. In that state, the
// connection delivers incoming packets and sends packets present on its input
// channel.
func (u *udpConnection) start(ctx context.Context, batchSize int, pool PacketPool) {
	if u.stopped.Load() {
		return
	}
	wasRunning := u.running.Swap(true)
	if wasRunning || u.stopped.Load() {
		// The double-check catches a stop racing with this start.
		return
	}

	// Receiver task
	go func() {
		defer handlePanic()
		u.receive(batchSize, pool)
		close(u.receiverDone)
	}()

	// Forwarder task
	go func() {
		defer handlePanic()
		u.send(ctx, batchSize, pool)
		close(u.senderDone)
	}()
}

// stop puts the connection in the stopped state. In that state, the connection
// no longer delivers incoming packets and ignores packets present on its input
// channel. The connection is fully stopped when this method returns. Stopping
// a stopped connection is a no-op — both Serve's graceful shutdown and the
// provider's owner may stop it.
func (u *udpConnection) stop() {
	if !u.stopped.CompareAndSwap(false, true) {
		return
	}
	wasRunning := u.running.Swap(false)

	// The socket is released even if the connection never started, so that a
	// provider that is abandoned before Serve still frees its addresses.
	_ = u.conn.Close() // Also unblocks the receiver.

	if wasRunning {
		// The queues themselves stay open: producers (the data plane
		// processors and the links) may still be pushing packets, and a send
		// on a closed channel would panic. The sender drains what made it in
		// and returns the buffers to the pool.
		close(u.stopSend)
		<-u.receiverDone
		<-u.senderDone
	}
}

func (u *udpConnection) receive(batchSize int, pool PacketPool) {
	slog.Debug("Receive", "connection", u.name)

	// A collection of socket messages, as the readBatch API expects them. We
	// keep using the same collection, call after call; only replacing the
	// buffer.
	msgs := newReadMessages(batchSize)

	// An array of corresponding packet references. Each corresponds to one
	// msg. The packet owns the buffer that we set in the matching msg, plus
	// the metadata that we'll add.
	packets := make([]*Packet, batchSize)
	numReusable := 0 // unused buffers from previous loop

	// The input counters' staging: accumulated over the packets of one read
	// batch and flushed before the next — the receive loop owns the batch
	// boundary and this connection's single link's metrics. Drop counters
	// stay per-event inside the links' receive.
	var input inputMetricsStaging

	for u.running.Load() {
		// collect packets.

		// Give a new buffer to the msgs elements that have been used in the
		// previous loop.
		for i := range batchSize - numReusable {
			p := pool.Get()
			packets[i] = p
			msgs[i].Buffers[0] = p.RawPacket
		}

		// Fill the packets
		numReusable = len(msgs)
		numPkts, err := u.conn.ReadBatch(msgs)
		if err != nil {
			slog.Debug("Error while reading batch", "connection", u.name, "err", err)
			continue
		}
		numReusable -= numPkts
		for i, msg := range msgs[:numPkts] {

			// Update size; readBatch does not.
			size := msg.N
			p := packets[i]
			p.RawPacket = p.RawPacket[:size]
			input.add(size)

			// Hand the packet to the link that owns this connection.
			u.link.receive(size, msg.Addr.(*net.UDPAddr), p)
		}
		input.flush(u.metrics)
	}

	// We have to stop receiving. Return the unused packets to the pool to
	// avoid creating a memory leak (the process is not required to exit).
	for _, p := range packets[batchSize-numReusable : batchSize] {
		pool.Put(p)
	}
}

func readUpTo(queue <-chan *Packet, n int, needsBlocking bool, pkts []*Packet) int {
	i := 0
	if needsBlocking {
		p, ok := <-queue
		if !ok {
			return i
		}
		pkts[i] = p
		i++
	}

	for ; i < n; i++ {
		select {
		case p, ok := <-queue:
			if !ok {
				return i
			}
			pkts[i] = p
		default:
			return i
		}
	}
	return i
}

func (u *udpConnection) send(ctx context.Context, batchSize int, pool PacketPool) {
	slog.Debug("Send", "connection", u.name)

	// We use this somewhat like a ring buffer.
	pkts := make([]*Packet, batchSize)

	// We use this as a temporary buffer, but allocate it just once to save on
	// garbage handling.
	msgs := newReadMessages(batchSize)

	queue := u.queue
	controlQueue := u.controlQueue
	conn := u.conn
	metrics := u.metrics
	toWrite := 0
	pace := pacer{room: cap(queue)}
	var wake *time.Timer

	// On the way out, whether by stop signal or by the running flag, the
	// unsent packets and everything stranded on the queues go back to the
	// pool.
	defer func() {
		for _, p := range pkts[:toWrite] {
			pool.Put(p)
		}
		u.drain(controlQueue, pool)
		u.drain(queue, pool)
	}()

	for u.running.Load() {
		var rate float64
		if u.policy != nil {
			rate = u.policy.Rate(u.ifID)
		}
		pace.setRate(rate, time.Now())
		trimmed := pace.trim(queue, func(p *Packet) {
			metrics[ClassOfSize(len(p.RawPacket))].DroppedPacketsBusyForwarder.Add(ctx, 1)
			pool.Put(p)
		})
		if u.bound != nil {
			u.bound.Store(int64(pace.keep()))
		}
		// Top-up our batch. The blocking wait for the first packet of a
		// batch also watches for the stop signal, so the queues never have
		// to be closed to unblock us. Paced data waits in its queue for its
		// turn, which the wait wakes for.
		if toWrite == 0 {
			data, woken := (<-chan *Packet)(queue), (<-chan time.Time)(nil)
			if wait := pace.wait(time.Now()); wait > 0 {
				if wake == nil {
					wake = time.NewTimer(wait)
				} else {
					wake.Reset(wait)
				}
				data, woken = nil, wake.C
			}
			select {
			case p := <-controlQueue:
				pkts[0] = p
				toWrite = 1
			case p := <-data:
				pkts[0] = p
				toWrite = 1
			case <-woken:
			case <-u.stopSend:
				return
			}
			if wake != nil {
				wake.Stop()
			}
			if toWrite == 0 {
				continue
			}
			pace.took(pkts[:1])
		}
		// Control first, at most its share of the batch, then data while its
		// turn holds, then control again in the room data left: while data
		// waits, control fills at most its share.
		n := readUpTo(controlQueue, min(batchSize/controlShare, batchSize-toWrite), false,
			pkts[toWrite:])
		pace.took(pkts[toWrite : toWrite+n])
		toWrite += n
		toWrite += pace.readData(queue, pkts[toWrite:], time.Now())
		n = readUpTo(controlQueue, batchSize-toWrite, false, pkts[toWrite:])
		pace.took(pkts[toWrite : toWrite+n])
		toWrite += n
		held := pace.holds(len(queue), trimmed)

		// Turn the packets into underlay messages that WriteBatch can send.
		// The connection's link names each packet's destination: the packet's
		// own resolved one for the internal link, the link's live locator for
		// an external one.
		for i, p := range pkts[:toWrite] {
			msgs[i].Buffers[0] = p.RawPacket
			msgs[i].Addr = u.link.egressAddr(p)
		}

		written, _ := conn.WriteBatch(msgs[:toWrite])
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as 0
			// packets written.
			written = 0
		}
		UpdateOutputMetrics(ctx, metrics, pkts[:written])
		if u.policy != nil {
			bytes := 0
			for _, p := range pkts[:written] {
				bytes += len(p.RawPacket)
			}
			u.policy.Wrote(u.ifID, written, bytes, held)
		}
		for _, p := range pkts[:written] {
			pool.Put(p)
		}
		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := ClassOfSize(len(pkts[written].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Add(ctx, 1)
			pool.Put(pkts[written])
			toWrite -= written + 1
			// Shift the leftovers to the head of the buffers.
			for i := range toWrite {
				pkts[i] = pkts[i+written+1]
			}
		} else {
			toWrite = 0
		}
	}
}

// controlQueueSize is how many packets each link's control egress queue
// holds: control traffic is light, and the sender takes it first.
const controlQueueSize = 64

// pacingSlack is how far ahead of its turn a paced connection's data may go,
// so that a fast rate still writes in batches.
const pacingSlack = time.Millisecond

// pacedSojourn is the longest a paced connection's data waits in its queue:
// the queue holds no more than the rate sends in it, about what an uplink's
// buffer holds, so a brake adds no wait an uplink would not, and its drops
// reach the senders as soon.
const pacedSojourn = 100 * time.Millisecond

// pacer holds the turn of a paced connection's next data packet: each packet
// the connection takes, data or control, moves the turn on by the packet's
// time at the rate, and leaves its size as the last. Without a rate, data
// goes at once. Its room is how many packets the data egress queue holds.
type pacer struct {
	bps  float64
	turn time.Time
	size int
	room int
}

// setRate takes the rate at now, in bits per second, zero for none. A turn
// that has passed starts again from now, so an idle link saves no credit.
func (p *pacer) setRate(bps float64, now time.Time) {
	p.bps = bps
	if p.turn.Before(now) {
		p.turn = now
	}
}

// wait returns how long data waits at now for its turn: none once the turn
// lies within pacingSlack.
func (p *pacer) wait(now time.Time) time.Duration {
	if p.bps == 0 {
		return 0
	}
	return max(0, p.turn.Sub(now.Add(pacingSlack)))
}

// took moves the turn on by the packets' time at the rate.
func (p *pacer) took(pkts []*Packet) {
	for _, pkt := range pkts {
		p.size = len(pkt.RawPacket)
		if p.bps != 0 {
			p.turn = p.turn.Add(time.Duration(float64(p.size*8) * float64(time.Second) / p.bps))
		}
	}
}

// keep returns the packets a paced queue holds at most: what the rate sends
// in pacedSojourn, at the size of the last packet the connection took, one
// at least and the queue's room at most. Zero without a rate or before the
// connection took a packet.
func (p *pacer) keep() int {
	if p.bps == 0 || p.size == 0 {
		return 0
	}
	return min(p.room, max(1, int(p.bps*pacedSojourn.Seconds()/float64(8*p.size))))
}

// holds reports whether the rate holds data back, with queued packets left
// in the queue after trimmed were dropped from it: some were, or more than
// half of keep wait. Data that arrives in clumps waits its turn under any
// rate, but only a rate that limits the link queues half the sojourn's
// worth of it.
func (p *pacer) holds(queued, trimmed int) bool {
	return p.bps != 0 && (trimmed > 0 || 2*queued > p.keep())
}

// trim drops the oldest data the queue holds past keep, handing each to
// drop, and returns how many it dropped.
func (p *pacer) trim(queue <-chan *Packet, drop func(*Packet)) int {
	keep := p.keep()
	if keep == 0 {
		return 0
	}
	dropped := 0
	for len(queue) > keep {
		select {
		case pkt := <-queue:
			drop(pkt)
			dropped++
		default:
			return dropped
		}
	}
	return dropped
}

// readData reads data packets from the queue into pkts without blocking:
// as many as fit without a rate, and while the turn lies within pacingSlack
// of now with one.
func (p *pacer) readData(queue <-chan *Packet, pkts []*Packet, now time.Time) int {
	if p.bps == 0 {
		return readUpTo(queue, len(pkts), false, pkts)
	}
	n := 0
	for n < len(pkts) && !p.turn.After(now.Add(pacingSlack)) {
		select {
		case pkt := <-queue:
			pkts[n] = pkt
			p.took(pkts[n : n+1])
			n++
		default:
			return n
		}
	}
	return n
}

// drain returns the packets stranded on one of the stopped connection's
// queues to the pool.
func (u *udpConnection) drain(queue <-chan *Packet, pool PacketPool) {
	for {
		select {
		case p := <-queue:
			pool.Put(p)
		default:
			return
		}
	}
}

// An externalLink is one neighbor's exclusive unconnected socket, bound to
// the entry's local address and aimed at the entry's current locator — live
// state the serving generation re-aims in place, read at egress. The
// kernel's connected-socket filter is replaced by two software tiers:
// arrivals are processed on the discriminator's echo — the BFD session's
// return-routability and blind-guess barrier, no weaker than the address
// match the connected socket bought — and only the provider's record moves
// the locator: an authenticated confirm, in either direction, or for an
// unproven candidate the source its BFD session answers. Bare arrival never
// does, though every arrival records the source the link last observed, the
// record the confirms read and the address the link's own conversation
// answers: the node's one-hop sends — replies and the confirm's dial alike,
// the only one-hop traffic an external link carries, for the router forwards
// no one-hop packet but the local AS's own — and the BFD session's stream
// pay the observation back while it stands apart from the locator, so a peer
// that moved keeps reaching the link whose entry still names its former
// address. Transit carries the locator: the provider's record alone steers
// the traffic that forwards through the node.
type externalLink struct {
	procQs []chan *Packet
	// controlQ is the processor queue of the link's control arrivals.
	controlQ chan *Packet
	name     string // For logs
	egressQ  chan *Packet
	// egressControlQ is the egress queue of the control class, which the
	// sender takes from first.
	egressControlQ chan *Packet
	metrics        *InterfaceMetrics
	pool           PacketPool
	bfdSession     Session
	// bfdReader decodes the BFD arrivals the receive loop hands the session
	// itself.
	bfdReader *bfdReader
	// raw is the link's own socket: the writer a BFD session sends its
	// prebuilt control packets through, beneath the egress queues.
	raw underlay.UDPConn
	// locator is the entry's current remote address: the destination transit
	// carries, replaced in place by a re-aim.
	locator atomic.Pointer[net.UDPAddr]
	// observed is the interface's observation record: the source of the
	// link's last arrival, or of a predecessor's on the same flow, and the
	// destination its answers carry.
	observed *Observation
	// onObserved runs after each move of observed; nil runs nothing.
	onObserved func()
	// bound is the packets the paced data egress queue holds at most, which
	// the sender sets; zero while unpaced.
	bound atomic.Int64
	seed  uint32
	ifID  uint16
}

func (l *externalLink) start(
	ctx context.Context,
	procQs []chan *Packet,
	controlQ chan *Packet,
	pool PacketPool,
) {
	// The queues and pool are never known before all configured links have
	// been instantiated. So we get them only now. We didn't need them earlier
	// since the connections have not been started yet.
	l.procQs = procQs
	l.controlQ = controlQ
	l.pool = pool
}

func (l *externalLink) stop() {}

func (l *externalLink) IfID() uint16 {
	return l.ifID
}

func (l *externalLink) Metrics() *InterfaceMetrics {
	return l.metrics
}

func (l *externalLink) Scope() LinkScope {
	return External
}

func (l *externalLink) BFDSession() Session {
	return l.bfdSession
}

func (l *externalLink) IsUp() bool {
	if l.bfdSession == nil {
		return true
	}
	return l.bfdSession.IsUp()
}

// egressAddr returns the packet's underlay destination: the link's live
// locator for transit, and the answer address for the node's own one-hop
// conversation with the peer — the path type marks it, for the router
// forwards no one-hop packet but one this AS originated.
func (l *externalLink) egressAddr(p *Packet) *net.UDPAddr {
	if len(p.RawPacket) > pathTypeOffset &&
		path.Type(p.RawPacket[pathTypeOffset]) == onehop.PathType {
		return l.answerAddr()
	}
	return l.locator.Load()
}

// answerAddr returns the destination the link's own conversation with the
// peer carries: its last observed source — the address the peer's latest
// arrival proved answers — else the locator until an arrival names one.
func (l *externalLink) answerAddr() *net.UDPAddr {
	if addr := l.observed.source.Load(); addr != nil {
		return addr
	}
	return l.locator.Load()
}

// WriteRaw sends a prebuilt packet on the link's own socket, beneath the
// forwarding queues — the BFD session's send path, which must keep
// transmitting while the link is down — aimed at the link's answer address,
// for the prebuilt control packet carries no destination of its own: the
// keepalive answers the peer's stream where its own packets came from.
func (l *externalLink) WriteRaw(b []byte) error {
	_, err := l.raw.WriteToUDP(b, l.answerAddr())
	return err
}

// Resolve should not be useful on an external link so we don't implement it.
func (l *externalLink) Resolve(p *Packet, host addr.Host, port uint16) error {
	return errResolveOnExternalLink
}

// Send queues the packet on the egress queue of its class, which drops its
// oldest packet when full.
func (l *externalLink) Send(p *Packet) bool {
	return l.sendOverOldest(egressQueue(p, l.egressQ, l.egressControlQ), p)
}

// sendOverOldest queues the packet on the queue over its oldest packet,
// returning the one dropped to the pool as a busy forwarder's drop.
func (l *externalLink) sendOverOldest(q chan *Packet, p *Packet) bool {
	dropped, ok := enqueueOverOldest(q, p)
	if dropped != nil {
		l.metrics[ClassOfSize(len(dropped.RawPacket))].DroppedPacketsBusyForwarder.Add(
			context.Background(), 1)
		l.pool.Put(dropped)
	}
	return ok
}

// SendBlocking queues the packet on the egress queue of its class, blocking
// while that queue is full.
func (l *externalLink) SendBlocking(p *Packet) {
	egressQueue(p, l.egressQ, l.egressControlQ) <- p
}

// EgressCapacity returns how many packets the link's egress queues hold.
func (l *externalLink) EgressCapacity() int {
	return cap(l.egressQ) + cap(l.egressControlQ)
}

// EgressFill returns how full the link's data egress queue is: the share of
// its packets the queue holds, or, while paced, the share of its bound,
// whichever is greater.
func (l *externalLink) EgressFill() float64 {
	n := float64(len(l.egressQ))
	fill := n / float64(cap(l.egressQ))
	if bound := l.bound.Load(); bound > 0 {
		fill = max(fill, min(1, n/float64(bound)))
	}
	return fill
}

func (l *externalLink) receive(size int, srcAddr *net.UDPAddr, p *Packet) {
	metrics := l.metrics
	sc := ClassOfSize(size)

	// The arrival's source is the link's latest observation, the address its
	// answers carry; the packet itself carries none, for every send on this
	// connection follows the link's own addresses. Only a move replaces the
	// record and reports it.
	ap := netip.AddrPortFrom(srcAddr.AddrPort().Addr().Unmap(), srcAddr.AddrPort().Port())
	if last := l.observed.source.Load(); last == nil || last.AddrPort() != ap {
		l.observed.source.Store(net.UDPAddrFromAddrPort(ap))
		if l.onObserved != nil {
			l.onObserved()
		}
	}

	p.Link = l

	class := classOf(p.RawPacket, false)
	if class == classLink {
		l.receiveBFD(sc, p)
		return
	}
	if l.bfdSession != nil {
		l.bfdSession.Heard()
	}
	switch class {
	case classControl:
		p.control = true
		queueArrival(l.controlQ, p, l.pool, metrics, sc)
		return
	}
	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if !ok {
		l.pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Add(context.Background(), 1)
		return
	}
	queueArrival(l.procQs[procID], p, l.pool, metrics, sc)
}

// receiveBFD hands a BFD arrival to the link's session from the receive
// loop, ahead of every queue, counting it processed as a processor would,
// and returns its buffer to the pool.
func (l *externalLink) receiveBFD(sc sizeClass, p *Packet) {
	ctx := context.Background()
	l.metrics[sc].ProcessedPackets.Add(ctx, 1)
	if !l.bfdReader.read(p.RawPacket, l.bfdSession) {
		l.metrics[sc].DroppedPacketsInvalid.Add(ctx, 1)
	}
	l.pool.Put(p)
}

// An internalLink addresses any host internal to the enclosing AS. Incoming
// packets are dispatched to the processors if recognizable as SCION traffic;
// all other traffic (e.g. STUN) is dropped.
type internalLink struct {
	procQ  chan *Packet
	procQs []chan *Packet
	// controlQ is the processor queue of the link's control arrivals.
	controlQ chan *Packet
	egressQ  chan *Packet
	// egressControlQ is the egress queue of the control class, which the
	// sender takes from first.
	egressControlQ chan *Packet
	procStop       chan struct{}
	procDone       chan struct{}
	// lifeMtx guards the lifecycle fields below against a stop racing with
	// a late start.
	lifeMtx sync.Mutex
	stopped bool
	metrics *InterfaceMetrics
	pool    PacketPool
	svc     *Services[netip.AddrPort]
	seed    uint32
}

func (l *internalLink) start(
	ctx context.Context,
	procQs []chan *Packet,
	controlQ chan *Packet,
	pool PacketPool,
) {
	maxCap := 0
	for _, q := range procQs {
		maxCap = max(maxCap, cap(q))
	}
	l.lifeMtx.Lock()
	defer l.lifeMtx.Unlock()
	if l.stopped {
		// A stop raced with this start; do not resurrect the link.
		return
	}
	l.procQ = make(chan *Packet, maxCap)
	l.procStop = make(chan struct{})
	l.procDone = make(chan struct{})

	// The queues and pool are never known before all configured links have
	// been instantiated. So we get them only now. We didn't need them earlier
	// since the connections have not been started yet.
	l.procQs = procQs
	l.controlQ = controlQ
	l.pool = pool

	go func() {
		defer handlePanic()
		l.runProcessor()
	}()
}

func (l *internalLink) runProcessor() {
	for {
		select {
		case p := <-l.procQ:
			// Non-SCION traffic is not supported (yet); drop it.
			p.Link = nil
			l.pool.Put(p)
		case <-l.procStop:
			for {
				select {
				case p := <-l.procQ:
					sc := ClassOfSize(len(p.RawPacket))
					l.metrics[sc].DroppedPacketsBusyProcessor.Add(context.Background(), 1)
					l.pool.Put(p)
				default:
					close(l.procDone)
					return
				}
			}
		}
	}
}

func (l *internalLink) stop() {
	l.lifeMtx.Lock()
	defer l.lifeMtx.Unlock()
	if l.stopped { // Already stopped; stopping twice is a no-op.
		return
	}
	l.stopped = true
	if l.procStop == nil { // Not started.
		return
	}
	close(l.procStop)
	<-l.procDone
}

func (l *internalLink) IfID() uint16 {
	return 0
}

func (l *internalLink) Metrics() *InterfaceMetrics {
	return l.metrics
}

func (l *internalLink) Scope() LinkScope {
	return Internal
}

func (l *internalLink) BFDSession() Session {
	return nil
}

func (l *internalLink) IsUp() bool {
	return true
}

// Resolve updates the packet's underlay destination according to the given
// SCION host/service address and SCION port number. On the UDP/IP underlay,
// host addresses are bit-for-bit identical to underlay addresses and the port
// space is the same.
func (l *internalLink) Resolve(p *Packet, dst addr.Host, port uint16) error {
	var dstAddr netip.Addr
	switch dst.Type() {
	case addr.HostTypeSVC:
		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		a, ok := l.svc.Any(dst.SVC().Base())
		if !ok {
			return ErrNoSVCBackend
		}
		dstAddr = a.Addr()
		// Supplied port is irrelevant. Port is in svc record.
		port = a.Port()
	case addr.HostTypeIP:
		dstAddr = dst.IP()
		if dstAddr.Is4In6() {
			return ErrUnsupportedV4MappedV6Address
		}
		if dstAddr.IsUnspecified() {
			return ErrUnsupportedUnspecifiedAddress
		}
	default:
		panic(fmt.Sprintf("unexpected address type returned from DstAddr: %s", dst.Type()))
	}
	if port == 0 {
		port = underlay.EndhostPort
	}

	// Packets that get here must have come from an external link; which does
	// not attach a RemoteAddr to the packet. So, RemoteAddr is not generally
	// usable. We must allocate a new object. The precautions needed to pool
	// them cost more than the pool saves (verified experimentally, upstream).
	p.RemoteAddr = unsafe.Pointer(&net.UDPAddr{
		IP:   dstAddr.AsSlice(),
		Zone: dstAddr.Zone(),
		Port: int(port),
	})
	return nil
}

// egressAddr returns the destination the packet's own resolution carries:
// the internal link resolves each packet's host to an underlay address
// before it queues.
func (l *internalLink) egressAddr(p *Packet) *net.UDPAddr {
	return (*net.UDPAddr)(p.RemoteAddr)
}

// Send queues the packet on the egress queue of its class, which drops its
// oldest packet when full. The packet's destination is already in the
// packet's meta-data.
func (l *internalLink) Send(p *Packet) bool {
	dropped, ok := enqueueOverOldest(egressQueue(p, l.egressQ, l.egressControlQ), p)
	if dropped != nil {
		l.metrics[ClassOfSize(len(dropped.RawPacket))].DroppedPacketsBusyForwarder.Add(
			context.Background(), 1)
		l.pool.Put(dropped)
	}
	return ok
}

// SendBlocking queues the packet on the egress queue of its class, blocking
// while that queue is full. The packet's destination is already in the
// packet's meta-data.
func (l *internalLink) SendBlocking(p *Packet) {
	egressQueue(p, l.egressQ, l.egressControlQ) <- p
}

// EgressCapacity returns how many packets the link's egress queues hold.
func (l *internalLink) EgressCapacity() int {
	return cap(l.egressQ) + cap(l.egressControlQ)
}

// EgressFill returns the share of its data egress queue the link holds.
func (l *internalLink) EgressFill() float64 {
	return float64(len(l.egressQ)) / float64(cap(l.egressQ))
}

func (l *internalLink) receive(size int, srcAddr *net.UDPAddr, p *Packet) {
	metrics := l.metrics
	sc := ClassOfSize(size)

	p.Link = l
	// This is an unconnected link. We must record the src address in case the
	// packet is turned around, e.g., by SCMP.
	p.RemoteAddr = unsafe.Pointer(srcAddr)

	// The node's own sockets are the internal link's only senders, so the
	// control DSCP they mark counts here. No BFD session runs on the link:
	// a BFD arrival is data, which the processor discards.
	if classOf(p.RawPacket, true) == classControl {
		p.control = true
		queueArrival(l.controlQ, p, l.pool, metrics, sc)
		return
	}
	var q chan *Packet
	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if ok {
		q = l.procQs[procID]
	} else {
		q = l.procQ
	}
	queueArrival(q, p, l.pool, metrics, sc)
}

// makeHashSeed creates a new random number to serve as hash seed. Each receive
// loop is associated with its own hash seed to compute the proc queue where a
// packet should be delivered.
func makeHashSeed() uint32 {
	hashSeed := fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}
	return hashSeed
}

// computeProcID computes the processor ID for a given packet provided by the
// slice data. It assumes that numProcRoutines is non-negative and not larger
// than 4294967295. hashSeed is used for hash computation. If data is clearly
// not a valid SCION packet, it returns ok=false. Otherwise, it returns a
// processor ID smaller than numProcRoutines and ok=true.
func computeProcID(data []byte, numProcRoutines int, hashSeed uint32) (uint32, bool) {
	if len(data) < slayers.CmnHdrLen {
		return uint32(numProcRoutines), false
	}

	switch slayers.L4ProtocolType(data[4]) {
	case slayers.L4TCP, slayers.L4UDP, slayers.L4SCMP, slayers.L4BFD,
		slayers.HopByHopClass, slayers.End2EndClass,
		slayers.ExperimentationAndTesting, slayers.ExperimentationAndTesting2:
	default:
		return uint32(numProcRoutines), false
	}

	dstHostAddrLen := slayers.AddrType(data[9] >> 4 & 0xf).Length()
	srcHostAddrLen := slayers.AddrType(data[9] & 0xf).Length()
	addrHdrLen := 2*addr.IABytes + srcHostAddrLen + dstHostAddrLen
	if len(data) < slayers.CmnHdrLen+addrHdrLen {
		return uint32(numProcRoutines), false
	}

	s := hashSeed

	// inject the flowID
	s = hashFNV1a(s, data[1]&0xF) // The left 4 bits aren't part of the flowID.
	for _, c := range data[2:4] {
		s = hashFNV1a(s, c)
	}

	// Inject the src/dst addresses
	for _, c := range data[slayers.CmnHdrLen : slayers.CmnHdrLen+addrHdrLen] {
		s = hashFNV1a(s, c)
	}

	return s % uint32(numProcRoutines), true
}

// fnv1aOffset32 is an initial offset that can be used as initial state when
// calling hashFNV1a.
const fnv1aOffset32 uint32 = 2166136261

// hashFNV1a returns a hash value for the given initial state combined with the
// given byte. To get a hash for a sequence of bytes, invoke for each byte,
// passing the returned value of one call as the state for the next.
func hashFNV1a(state uint32, c byte) uint32 {
	const prime32 = 16777619
	return (state ^ uint32(c)) * prime32
}

// messages is a list of socket messages for the batch read/write APIs.
type messages []ipv4.Message

// newReadMessages allocates the messages for a batch of the given size.
func newReadMessages(n int) messages {
	m := make(messages, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the
		// buffer.
		m[i].Buffers = make([][]byte, 1)
	}
	return m
}
