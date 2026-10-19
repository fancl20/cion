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
	"unsafe"

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

var (
	errResolveOnExternalLink = errors.New("cannot resolve on external link")
	errInvalidServiceAddress = errors.New("invalid service address")
	errAlreadyInternalLink   = errors.New("internal link already exists")
	errDuplicateInterface    = errors.New("duplicate interface ID")
)

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
}

// udpLink is the extension of Link implemented by all the links of this
// provider.
type udpLink interface {
	Link
	start(ctx context.Context, procQs []chan *Packet, pool PacketPool)
	stop()
	receive(size int, srcAddr *net.UDPAddr, p *Packet)
	// egressAddr returns the underlay destination one packet queued on the
	// link's connection carries: the packet's own for a link that resolves
	// per packet — the internal link's hosts — and the link's live locator
	// for an external one, whose packets carry none.
	egressAddr(p *Packet) *net.UDPAddr
}

// NewUDPProvider returns a new provider for exclusive use by the caller,
// binding its sockets through the source.
func NewUDPProvider(
	batchSize int, receiveBufferSize int, sendBufferSize int, sockets underlay.Sockets,
) *UDPProvider {

	return &UDPProvider{
		batchSize:         batchSize,
		allLinks:          make(map[uint16]udpLink),
		svc:               NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
		sockets:           sockets,
	}
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
// receiver tasks are supplied at this point because they must be sized
// according to the number of connections that will be started.
func (u *UDPProvider) Start(
	ctx context.Context,
	pool PacketPool,
	procQs []chan *Packet,
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
		l.start(ctx, procQs, pool)
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
// serving generation re-aims in place. Two links may aim at one address;
// the store's write-time rules are the duplicate check that stands.
func (u *UDPProvider) NewExternalLink(
	qSize int,
	bfd Session,
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

	u.mu.Lock()
	defer u.mu.Unlock()

	// A duplicate interface ID would denote a serious configuration error:
	// the store allocates one interface ID per live entry.
	if l := u.allLinks[ifID]; l != nil {
		return nil, fmt.Errorf("%w: %d", errDuplicateInterface, ifID)
	}
	return u.newExternalLink(qSize, bfd, localAddr, remoteAddr, ifID, metrics)
}

func (u *UDPProvider) newExternalLink(
	qSize int,
	bfd Session,
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
	el := &externalLink{
		name:       remoteAddr.String(),
		egressQ:    queue,
		metrics:    metrics,
		bfdSession: bfd,
		raw:        c,
		seed:       makeHashSeed(),
		ifID:       ifID,
	}
	el.locator.Store(udpAddrPointer(remoteAddr))
	if bfd != nil {
		// The link hands the session its writer for prebuilt packets: a send
		// beneath the egress queue and the validation above it. Every
		// generation re-attaches its own writer this way, the session's state
		// and timers untouched across the swap.
		bfd.SetRawWriter(el)
	}
	uc := &udpConnection{
		conn:         c,
		name:         el.name,
		link:         el,
		queue:        queue,
		stopSend:     make(chan struct{}),
		metrics:      metrics, // send() needs them.
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}
	u.allConnections = append(u.allConnections, uc)
	u.allLinks[ifID] = el
	return el, nil
}

// Aim re-aims the interface's external link at a new locator in place — one
// field of live state, not a generational replacement: the link's queued
// sends and its BFD session's raw writes follow from the next packet on. A
// missing or internal interface aims nothing.
func (u *UDPProvider) Aim(ifID uint16, remote netip.AddrPort) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if l, ok := u.allLinks[ifID].(*externalLink); ok {
		l.locator.Store(udpAddrPointer(remote))
	}
}

// Observed returns the interface's external link's last observed underlay
// source — the data plane's witness of where the peer's packets come from,
// the record the authenticated link request's agreement rule reads — and
// the zero AddrPort when no external link holds the interface or none of
// its arrivals recorded one.
func (u *UDPProvider) Observed(ifID uint16) netip.AddrPort {
	u.mu.Lock()
	defer u.mu.Unlock()
	if l, ok := u.allLinks[ifID].(*externalLink); ok {
		if ap := l.observed.Load(); ap != nil {
			return *ap
		}
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
	il := &internalLink{
		egressQ: queue,
		metrics: metrics,
		svc:     u.svc,
		seed:    u.internalHashSeed,
	}
	uc := &udpConnection{
		conn:         c,
		name:         "internal",
		link:         il,
		queue:        queue,
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

// udpConnection is essentially a batch socket with a sending queue and a
// demultiplexer. The rest is about logs and metrics.
type udpConnection struct {
	conn         underlay.UDPConn
	name         string  // for logs. It's more informative than ifID.
	link         udpLink // Link with exclusive use of the connection.
	queue        chan *Packet
	stopSend     chan struct{} // Closed by stop; unblocks the sender without closing the queue.
	metrics      *InterfaceMetrics
	receiverDone chan struct{}
	senderDone   chan struct{}
	running      atomic.Bool
	stopped      atomic.Bool // Set by stop; a stopped connection cannot start.
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
		// The queue itself stays open: producers (the data plane processors
		// and the links) may still be pushing packets, and a send on a
		// closed channel would panic. The sender drains what made it in and
		// returns the buffers to the pool.
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
	conn := u.conn
	metrics := u.metrics
	toWrite := 0

	// On the way out, whether by stop signal or by the running flag, the
	// unsent packets and everything stranded on the queue go back to the
	// pool.
	defer func() {
		for _, p := range pkts[:toWrite] {
			pool.Put(p)
		}
		u.drain(queue, pool)
	}()

	for u.running.Load() {
		// Top-up our batch. The blocking wait for the first packet of a
		// batch also watches for the stop signal, so the queue never has to
		// be closed to unblock us.
		if toWrite == 0 {
			select {
			case p := <-queue:
				pkts[0] = p
				toWrite = 1
			case <-u.stopSend:
				return
			}
		}
		toWrite += readUpTo(queue, batchSize-toWrite, false, pkts[toWrite:])

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

// drain returns the packets stranded on the stopped connection's queue to
// the pool.
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
// match the connected socket bought — and only the authenticated confirm
// moves the locator; bare arrival never does, though every arrival records
// the source the link last observed, the record the confirm's agreement
// rule reads.
type externalLink struct {
	procQs     []chan *Packet
	name       string // For logs
	egressQ    chan<- *Packet
	metrics    *InterfaceMetrics
	pool       PacketPool
	bfdSession Session
	// raw is the link's own socket: the writer a BFD session sends its
	// prebuilt control packets through, beneath the egress queue.
	raw underlay.UDPConn
	// locator is the entry's current remote address: the destination every
	// queued send and every raw write carries, replaced in place by a re-aim.
	locator atomic.Pointer[net.UDPAddr]
	// observed is the source of the link's last arrival.
	observed atomic.Pointer[netip.AddrPort]
	seed     uint32
	ifID     uint16
}

func (l *externalLink) start(
	ctx context.Context,
	procQs []chan *Packet,
	pool PacketPool,
) {
	// procQs and pool are never known before all configured links have been
	// instantiated. So we get them only now. We didn't need them earlier since
	// the connections have not been started yet.
	l.procQs = procQs
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

// egressAddr returns the link's live locator: the packet carries no
// destination of its own on this connection.
func (l *externalLink) egressAddr(*Packet) *net.UDPAddr {
	return l.locator.Load()
}

// WriteRaw sends a prebuilt packet on the link's own socket, beneath the
// forwarding queue — the BFD session's send path, which must keep
// transmitting while the link is down — aimed at the link's locator, for
// the prebuilt control packet carries no destination of its own.
func (l *externalLink) WriteRaw(b []byte) error {
	_, err := l.raw.WriteToUDP(b, l.locator.Load())
	return err
}

// Resolve should not be useful on an external link so we don't implement it.
func (l *externalLink) Resolve(p *Packet, host addr.Host, port uint16) error {
	return errResolveOnExternalLink
}

func (l *externalLink) Send(p *Packet) bool {
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *externalLink) SendBlocking(p *Packet) {
	l.egressQ <- p
}

func (l *externalLink) receive(size int, srcAddr *net.UDPAddr, p *Packet) {
	metrics := l.metrics
	sc := ClassOfSize(size)

	// The arrival's source is the link's latest observation; the packet
	// itself carries none, for every send on this connection follows the
	// locator.
	ap := netip.AddrPortFrom(srcAddr.AddrPort().Addr().Unmap(), srcAddr.AddrPort().Port())
	l.observed.Store(&ap)

	p.Link = l

	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if !ok {
		l.pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Add(context.Background(), 1)
		return
	}
	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Add(context.Background(), 1)
	}
}

// An internalLink addresses any host internal to the enclosing AS. Incoming
// packets are dispatched to the processors if recognizable as SCION traffic;
// all other traffic (e.g. STUN) is dropped.
type internalLink struct {
	procQ    chan *Packet
	procQs   []chan *Packet
	egressQ  chan *Packet
	procStop chan struct{}
	procDone chan struct{}
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

	// procQs and pool are never known before all configured links have been
	// instantiated. So we get them only now. We didn't need them earlier since
	// the connections have not been started yet.
	l.procQs = procQs
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

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) Send(p *Packet) bool {
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) SendBlocking(p *Packet) {
	l.egressQ <- p
}

func (l *internalLink) receive(size int, srcAddr *net.UDPAddr, p *Packet) {
	metrics := l.metrics
	sc := ClassOfSize(size)

	p.Link = l
	// This is an unconnected link. We must record the src address in case the
	// packet is turned around, e.g., by SCMP.
	p.RemoteAddr = unsafe.Pointer(srcAddr)

	var q chan *Packet
	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if ok {
		q = l.procQs[procID]
	} else {
		q = l.procQ
	}
	select {
	case q <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Add(context.Background(), 1)
	}
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
