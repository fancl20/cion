// Package wireguard is CION's WireGuard application: wireguard-go embedded in
// the CION binary, carrying the tailnet's hosts and the node-to-node mesh.
// Hosts are tailnet clients of their node behind one shared UDP port — one
// device whose peers the registry's host entries program — nodes tunnel to
// each other through a WireGuard transport (conn.Bind) on the path library's
// SCION socket, and an in-process router forwards between the tunnels over
// packet pipes, the surface a resident service application borrows. The
// application publishes its entry to the directory the core node's application
// serves, authenticated by TRC-anchored certificate chains.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
)

// bindBatchSize bounds the datagram batches the binds exchange with
// wireguard-go; one datagram per call, a batch worth of buffering.
const bindBatchSize = 16

// datagram is one received datagram handed to a subscriber: the bytes owned
// by the subscriber, the sender as the endpoint wireguard-go caches.
type datagram struct {
	data []byte
	src  conn.Endpoint
}

// leases returns each destination's lease: the path its sends and its dials
// ride, read without waiting.
type leases interface {
	Lease(dst addr.IA) *scion.Lease
}

// meshSocket is the node's mesh transport: one SCION socket bound to an
// ephemeral port and registered under the wireguard service in its own AS,
// shared by every mesh device, fanning each received datagram out to all of
// them — all devices share the node's key pair, so each can decrypt a
// handshake, but only the device whose peer table holds the sender's public
// key completes it. Its sends, the relay's beside the mesh's, ride each
// peer's lease.
type meshSocket struct {
	conn   *scion.Conn
	leases leases
	cnt    *counters

	mtx sync.Mutex
	// subs holds one queue per opened device bind.
	subs map[*meshBind]chan datagram
	// routes holds the identity of the path each peer's last send rode over
	// its lease, a change of which counts a route switch.
	routes map[addr.IA]bus.PathID
	closed bool
	done   chan struct{}
}

func newMeshSocket(c *scion.Conn, leases leases, cnt *counters) *meshSocket {
	return &meshSocket{
		conn:   c,
		leases: leases,
		cnt:    cnt,
		subs:   make(map[*meshBind]chan datagram),
		routes: make(map[addr.IA]bus.PathID),
		done:   make(chan struct{}),
	}
}

// run reads the shared socket and delivers every datagram to every opened
// bind until the context ends — its end sets a read deadline that wakes the
// blocked read — or the socket fails, then finishes the socket, so every
// bind's receive function reports it closed. The socket stays open for
// Close.
func (s *meshSocket) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.finish()
			return
		}
		peer := from.(*scion.Addr)
		s.deliver(buf[:n], &meshEndpoint{addr: *peer})
	}
}

// deliver copies one received datagram into every subscriber's queue,
// dropping it for a subscriber whose queue is full.
func (s *meshSocket) deliver(data []byte, src conn.Endpoint) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for _, q := range s.subs {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		select {
		case q <- datagram{data: pkt, src: src}:
		default:
			s.cnt.droppedPackets.Add(1)
		}
	}
}

// Close closes the socket, failing a read loop still blocked on it.
func (s *meshSocket) Close() {
	_ = s.conn.Close()
}

// finish marks the socket retired exactly once.
func (s *meshSocket) finish() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
}

// subscribe registers a device bind's queue.
func (s *meshSocket) subscribe(b *meshBind, q chan datagram) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.subs[b] = q
	return nil
}

// unsubscribe deregisters a device bind's queue.
func (s *meshSocket) unsubscribe(b *meshBind) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s.subs, b)
}

// send carries a mesh device's encrypted datagrams to the peer on the mesh
// socket.
func (s *meshSocket) send(ep *meshEndpoint, bufs [][]byte) error {
	return s.sendOn(s.conn, ep.addr, bufs, &s.cnt.sentDatagrams, &s.cnt.sendFailures)
}

// sendOn carries datagrams on conn to dst over the path dst's lease holds,
// read without waiting — never a fetch inside a send — a batch carrying a
// data packet counting as the destination's use, keepalives and handshakes
// not. While the lease holds no path, the reversed path of the peer's latest
// arrival dst carries serves: replies ride arrival paths, the one route to a
// peer no local state names — a core replying to a leaf below it. It counts
// each datagram written in sent, and each datagram of a send it gives up on
// in failed.
func (s *meshSocket) sendOn(conn *scion.Conn, dst scion.Addr, bufs [][]byte, sent, failed *atomic.Int64) error {
	lease := s.leases.Lease(dst.IA)
	read := lease.Peek
	if slices.ContainsFunc(bufs, carriesData) {
		read = lease.Path
	}
	leased, err := read()
	switch {
	case err == nil:
		s.rode(dst.IA, leased.ID)
		dst.Path = leased.Path
	case dst.Path != nil && time.Until(scion.PathExpiry(dst.Path)) > scion.LeaseExpiryMargin:
	default:
		failed.Add(int64(len(bufs)))
		return fmt.Errorf("resolving a path to %s: %w", dst.IA, err)
	}
	for i, buf := range bufs {
		if _, err := conn.WriteTo(buf, &dst); err != nil {
			failed.Add(int64(len(bufs) - i))
			return err
		}
		sent.Add(1)
	}
	return nil
}

// rode notes the identity of the path a send to the peer rode, counting a
// route switch when it differs from the last send's.
func (s *meshSocket) rode(ia addr.IA, id bus.PathID) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if last, ok := s.routes[ia]; ok && last != id {
		s.cnt.routeSwitches.Add(1)
	}
	s.routes[ia] = id
}

// carriesData reports whether a datagram is a WireGuard data packet: a
// transport message longer than an empty keepalive.
func carriesData(pkt []byte) bool {
	return messageType(pkt) == device.MessageTransportType && len(pkt) > device.MessageTransportSize
}

// meshBind is one mesh device's half of the shared socket: the conn.Bind
// wireguard-go owns, reading the socket's fan-out and sending over the
// socket's leases.
type meshBind struct {
	socket *meshSocket
	recv   chan datagram
	// closed wakes the receive function the device retires.
	closed chan struct{}
	once   sync.Once
}

func newMeshBind(socket *meshSocket) *meshBind {
	return &meshBind{socket: socket, closed: make(chan struct{})}
}

// Open registers with the shared socket. The requested port is ignored — the
// socket owns the service registration — and echoed back as the actual one.
func (b *meshBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.once = sync.Once{}
	b.closed = make(chan struct{})
	b.recv = make(chan datagram, bindBatchSize)
	if err := b.socket.subscribe(b, b.recv); err != nil {
		return nil, 0, err
	}
	return []conn.ReceiveFunc{b.receive}, port, nil
}

// Close deregisters from the shared socket and wakes the device's receive
// routine, whose retirement wireguard-go waits for.
func (b *meshBind) Close() error {
	b.socket.unsubscribe(b)
	b.once.Do(func() { close(b.closed) })
	return nil
}

func (b *meshBind) SetMark(uint32) error { return nil }

// Send carries the datagrams to the peer over the SCION transport.
func (b *meshBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	peer, ok := ep.(*meshEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	return b.socket.send(peer, bufs)
}

// ParseEndpoint builds a peer endpoint from its IPC string form,
// "isd-as,service": the peer named by its ISD-AS and the wireguard service,
// which the peer's own AS resolves to its registered socket.
func (b *meshBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed mesh endpoint %q", s)
	}
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing mesh endpoint ISD-AS: %w", err)
	}
	svc, err := parseServiceName(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing mesh endpoint service: %w", err)
	}
	return &meshEndpoint{addr: scion.Addr{IA: ia, Service: svc}}, nil
}

func (b *meshBind) BatchSize() int { return bindBatchSize }

// receive takes the next datagram the socket fanned out to this device.
func (b *meshBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case dg := <-b.recv:
		copy(packets[0], dg.data)
		sizes[0] = len(dg.data)
		eps[0] = dg.src
		return 1, nil
	case <-b.closed:
		return 0, net.ErrClosed
	case <-b.socket.done:
		return 0, net.ErrClosed
	}
}

// meshEndpoint is a mesh peer as wireguard-go sees it: the SCION address the
// transport dials — a service destination until the peer's first arrival
// roams it to the arrival's underlay address and reversed path.
type meshEndpoint struct {
	addr scion.Addr
}

func (e *meshEndpoint) ClearSrc() {}
func (e *meshEndpoint) SrcToString() string {
	return e.addr.Addr.String()
}
func (e *meshEndpoint) DstToString() string { return e.addr.String() }
func (e *meshEndpoint) DstToBytes() []byte {
	raw := make([]byte, 0, 10)
	ia := uint64(e.addr.IA)
	raw = append(raw,
		byte(ia>>56), byte(ia>>48), byte(ia>>40), byte(ia>>32),
		byte(ia>>24), byte(ia>>16), byte(ia>>8), byte(ia))
	// The cookie MAC's digest of the destination: the service value in place
	// of the address on a service endpoint.
	if e.addr.Service != 0 {
		svc := uint16(e.addr.Service)
		return append(raw, byte(svc>>8), byte(svc))
	}
	return append(raw, e.addr.Addr.Addr().AsSlice()...)
}
func (e *meshEndpoint) DstIP() netip.Addr { return e.addr.Addr.Addr() }
func (e *meshEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// endpointString encodes a mesh endpoint as the IPC form ParseEndpoint
// reads: the peer's ISD-AS and the wireguard service.
func endpointString(ia addr.IA) string {
	return ia.String() + "," + serviceName(SvcWireguard)
}

// serviceName returns the service's name — the word the endpoint string
// names a service by, the way the drafts' registry names theirs.
func serviceName(svc addr.SVC) string {
	switch svc {
	case SvcWireguard:
		return "wireguard"
	case SvcDirectory:
		return "directory"
	default:
		return svc.String()
	}
}

// parseServiceName decodes a service name serviceName encodes; a name the
// table does not hold is refused rather than guessed.
func parseServiceName(name string) (addr.SVC, error) {
	switch name {
	case "wireguard":
		return SvcWireguard, nil
	case "directory":
		return SvcDirectory, nil
	default:
		return 0, fmt.Errorf("unknown service %q", name)
	}
}
