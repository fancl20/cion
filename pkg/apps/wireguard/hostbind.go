package wireguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// hostSocket is the node's shared host-facing port: one plain UDP socket
// behind which every host-facing device listens — hosts are plain internet
// clients with a single endpoint to reach — beside the relay socket other
// nodes reach the port's relay at. The relay classifies each datagram before
// a device sees it and carries those of a host's sessions with other nodes
// onward unchanged; the rest are demultiplexed the way the mesh socket's
// are: a dispatcher delivers each datagram to every device, and the device
// whose peer table holds the sender's public key completes the handshake.
type hostSocket struct {
	conn  *net.UDPConn
	relay *hostRelay
	cnt   *counters

	mtx    sync.Mutex
	subs   map[*hostBind]chan datagram
	closed bool
	done   chan struct{}
}

func newHostSocket(c *net.UDPConn, relay *hostRelay, cnt *counters) *hostSocket {
	return &hostSocket{
		conn:  c,
		relay: relay,
		cnt:   cnt,
		subs:  make(map[*hostBind]chan datagram),
		done:  make(chan struct{}),
	}
}

// LocalPort returns the bound host-facing port.
func (s *hostSocket) LocalPort() uint16 { return uint16(s.conn.LocalAddr().(*net.UDPAddr).Port) }

// run reads the shared socket until the context ends — its end sets a read
// deadline that wakes the blocked read — or the socket fails, then finishes
// the socket, so every bind's receive function reports it closed. A datagram
// the relay carries leaves for its node, one it answers with a cookie reply
// gets the reply back from the shared port, one it drops counts, and every
// other reaches every opened bind. The port stays bound for Close.
func (s *hostSocket) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.finish()
			return
		}
		s.cnt.hostDatagrams.Add(1)
		pkt, src := buf[:n], from.AddrPort()
		switch node, reply, verdict := s.relay.fromHost(pkt, src); verdict {
		case relayToDevice:
			s.deliver(pkt, &hostEndpoint{addr: src})
		case relayOnward:
			s.relay.forward(node, pkt)
		case relayCookie:
			if _, err := s.conn.WriteToUDPAddrPort(reply, src); err != nil {
				s.cnt.relayDrops.Add(1)
				continue
			}
			s.cnt.relayCookies.Add(1)
		case relayDrop:
			s.cnt.relayDrops.Add(1)
		}
	}
}

// runRelay reads the relay socket until the context ends or the socket
// fails. A datagram the relay carries leaves unchanged for its host's
// endpoint from the shared port, one it drops counts, and every other
// reaches every opened bind with a relay endpoint naming the node it came
// from.
func (s *hostSocket) runRelay(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = s.relay.conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.relay.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		node := from.(*scion.Addr)
		pkt := buf[:n]
		switch host, verdict := s.relay.fromNode(pkt, node.IA); verdict {
		case relayToDevice:
			s.deliver(pkt, &hostEndpoint{relay: *node})
		case relayOnward:
			if _, err := s.conn.WriteToUDPAddrPort(pkt, host); err != nil {
				s.cnt.relayDrops.Add(1)
				continue
			}
			s.cnt.relayedDatagrams.Add(1)
		case relayDrop:
			s.cnt.relayDrops.Add(1)
		}
	}
}

// deliver copies one received datagram into every subscriber's queue,
// dropping it for a subscriber whose queue is full.
func (s *hostSocket) deliver(data []byte, src conn.Endpoint) {
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
func (s *hostSocket) Close() {
	_ = s.conn.Close()
}

// finish marks the socket retired exactly once.
func (s *hostSocket) finish() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
}

func (s *hostSocket) subscribe(b *hostBind, q chan datagram) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.subs[b] = q
	return nil
}

func (s *hostSocket) unsubscribe(b *hostBind) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s.subs, b)
}

// hostBind is one host device's half of the shared port.
type hostBind struct {
	socket *hostSocket
	// bridge carries the sends of DERP-sourced peers; nil when the node
	// runs no DERP presence.
	bridge *derpBridge
	recv   chan datagram
	// closed wakes the receive function the device retires.
	closed chan struct{}
	once   sync.Once
}

func newHostBind(socket *hostSocket, bridge *derpBridge) *hostBind {
	return &hostBind{socket: socket, bridge: bridge, closed: make(chan struct{})}
}

// Open registers with the shared socket. The requested port is ignored — the
// socket owns the configured listen port — and echoed back as the actual one.
func (b *hostBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
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
func (b *hostBind) Close() error {
	b.socket.unsubscribe(b)
	b.once.Do(func() { close(b.closed) })
	return nil
}

func (b *hostBind) SetMark(uint32) error { return nil }

// Send carries the datagrams to the host over the leg the peer's last
// authenticated datagram arrived on: the plain UDP socket to the arrival
// address, the DERP presence to the key a DERP-sourced datagram named, or
// the relay socket to the node that relayed the host's datagram.
func (b *hostBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	peer, ok := ep.(*hostEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	switch {
	case peer.onDERP():
		if b.bridge == nil {
			return errors.New("no DERP presence for a DERP-sourced peer")
		}
		for _, buf := range bufs {
			if err := b.bridge.send(peer.derp, buf); err != nil {
				return err
			}
		}
		return nil
	case peer.onRelay():
		return b.socket.relay.send(peer.relay, bufs)
	}
	for _, buf := range bufs {
		if _, err := b.socket.conn.WriteToUDPAddrPort(buf, peer.addr); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint builds no endpoint: host devices address no endpoints —
// hosts dial the node, and reply traffic follows the arrival address
// wireguard-go caches.
func (b *hostBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("host devices address no endpoints")
}

func (b *hostBind) BatchSize() int { return bindBatchSize }

// receive takes the next datagram the socket fanned out to this device.
func (b *hostBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
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

// hostEndpoint is a host as wireguard-go sees it: the leg its last
// authenticated datagram arrived on — the internet address of a UDP
// arrival, which replies return to; the sender's key of a DERP arrival,
// which replies return over the DERP presence; or the relaying node of a
// relay arrival, which replies return to over the relay socket.
type hostEndpoint struct {
	addr netip.AddrPort
	derp PublicKey
	// relay is the node a relay arrival came from — its ISD-AS and the
	// reversed path the datagram arrived on; its ISD-AS is zero off the
	// relay leg.
	relay scion.Addr
}

// onDERP reports whether the endpoint names the DERP leg.
func (e *hostEndpoint) onDERP() bool { return e.derp != PublicKey{} }

// onRelay reports whether the endpoint names the relay leg.
func (e *hostEndpoint) onRelay() bool { return !e.relay.IA.IsZero() }

func (e *hostEndpoint) ClearSrc()           {}
func (e *hostEndpoint) SrcToString() string { return "" }
func (e *hostEndpoint) DstToString() string {
	switch {
	case e.onDERP():
		return "derp:" + e.derp.String()
	case e.onRelay():
		return "relay:" + e.relay.IA.String()
	}
	return e.addr.String()
}

// DstToBytes returns the source digest wireguard-go's cookie replies bind
// to: the arrival address, or on the relay leg the relaying node's ISD-AS.
func (e *hostEndpoint) DstToBytes() []byte {
	if e.onRelay() {
		return binary.BigEndian.AppendUint64(nil, uint64(e.relay.IA))
	}
	return e.addr.Addr().AsSlice()
}
func (e *hostEndpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (e *hostEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
