package wireguard

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// hostSocket is the node's shared host-facing port: one plain UDP socket
// behind which every host-facing device listens — hosts are plain internet
// clients with a single endpoint to reach — demultiplexed the way the mesh
// socket is: a dispatcher delivers each datagram to every device, and the
// device whose peer table holds the sender's public key completes the
// handshake.
type hostSocket struct {
	conn *net.UDPConn
	cnt  *counters

	mtx    sync.Mutex
	subs   map[*hostBind]chan datagram
	closed bool
	done   chan struct{}
}

func newHostSocket(c *net.UDPConn, cnt *counters) *hostSocket {
	return &hostSocket{
		conn: c,
		cnt:  cnt,
		subs: make(map[*hostBind]chan datagram),
		done: make(chan struct{}),
	}
}

// LocalPort returns the bound host-facing port.
func (s *hostSocket) LocalPort() uint16 { return uint16(s.conn.LocalAddr().(*net.UDPAddr).Port) }

// run reads the shared socket and delivers every datagram to every opened
// bind until Close retires it.
func (s *hostSocket) run() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.finish()
			return
		}
		s.deliver(buf[:n], &hostEndpoint{addr: from.AddrPort()})
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

// Close stops the read loop by closing the socket.
func (s *hostSocket) Close() {
	s.conn.Close() //nolint:errcheck
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
	recv   chan datagram
	// closed wakes the receive function the device retires.
	closed chan struct{}
	once   sync.Once
}

func newHostBind(socket *hostSocket) *hostBind {
	return &hostBind{socket: socket, closed: make(chan struct{})}
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

// Send carries the datagrams to the host over the plain UDP socket.
func (b *hostBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	peer, ok := ep.(*hostEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
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

// hostEndpoint is a host as wireguard-go sees it: the internet address its
// datagrams arrived from, which replies return to.
type hostEndpoint struct {
	addr netip.AddrPort
}

func (e *hostEndpoint) ClearSrc()           {}
func (e *hostEndpoint) SrcToString() string { return "" }
func (e *hostEndpoint) DstToString() string { return e.addr.String() }
func (e *hostEndpoint) DstToBytes() []byte  { return e.addr.Addr().AsSlice() }
func (e *hostEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *hostEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
