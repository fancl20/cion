// Package wireguard is CION's WireGuard application (proposal 0006,
// ADR-0005): wireguard-go embedded in the CION binary, serving plain hosts.
// Hosts are standard WireGuard clients of their local node behind one shared
// UDP port — the public key they send with selects their exit — nodes tunnel
// to each other through a WireGuard transport (conn.Bind) on the path
// library's SCION socket, an in-process router forwards between the tunnels
// over packet pipes, and internet egress flows through gVisor's netstack.
// The application publishes its public key to the directory the core node's
// application serves, authenticated by TRC-anchored certificate chains.
package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/fancl20/cion/pkg/scion"
)

// bindBatchSize bounds the datagram batches the binds exchange with
// wireguard-go; one datagram per call, a batch worth of buffering.
const bindBatchSize = 16

// pathRefreshMargin is how close to a cached path's expiry the transport
// re-resolves: a path whose hops lapse inside the margin is refreshed before
// it fails, not after.
const pathRefreshMargin = 30 * time.Second

// datagram is one received datagram handed to a subscriber: the bytes owned
// by the subscriber, the sender as the endpoint wireguard-go caches.
type datagram struct {
	data []byte
	src  conn.Endpoint
}

// meshSocket is the node's mesh transport: one SCION socket bound to an
// ephemeral port and registered under the wireguard service in its own AS,
// shared by every mesh device, fanning each received datagram out to all of
// them — all devices share the node's key pair, so each can decrypt a
// handshake, but only the device whose peer table holds the sender's public
// key completes it. It also owns the freshest-path cache sends resolve
// through.
type meshSocket struct {
	conn     *scion.Conn
	provider *scion.PathProvider
	cnt      *counters

	mtx sync.Mutex
	// subs holds one queue per opened device bind.
	subs map[*meshBind]chan datagram
	// paths caches the freshest local path per peer ISD-AS.
	paths map[addr.IA]*spath.Decoded
	// expiry caches each path's hop expiry, beside the path itself.
	expiry map[addr.IA]time.Time
	closed bool
	done   chan struct{}
}

func newMeshSocket(c *scion.Conn, provider *scion.PathProvider, cnt *counters) *meshSocket {
	return &meshSocket{
		conn:     c,
		provider: provider,
		cnt:      cnt,
		subs:     make(map[*meshBind]chan datagram),
		paths:    make(map[addr.IA]*spath.Decoded),
		expiry:   make(map[addr.IA]time.Time),
		done:     make(chan struct{}),
	}
}

// run reads the shared socket and delivers every datagram to every opened
// bind until the socket fails — Close closes it — and every bind's receive
// function reports it closed.
func (s *meshSocket) run() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.finish()
			return
		}
		peer, ok := from.(*scion.Addr)
		if !ok {
			continue
		}
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

// Close stops the read loop by closing the socket; the loop's failure path
// finishes the socket and wakes every bind.
func (s *meshSocket) Close() {
	s.conn.Close() //nolint:errcheck
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

// send carries encrypted datagrams to the peer, resolving the peer endpoint
// Addr{IA, Addr, Path} from local state — never a fetch inside a send —
// caching the freshest path per peer and re-resolving when the cached path
// nears expiry or a send fails. An endpoint carrying the reversed path of
// the peer's latest arrival seeds the cache: replies ride arrival paths,
// the one route to a peer no local state names — a core replying to a leaf
// below it. One refresh and retry per send.
func (s *meshSocket) send(ep *meshEndpoint, bufs [][]byte) error {
	dst := ep.addr
	for attempt := 0; ; attempt++ {
		path := s.cachedPath(dst.IA)
		if path == nil && dst.Path != nil &&
			time.Since(scion.PathExpiry(dst.Path)) <= -pathRefreshMargin {
			path = dst.Path
			s.setPath(dst.IA, path)
		}
		if path == nil {
			refreshed, err := s.provider.LocalPath(dst.IA)
			if err != nil {
				s.cnt.sendFailures.Add(int64(len(bufs)))
				return fmt.Errorf("resolving a path to %s: %w", dst.IA, err)
			}
			s.setPath(dst.IA, refreshed)
			path = refreshed
		}
		dst.Path = path
		var sendErr error
		for _, buf := range bufs {
			if _, sendErr = s.conn.WriteTo(buf, &dst); sendErr != nil {
				break
			}
			s.cnt.sentDatagrams.Add(1)
		}
		if sendErr == nil {
			return nil
		}
		// The cached path failed to carry the datagram — expired en route or
		// rejected by a router. Invalidate it and retry once on a fresh one.
		if attempt == 0 {
			s.cnt.pathRefreshes.Add(1)
		}
		s.mtx.Lock()
		delete(s.paths, dst.IA)
		s.mtx.Unlock()
		// The endpoint's carried path is the one that just failed; the retry
		// resolves fresh instead of reusing it.
		dst.Path = nil
		if attempt > 0 {
			s.cnt.sendFailures.Add(int64(len(bufs)))
			return sendErr
		}
	}
}

// setPath caches the freshest path for a peer, counting the refresh when it
// replaces one the margin refused.
func (s *meshSocket) setPath(ia addr.IA, path *spath.Decoded) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if _, ok := s.paths[ia]; ok {
		// A cached path the margin refused: a refresh by expiry.
		s.cnt.pathRefreshes.Add(1)
	}
	s.paths[ia] = path
	s.expiry[ia] = scion.PathExpiry(path)
}

// warmPath caches a route resolved outside a send — the sync loop's place,
// where a fetch belongs. Leaf-to-leaf routes compose up and down segments
// and need the lookup; sends only ever read the cache.
func (s *meshSocket) warmPath(ia addr.IA, path *spath.Decoded) {
	if path == nil {
		return
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.paths[ia] = path
	s.expiry[ia] = scion.PathExpiry(path)
}

// cachedPath returns the cached path for the peer when it exists and its hops
// do not lapse inside the refresh margin.
func (s *meshSocket) cachedPath(ia addr.IA) *spath.Decoded {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	path, ok := s.paths[ia]
	if !ok {
		return nil
	}
	if time.Since(s.expiry[ia]) > -pathRefreshMargin {
		return nil
	}
	return path
}

// meshBind is one mesh device's half of the shared socket: the conn.Bind
// wireguard-go owns, reading the socket's fan-out and sending through the
// path cache.
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
