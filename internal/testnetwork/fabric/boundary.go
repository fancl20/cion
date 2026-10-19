package fabric

import (
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The mapping band: the ports the boundary's per-socket mappings draw,
// below the kernel's ephemeral range and beside — not inside — the labs'
// pinned band and the node's link band, so a mapping's port is always a
// port no node claims and a changed mapping always spells a different
// address.
const (
	mappingPortBase = 26000
	mappingPortSpan = 500
)

// MappingIdle is how long a mapping lives past its last packet, either
// direction: the idle timeout a link's BFD stream — one packet per
// interval, both directions — rides out by construction, and a silenced
// node's mapping does not.
const MappingIdle = 2 * time.Second

// Boundary is the translation between the inside hosts and the outside:
// the gateway address it owns — the address the translated nodes' packets
// leave from, never their own — and the upstream host beyond it. Packets
// from inside to outside are rewritten to leave from the gateway under a
// port drawn from the mapping band, one mapping per inside socket under the
// endpoint-independent policy the translator held; the first-contact dials
// to the gateway's forwarded port are carried to the upstream's; packets
// from outside to a drawn port are reverse-translated to the mapping's
// inside socket; every other packet to the gateway is dropped, the silence
// a real translation gives. The rewrite renews the IP and UDP checksums;
// the reverse-translated delivery back to the inside socket is the proof it
// renewed them right.
type Boundary struct {
	f        *Fabric
	gateway  netip.Addr
	upstream netip.Addr
	// firstContact is the gateway port forwarded to the upstream's own —
	// the rendezvous port of the exchange the translated node dials
	// through.
	firstContact uint16
	inside       map[netip.Addr]bool

	mtx      sync.Mutex
	mappings map[uint16]*mapping // by the gateway port drawn
	bySock   map[netip.AddrPort]uint16
	draws    int
}

// mapping is one inside socket's translation: the gateway port its packets
// leave from and the far side's return traffic dials.
type mapping struct {
	sock netip.AddrPort
	used time.Time
}

// Translate draws a boundary on the fabric: the gateway address it owns —
// a host no node may hold, for the boundary answers it — the upstream host
// the first-contact port forwards to at the same port, and the inside
// hosts whose packets it carries. Every host beyond the inside set and the
// gateway is outside.
func (f *Fabric) Translate(
	gateway, upstream netip.Addr, firstContact uint16, inside ...netip.Addr,
) *Boundary {

	f.t.Helper()
	if len(inside) == 0 {
		f.t.Fatalf("a boundary carries at least one inside host")
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if _, ok := f.hosts[gateway]; ok {
		f.t.Fatalf("a node already holds the gateway host %v", gateway)
	}
	for _, host := range inside {
		if host == gateway || host == upstream {
			f.t.Fatalf("the boundary's inside host %v is its own gateway or upstream", host)
		}
	}
	b := &Boundary{
		f:            f,
		gateway:      gateway,
		upstream:     upstream,
		firstContact: firstContact,
		inside:       make(map[netip.Addr]bool, len(inside)),
		mappings:     make(map[uint16]*mapping),
		bySock:       make(map[netip.AddrPort]uint16),
	}
	for _, host := range inside {
		b.inside[host] = true
	}
	f.bounds = append(f.bounds, b)
	return b
}

// rewrite applies the boundary's rules to one packet: the rewritten packet
// and whether the boundary claimed it — nil packet for one it dropped.
func (b *Boundary) rewrite(pkt []byte) ([]byte, bool) {
	ip := header.IPv4(pkt)
	src := toNetip(ip.SourceAddress())
	dst := toNetip(ip.DestinationAddress())
	isUDP := ip.TransportProtocol() == header.UDPProtocolNumber &&
		len(pkt) >= int(ip.HeaderLength())+header.UDPMinimumSize
	if b.inside[src] {
		switch {
		case b.inside[dst]:
			// Inside to inside: nothing crosses the boundary.
			return nil, false
		case dst == b.gateway && isUDP &&
			udpOf(pkt).DestinationPort() == b.firstContact:
			// The first-contact leg: a dial to the gateway's rendezvous
			// port is carried to the upstream's, its source mapped like any
			// crossing.
			udp := header.UDP(pkt[ip.HeaderLength():])
			port := b.mappingFor(netip.AddrPortFrom(src, udp.SourcePort()))
			return rewriteDatagram(pkt, b.gateway, port, b.upstream,
				b.firstContact), true
		case dst == b.gateway:
			// The gateway answers nothing else: the silence a real
			// translation gives.
			return nil, true
		default:
			if !isUDP {
				return nil, false
			}
			// Inside to outside: the source becomes the gateway under the
			// inside socket's mapping.
			udp := header.UDP(pkt[ip.HeaderLength():])
			port := b.mappingFor(netip.AddrPortFrom(src, udp.SourcePort()))
			return rewriteDatagram(pkt, b.gateway, port, dst,
				udp.DestinationPort()), true
		}
	}
	if dst == b.gateway {
		if !isUDP {
			return nil, true
		}
		// Outside to a drawn port: reverse-translated to the inside socket
		// the mapping records, its source untouched.
		udp := header.UDP(pkt[ip.HeaderLength():])
		m := b.reverseLookup(udp.DestinationPort())
		if m == nil {
			return nil, true
		}
		return rewriteDatagram(pkt, src, udp.SourcePort(),
			m.sock.Addr(), m.sock.Port()), true
	}
	if b.inside[dst] {
		// Outside to an inside host: the inside is unreachable from the
		// outside — the silence a real translation gives, for every
		// crossing is named for the gateway. The neighbors' traffic rides
		// the links, whose locators the observations spell.
		return nil, true
	}
	return nil, false
}

// udpOf reads the packet's UDP header, for a packet already known UDP.
func udpOf(pkt []byte) header.UDP {
	return header.UDP(pkt[header.IPv4(pkt).HeaderLength():])
}

// mappingFor returns the inside socket's mapping's gateway port, drawing
// one where none stands: every destination, the one port — the mapping an
// endpoint-independent translation gives a socket. Each crossing refreshes
// the mapping's idle window on the fabric's clock.
func (b *Boundary) mappingFor(sock netip.AddrPort) uint16 {
	now := b.f.clock.Now()
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.retireIdleLocked(now)
	if port, ok := b.bySock[sock]; ok {
		b.mappings[port].used = now
		return port
	}
	for {
		b.draws++
		port := uint16(mappingPortBase + b.draws%mappingPortSpan)
		if _, ok := b.mappings[port]; !ok {
			b.bySock[sock] = port
			b.mappings[port] = &mapping{sock: sock, used: now}
			return port
		}
	}
}

// reverseLookup returns the mapping a drawn gateway port spells, refreshed
// by the packet that reached it, or nil where none stands.
func (b *Boundary) reverseLookup(port uint16) *mapping {
	now := b.f.clock.Now()
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.retireIdleLocked(now)
	m, ok := b.mappings[port]
	if !ok {
		return nil
	}
	m.used = now
	return m
}

// retireIdleLocked drops the mappings whose idle window elapsed; they
// return as fresh draws, never the same port twice.
func (b *Boundary) retireIdleLocked(now time.Time) {
	for port, m := range b.mappings {
		if now.Sub(m.used) < MappingIdle {
			continue
		}
		delete(b.mappings, port)
		delete(b.bySock, m.sock)
	}
}

// Rebind retires every mapping at once: the next inside packet draws a
// fresh one, the changed mapping a restart's proof needs.
func (b *Boundary) Rebind() {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	clear(b.mappings)
	clear(b.bySock)
}

// Mappings returns the inside sockets whose mappings stand, in draw order —
// the idle window retiring the ones past it.
func (b *Boundary) Mappings() []netip.AddrPort {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.retireIdleLocked(b.f.clock.Now())
	ports := make([]uint16, 0, len(b.mappings))
	for port := range b.mappings {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	socks := make([]netip.AddrPort, len(ports))
	for i, port := range ports {
		socks[i] = b.mappings[port].sock
	}
	return socks
}

// MappingPort reports whether an address's port lies in the boundary's
// drawn mapping band.
func MappingPort(ap netip.AddrPort) bool {
	return ap.Port() >= mappingPortBase && ap.Port() < mappingPortBase+mappingPortSpan
}

// rewriteDatagram rewrites the packet's UDP datagram — its source and
// destination addresses and ports — renewing the IP and UDP checksums; the
// receiver's acceptance of the rewritten packet is the proof they renewed
// right.
func rewriteDatagram(
	pkt []byte, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16,
) []byte {

	ip := header.IPv4(pkt)
	udp := header.UDP(pkt[ip.HeaderLength():])
	ip.SetSourceAddress(tcpip.AddrFrom4(src.As4()))
	ip.SetDestinationAddress(tcpip.AddrFrom4(dst.As4()))
	udp.SetSourcePort(srcPort)
	udp.SetDestinationPort(dstPort)
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	// The UDP checksum covers the pseudo-header of the new addresses beside
	// the header and payload: computed whole, for a translated datagram is
	// a new one, and over a zeroed checksum field.
	udp.SetChecksum(0)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
		ip.SourceAddress(), ip.DestinationAddress(), udp.Length())
	xsum = checksum.Checksum(udp[header.UDPMinimumSize:], xsum)
	xsum = udp.CalculateChecksum(xsum)
	if xsum != math.MaxUint16 {
		xsum = ^xsum
	}
	udp.SetChecksum(xsum)
	return pkt
}
