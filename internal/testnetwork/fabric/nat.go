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

// The mapping band: the ports the NAT's mappings draw, below the
// kernel's ephemeral range and beside — not inside — the labs' pinned band
// and the node's link band, so a mapping's port is always a port no node
// claims and a changed mapping always spells a different address.
const (
	mappingPortBase = 26000
	mappingPortSpan = 500
)

// MappingTimeout is how long a mapping lives past its last packet, either
// direction: the idle timeout a link's BFD stream — one packet per
// interval, both directions — rides out by construction, and a silenced
// node's mapping does not.
const MappingTimeout = 2 * time.Second

// Behavior is a NAT's mapping and filtering behavior, as RFC 4787 names
// them.
type Behavior struct {
	// AddressPortDependentMapping draws a mapping per destination address
	// and port of an inside socket, where endpoint-independent mapping keeps
	// one mapping per socket for every destination.
	AddressPortDependentMapping bool
	// AddressPortDependentFiltering admits an outside packet to a mapping
	// only from an address and port the mapping's inside socket sent to,
	// where endpoint-independent filtering admits any outside source.
	AddressPortDependentFiltering bool
}

// The behaviors the labs draw.
var (
	// FullCone maps and filters independently of the endpoint: any outside
	// source reaches an inside socket's one mapping.
	FullCone = Behavior{}
	// PortRestricted keeps one mapping per inside socket and admits only
	// the endpoints the socket sent to.
	PortRestricted = Behavior{AddressPortDependentFiltering: true}
	// Symmetric draws a mapping per destination and admits only that
	// destination.
	Symmetric = Behavior{AddressPortDependentMapping: true, AddressPortDependentFiltering: true}
)

// NAT translates between the inside hosts and the outside: the gateway
// address it owns — the address its inside nodes' packets leave from, never
// their own — and, when it forwards a first-contact port, the upstream host
// beyond it. Packets from inside to outside are rewritten to leave from the
// gateway under a port drawn from the mapping band, as the NAT's behavior
// maps them; the first-contact dials to the gateway's forwarded port are
// carried to the upstream's; packets from outside to a drawn port the
// behavior admits are reverse-translated to the mapping's inside socket;
// every other packet from outside to the band or to an inside host is
// dropped, the silence a real NAT gives. A packet to the gateway from
// inside, or from outside beyond the band, is the gateway's own: the
// router's, where a node runs on it, and silence where none does. The
// rewrite renews the IP and UDP checksums; the reverse-translated delivery
// back to the inside socket is the proof it renewed them right.
type NAT struct {
	f        *Fabric
	behavior Behavior
	gateway  netip.Addr
	upstream netip.Addr
	// firstContact is the gateway port forwarded to the upstream's own —
	// the rendezvous port of the exchange the node behind a NAT dials
	// through. Zero forwards none.
	firstContact uint16
	inside       map[netip.Addr]bool

	mtx      sync.Mutex
	mappings map[uint16]*mapping // by the gateway port drawn
	byFlow   map[flow]uint16
	draws    int
}

// flow keys a mapping: the inside socket and, under endpoint-dependent
// mapping, the destination it sent to.
type flow struct {
	sock, dst netip.AddrPort
}

// mapping is one translation: the inside socket whose packets leave from
// the gateway port, the destinations they went to — the endpoints
// address-and-port filtering admits — and when a packet last crossed it.
type mapping struct {
	key  flow
	sent map[netip.AddrPort]bool
	used time.Time
}

// ForwardingNAT draws a full-cone NAT on the fabric: the gateway address
// it owns — a host only its router may hold — the
// upstream host the first-contact port forwards to at the same port, and
// the inside hosts whose packets it carries. Every host beyond the inside
// set and the gateway is outside.
func (f *Fabric) ForwardingNAT(
	gateway, upstream netip.Addr, firstContact uint16, inside ...netip.Addr,
) *NAT {

	f.t.Helper()
	return f.newNAT(FullCone, gateway, upstream, firstContact, inside)
}

// NAT draws a NAT of the given behavior on the fabric: the
// gateway address it owns and the inside hosts whose packets it carries.
// It forwards no first-contact port: an inside node dials its peers'
// published addresses, as it would through a real NAT.
func (f *Fabric) NAT(behavior Behavior, gateway netip.Addr, inside ...netip.Addr) *NAT {
	f.t.Helper()
	return f.newNAT(behavior, gateway, netip.Addr{}, 0, inside)
}

func (f *Fabric) newNAT(
	behavior Behavior, gateway, upstream netip.Addr, firstContact uint16, inside []netip.Addr,
) *NAT {

	f.t.Helper()
	if len(inside) == 0 {
		f.t.Fatalf("a NAT carries at least one inside host")
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if _, ok := f.hosts[gateway]; ok {
		f.t.Fatalf("a node already holds the gateway host %v", gateway)
	}
	for _, host := range inside {
		if host == gateway || host == upstream {
			f.t.Fatalf("the NAT's inside host %v is its own gateway or upstream", host)
		}
	}
	b := &NAT{
		f:            f,
		behavior:     behavior,
		gateway:      gateway,
		upstream:     upstream,
		firstContact: firstContact,
		inside:       make(map[netip.Addr]bool, len(inside)),
		mappings:     make(map[uint16]*mapping),
		byFlow:       make(map[flow]uint16),
	}
	for _, host := range inside {
		b.inside[host] = true
	}
	f.nats = append(f.nats, b)
	return b
}

// Gateway returns the address the NAT's crossings leave from.
func (b *NAT) Gateway() netip.Addr { return b.gateway }

// Router boots the stack of the NAT's own box, the router a node runs on:
// the gateway, its own host, beside the inside host given, one of the NAT's
// inside hosts. A socket bound to the wildcard sends to the NAT's inside
// hosts from the inside host, crossing nothing, and to every other host
// from the gateway, untranslated; it receives at both. The stack's
// ephemeral ports lie above the mapping band, whose ports at the gateway
// are the NAT's.
func (b *NAT) Router(inside netip.Addr) *Node {
	f := b.f
	f.t.Helper()
	if !b.inside[inside] {
		f.t.Fatalf("the router's inside host %v is none of the NAT's inside hosts", inside)
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, host := range []netip.Addr{b.gateway, inside} {
		if _, ok := f.hosts[host]; ok {
			f.t.Fatalf("a node already holds the router's host %v", host)
		}
	}
	routes := []tcpip.Route{{
		Destination: anyHost(), NIC: 1, SourceHint: tcpip.AddrFrom4(b.gateway.As4()),
	}}
	for host := range b.inside {
		routes = append(routes, tcpip.Route{
			Destination: oneHost(host), NIC: 1, SourceHint: tcpip.AddrFrom4(inside.As4()),
		})
	}
	n := f.bootLocked([]netip.Addr{b.gateway, inside}, routes)
	if err := n.stack.SetPortRange(mappingPortBase+mappingPortSpan, math.MaxUint16); err != nil {
		f.t.Fatalf("lifting the router's ephemeral ports above the mapping band: %v", err)
	}
	return n
}

// egress applies the NAT's rules to a packet leaving one of its inside
// hosts: the rewritten packet and whether the NAT claimed it — nil
// packet for one it dropped. A packet between two inside hosts crosses
// nothing and is not claimed, nor is one to the gateway, the gateway's own:
// no mapping answers an inside host, for the NAT hairpins nothing.
func (b *NAT) egress(pkt []byte) ([]byte, bool) {
	ip := header.IPv4(pkt)
	src := toNetip(ip.SourceAddress())
	dst := toNetip(ip.DestinationAddress())
	if !b.inside[src] || b.inside[dst] {
		return nil, false
	}
	isUDP := ip.TransportProtocol() == header.UDPProtocolNumber &&
		len(pkt) >= int(ip.HeaderLength())+header.UDPMinimumSize
	switch {
	case dst == b.gateway && isUDP && b.firstContact != 0 &&
		udpOf(pkt).DestinationPort() == b.firstContact:
		// The first-contact leg: a dial to the gateway's rendezvous port is
		// carried to the upstream's, its source mapped like any crossing.
		udp := udpOf(pkt)
		to := netip.AddrPortFrom(b.upstream, b.firstContact)
		port := b.mappingFor(netip.AddrPortFrom(src, udp.SourcePort()), to)
		return rewriteDatagram(pkt, b.gateway, port, b.upstream, b.firstContact), true
	case dst == b.gateway || !isUDP:
		return nil, false
	default:
		// Inside to outside: the source becomes the gateway under the
		// mapping the behavior draws for the socket and destination.
		udp := udpOf(pkt)
		to := netip.AddrPortFrom(dst, udp.DestinationPort())
		port := b.mappingFor(netip.AddrPortFrom(src, udp.SourcePort()), to)
		return rewriteDatagram(pkt, b.gateway, port, dst, udp.DestinationPort()), true
	}
}

// ingress applies the NAT's rules to a packet arriving from outside:
// one addressed to the gateway's mapping band is reverse-translated to the
// inside socket of the mapping its port spells, when the behavior admits
// its source, and dropped otherwise; one addressed to an inside host
// directly is dropped, for every crossing is named for the gateway. A
// packet from an inside host is not the NAT's to admit, nor is one from
// the gateway itself, the router's own, or one to the gateway beyond the
// band.
func (b *NAT) ingress(pkt []byte) ([]byte, bool) {
	ip := header.IPv4(pkt)
	src := toNetip(ip.SourceAddress())
	dst := toNetip(ip.DestinationAddress())
	if b.inside[src] || src == b.gateway {
		return nil, false
	}
	if b.inside[dst] {
		// The neighbors' traffic rides the links, whose locators the
		// observations spell.
		return nil, true
	}
	if dst != b.gateway || ip.TransportProtocol() != header.UDPProtocolNumber ||
		len(pkt) < int(ip.HeaderLength())+header.UDPMinimumSize ||
		!inMappingBand(udpOf(pkt).DestinationPort()) {
		return nil, false
	}
	udp := udpOf(pkt)
	m := b.admit(udp.DestinationPort(), netip.AddrPortFrom(src, udp.SourcePort()))
	if m == nil {
		return nil, true
	}
	return rewriteDatagram(pkt, src, udp.SourcePort(), m.key.sock.Addr(), m.key.sock.Port()), true
}

// udpOf reads the packet's UDP header, for a packet already known UDP.
func udpOf(pkt []byte) header.UDP {
	return header.UDP(pkt[header.IPv4(pkt).HeaderLength():])
}

// mappingFor returns the gateway port of the mapping the behavior keys the
// socket's packet to the destination by, drawing one where none stands:
// one per socket under endpoint-independent mapping, one per socket and
// destination under endpoint-dependent mapping. The crossing records the
// destination for the filtering and refreshes the mapping's idle window on
// the fabric's clock.
func (b *NAT) mappingFor(sock, dst netip.AddrPort) uint16 {
	now := b.f.clock.Now()
	key := flow{sock: sock}
	if b.behavior.AddressPortDependentMapping {
		key.dst = dst
	}
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.retireIdleLocked(now)
	if port, ok := b.byFlow[key]; ok {
		m := b.mappings[port]
		m.used = now
		m.sent[dst] = true
		return port
	}
	for {
		b.draws++
		port := uint16(mappingPortBase + b.draws%mappingPortSpan)
		if _, ok := b.mappings[port]; !ok {
			b.byFlow[key] = port
			b.mappings[port] = &mapping{
				key:  key,
				sent: map[netip.AddrPort]bool{dst: true},
				used: now,
			}
			return port
		}
	}
}

// admit returns the mapping a drawn gateway port spells when the behavior
// admits the source to it, refreshed by the packet that reached it, or nil
// where none stands or the filtering refuses the source.
func (b *NAT) admit(port uint16, src netip.AddrPort) *mapping {
	now := b.f.clock.Now()
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.retireIdleLocked(now)
	m, ok := b.mappings[port]
	if !ok || b.behavior.AddressPortDependentFiltering && !m.sent[src] {
		return nil
	}
	m.used = now
	return m
}

// retireIdleLocked drops the mappings whose idle window elapsed; they
// return as fresh draws, never the same port twice.
func (b *NAT) retireIdleLocked(now time.Time) {
	for port, m := range b.mappings {
		if now.Sub(m.used) < MappingTimeout {
			continue
		}
		delete(b.mappings, port)
		delete(b.byFlow, m.key)
	}
}

// Rebind retires every mapping at once: the next inside packet draws a
// fresh one, the changed mapping a restart's proof needs.
func (b *NAT) Rebind() {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	clear(b.mappings)
	clear(b.byFlow)
}

// Mappings returns the inside sockets of the mappings that stand, in draw
// order — the idle window retiring the ones past it. A socket appears once
// per mapping it holds.
func (b *NAT) Mappings() []netip.AddrPort {
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
		socks[i] = b.mappings[port].key.sock
	}
	return socks
}

// MappingPort reports whether an address's port lies in the NAT's
// drawn mapping band.
func MappingPort(ap netip.AddrPort) bool {
	return inMappingBand(ap.Port())
}

// inMappingBand reports whether the port lies in the mapping band.
func inMappingBand(port uint16) bool {
	return port >= mappingPortBase && port < mappingPortBase+mappingPortSpan
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
