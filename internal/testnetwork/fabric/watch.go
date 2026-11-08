package fabric

import (
	"maps"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// watch is one drawn observation: the address it watches, and the hosts
// whose UDP datagrams the fabric delivered there.
type watch struct {
	dst   netip.AddrPort
	heard map[netip.Addr]bool
}

// tally is one drawn count: the port it counts at, and the UDP datagrams
// the fabric delivered there, by their source and destination hosts.
type tally struct {
	port  uint16
	count map[[2]netip.Addr]int
}

// Watch records the hosts whose UDP datagrams the fabric delivers to the
// address from now on, as the destination receives them, after every NAT
// between; the returned heard reports whether one from the host has
// arrived. The watch holds for the fabric's life.
func (f *Fabric) Watch(dst netip.AddrPort) (heard func(src netip.Addr) bool) {
	w := &watch{dst: dst, heard: make(map[netip.Addr]bool)}
	f.mtx.Lock()
	f.watches = append(f.watches, w)
	f.mtx.Unlock()
	return func(src netip.Addr) bool {
		f.mtx.Lock()
		defer f.mtx.Unlock()
		return w.heard[src]
	}
}

// Tally counts the UDP datagrams the fabric delivers to the port on any
// host from now on, as the destinations receive them, after every NAT
// between, by their source and destination hosts; the returned counts
// reports the tally so far. The tally holds for the fabric's life.
func (f *Fabric) Tally(port uint16) (counts func() map[[2]netip.Addr]int) {
	t := &tally{port: port, count: make(map[[2]netip.Addr]int)}
	f.mtx.Lock()
	f.tallies = append(f.tallies, t)
	f.mtx.Unlock()
	return func() map[[2]netip.Addr]int {
		f.mtx.Lock()
		defer f.mtx.Unlock()
		return maps.Clone(t.count)
	}
}

// recordLocked notes the packet in the watches on the address it is
// delivered to and in the tallies on its port; the caller holds the
// fabric's lock.
func (f *Fabric) recordLocked(dst netip.Addr, pkt []byte) {
	ip := header.IPv4(pkt)
	if len(f.watches) == 0 && len(f.tallies) == 0 || ip.TransportProtocol() != header.UDPProtocolNumber ||
		len(pkt) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return
	}
	port := udpOf(pkt).DestinationPort()
	to := netip.AddrPortFrom(dst, port)
	src := toNetip(ip.SourceAddress())
	for _, w := range f.watches {
		if w.dst == to {
			w.heard[src] = true
		}
	}
	for _, t := range f.tallies {
		if t.port == port {
			t.count[[2]netip.Addr{src, dst}]++
		}
	}
}
