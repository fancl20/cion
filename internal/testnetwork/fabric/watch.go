package fabric

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// watch is one drawn observation: the address it watches, and the hosts
// whose UDP datagrams the fabric delivered there.
type watch struct {
	dst   netip.AddrPort
	heard map[netip.Addr]bool
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

// recordLocked notes the packet in the watches on the address it is
// delivered to; the caller holds the fabric's lock.
func (f *Fabric) recordLocked(dst netip.Addr, pkt []byte) {
	ip := header.IPv4(pkt)
	if len(f.watches) == 0 || ip.TransportProtocol() != header.UDPProtocolNumber ||
		len(pkt) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return
	}
	to := netip.AddrPortFrom(dst, udpOf(pkt).DestinationPort())
	src := toNetip(ip.SourceAddress())
	for _, w := range f.watches {
		if w.dst == to {
			w.heard[src] = true
		}
	}
}
