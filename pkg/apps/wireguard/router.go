package wireguard

import (
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// route is one destination entry: packets for destinations matched by the
// prefix go to the device on its pipe.
type route struct {
	prefix netip.Prefix
	dst    *pipe
}

// router moves plaintext packets between the devices' pipes by destination:
// each owned host's /32 to the host device, each directory peer's slice to
// its mesh device — longest prefix first — and no default anywhere: a
// destination no slice claims counts unroutable, and internet egress is a
// service on the overlay the egress record decides, never a property of the
// routing (ADR-0011). The router also enforces the overlay MTU, since no
// kernel TUN exists to do it.
type router struct {
	mtu int
	cnt *counters

	mtx sync.RWMutex
	// hosts maps each owned host's address to the host device's pipe.
	hosts map[netip.Addr]*pipe
	// nets holds one route per mesh device: the peer's overlay slice.
	nets []route
}

func newRouter(mtu int, cnt *counters) *router {
	return &router{
		mtu:   mtu,
		cnt:   cnt,
		hosts: make(map[netip.Addr]*pipe),
	}
}

// rebuild recomposes the table from the devices it is handed: the host
// device with its owned hosts, and the mesh devices with their slices.
// Routes appear and disappear in process state, with nothing in the
// operating system to keep matched.
func (r *router) rebuild(hosts []hostRoute, nets []route) {
	hostMap := make(map[netip.Addr]*pipe, len(hosts))
	for _, h := range hosts {
		hostMap[h.addr] = h.pipe
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.hosts = hostMap
	r.nets = nets
}

// hostRoute is one owned host: its tailnet address and the host device's
// pipe.
type hostRoute struct {
	addr netip.Addr
	pipe *pipe
}

// routeFromEgress routes a packet the egress produced — a reply or a relay —
// toward its host or mesh destination. It never takes a default: replies
// name overlay destinations or are dropped.
func (r *router) routeFromEgress(pkt []byte) {
	r.route(pkt)
}

// route sends one plaintext packet on by its destination, dropping it when it
// exceeds the overlay MTU or nothing claims it.
func (r *router) route(pkt []byte) {
	if len(pkt) > r.mtu {
		r.cnt.droppedPackets.Add(1)
		return
	}
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		r.cnt.droppedPackets.Add(1)
		return
	}
	dst := addressToNetip(header.IPv4(pkt).DestinationAddress())

	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if p, ok := r.hosts[dst]; ok {
		p.deliver(pkt)
		return
	}
	var best *route
	for i := range r.nets {
		rt := &r.nets[i]
		if !rt.prefix.Contains(dst) {
			continue
		}
		if best == nil || rt.prefix.Bits() > best.prefix.Bits() {
			best = rt
		}
	}
	if best != nil {
		best.dst.deliver(pkt)
		return
	}
	r.cnt.unroutablePackets.Add(1)
}
