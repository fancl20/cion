package wireguard

import (
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// route is one destination entry: packets for destinations matched by the
// prefix go to the device on its pipe.
type route struct {
	prefix netip.Prefix
	dst    *pipe
}

// Router is the overlay routing surface the application lends a resident
// service application: Route carries a plaintext packet the service produced
// toward its overlay destination, and Deliver installs one address the
// service serves on — the router handing packets addressed to it to the
// delivery — for as long as the returned function stands uncalled. The SOCKS
// application (ADR-0012) is the shape's first borrower, the way the
// coordination application borrows the store.
type Router interface {
	// Route sends one plaintext packet the service produced — a reply or a
	// relay — on by its destination, dropping it when it exceeds the overlay
	// MTU or nothing claims the destination. It never takes a default.
	Route(pkt []byte)
	// Deliver hands packets addressed to addr to deliver; the returned
	// function uninstalls the delivery, the address counting unroutable
	// again once it runs. The delivery is address-exact, never a covering
	// prefix.
	Deliver(addr netip.Addr, deliver func(pkt []byte)) func()
}

// router moves plaintext packets between the devices' pipes by destination:
// each owned host's /32 to the host device, each installed service's address
// to its delivery, each directory peer's slice to its mesh device — longest
// prefix first — and no default anywhere: a destination no slice claims
// counts unroutable, and internet egress is a service on the overlay the
// egress record decides, never a property of the routing (ADR-0011). The
// router also enforces the overlay MTU, since no kernel TUN exists to do it.
type router struct {
	mtu int
	cnt *counters

	mtx sync.RWMutex
	// hosts maps each owned host's address to the host device's pipe.
	hosts map[netip.Addr]*pipe
	// local maps each served address to its delivery — a resident service
	// application's inbound path, installed and uninstalled with the
	// application.
	local map[netip.Addr]func(pkt []byte)
	// nets holds one route per mesh device: the peer's overlay slice.
	nets []route
}

func newRouter(mtu int, cnt *counters) *router {
	return &router{
		mtu:   mtu,
		cnt:   cnt,
		hosts: make(map[netip.Addr]*pipe),
		local: make(map[netip.Addr]func(pkt []byte)),
	}
}

// rebuild recomposes the table from the devices it is handed: the host
// device with its owned hosts, and the mesh devices with their slices.
// Routes appear and disappear in process state, with nothing in the
// operating system to keep matched. The installed deliveries stand apart:
// they belong to the applications that borrowed the router, not to the
// directory's devices.
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

// Route routes a packet a resident service produced — a reply or a relay —
// toward its host or mesh destination. It never takes a default: replies
// name overlay destinations or are dropped.
func (r *router) Route(pkt []byte) {
	r.route(pkt)
}

// Deliver installs one served address's delivery, the shape Router names.
func (r *router) Deliver(addr netip.Addr, deliver func(pkt []byte)) func() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.local[addr] = deliver
	return func() {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		delete(r.local, addr)
	}
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
	if deliver, ok := r.local[dst]; ok {
		deliver(pkt)
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

// addressToNetip converts a netstack address.
func addressToNetip(a tcpip.Address) netip.Addr {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}
