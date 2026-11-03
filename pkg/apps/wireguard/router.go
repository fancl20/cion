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
// toward its overlay destination, Deliver installs one address the service
// serves on — the router handing packets addressed to it to the delivery —
// and DeliverDefault installs the delivery of the hosts' packets for the
// internet, each for as long as the returned function stands uncalled. The
// egress application borrows it, the way the coordination application
// borrows the store.
type Router interface {
	// Route sends one plaintext packet the service produced — a reply or a
	// relay — on by its destination: into the host device for any directory
	// host, whose peer table picks the session, and otherwise the way a
	// forwarded packet goes, dropping it when it exceeds the overlay MTU or
	// nothing claims the destination. It never takes the default.
	Route(pkt []byte)
	// Deliver hands packets addressed to addr to deliver; the returned
	// function uninstalls the delivery, the address counting unroutable
	// again once it runs. The delivery is address-exact, never a covering
	// prefix.
	Deliver(addr netip.Addr, deliver func(pkt []byte)) func()
	// DeliverDefault hands the packets the host device decrypted for
	// destinations outside the tailnet to deliver; the returned function
	// uninstalls the delivery, those destinations counting unroutable again
	// once it runs. A mesh device's packets never take it.
	DeliverDefault(deliver func(pkt []byte)) func()
}

// router moves plaintext packets between the devices' pipes by destination
// and by arrival: each owned host's /32 to the host device, each installed
// service's address to its delivery, each directory peer's slice to its mesh
// device — longest prefix first. A destination outside the tailnet that the
// host device decrypted goes to the default delivery; one a mesh device
// decrypted, or a tailnet destination nothing claims, counts unroutable. A
// packet the node's own services produce enters the host device for any
// directory host. The router also enforces the overlay MTU, since no kernel
// TUN exists to do it.
type router struct {
	mtu int
	cnt *counters

	mtx sync.RWMutex
	// hostPipe is the host device's pipe.
	hostPipe *pipe
	// hosts maps every directory host's address to whether the node owns
	// it.
	hosts map[netip.Addr]bool
	// local maps each served address to its delivery — a resident service
	// application's inbound path, installed and uninstalled with the
	// application.
	local map[netip.Addr]func(pkt []byte)
	// fallback is the default delivery; nil while none stands.
	fallback func(pkt []byte)
	// nets holds one route per mesh device: the peer's overlay slice.
	nets []route
}

func newRouter(mtu int, cnt *counters) *router {
	return &router{
		mtu:   mtu,
		cnt:   cnt,
		hosts: make(map[netip.Addr]bool),
		local: make(map[netip.Addr]func(pkt []byte)),
	}
}

// rebuild recomposes the table from the devices it is handed: the host
// device with every directory host, and the mesh devices with their slices.
// Routes appear and disappear in process state, with nothing in the
// operating system to keep matched. The installed deliveries stand apart:
// they belong to the applications that borrowed the router, not to the
// directory's devices.
func (r *router) rebuild(hostPipe *pipe, hosts []hostRoute, nets []route) {
	served := make(map[netip.Addr]bool, len(hosts))
	for _, h := range hosts {
		served[h.addr] = h.owned
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.hostPipe = hostPipe
	r.hosts = served
	r.nets = nets
}

// hostRoute is one directory host the host device holds: its tailnet
// address, and whether the node owns it.
type hostRoute struct {
	addr  netip.Addr
	owned bool
}

// Route routes a packet a resident service produced — a reply or a relay —
// toward its destination: a directory host's address enters the host
// device, whose peer table picks the session, and every other destination
// routes the way a forwarded packet's does. It never takes the default:
// replies name overlay destinations or are dropped.
func (r *router) Route(pkt []byte) {
	if !r.admit(pkt) {
		return
	}
	dst := addressToNetip(header.IPv4(pkt).DestinationAddress())
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if _, ok := r.hosts[dst]; ok {
		r.hostPipe.deliver(pkt)
		return
	}
	r.forwardLocked(pkt, dst)
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

// DeliverDefault installs the default delivery, the shape Router names.
func (r *router) DeliverDefault(deliver func(pkt []byte)) func() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.fallback = deliver
	return func() {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		r.fallback = nil
	}
}

// routeFromHost routes one plaintext packet the host device decrypted: a
// destination outside the tailnet goes to the default delivery — counting
// unroutable while none stands — and every other destination routes the way
// a forwarded packet's does.
func (r *router) routeFromHost(pkt []byte) {
	if !r.admit(pkt) {
		return
	}
	dst := addressToNetip(header.IPv4(pkt).DestinationAddress())
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if Tailnet.Contains(dst) {
		r.forwardLocked(pkt, dst)
		return
	}
	if r.fallback == nil {
		r.cnt.unroutablePackets.Add(1)
		return
	}
	r.fallback(pkt)
}

// route sends one plaintext packet a mesh device decrypted on by its
// destination, dropping it when it exceeds the overlay MTU or nothing claims
// it.
func (r *router) route(pkt []byte) {
	if !r.admit(pkt) {
		return
	}
	dst := addressToNetip(header.IPv4(pkt).DestinationAddress())
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	r.forwardLocked(pkt, dst)
}

// admit reports whether the packet fits the overlay MTU and carries the IPv4
// header the router reads, counting a drop when it does not.
func (r *router) admit(pkt []byte) bool {
	if len(pkt) > r.mtu || len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		r.cnt.droppedPackets.Add(1)
		return false
	}
	return true
}

// forwardLocked sends a packet on by its destination: an owned host's /32 to
// the host device, a served address to its delivery, a mesh slice to its
// device — longest prefix first — and anything else counts unroutable. The
// caller holds the read lock.
func (r *router) forwardLocked(pkt []byte, dst netip.Addr) {
	if r.hosts[dst] {
		r.hostPipe.deliver(pkt)
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
		panic("netstack address is no IP address")
	}
	return ip.Unmap()
}
