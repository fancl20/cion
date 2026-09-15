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
// each host peer's /32 to its host device, each directory peer's subnet to
// its mesh device — longest prefix first, so remote overlay subnets win over
// any default — and everything else to the exit whose device decrypted the
// packet: traffic from exit X's host device defaults to X's mesh device, and
// traffic decrypted by a mesh device for no overlay destination has reached
// the exit this node offers and enters the netstack egress. The router also
// enforces the overlay MTU, since no kernel TUN exists to do it.
type router struct {
	mtu int
	cnt *counters
	// egress receives packets no overlay destination claims, when this node
	// runs one; nil drops them.
	egress func(pkt []byte)

	mtx sync.RWMutex
	// hosts maps each host peer's address to its exit device's pipe.
	hosts map[netip.Addr]*pipe
	// nets holds one route per mesh device: the peer's overlay subnet.
	nets []route
	// exits maps each host device's pipe to its exit's mesh pipe. A nil
	// mesh pipe is the local exit: its default enters the egress.
	exits map[*pipe]*pipe
}

func newRouter(mtu int, cnt *counters) *router {
	return &router{
		mtu:   mtu,
		cnt:   cnt,
		hosts: make(map[netip.Addr]*pipe),
		exits: make(map[*pipe]*pipe),
	}
}

// setEgress installs the egress sink default-routed mesh traffic enters.
func (r *router) setEgress(fn func(pkt []byte)) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.egress = fn
}

// rebuild recomposes the table from the devices it is handed: the host
// devices with their peers and exits, and the mesh devices with their
// subnets. Routes appear and disappear in process state, with nothing in the
// operating system to keep matched.
func (r *router) rebuild(hosts []hostRoute, nets []route, exits map[*pipe]*pipe) {
	hostMap := make(map[netip.Addr]*pipe, len(hosts))
	for _, h := range hosts {
		hostMap[h.addr] = h.pipe
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.hosts = hostMap
	r.nets = nets
	r.exits = exits
}

// hostRoute is one configured host peer: its overlay address and its exit
// device's pipe.
type hostRoute struct {
	addr netip.Addr
	pipe *pipe
}

// routeFromEgress routes a packet the egress produced — a reply or a relay —
// toward its host or mesh destination. It never takes a default: replies
// name overlay destinations or are dropped.
func (r *router) routeFromEgress(pkt []byte) {
	r.route(pkt, nil)
}

// routeFrom binds a device pipe into the routing as its packets' source, the
// form the devices' drain loops feed.
func (r *router) routeFrom(p *pipe) func(pkt []byte) {
	return func(pkt []byte) { r.route(pkt, p) }
}

// route sends one plaintext packet on by its destination, dropping it when it
// exceeds the overlay MTU or nothing claims it. A nil from is the egress; a
// host pipe's unclaimed traffic takes its exit's default; a mesh pipe's has
// reached the exit this node offers.
func (r *router) route(pkt []byte, from *pipe) {
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
	switch from {
	case nil:
		// A reply from the egress that names no overlay destination has no
		// route to take.
		r.cnt.unroutablePackets.Add(1)
	default:
		// Exit selection is the router's default: traffic decrypted by a
		// host device flows to its exit's mesh device — the local exit
		// enters the egress — and traffic decrypted by a mesh device has
		// reached the exit this node offers.
		if mesh, ok := r.exits[from]; ok && mesh != nil {
			mesh.deliver(pkt)
			return
		}
		if r.egress != nil {
			r.egress(pkt)
			return
		}
		r.cnt.unroutablePackets.Add(1)
	}
}
