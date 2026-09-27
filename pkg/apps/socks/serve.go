package socks

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	netipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// serve speaks one accepted connection's conversation: method none is
// offered and the rest refused, then the one request the client sends
// decides the command. The connection passes to whichever handler serves
// it — the flow's splice or the association — and the paths that keep
// nothing close it.
func (a *App) serve(conn net.Conn) {
	if err := negotiate(conn); err != nil {
		_ = conn.Close()
		return
	}
	cmd, dst, err := readRequest(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	switch cmd {
	case cmdConnect:
		a.connect(conn, dst)
	case cmdAssociate:
		a.associate(conn, dst)
	default:
		// BIND and anything unnamed: told, not implied.
		_, _ = conn.Write(reply(repCommandNotSupported, netip.Addr{}, 0))
		_ = conn.Close()
	}
}

// connect serves CONNECT — the old handleTCP told from the other end: one
// accepted leg spliced to one outbound connection dialed from the node's
// own sockets under the standing dial timeout, each direction a copy with
// half-close propagation, the flow entering the TCP table, counting against
// the bound, and swept by the idle sweep. A refusal is told, not implied:
// the client learns the cause on its own leg.
func (a *App) connect(conn net.Conn, dst destination) {
	a.mtx.Lock()
	full := a.atCapacityLocked()
	a.mtx.Unlock()
	if full {
		a.cnt.droppedPackets.Add(1)
		_, _ = conn.Write(reply(repGeneralFailure, netip.Addr{}, 0))
		_ = conn.Close()
		return
	}
	out, err := a.dialer.DialContext(context.Background(), "tcp", dst.dialAddr())
	if err != nil {
		a.cnt.droppedPackets.Add(1)
		slog.Warn("SOCKS dialing the internet leg", "dst", dst.String(), "err", err)
		_, _ = conn.Write(reply(repOfDial(err), netip.Addr{}, 0))
		_ = conn.Close()
		return
	}
	flow := &tcpFlow{in: conn, out: out}
	flow.last.Store(time.Now().UnixNano())
	a.mtx.Lock()
	a.tcpFlows[flow] = struct{}{}
	a.mtx.Unlock()
	if _, err := conn.Write(reply(repSucceeded, netip.Addr{}, 0)); err != nil {
		a.removeTCPFlow(flow)
		return
	}
	go func() {
		defer a.removeTCPFlow(flow)
		spliceConns(flow.in, flow.out, &flow.last)
	}()
}

// associate serves UDP ASSOCIATE: the reply names the exit's true tailnet
// address and the relay endpoint's port — a bound UDP socket on the
// netstack at the node's own address, an ephemeral port the bind allocates
// — and the association's lifetime is its TCP connection: the leg's close
// sweeps the association's sockets and releases the relay port at once.
// The association itself counts one flow against the bound, TCP and UDP
// together; a refusal is told on the leg.
func (a *App) associate(conn net.Conn, _ destination) {
	relay, err := gonet.DialUDP(a.stack, &tcpip.FullAddress{
		NIC:  a.nicID,
		Addr: netipToAddress(a.own),
		Port: 0,
	}, nil, netipv4.ProtocolNumber)
	if err != nil {
		a.cnt.droppedPackets.Add(1)
		slog.Warn("SOCKS binding the relay endpoint", "err", err)
		_, _ = conn.Write(reply(repGeneralFailure, netip.Addr{}, 0))
		_ = conn.Close()
		return
	}
	port := uint16(relay.LocalAddr().(*net.UDPAddr).Port)
	asc := &association{
		tcp:   conn,
		relay: relay,
		out:   make(map[netip.AddrPort]*udpLeg),
	}
	asc.last.Store(time.Now().UnixNano())
	a.mtx.Lock()
	if a.atCapacityLocked() {
		a.mtx.Unlock()
		a.cnt.droppedPackets.Add(1)
		_ = relay.Close()
		_, _ = conn.Write(reply(repGeneralFailure, netip.Addr{}, 0))
		_ = conn.Close()
		return
	}
	a.assocs[asc] = struct{}{}
	a.mtx.Unlock()
	if _, err := conn.Write(reply(repSucceeded, a.own, port)); err != nil {
		a.teardown(asc)
		return
	}
	go a.watchLeg(asc)
	go a.serveRelay(asc)
}

// watchLeg waits out the association's TCP connection: its end — the
// client's close, a reset, an error — sweeps the association whole.
func (a *App) watchLeg(asc *association) {
	buf := make([]byte, 512)
	for {
		if _, err := asc.tcp.Read(buf); err != nil {
			a.teardown(asc)
			return
		}
		// Nothing rides the leg once the association stands; whatever
		// arrives is discarded.
	}
}

// serveRelay serves the association's relay endpoint until it closes. Each
// datagram the client sends names its destination, and the reply path
// answers the association peer's arrival address — the source the client's
// datagrams arrived from, never the address its TCP request named.
func (a *App) serveRelay(asc *association) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := asc.relay.ReadFrom(buf)
		if err != nil {
			return
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok || udp.IP == nil {
			continue
		}
		peer, _ := netip.AddrFromSlice(udp.IP)
		a.datagram(asc, netip.AddrPortFrom(peer.Unmap(), uint16(udp.Port)), buf[:n])
	}
}

// datagram relays one client datagram: fragmented and malformed ones are
// refused — dropped, the UDP leg having no error channel — and each
// destination the client names gets one outbound socket of the node's own,
// the socket itself the reply mapping, one flow against the bound, swept by
// idle and by the association's teardown alike.
func (a *App) datagram(asc *association, from netip.AddrPort, data []byte) {
	dstDest, payload, ok := parseDatagram(data)
	if !ok {
		a.cnt.droppedPackets.Add(1)
		return
	}
	dst, err := dstDest.resolve()
	if err != nil {
		a.cnt.droppedPackets.Add(1)
		return
	}
	now := time.Now().UnixNano()
	a.mtx.Lock()
	if _, live := a.assocs[asc]; !live {
		a.mtx.Unlock()
		return
	}
	leg, ok := asc.out[dst]
	if !ok {
		if a.atCapacityLocked() {
			a.mtx.Unlock()
			a.cnt.droppedPackets.Add(1)
			return
		}
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			a.mtx.Unlock()
			slog.Warn("SOCKS binding the UDP leg", "dst", dst, "err", err)
			return
		}
		leg = &udpLeg{assoc: asc, dst: dst, conn: conn}
		leg.last.Store(now)
		asc.out[dst] = leg
		a.udpLegs[leg] = struct{}{}
		go a.pumpLeg(leg)
	}
	asc.peer = from
	asc.last.Store(now)
	leg.last.Store(now)
	conn := leg.conn
	a.mtx.Unlock()
	if _, err := conn.WriteToUDPAddrPort(payload, dst); err != nil {
		a.removeLeg(leg)
	}
}

// pumpLeg relays one destination's replies: each returns through the
// association's relay with the SOCKS header rewritten — the source the
// destination it came from — to the association peer's arrival address.
func (a *App) pumpLeg(leg *udpLeg) {
	defer a.removeLeg(leg)
	buf := make([]byte, 64<<10)
	for {
		n, from, err := leg.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		a.mtx.Lock()
		_, live := a.assocs[leg.assoc]
		relay := leg.assoc.relay
		peer := leg.assoc.peer
		now := time.Now().UnixNano()
		leg.assoc.last.Store(now)
		leg.last.Store(now)
		a.mtx.Unlock()
		if !live {
			return
		}
		if _, err := relay.WriteTo(
			appendDatagram(nil, from, buf[:n]), net.UDPAddrFromAddrPort(peer)); err != nil {
			return
		}
	}
}
