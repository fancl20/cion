package egress

import (
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// icmpSocket is the datagram ICMP socket the echo relay rides.
type icmpSocket interface {
	WriteTo(b []byte, dst netip.Addr) error
	ReadFrom(b []byte) (int, netip.Addr, error)
	Close() error
}

// osICMPSocket is the unprivileged ping socket.
type osICMPSocket struct {
	conn *icmp.PacketConn
}

// openICMPSocket opens the unprivileged ping socket, which the system offers
// only to the groups its ping group range names.
func openICMPSocket() (icmpSocket, error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &osICMPSocket{conn: conn}, nil
}

func (s *osICMPSocket) WriteTo(b []byte, dst netip.Addr) error {
	_, err := s.conn.WriteTo(b, &net.UDPAddr{IP: dst.AsSlice()})
	return err
}

func (s *osICMPSocket) ReadFrom(b []byte) (int, netip.Addr, error) {
	n, from, err := s.conn.ReadFrom(b)
	if err != nil {
		return 0, netip.Addr{}, err
	}
	udp, ok := from.(*net.UDPAddr)
	if !ok {
		return 0, netip.Addr{}, net.InvalidAddrError(from.String())
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return 0, netip.Addr{}, net.InvalidAddrError(from.String())
	}
	return n, ip.Unmap(), nil
}

func (s *osICMPSocket) Close() error { return s.conn.Close() }

// echoFlow is one echo request in flight: where its reply returns.
type echoFlow struct {
	// host is the host that sent the request, and dst the destination it
	// pinged, the one source its reply comes from.
	host, dst netip.Addr
	// id and seq are the host's own identifier and sequence, restored on
	// the reply.
	id, seq uint16
	// sent is when the request left, which the echo timeout counts from.
	sent time.Time
}

// relayEcho relays one echo request a host sent toward the internet: it
// leaves the node's own ICMP socket under a relay sequence, which the reply
// is demultiplexed by — the system rewrites the identifier to the socket's
// own — and its mapping waits for the reply under the echo bound and the
// echo timeout. Other ICMP, a fragment, a malformed packet, a request past
// the echo bound, and every request where the system offers no ping socket
// drop and count.
func (a *App) relayEcho(pkt []byte) {
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.More() || ip.FragmentOffset() != 0 ||
		len(ip.Payload()) < header.ICMPv4MinimumSize {

		a.cnt.droppedPackets.Add(1)
		return
	}
	request := header.ICMPv4(ip.Payload())
	if request.Type() != header.ICMPv4Echo {
		a.cnt.droppedPackets.Add(1)
		return
	}
	dst := addressToNetip(ip.DestinationAddress())
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.stopped || a.echoSocket == nil || len(a.echoes) >= a.echoBound {
		a.cnt.droppedPackets.Add(1)
		return
	}
	seq := a.echoSeq
	a.echoSeq++
	relay := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(request.Payload())))
	relay.SetType(header.ICMPv4Echo)
	relay.SetSequence(seq)
	copy(relay.Payload(), request.Payload())
	if err := a.echoSocket.WriteTo(relay, dst); err != nil {
		a.cnt.droppedPackets.Add(1)
		slog.Debug("Egress relaying an echo request", "dst", dst, "err", err)
		return
	}
	a.echoes[seq] = echoFlow{
		host: addressToNetip(ip.SourceAddress()),
		dst:  dst,
		id:   request.Ident(),
		seq:  request.Sequence(),
		sent: time.Now(),
	}
}

// relayEchoReplies takes the echo replies the internet returns on the
// socket until it closes, each rewritten to the request its relay sequence
// names and routed to the request's host. A reply no mapping names, or one
// from another source than the request's destination, is dropped.
func (a *App) relayEchoReplies(socket icmpSocket) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := socket.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < header.ICMPv4MinimumSize {
			continue
		}
		reply := header.ICMPv4(buf[:n])
		if reply.Type() != header.ICMPv4EchoReply {
			continue
		}
		a.mtx.Lock()
		flow, ok := a.echoes[reply.Sequence()]
		ok = ok && flow.dst == from
		if ok {
			delete(a.echoes, reply.Sequence())
		}
		a.mtx.Unlock()
		if ok {
			a.router.Route(echoReplyPacket(flow, reply.Payload()))
		}
	}
}

// echoReplyPacket builds the IPv4 packet returning an echo reply to its
// host: from the destination the host pinged, to the host, under the host's
// own identifier and sequence, with fresh checksums.
func echoReplyPacket(flow echoFlow, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(flow.dst.As4()),
		DstAddr:     tcpip.AddrFrom4(flow.host.As4()),
	})
	ip.SetChecksum(internetChecksum(pkt[:header.IPv4MinimumSize]))
	reply := header.ICMPv4(ip.Payload())
	reply.SetType(header.ICMPv4EchoReply)
	reply.SetIdent(flow.id)
	reply.SetSequence(flow.seq)
	copy(reply.Payload(), payload)
	reply.SetChecksum(internetChecksum(reply))
	return pkt
}

// internetChecksum is the ones-complement checksum IPv4 and ICMP carry.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
