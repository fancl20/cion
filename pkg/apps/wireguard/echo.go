package wireguard

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// echoRelay relays echo ICMP per identifier: each host's request is
// re-sent from the exit's own ICMP socket with a relay sequence number the
// reply demultiplexes by, and the reply is rewritten back to the host's
// identifier. Other ICMP is best-effort toward the flow it names; other IP
// protocols are dropped before this. An operating system without unprivileged
// ping sockets degrades the relay to dropping.
type echoRelay struct {
	cnt    *counters
	socket icmpSocket
	idle   time.Duration

	mtx sync.Mutex
	// pending maps each relay sequence number to the host flow it serves.
	pending map[uint16]echoFlow
	// nextSeq hands out relay sequence numbers.
	nextSeq uint16
	// degraded marks a socket that failed; requests drop without a log
	// storm until the next one tries again.
	degraded bool
}

// echoFlow is one host's echoed flow: where the rewritten reply returns.
type echoFlow struct {
	host netip.Addr
	// id is the host's original identifier, restored on the reply.
	id uint16
	// seq is the host's original sequence number, restored on the reply.
	seq uint16
	// last is the flow's latest activity, for idle expiry.
	last time.Time
}

// icmpSocket is the datagram ICMP the relay rides.
type icmpSocket interface {
	WriteTo(b []byte, dst netip.Addr) error
	ReadFrom(b []byte) (int, netip.Addr, error)
	Close() error
}

// osICMPSocket is the unprivileged ping socket.
type osICMPSocket struct {
	conn *icmp.PacketConn
}

func newOSICMPSocket() (*osICMPSocket, error) {
	conn, err := icmp.ListenPacket("udp4", ":0")
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
	if !ok || udp.IP == nil {
		return 0, netip.Addr{}, net.InvalidAddrError(from.String())
	}
	ip, _ := netip.AddrFromSlice(udp.IP)
	return n, ip.Unmap(), nil
}

func (s *osICMPSocket) Close() error { return s.conn.Close() }

func newEchoRelay(cnt *counters, socket icmpSocket, idle time.Duration) *echoRelay {
	if idle == 0 {
		idle = egressIdle
	}
	r := &echoRelay{cnt: cnt, pending: make(map[uint16]echoFlow), idle: idle}
	if socket == nil {
		if os, err := newOSICMPSocket(); err == nil {
			socket = os
		} else {
			// No unprivileged ping sockets: the relay degrades to
			// dropping, best-effort as the milestone scopes ICMP.
			slog.Warn("No unprivileged ICMP socket; echo relay disabled", "err", err)
			socket = droppedICMP{}
		}
	}
	r.socket = socket
	return r
}

// droppedICMPSocket absorbs requests a host operating system cannot carry.
type droppedICMP struct{}

func (droppedICMP) WriteTo([]byte, netip.Addr) error         { return net.ErrClosed }
func (droppedICMP) ReadFrom([]byte) (int, netip.Addr, error) { return 0, netip.Addr{}, net.ErrClosed }
func (droppedICMP) Close() error                             { return nil }

// request relays one echo request packet from a host.
func (r *echoRelay) request(pkt []byte, reply func([]byte)) {
	ipHdr := header.IPv4(pkt)
	if len(pkt) < header.IPv4MinimumSize+header.ICMPv4MinimumSize ||
		ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber {
		r.cnt.egressDroppedPackets.Add(1)
		return
	}
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	if icmpHdr.Type() != header.ICMPv4Echo {
		// Other ICMP toward the internet is best-effort; nothing names a
		// flow to it, so it drops.
		r.cnt.egressDroppedPackets.Add(1)
		return
	}
	host := addressToNetip(ipHdr.SourceAddress())
	dst := addressToNetip(ipHdr.DestinationAddress())

	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.degraded || len(r.pending) >= maxEgressFlows {
		r.cnt.egressDroppedPackets.Add(1)
		return
	}
	relaySeq := r.nextSeq
	r.nextSeq++
	// The unprivileged ping socket's kernel rewrites the identifier to the
	// socket's own; the relay sequence number is the demultiplexer.
	req := make([]byte, header.ICMPv4MinimumSize+len(icmpHdr.Payload()))
	req[0] = byte(header.ICMPv4Echo)
	binary.BigEndian.PutUint16(req[4:], relaySeq)
	copy(req[header.ICMPv4MinimumSize:], icmpHdr.Payload())
	if err := r.socket.WriteTo(req, dst); err != nil {
		r.degraded = true
		r.cnt.egressDroppedPackets.Add(1)
		slog.Warn("Echo relay send failed; degrading", "dst", dst, "err", err)
		return
	}
	r.pending[relaySeq] = echoFlow{
		host: host,
		id:   icmpHdr.Ident(),
		seq:  icmpHdr.Sequence(),
		last: time.Now(),
	}
}

// readLoop takes the echo replies the internet returns and rewrites each to
// the host flow that requested it.
func (r *echoRelay) readLoop(reply func([]byte)) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := r.socket.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < header.ICMPv4MinimumSize {
			continue
		}
		icmpHdr := header.ICMPv4(buf[:n])
		if icmpHdr.Type() != header.ICMPv4EchoReply {
			continue
		}
		r.mtx.Lock()
		flow, ok := r.pending[icmpHdr.Sequence()]
		if ok {
			delete(r.pending, icmpHdr.Sequence())
		}
		r.mtx.Unlock()
		if !ok {
			continue
		}
		if reply == nil {
			continue
		}
		reply(echoReplyPacket(from, flow, icmpHdr.Payload()))
	}
}

// expire drops mappings silent past the idle bound.
func (r *echoRelay) expire(now time.Time) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	for seq, flow := range r.pending {
		if now.Sub(flow.last) > r.idle {
			delete(r.pending, seq)
		}
	}
}

func (r *echoRelay) len() int {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	return len(r.pending)
}

func (r *echoRelay) close() {
	_ = r.socket.Close()
}

// echoReplyPacket builds the IPv4 packet returning an echoed reply to its
// host: from the internet destination the host named, to the host, with the
// host's own identifier and sequence restored.
func echoReplyPacket(from netip.Addr, flow echoFlow, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     netipToAddress(from),
		DstAddr:     netipToAddress(flow.host),
	})
	ipHdr.SetChecksum(internetChecksum(pkt[:header.IPv4MinimumSize]))

	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetIdent(flow.id)
	icmpHdr.SetSequence(flow.seq)
	copy(icmpHdr.Payload(), payload)
	// The relay's socket verified the reply's checksum; the rewritten header
	// carries a fresh one.
	icmpHdr.SetChecksum(internetChecksum(ipHdr.Payload()))
	return pkt
}

// netipToAddress converts an overlay or internet address for a netstack
// header.
func netipToAddress(ip netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(ip.AsSlice())
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
