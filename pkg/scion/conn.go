// Package scion is the node's SCION library, the application seam of
// ADR-0005: the socket (Conn) that carries datagrams over SCION paths and
// reverses arrival paths for replies, the address (Addr) naming a peer by
// ISD-AS and underlay address or service, and the path resolver
// (PathProvider) that composes discovered segments into end-to-end paths.
// Applications on a CION node link this package — and nothing else of the
// control plane — to become path-aware.
package scion

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/dataplane"
)

// Addr is the SCION network address of a peer. It doubles as the return
// route: replies leave on the IfID the peer's packet arrived on, or over the
// reversed arrival path when the peer reached us over a full SCION path.
//
// The interface ID and path are deliberately not part of String, so the
// address quic-go sees for a connection stays stable regardless of the
// interface a particular packet traveled on.
type Addr struct {
	// IA is the ISD-AS of the peer.
	IA addr.IA
	// Addr is the peer's underlay address.
	Addr netip.AddrPort
	// Service is the peer's SCION service destination. When non-zero, the
	// peer is named by ISD-AS and service instead of underlay address: the
	// destination is serialized as a service host, and the receiving AS's
	// router delivers to the registered backend — to no port the sender
	// names. Zero on every address a receive path derives, whose sources are
	// ordinary IPs.
	Service addr.SVC
	// IfID is the local egress interface toward the peer; zero means it is
	// resolved from the link table on write.
	IfID uint16
	// Path is the full data-plane path to the peer, supplied by the path
	// provider; nil sends over a one-hop path resolved from the link table.
	// The hop-field MACs come from the segment, computed by each on-path AS
	// at beacon time, not by the sender.
	Path *spath.Decoded
}

func (a *Addr) Network() string { return "scion" }

func (a *Addr) String() string {
	if a.Service != 0 {
		return fmt.Sprintf("%s,svc:%04x", a.IA, uint16(a.Service))
	}
	return fmt.Sprintf("%s,%s", a.IA, a.Addr)
}

// Conn is a net.PacketConn that carries datagrams over the SCION network on
// one-hop paths to directly connected neighbors, and over full paths to any
// peer a resolved Addr names. It implements the interface quic-go requires of
// a connection, so an HTTP/3 server or client rides the SCION data plane
// unchanged, and carries SCMP echo messages beside the UDP datagrams
// (scmp.go).
type Conn struct {
	localIA addr.IA
	// local is the advertised underlay address of the endpoint. Incoming
	// packets addressed to it are delivered here by the router.
	local netip.AddrPort
	// internal is the router's internal link address; raw SCION packets are
	// submitted there for forwarding.
	internal *net.UDPAddr
	// mac MACs the hop fields of outgoing one-hop paths, with the same key
	// the data plane verifies.
	mac hash.Hash
	// links snapshots the external links, interface ID to neighbor IA, to
	// resolve the egress interface of fresh one-hop paths. Read live, so a
	// topology change reaches the conn without rebuilding it.
	links func() map[uint16]addr.IA
	// ifDown is the node's shared negative cache of interface-down signals;
	// nil drops them as before.
	ifDown *InterfaceDownCache

	conn *net.UDPConn

	mtx    sync.Mutex // Guards the MAC hasher and the closed flag.
	closed bool
}

// ConnConfig configures a Conn.
type ConnConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Bind is the underlay "host:port" address to listen on and advertise.
	// Port 0 binds an ephemeral one.
	Bind string
	// InternalAddr is the router's internal underlay address.
	InternalAddr string
	// MACKey is the data-plane forwarding key, used to MAC one-hop paths.
	MACKey []byte
	// Links snapshots the external links, interface ID to neighbor IA; the
	// conn resolves one-hop egress through it live.
	Links func() map[uint16]addr.IA
	// InterfaceDown is the node's shared negative cache of SCMP
	// interface-down signals; the conn's receive paths recognize the signal
	// and record it. Nil drops them.
	InterfaceDown *InterfaceDownCache
}

// NewConn binds the endpoint's underlay address. Packets it sends are
// submitted to the router's internal link; packets the router delivers to
// the bound address are received from it.
func NewConn(cfg ConnConfig) (*Conn, error) {
	local, err := dataplane.ResolveAddrPort(cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("parsing bind address: %w", err)
	}
	internal, err := net.ResolveUDPAddr("udp", cfg.InternalAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing internal address: %w", err)
	}
	if _, err := scrypto.InitMac(cfg.MACKey); err != nil {
		return nil, fmt.Errorf("initializing MAC: %w", err)
	}
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(cfg.MACKey)
		return mac
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("binding endpoint address: %w", err)
	}
	// A zero port is replaced by the bound one, so the advertised address is
	// the one replies can reach.
	bound := conn.LocalAddr().(*net.UDPAddr)
	boundIP, ok := netip.AddrFromSlice(bound.IP)
	if !ok {
		return nil, fmt.Errorf("invalid bound address %v", bound)
	}
	local = netip.AddrPortFrom(boundIP.Unmap(), uint16(bound.Port))
	return &Conn{
		localIA:  cfg.IA,
		local:    local,
		internal: internal,
		mac:      macFactory(),
		links:    cfg.Links,
		ifDown:   cfg.InterfaceDown,
		conn:     conn,
	}, nil
}

// recordInterfaceDown recognizes an interface-down signal in a received
// packet — the drafts' error the library's receive paths once dropped
// silently — and enters it in the shared cache. Reports whether one was
// recognized.
func (c *Conn) recordInterfaceDown(raw []byte) bool {
	if c.ifDown == nil {
		return false
	}
	sig, ok := parseInterfaceDownPacket(raw)
	if !ok {
		return false
	}
	c.ifDown.Record(sig)
	return true
}

// LocalPort returns the bound underlay port. An SCMP echo request sent by
// this connection carries it as the identifier, so the reply is delivered
// back here.
func (c *Conn) LocalPort() uint16 { return c.local.Port() }

// LocalAddr returns the endpoint's SCION address.
func (c *Conn) LocalAddr() net.Addr {
	return &Addr{IA: c.localIA, Addr: c.local}
}

// Close releases the underlay socket.
func (c *Conn) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.closed = true
	return c.conn.Close()
}

// ReadFrom reads the next datagram, returning it with the peer's address.
// Packets that are not SCION/UDP over a one-hop path are dropped silently —
// unless they are the interface-down signal the cache recognizes — the
// drafts' error the library's receive paths once dropped silently.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, dataplane.BufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		payload, from, err := parseDatagramPacket(buf[:n])
		if err != nil {
			c.recordInterfaceDown(buf[:n])
			continue
		}
		if len(payload) > len(b) {
			payload = payload[:len(b)]
		}
		return copy(b, payload), from, nil
	}
}

// WriteTo sends the datagram to the peer as a SCION packet. A peer address
// carrying a path sends over that path — serialized fresh for every packet,
// so the routers' in-flight segment-ID updates never accumulate. A one-hop
// peer address has its path created fresh for every packet instead: the
// egress interface is taken from the address if the peer set one (replies),
// and resolved from the link table otherwise (client traffic). A peer
// address carrying a service names the destination by it: the receiving AS's
// internal link delivers to the registered backend, so no destination port
// is consulted and the wire carries zero.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	peer, ok := addr.(*Addr)
	if !ok || peer == nil {
		return 0, fmt.Errorf("unexpected address type %T", addr)
	}
	dstPort := peer.Addr.Port()
	if peer.Service != 0 {
		dstPort = 0
	}
	raw, err := c.writePacket(peer, slayers.L4UDP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeUDP(scn, c.local.Port(), dstPort, b)
	})
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.WriteToUDP(raw, c.internal); err != nil {
		return 0, err
	}
	return len(b), nil
}

// writePacket serializes a full SCION packet addressing the peer — with
// nextHdr as the layer after the SCION header — through the builder; the
// mutex guards the MAC hasher one-hop paths use.
func (c *Conn) writePacket(
	peer *Addr,
	nextHdr slayers.L4ProtocolType,
	build func(*slayers.SCION) ([]byte, error),
) ([]byte, error) {

	ifID := peer.IfID
	if peer.Path == nil && ifID == 0 {
		var err error
		if ifID, err = c.resolveLink(peer.IA); err != nil {
			return nil, err
		}
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	scn, err := c.scionHeader(peer, ifID, nextHdr)
	if err != nil {
		return nil, err
	}
	return build(scn)
}

// SetDeadline sets the read and write deadlines of the underlay socket.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the underlay socket.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the underlay socket.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// resolveLink reads the link table's snapshot for the neighbor's egress
// interface. A nil source — a conn with no link table — resolves nothing.
func (c *Conn) resolveLink(neighborIA addr.IA) (uint16, error) {
	if c.links != nil {
		for ifID, neighbor := range c.links() {
			if neighbor.Equal(neighborIA) {
				return ifID, nil
			}
		}
	}
	return 0, fmt.Errorf("no link to neighbor %s", neighborIA)
}

// scionHeader returns the SCION layer addressing the peer, over the peer's
// supplied path or over a fresh one-hop path on the given interface. It must
// be called with the mutex held: the one-hop hop-field MAC uses the shared
// hasher.
func (c *Conn) scionHeader(peer *Addr, ifID uint16, nextHdr slayers.L4ProtocolType) (*slayers.SCION, error) {
	scn := &slayers.SCION{
		NextHdr: nextHdr,
		SrcIA:   c.localIA,
		DstIA:   peer.IA,
	}
	if peer.Path != nil {
		scn.PathType = spath.PathType
		scn.Path = peer.Path
	} else {
		segID := make([]byte, 2)
		if _, err := rand.Read(segID); err != nil {
			return nil, err
		}
		info := path.InfoField{
			SegID:     binary.BigEndian.Uint16(segID),
			ConsDir:   true,
			Timestamp: util.TimeToSecs(time.Now()),
		}
		firstHop := path.HopField{ConsIngress: 0, ConsEgress: ifID, ExpTime: 63}
		firstHop.Mac = path.MAC(c.mac, info, firstHop, nil)
		scn.PathType = onehop.PathType
		scn.Path = &onehop.Path{Info: info, FirstHop: firstHop}
	}
	if err := scn.SetSrcAddr(addr.HostIP(c.local.Addr())); err != nil {
		return nil, err
	}
	dstHost := addr.HostIP(peer.Addr.Addr())
	if peer.Service != 0 {
		dstHost = addr.HostSVC(peer.Service)
	}
	if err := scn.SetDstAddr(dstHost); err != nil {
		return nil, err
	}
	return scn, nil
}

// serializeUDP wraps the payload in the SCION/UDP layers after the given
// header.
func serializeUDP(scn *slayers.SCION, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	udp := &slayers.UDP{SrcPort: srcPort, DstPort: dstPort}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, udp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// parseDatagramPacket extracts the datagram and the peer's address from a
// received SCION packet. A one-hop arrival records the interface it arrived
// on, so replies take a fresh one-hop path over that link; a full SCION path
// is reversed for the reply, generalizing the one-hop case.
func parseDatagramPacket(raw []byte) ([]byte, *Addr, error) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		return nil, nil, errors.New("no SCION layer")
	}
	scn := scnL.(*slayers.SCION)
	udpL := pkt.Layer(slayers.LayerTypeSCIONUDP)
	if udpL == nil {
		return nil, nil, errors.New("no UDP layer")
	}
	udp := udpL.(*slayers.UDP)
	from, err := peerAddr(scn)
	if err != nil {
		return nil, nil, err
	}
	from.Addr = netip.AddrPortFrom(from.Addr.Addr(), udp.SrcPort)
	return udp.LayerPayload(), from, nil
}

// peerAddr derives the reply route from a received packet's SCION layer: the
// source's IA and address, and the reversed arrival path.
func peerAddr(scn *slayers.SCION) (*Addr, error) {
	src, err := scn.SrcAddr()
	if err != nil {
		return nil, err
	}
	srcAddr := src.IP()
	if !srcAddr.IsValid() {
		return nil, errors.New("no source IP")
	}
	if scn.SrcIA.IsWildcard() {
		return nil, errors.New("wildcard source IA")
	}
	from := &Addr{IA: scn.SrcIA, Addr: netip.AddrPortFrom(srcAddr, 0)}
	switch p := scn.Path.(type) {
	case *onehop.Path:
		// The router fills the second hop's ingress interface with the link
		// the packet came in on; that is the interface replies leave on.
		from.IfID = p.SecondHop.ConsIngress
	case *spath.Raw:
		// Replies reverse the arrival path. The routers updated the path's
		// segment IDs in flight, so the reversed path starts with the IDs
		// this end's hop MACs verify against. ToDecoded copies the values
		// out of the receive buffer, and Reverse reverses the copy.
		decoded, err := p.ToDecoded()
		if err != nil {
			return nil, err
		}
		reversed, err := decoded.Reverse()
		if err != nil {
			return nil, err
		}
		from.Path = reversed.(*spath.Decoded)
	default:
		return nil, fmt.Errorf("unsupported path type %v", scn.PathType)
	}
	return from, nil
}
