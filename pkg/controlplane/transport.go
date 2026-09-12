// Package controlplane implements CION's control plane: discovery of directly
// connected neighbors, and the control endpoint that serves trust material
// RPCs over HTTP/3 (QUIC) riding the SCION network.
package controlplane

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

	"github.com/fancl20/cion/pkg/dataplane"
)

// EndpointPort is the SCION UDP port of the control endpoint. The port is
// fixed so that a node can reach a neighbor's endpoint knowing only the
// underlay address advertised in the discovery greeting.
const EndpointPort = 30044

// Addr is the SCION network address of a control endpoint. It doubles as the
// return route: replies leave on the IfID the peer's packet arrived on.
//
// The interface ID is deliberately not part of String, so the address quic-go
// sees for a connection stays stable regardless of the interface a
// particular packet traveled on.
type Addr struct {
	// IA is the ISD-AS of the peer.
	IA addr.IA
	// Addr is the peer's underlay address.
	Addr netip.AddrPort
	// IfID is the local egress interface toward the peer; zero means it is
	// resolved from the link table on write.
	IfID uint16
}

func (a *Addr) Network() string { return "scion" }

func (a *Addr) String() string {
	return fmt.Sprintf("%s,%s", a.IA, a.Addr)
}

// SCIONConn is a net.PacketConn that carries datagrams over the SCION
// network on one-hop paths to directly connected neighbors. It implements
// the interface quic-go requires of a connection, so an HTTP/3 server or
// client rides the SCION data plane unchanged.
type SCIONConn struct {
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
	// links maps the neighbor IA of each external link to its interface ID,
	// to resolve the egress interface of fresh one-hop paths.
	links map[addr.IA]uint16

	conn *net.UDPConn

	mtx    sync.Mutex // Guards the MAC hasher and the closed flag.
	closed bool
}

// SCIONConnConfig configures a SCIONConn.
type SCIONConnConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Bind is the underlay "host:port" address to listen on and advertise.
	Bind string
	// InternalAddr is the router's internal underlay address.
	InternalAddr string
	// MACKey is the data-plane forwarding key, used to MAC one-hop paths.
	MACKey []byte
	// Links maps each external interface ID to the IA of the neighbor.
	Links map[uint16]addr.IA
}

// NewSCIONConn binds the endpoint's underlay address. Packets it sends are
// submitted to the router's internal link; packets the router delivers to
// the bound address are received from it.
func NewSCIONConn(cfg SCIONConnConfig) (*SCIONConn, error) {
	local, err := dataplane.ResolveAddrPort(cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("parsing bind address: %w", err)
	}
	internal, err := net.ResolveUDPAddr("udp", cfg.InternalAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing internal address: %w", err)
	}
	if len(cfg.Links) == 0 {
		return nil, fmt.Errorf("no links configured")
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
	links := make(map[addr.IA]uint16, len(cfg.Links))
	for ifID, neighborIA := range cfg.Links {
		links[neighborIA] = ifID
	}
	return &SCIONConn{
		localIA:  cfg.IA,
		local:    local,
		internal: internal,
		mac:      macFactory(),
		links:    links,
		conn:     conn,
	}, nil
}

// LocalAddr returns the endpoint's SCION address.
func (c *SCIONConn) LocalAddr() net.Addr {
	return &Addr{IA: c.localIA, Addr: c.local}
}

// Close releases the underlay socket.
func (c *SCIONConn) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.closed = true
	return c.conn.Close()
}

// ReadFrom reads the next datagram, returning it with the peer's address.
// Packets that are not SCION/UDP over a one-hop path are dropped silently;
// greetings share the CS service address and are none of our business.
func (c *SCIONConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, dataplane.BufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		payload, from, err := parseDatagramPacket(buf[:n])
		if err != nil {
			continue
		}
		if len(payload) > len(b) {
			payload = payload[:len(b)]
		}
		return copy(b, payload), from, nil
	}
}

// WriteTo sends the datagram to the peer as a SCION packet over a one-hop
// path. The path is created fresh for every packet: the egress interface is
// taken from the address if the peer set one (replies), and resolved from
// the link table otherwise (client traffic).
func (c *SCIONConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	peer, ok := addr.(*Addr)
	if !ok {
		return 0, fmt.Errorf("unexpected address type %T", addr)
	}
	ifID := peer.IfID
	if ifID == 0 {
		var err error
		if ifID, err = c.resolveLink(peer.IA); err != nil {
			return 0, err
		}
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	raw, err := c.datagramPacket(peer, ifID, b)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.WriteToUDP(raw, c.internal); err != nil {
		return 0, err
	}
	return len(b), nil
}

// SetDeadline sets the read and write deadlines of the underlay socket.
func (c *SCIONConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the underlay socket.
func (c *SCIONConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the underlay socket.
func (c *SCIONConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *SCIONConn) resolveLink(neighborIA addr.IA) (uint16, error) {
	ifID, ok := c.links[neighborIA]
	if !ok {
		return 0, fmt.Errorf("no link to neighbor %s", neighborIA)
	}
	return ifID, nil
}

// datagramPacket returns a serialized SCION packet carrying the datagram to
// the peer, to be forwarded over the link with the given interface ID.
func (c *SCIONConn) datagramPacket(peer *Addr, ifID uint16, payload []byte) ([]byte, error) {
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

	scn := &slayers.SCION{
		NextHdr:  slayers.L4UDP,
		PathType: onehop.PathType,
		Path:     &onehop.Path{Info: info, FirstHop: firstHop},
		SrcIA:    c.localIA,
		DstIA:    peer.IA,
	}
	if err := scn.SetSrcAddr(addr.HostIP(c.local.Addr())); err != nil {
		return nil, err
	}
	if err := scn.SetDstAddr(addr.HostIP(peer.Addr.Addr())); err != nil {
		return nil, err
	}
	udp := &slayers.UDP{SrcPort: c.local.Port(), DstPort: peer.Addr.Port()}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, udp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// parseDatagramPacket extracts the datagram and the peer's address from a
// received SCION packet. The peer's address records the interface the packet
// arrived on, so replies reverse the path.
func parseDatagramPacket(raw []byte) ([]byte, *Addr, error) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		return nil, nil, errors.New("no SCION layer")
	}
	scn := scnL.(*slayers.SCION)
	ohp, ok := scn.Path.(*onehop.Path)
	if !ok {
		return nil, nil, errors.New("not a one-hop path")
	}
	udpL := pkt.Layer(slayers.LayerTypeSCIONUDP)
	if udpL == nil {
		return nil, nil, errors.New("no UDP layer")
	}
	udp := udpL.(*slayers.UDP)
	src, err := scn.SrcAddr()
	if err != nil {
		return nil, nil, err
	}
	srcAddr := src.IP()
	if !srcAddr.IsValid() {
		return nil, nil, errors.New("no source IP")
	}
	if scn.SrcIA.IsWildcard() {
		return nil, nil, errors.New("wildcard source IA")
	}
	from := &Addr{
		IA:   scn.SrcIA,
		Addr: netip.AddrPortFrom(srcAddr, udp.SrcPort),
		// The router fills the second hop's ingress interface with the link
		// the packet came in on; that is the interface replies leave on.
		IfID: ohp.SecondHop.ConsIngress,
	}
	return udp.LayerPayload(), from, nil
}
