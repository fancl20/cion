package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
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

// DiscoveryPort is the SCION UDP port used by the discovery greeting. The
// port is irrelevant for delivery (greetings are addressed to the CS service
// address), but a fixed value keeps the traffic identifiable.
const DiscoveryPort = 30043

const greetingVersion = 1

// Neighbor is the state of a directly connected neighbor AS, learned from
// discovery greetings.
type Neighbor struct {
	// IA is the ISD-AS of the neighbor.
	IA addr.IA
	// IfID is the neighbor's interface ID of the direct link.
	IfID uint16
	// ControlAddr is the underlay address of the neighbor's control service.
	ControlAddr netip.AddrPort
	// LastSeen is the time of the last received greeting.
	LastSeen time.Time
}

// Greeting is the discovery message exchanged between directly connected
// nodes. It is carried as the payload of a SCION/UDP packet addressed to the
// CS service of the neighbor, over a one-hop path; the one-hop path both
// directions of the link and requires no path state on either side.
type Greeting struct {
	// IA is the ISD-AS of the sender.
	IA addr.IA
	// IfID is the sender's interface ID of the link the greeting travels on.
	IfID uint16
	// ControlAddr is the underlay address of the sender's control service.
	ControlAddr netip.AddrPort
}

func (g Greeting) Marshal() []byte {
	a := g.ControlAddr.String()
	buf := make([]byte, 0, 15+len(a))
	buf = binary.BigEndian.AppendUint16(buf, greetingVersion)
	buf = binary.BigEndian.AppendUint16(buf, g.IfID)
	buf = binary.BigEndian.AppendUint64(buf, uint64(g.IA))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a)))
	return append(buf, a...)
}

func ParseGreeting(b []byte) (Greeting, error) {
	rd := &binReader{b: b}
	version := rd.uint16()
	if rd.err != nil {
		return Greeting{}, fmt.Errorf("reading greeting: %w", rd.err)
	}
	if version != greetingVersion {
		return Greeting{}, fmt.Errorf("unsupported greeting version: %d", version)
	}
	g := Greeting{
		IfID: rd.uint16(),
		IA:   addr.IA(rd.uint64()),
	}
	n := int(rd.uint16())
	a := rd.bytes(n)
	if rd.err != nil {
		return Greeting{}, fmt.Errorf("reading greeting: %w", rd.err)
	}
	controlAddr, err := netip.ParseAddrPort(string(a))
	if err != nil {
		return Greeting{}, fmt.Errorf("parsing control address: %w", err)
	}
	g.ControlAddr = controlAddr
	return g, nil
}

type binReader struct {
	b   []byte
	err error
}

func (r *binReader) uint16() uint16 {
	if len(r.b) < 2 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *binReader) uint64() uint64 {
	if len(r.b) < 8 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *binReader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.err = errors.New("truncated")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// Discovery exchanges greetings with directly connected neighbors and keeps
// the resulting neighbor table. Greetings are sent over the router's internal
// network and forwarded by the data plane over each external link; incoming
// greetings are delivered back to the control service via the CS service
// address.
type Discovery struct {
	localIA     addr.IA
	controlAddr netip.AddrPort
	macFactory  func() hash.Hash
	internal    *net.UDPAddr       // The router's internal underlay address.
	links       map[uint16]addr.IA // Interface ID to neighbor IA.
	conn        *net.UDPConn

	mtx       sync.Mutex
	neighbors map[uint16]Neighbor // By local interface ID.

	interval time.Duration
	timeout  time.Duration
}

// DiscoveryConfig configures a Discovery instance.
type DiscoveryConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// ControlAddr is the underlay address to listen on and to advertise to
	// neighbors. It must be reachable from the neighbor ASes.
	ControlAddr string
	// MACKey is the forwarding key, shared with the data plane, used to MAC
	// the one-hop paths of outgoing greetings.
	MACKey []byte
	// InternalAddr is the router's internal underlay address.
	InternalAddr string
	// Links maps each external interface ID to the IA of the neighbor.
	Links map[uint16]addr.IA
	// Interval between greetings; defaults to 1s if zero.
	Interval time.Duration
}

func NewDiscovery(cfg DiscoveryConfig) (*Discovery, error) {
	controlAddr, err := dataplane.ResolveAddrPort(cfg.ControlAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing control address: %w", err)
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
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(controlAddr))
	if err != nil {
		return nil, fmt.Errorf("binding control address: %w", err)
	}

	interval := cfg.Interval
	if interval == 0 {
		interval = time.Second
	}
	return &Discovery{
		localIA:     cfg.IA,
		controlAddr: controlAddr,
		macFactory:  macFactory,
		internal:    internal,
		links:       cfg.Links,
		conn:        conn,
		neighbors:   make(map[uint16]Neighbor, len(cfg.Links)),
		interval:    interval,
		timeout:     3 * interval,
	}, nil
}

// Register advertises the control service address in the data plane so that
// greetings addressed to the CS service are delivered to this instance.
func (d *Discovery) Register(provider *dataplane.UDPProvider) error {
	return provider.AddSvc(addr.SvcCS, addr.HostIP(d.controlAddr.Addr()), d.controlAddr.Port())
}

// Run sends greetings on every configured link and processes incoming ones
// until the context is canceled.
func (d *Discovery) Run(ctx context.Context) {
	go func() {
		defer handlePanic()
		d.receive(ctx)
	}()

	d.send(ctx)
}

func (d *Discovery) send(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		d.sendOnce()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Discovery) sendOnce() {
	g := Greeting{IA: d.localIA, ControlAddr: d.controlAddr}
	for ifID, neighborIA := range d.links {
		g.IfID = ifID
		raw, err := d.greetingPacket(neighborIA, ifID)
		if err != nil {
			slog.Error("Building greeting", "interface", ifID, "err", err)
			continue
		}
		if _, err := d.conn.WriteToUDP(raw, d.internal); err != nil {
			slog.Error("Sending greeting", "interface", ifID, "err", err)
		}
	}
}

func (d *Discovery) receive(ctx context.Context) {
	buf := make([]byte, dataplane.BufferSize)

	for {
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			slog.Error("Reading greeting", "err", err)
			continue
		}
		g, ifID, err := parseGreetingPacket(buf[:n])
		if err != nil {
			slog.Error("Parsing greeting packet", "err", err)
			continue
		}
		d.record(ifID, g)
	}
}

func (d *Discovery) record(ifID uint16, g Greeting) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	neighborIA, ok := d.links[ifID]
	if !ok || neighborIA != g.IA {
		slog.Error("Greeting from unexpected neighbor",
			"interface", ifID, "expected", neighborIA, "got", g.IA)
		return
	}
	d.neighbors[ifID] = Neighbor{
		IA:          g.IA,
		IfID:        g.IfID,
		ControlAddr: g.ControlAddr,
		LastSeen:    time.Now(),
	}
}

// Neighbors returns the currently reachable neighbors, by interface ID.
// Neighbors whose last greeting is older than three intervals are omitted.
func (d *Discovery) Neighbors() map[uint16]Neighbor {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make(map[uint16]Neighbor, len(d.neighbors))
	now := time.Now()
	for ifID, n := range d.neighbors {
		if now.Sub(n.LastSeen) > d.timeout {
			continue
		}
		out[ifID] = n
	}
	return out
}

// greetingPacket returns a serialized SCION packet carrying a greeting for
// the given neighbor, to be sent over the link with the given interface ID.
func (d *Discovery) greetingPacket(neighborIA addr.IA, ifID uint16) ([]byte, error) {
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
	firstHop.Mac = path.MAC(d.macFactory(), info, firstHop, nil)

	scn := &slayers.SCION{
		NextHdr:  slayers.L4UDP,
		PathType: onehop.PathType,
		Path:     &onehop.Path{Info: info, FirstHop: firstHop},
		SrcIA:    d.localIA,
		DstIA:    neighborIA,
	}
	if err := scn.SetSrcAddr(addr.HostIP(d.controlAddr.Addr())); err != nil {
		return nil, err
	}
	if err := scn.SetDstAddr(addr.HostSVC(addr.SvcCS)); err != nil {
		return nil, err
	}
	udp := &slayers.UDP{SrcPort: DiscoveryPort, DstPort: DiscoveryPort}
	g := Greeting{IA: d.localIA, IfID: ifID, ControlAddr: d.controlAddr}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, udp, gopacket.Payload(g.Marshal()))
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// parseGreetingPacket extracts the greeting and the ingress interface ID
// (from the second hop of the one-hop path, filled in by the local router)
// from a received SCION packet.
func parseGreetingPacket(raw []byte) (Greeting, uint16, error) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		return Greeting{}, 0, fmt.Errorf("no SCION layer")
	}
	scn := scnL.(*slayers.SCION)
	ohp, ok := scn.Path.(*onehop.Path)
	if !ok {
		return Greeting{}, 0, fmt.Errorf("not a one-hop path")
	}
	udpL := pkt.Layer(slayers.LayerTypeSCIONUDP)
	if udpL == nil {
		return Greeting{}, 0, fmt.Errorf("no UDP layer")
	}
	g, err := ParseGreeting(udpL.(*slayers.UDP).LayerPayload())
	if err != nil {
		return Greeting{}, 0, err
	}
	return g, ohp.SecondHop.ConsIngress, nil
}

func handlePanic() {
	if r := recover(); r != nil {
		slog.Error("Panic in control plane", "panic", r)
	}
}
