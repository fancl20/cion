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
	"github.com/fancl20/cion/pkg/links"
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
// CS service of the neighbor, over a one-hop path; the one-hop path serves
// both directions of the link and requires no path state on either side.
type Greeting struct {
	// IA is the ISD-AS of the sender.
	IA addr.IA
	// IfID is the sender's interface ID of the link the greeting travels on.
	IfID uint16
	// ControlAddr is the underlay address of the sender's control service.
	ControlAddr netip.AddrPort
	// CoreIA and CoreAddr name the control endpoint of the core the sender
	// reaches — itself, on the core. Nodes relay what they learned, so a
	// node without a direct link to the core learns where its enrollment
	// fetch is aimed once beaconing supplies the path. Zero CoreIA omits
	// the fields.
	CoreIA   addr.IA
	CoreAddr netip.AddrPort
}

func (g Greeting) Marshal() []byte {
	a := g.ControlAddr.String()
	buf := make([]byte, 0, 15+len(a))
	buf = binary.BigEndian.AppendUint16(buf, greetingVersion)
	buf = binary.BigEndian.AppendUint16(buf, g.IfID)
	buf = binary.BigEndian.AppendUint64(buf, uint64(g.IA))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a)))
	buf = append(buf, a...)
	if g.CoreIA.IsZero() {
		return buf
	}
	core := g.CoreAddr.String()
	buf = binary.BigEndian.AppendUint64(buf, uint64(g.CoreIA))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(core)))
	return append(buf, core...)
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
	// The core endpoint is trailing and optional; greetings without it come
	// from nodes that know no core yet.
	if len(rd.b) == 0 {
		return g, nil
	}
	g.CoreIA = addr.IA(rd.uint64())
	n = int(rd.uint16())
	core := rd.bytes(n)
	if rd.err != nil {
		return Greeting{}, fmt.Errorf("reading greeting core endpoint: %w", rd.err)
	}
	coreAddr, err := netip.ParseAddrPort(string(core))
	if err != nil {
		return Greeting{}, fmt.Errorf("parsing core endpoint address: %w", err)
	}
	g.CoreAddr = coreAddr
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
	internal    *net.UDPAddr // The router's internal underlay address.
	store       links.DB     // The neighbor table, read live.
	conn        *net.UDPConn

	mtx       sync.Mutex
	neighbors map[uint16]Neighbor // By local interface ID.
	// core is the core endpoint learned from greetings — itself announced by
	// the core, relayed by every other node.
	core coreState

	interval time.Duration
	timeout  time.Duration
	// changed is called after each recorded greeting, off the lock.
	changed func()
}

// coreState is the core control endpoint: the core's own announcement,
// which never decays, or one learned from a greeting, which does.
type coreState struct {
	ia       addr.IA
	addr     netip.AddrPort
	lastSeen time.Time
	own      bool
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
	// Store is the neighbor table, read live: greetings are validated
	// against the current snapshot, and a node may start with zero links.
	Store links.DB
	// Interval between greetings; defaults to 1s if zero.
	Interval time.Duration
	// Changed is called after each recorded greeting — the arrival the
	// neighbor table learned from. It runs outside the instance's lock, free
	// to read Neighbors; nil keeps nothing.
	Changed func()
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
	if cfg.Store == nil {
		return nil, fmt.Errorf("no link store configured")
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
		store:       cfg.Store,
		conn:        conn,
		neighbors:   make(map[uint16]Neighbor),
		interval:    interval,
		timeout:     3 * interval,
		changed:     cfg.Changed,
	}, nil
}

// Register advertises the control service address in the data plane so that
// greetings addressed to the CS service are delivered to this instance.
func (d *Discovery) Register(provider *dataplane.UDPProvider) error {
	return provider.AddSvc(addr.SvcCS, addr.HostIP(d.controlAddr.Addr()), d.controlAddr.Port())
}

// Close releases the resources of the discovery service, unblocking Run.
// The instance cannot be used afterwards.
func (d *Discovery) Close() error {
	return d.conn.Close()
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
	coreIA, coreAddr := d.greetingCore()
	g := Greeting{IA: d.localIA, ControlAddr: d.controlAddr, CoreIA: coreIA, CoreAddr: coreAddr}
	for ifID, neighborIA := range d.linkTable() {
		g.IfID = ifID
		raw, err := d.greetingPacket(g, neighborIA, ifID)
		if err != nil {
			slog.Error("Building greeting", "interface", ifID, "err", err)
			continue
		}
		if _, err := d.conn.WriteToUDP(raw, d.internal); err != nil {
			slog.Error("Sending greeting", "interface", ifID, "err", err)
		}
	}
}

// linkTable snapshots the serving links' interface IDs and neighbors — the
// table the data plane generation carries.
func (d *Discovery) linkTable() map[uint16]addr.IA {
	entries, err := d.store.All(context.Background())
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return nil
	}
	table := make(map[uint16]addr.IA, len(entries))
	for _, l := range entries {
		if l.Serving() && !l.NeighborIA.IsZero() {
			table[l.IfID] = l.NeighborIA
		}
	}
	return table
}

func (d *Discovery) receive(ctx context.Context) {
	buf := make([]byte, dataplane.BufferSize)

	for {
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
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
	if !d.learn(ifID, g) {
		return
	}
	// The hook runs off the lock, free to read the table it just changed.
	if d.changed != nil {
		d.changed()
	}
}

// learn validates and records one greeting arrival under the lock,
// reporting whether the neighbor table learned from it.
func (d *Discovery) learn(ifID uint16, g Greeting) bool {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	entry := d.entry(ifID)
	if entry == nil {
		slog.Error("Greeting on unknown interface", "interface", ifID, "got", g.IA)
		return false
	}
	if entry.NeighborIA.IsZero() {
		// A link whose neighbor was not named yet — a joiner's first contact
		// — adopts the greeting's ISD-AS, and the remote interface ID with
		// it.
		entry.NeighborIA = g.IA
		entry.RemoteIfID = g.IfID
		if err := d.store.Update(context.Background(), entry); err != nil {
			slog.Error("Adopting the neighbor of a link", "interface", ifID, "err", err)
			return false
		}
	} else if !entry.NeighborIA.Equal(g.IA) {
		slog.Error("Greeting from unexpected neighbor",
			"interface", ifID, "expected", entry.NeighborIA, "got", g.IA)
		return false
	} else if entry.RemoteIfID != g.IfID {
		entry.RemoteIfID = g.IfID
		if err := d.store.Update(context.Background(), entry); err != nil {
			slog.Error("Recording the neighbor's interface ID",
				"interface", ifID, "err", err)
			return false
		}
	}
	now := time.Now()
	d.neighbors[ifID] = Neighbor{
		IA:          g.IA,
		IfID:        g.IfID,
		ControlAddr: g.ControlAddr,
		LastSeen:    now,
	}
	// Relay the freshest core endpoint: every node includes the one it
	// reaches in its greetings, so nodes without a direct link to the core
	// learn where their enrollment fetch and registrations are aimed. A
	// greeting relaying the node's own endpoint refreshes it without
	// downgrading it to a learned one that could decay.
	if !g.CoreIA.IsZero() {
		if d.core.own && g.CoreIA.Equal(d.core.ia) {
			d.core.lastSeen = now
		} else {
			d.core = coreState{ia: g.CoreIA, addr: g.CoreAddr, lastSeen: now}
		}
	}
	return true
}

// entry returns the link store's entry of an interface.
func (d *Discovery) entry(ifID uint16) *links.Link {
	entries, err := d.store.All(context.Background())
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return nil
	}
	for _, l := range entries {
		if l.IfID == ifID && l.Live() {
			return l
		}
	}
	return nil
}

// Neighbors returns the neighbors learned from greetings, by interface ID,
// with their LastSeen — identity for whoever asks. The entries stand
// however stale their arrivals: liveness is the health monitor's verdict
// (ADR-0008), and the one recency derivation left — the selection sweep's
// grace for a candidate still proving itself — reads LastSeen directly.
func (d *Discovery) Neighbors() map[uint16]Neighbor {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make(map[uint16]Neighbor, len(d.neighbors))
	for ifID, n := range d.neighbors {
		out[ifID] = n
	}
	return out
}

// SetCoreEndpoint names the core this node serves, announced in every
// greeting without decaying: a core that starts before its neighbors still
// announces itself once they arrive.
func (d *Discovery) SetCoreEndpoint(ia addr.IA, addr netip.AddrPort) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	d.core = coreState{ia: ia, addr: addr, lastSeen: time.Now(), own: true}
}

// CoreEndpoint returns the core control endpoint learned from greetings,
// fresh within the greeting timeout; the core's own never goes stale.
func (d *Discovery) CoreEndpoint() (addr.IA, netip.AddrPort, bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.core.ia.IsZero() || (!d.core.own && time.Since(d.core.lastSeen) > d.timeout) {
		return 0, netip.AddrPort{}, false
	}
	return d.core.ia, d.core.addr, true
}

// greetingCore returns the core endpoint to announce, if any.
func (d *Discovery) greetingCore() (addr.IA, netip.AddrPort) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.core.ia.IsZero() || (!d.core.own && time.Since(d.core.lastSeen) > d.timeout) {
		return 0, netip.AddrPort{}
	}
	return d.core.ia, d.core.addr
}

// greetingPacket returns a serialized SCION packet carrying a greeting for
// the given neighbor, to be sent over the link with the given interface ID.
func (d *Discovery) greetingPacket(g Greeting, neighborIA addr.IA, ifID uint16) ([]byte, error) {
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
