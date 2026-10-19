package testnetwork

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// The translator's mapping band: the ports its per-socket mappings draw,
// below the kernel's ephemeral range and beside — not inside — the labs'
// pinned band and the node's link band, so a mapping's port is always a
// port no node claims and a changed mapping always spells a different
// address.
const (
	transitPortBase = 26000
	transitPortSpan = 500
)

// mappingIdle is how long a mapping lives past its last packet: the idle
// timeout a link's BFD stream — one packet per interval, both directions —
// rides out by construction, and a restarted node's fresh mapping does not.
const mappingIdle = 2 * time.Second

// translator is the lab's port-remapping translation for the rendezvous
// exchange, in userspace on the namespace's loopback: the translated
// node's rendezvous dials reach the founder only through the gateway, each
// dialing socket's packets leaving from a mapping port the translator drew
// — never the socket's own — so the mapping the founder observes is a port
// nothing else spells. Carrying the link's own traffic through the same
// userspace trick the lab cannot honestly do — the kernel's wildcard binds
// are dual-stack and its source selection for them varies per destination,
// so a relay the peers dial directly cannot stand in for a NAT the packets
// traverse transparently — and the link-level proofs stay with the
// unconnected socket's own tests.
type translator struct {
	gw       netip.Addr // the gateway: the translated node's route to the founder
	upstream netip.Addr // the founder's real address

	mtx   sync.Mutex
	flows map[uint16]*mapping // by source port: one socket one mapping, the NAT's own key
	draws int
}

// draw maps the translator's next port, never one drawn before.
func (x *translator) draw() uint16 {
	x.draws++
	return uint16(transitPortBase + x.draws%transitPortSpan)
}

// mapping is one dialing socket's translation: the gateway port its
// packets leave from and the founder's return traffic dials.
type mapping struct {
	sock *net.UDPConn
	src  netip.AddrPort
	used time.Time
}

// newTranslator starts the translation between the node and the founder,
// the gateway's rendezvous port forwarded from the start.
func newTranslator(t *testing.T, gw, upstream netip.Addr) *translator {
	t.Helper()
	x := &translator{
		gw:       gw,
		upstream: upstream,
		flows:    make(map[uint16]*mapping),
	}
	forward, err := net.ListenUDP("udp4",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(gw, measured.RendezvousPort)))
	if err != nil {
		t.Fatalf("binding the gateway's rendezvous forward: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	go func() {
		buf := make([]byte, 9000)
		for {
			n, src, err := forward.ReadFromUDP(buf)
			if err != nil {
				return
			}
			m := x.flow(src.AddrPort())
			if m == nil {
				return
			}
			_, _ = m.sock.WriteToUDP(buf[:n],
				net.UDPAddrFromAddrPort(netip.AddrPortFrom(upstream, measured.RendezvousPort)))
		}
	}()
	go x.sweep()
	return x
}

// flow returns the source socket's mapping, drawing one when the translator
// holds none: the mapping an endpoint-independent translation gives a
// socket — every destination, the one port.
func (x *translator) flow(src netip.AddrPort) *mapping {
	x.mtx.Lock()
	defer x.mtx.Unlock()
	if x.flows == nil {
		return nil
	}
	if m, ok := x.flows[src.Port()]; ok {
		m.src = src
		return m
	}
	c, err := net.ListenUDP("udp4",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(x.gw, x.draw())))
	if err != nil {
		return nil
	}
	m := &mapping{sock: c, src: src, used: time.Now()}
	x.flows[src.Port()] = m
	go x.serveMapping(m)
	return m
}

// serveMapping relays the founder's return traffic to the dialing socket.
func (x *translator) serveMapping(m *mapping) {
	buf := make([]byte, 9000)
	for {
		n, _, err := m.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		x.mtx.Lock()
		m.used = time.Now()
		dst := m.src
		x.mtx.Unlock()
		_, _ = m.sock.WriteToUDP(buf[:n], net.UDPAddrFromAddrPort(dst))
	}
}

// sweep retires the mappings whose last packet is older than the idle
// timeout, until the translator stops.
func (x *translator) sweep() {
	for range time.Tick(mappingIdle / 2) {
		x.mtx.Lock()
		if x.flows == nil {
			x.mtx.Unlock()
			return
		}
		now := time.Now()
		for port, m := range x.flows {
			if now.Sub(m.used) < mappingIdle {
				continue
			}
			delete(x.flows, port)
			_ = m.sock.Close()
		}
		x.mtx.Unlock()
	}
}

// mappingPort reports whether an address spells one of the translator's
// drawn mappings.
func mappingPort(ap netip.AddrPort) bool {
	return ap.Port() >= transitPortBase && ap.Port() < transitPortBase+transitPortSpan
}

// TestTranslatedJoinerRecordsTheObservation is the translation lab's
// exchange-level proof: a joiner whose rendezvous dials traverse a
// port-remapping translator — every dial leaving through a mapping port the
// translator drew, never the socket's own — joins, and the founder's entry
// for it records the observed mapping: the gateway's host under a drawn
// port, never the address the claim spells. The link-level proofs the full
// lab wants — the mapping-carried data path holding a link up past the
// mapping's idle timeout, and a restart's fresh mapping re-aiming the
// former neighbor — need a translation the packets traverse without being
// addressed to it, which a userspace relay cannot stand in for; those stay
// with the unconnected socket's and the confirm's own tests.
func TestTranslatedJoinerRecordsTheObservation(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	wpki := webpkitest.New(t)
	ipA, gw, ipJ := hostSlot(t), hostSlot(t), hostSlot(t)
	newTranslator(t, gw, ipA)
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	j := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipJ)
		cfg.Control = FreeUDPAddrOn(t, ipJ)
		cfg.Neighbors = []string{gw.String()}
		cfg.RootCAs = wpki.Pool
	})
	ctx := t.Context()

	// The joiner's identity completes through the translation, and the
	// founder's entry for it appears aimed at a drawn mapping — the address
	// the exchange itself proved answers, not the claim.
	Poll(t, "A's entry for the translated joiner", func() bool {
		e := entryOf(ctx, a, j.app.IA())
		return e != nil && e.Live() && e.Remote.Addr() == gw && mappingPort(e.Remote)
	})
	// The join completes over the link the exchange seeded.
	Poll(t, "the translated joiner's link to A", func() bool {
		e := entryOf(ctx, j, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
}
