package scion

import (
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

// IfDownCacheTTL is how long a recognized interface-down signal holds: the
// retention the drafts describe as current practice — the cache only
// deprioritizes, so a short window prices a forged signal at exactly one
// skipped path.
const IfDownCacheTTL = 10 * time.Second

// InterfaceDownSignal is one recognized SCMP External Interface Down
// message: the signaled ISD-AS and interface entering the cache, and the
// quoted packet's destination — whose cached path just failed, the
// WireGuard bind's drop key.
type InterfaceDownSignal struct {
	// IA is the ISD-AS whose interface is signaled down.
	IA addr.IA
	// IfID is the signaled interface ID.
	IfID uint16
	// Dst is the quoted packet's destination ISD-AS; zero when the quote
	// does not decode.
	Dst addr.IA
	// DstHost is the quoted packet's destination host.
	DstHost netip.Addr
}

// InterfaceDownCache is the node's short negative cache of SCMP
// interface-down signals, shared by its conns and consulted by path
// composition: a signaled ISD-AS and interface are held for IfDownCacheTTL,
// and a composed path crossing one is skipped while the entry lives — kept
// only when nothing else exists, as lowering preference is all the drafts
// ask of a source. The cache removes no state, triggers no fetch, and
// overrides nothing the node measures itself: SCMP is unauthenticated, any
// speaker on a path could forge the signal, and a forged one is worth one
// skipped path for ten seconds.
type InterfaceDownCache struct {
	ttl time.Duration

	mtx sync.Mutex
	// signaled holds the entries' expiry by ISD-AS and interface.
	signaled map[ifDownKey]time.Time
	// onSignal receives every recognized signal; the WireGuard bind drops
	// the quoted destination's cached path through it.
	onSignal func(InterfaceDownSignal)
}

type ifDownKey struct {
	ia   addr.IA
	ifID uint16
}

// NewInterfaceDownCache returns a cache holding signals for IfDownCacheTTL.
func NewInterfaceDownCache() *InterfaceDownCache {
	return &InterfaceDownCache{
		ttl:      IfDownCacheTTL,
		signaled: make(map[ifDownKey]time.Time),
	}
}

// OnSignal registers the receiver of every recognized signal. The bind's
// existing failure-and-refresh behavior completes the loop: the signal
// drops the quoted destination's cached path, and its next send re-resolves
// through the filtered composition.
func (c *InterfaceDownCache) OnSignal(fn func(InterfaceDownSignal)) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.onSignal = fn
}

// Record enters a recognized signal and delivers it to the registered
// receiver.
func (c *InterfaceDownCache) Record(sig InterfaceDownSignal) {
	c.mtx.Lock()
	now := time.Now()
	c.signaled[ifDownKey{ia: sig.IA, ifID: sig.IfID}] = now.Add(c.ttl)
	fn := c.onSignal
	c.mtx.Unlock()
	if fn != nil {
		fn(sig)
	}
}

// Holds reports whether an interface is signaled down and the entry has not
// lapsed.
func (c *InterfaceDownCache) Holds(ia addr.IA, ifID uint16) bool {
	if c == nil {
		return false
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	expiry, ok := c.signaled[ifDownKey{ia: ia, ifID: ifID}]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(c.signaled, ifDownKey{ia: ia, ifID: ifID})
		return false
	}
	return true
}

// Empty reports whether no live entry remains — a storm's worth of signals
// aged out entirely, nothing persisted.
func (c *InterfaceDownCache) Empty() bool {
	return !c.HoldsAny()
}

// HoldsAny reports whether any live entry remains.
func (c *InterfaceDownCache) HoldsAny() bool {
	if c == nil {
		return false
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	now := time.Now()
	live := false
	for k, expiry := range c.signaled {
		if now.After(expiry) {
			delete(c.signaled, k)
			continue
		}
		live = true
	}
	return live
}

// parseInterfaceDownPacket recognizes an SCMP External Interface Down
// error in a received packet: the signaled ISD-AS and interface from the
// message, the failed destination from the quote. Anything else — every
// packet that is not a type-5 error — reports false.
func parseInterfaceDownPacket(raw []byte) (InterfaceDownSignal, bool) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scmpL := pkt.Layer(slayers.LayerTypeSCMP)
	if scmpL == nil {
		return InterfaceDownSignal{}, false
	}
	scmp := scmpL.(*slayers.SCMP)
	if scmp.TypeCode.Type() != slayers.SCMPTypeExternalInterfaceDown {
		return InterfaceDownSignal{}, false
	}
	var hdr slayers.SCMPExternalInterfaceDown
	if err := hdr.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return InterfaceDownSignal{}, false
	}
	sig := InterfaceDownSignal{IA: hdr.IA, IfID: uint16(hdr.IfID)}
	// The quote follows the message: its destination names whose cached
	// path just failed.
	quote := hdr.LayerPayload()
	if len(quote) >= slayers.CmnHdrLen+addr.IABytes {
		var scn slayers.SCION
		if err := scn.DecodeFromBytes(quote, gopacket.NilDecodeFeedback); err == nil {
			sig.Dst = scn.DstIA
			// A service-destined quote — control traffic rides the service
			// addresses — names no host to drop by.
			if dst, err := scn.DstAddr(); err == nil && dst.Type() == addr.HostTypeIP {
				sig.DstHost = dst.IP()
			}
		}
	}
	return sig, true
}
