package dataplane

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// Router handles SCION packet forwarding.
type Router struct {
	LocalIA addr.IA
	// ExternalNextHops maps an interface ID (local to this router) to the external address of the neighbor router.
	ExternalNextHops map[uint16]netip.AddrPort
	// MacFactory creates a new hash instance for MAC verification.
	MacFactory func() hash.Hash
	// pool manages reusable packet processors to reduce allocations.
	pool     *sync.Pool
	poolOnce sync.Once
}

type packetProcessor struct {
	scionLayer slayers.SCION
	parser     *gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType
	scionPath  scion.Decoded
	mac        hash.Hash
	macBuf     []byte
}

// NextHop describes where to send the packet next.
type NextHop struct {
	// Addr is the underlay address of the next hop.
	Addr netip.AddrPort
}

// Process determines the next hop for a SCION packet.
// ingressID is the ID of the interface the packet arrived on. Use 0 if the packet arrived from within the AS.
// The function returns the next hop and modifies the packet buffer in place (e.g. updating path pointers).
func (r *Router) Process(packet []byte, ingressID uint16) (NextHop, error) {
	// Initialize pool lazily
	r.poolOnce.Do(func() {
		r.pool = &sync.Pool{
			New: func() interface{} {
				p := &packetProcessor{
					decoded: make([]gopacket.LayerType, 0, 4),
					macBuf:  make([]byte, path.MACBufferSize),
				}
				// Initialize parser with pointers to the layers we want to decode
				p.parser = gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &p.scionLayer)
				p.parser.IgnoreUnsupported = true
				if r.MacFactory != nil {
					p.mac = r.MacFactory()
				}
				return p
			},
		}
	})

	proc := r.pool.Get().(*packetProcessor)
	defer r.pool.Put(proc)

	// Reset relevant state
	proc.decoded = proc.decoded[:0]
	// Reset SCION layer path to ensure clean decoding state (important if previous packet had different path type)
	proc.scionLayer.Path = nil

	if err := proc.parser.DecodeLayers(packet, &proc.decoded); err != nil {
		return NextHop{}, fmt.Errorf("failed to decode SCION layer: %w", err)
	}
	if len(proc.decoded) == 0 {
		return NextHop{}, fmt.Errorf("not a SCION packet")
	}

	// 1. Parse Path
	raw, ok := proc.scionLayer.Path.(*scion.Raw)
	if !ok {
		return NextHop{}, fmt.Errorf("path is not SCION path")
	}

	if err := proc.scionPath.DecodeFromBytes(raw.Raw); err != nil {
		return NextHop{}, fmt.Errorf("failed to decode SCION path: %w", err)
	}

	// 2. Get Current Info and Hop Fields
	pathMeta := proc.scionPath.PathMeta
	if int(pathMeta.CurrINF) >= len(proc.scionPath.InfoFields) || int(pathMeta.CurrHF) >= len(proc.scionPath.HopFields) {
		return NextHop{}, fmt.Errorf("path indices out of bounds")
	}

	info := proc.scionPath.InfoFields[pathMeta.CurrINF]
	hop := proc.scionPath.HopFields[pathMeta.CurrHF]

	// 3. Validate Expiration
	ts := time.Unix(int64(info.Timestamp), 0)
	expires := ts.Add(path.ExpTimeToDuration(hop.ExpTime))
	if time.Now().After(expires) {
		return NextHop{}, fmt.Errorf("hop expired")
	}

	// 4. Determine Direction & Ingress/Egress IDs
	var inID, outID uint16
	if info.ConsDir {
		inID = hop.ConsIngress
		outID = hop.ConsEgress
	} else {
		inID = hop.ConsEgress
		outID = hop.ConsIngress
	}

	// 5. Ingress Processing
	if ingressID != 0 {
		// INGRESS ROUTER LOGIC (Packet arrived from neighbor)
		if ingressID != inID {
			return NextHop{}, fmt.Errorf("ingress interface mismatch: expected %d, got %d", inID, ingressID)
		}

		// Update SegID if moving against construction direction
		if !info.ConsDir {
			info.UpdateSegID(hop.Mac)
			// Write back updated info field to path struct (needed for MAC check and serialization)
			proc.scionPath.InfoFields[pathMeta.CurrINF] = info
		}
	} else {
		// EGRESS ROUTER LOGIC (Packet arrived from internal/local)
		// No ingress interface to check or SegID to update (unless it's a specific case not covered here)
	}

	// 6. Validate MAC (after potential SegID update)
	if proc.mac != nil {
		proc.mac.Reset()
		expectedMac := path.MAC(proc.mac, info, hop, proc.macBuf)

		// Compare only the length of the hop MAC (usually 6 bytes)
		if subtle.ConstantTimeCompare(hop.Mac[:], expectedMac[:len(hop.Mac)]) != 1 {
			return NextHop{}, fmt.Errorf("MAC verification failed")
		}
	}

	// 7. Forwarding Logic
	if ingressID != 0 && outID == 0 {
		// Destination is local.
		// Verify DstIA matches LocalIA
		if proc.scionLayer.DstIA != r.LocalIA {
			return NextHop{}, fmt.Errorf("packet destined for %s arrived at %s with no egress interface", proc.scionLayer.DstIA, r.LocalIA)
		}

		// Commit path changes to buffer before local delivery
		if err := proc.scionPath.SerializeTo(raw.Raw); err != nil {
			return NextHop{}, fmt.Errorf("failed to serialize updated path: %w", err)
		}

		// Get Destination Host Address
		dstAddr, err := proc.scionLayer.DstAddr()
		if err != nil {
			return NextHop{}, fmt.Errorf("failed to get destination address: %w", err)
		}

		ip := dstAddr.IP()
		return NextHop{Addr: netip.AddrPortFrom(ip, 0)}, nil
	}

	// Forwarding to External Router
	if outID == 0 {
		return NextHop{}, fmt.Errorf("received packet with egress 0 from internal")
	}

	nextHopAddr, ok := r.ExternalNextHops[outID]
	if !ok {
		return NextHop{}, fmt.Errorf("unknown external interface: %d", outID)
	}

	// Egress Router updates (if ConsDir) and increments the Hop Field index
	if err := r.processEgress(raw, &proc.scionPath, info, hop); err != nil {
		return NextHop{}, err
	}

	return NextHop{Addr: nextHopAddr}, nil
}

// processEgress handles the logic for a packet leaving the AS.
// It updates the SegID if necessary (Construction Direction) and increments the path index.
func (r *Router) processEgress(raw *scion.Raw, p *scion.Decoded, info path.InfoField, hop path.HopField) error {
	// Update SegID if moving in construction direction
	if info.ConsDir {
		info.UpdateSegID(hop.Mac)
		p.InfoFields[p.PathMeta.CurrINF] = info
	}

	// Increment path index
	p.PathMeta.CurrHF++

	// Check boundaries (simple version)
	if int(p.PathMeta.CurrHF) >= p.NumHops {
		return fmt.Errorf("path index overflow")
	}

	// Write back to layer
	if err := p.SerializeTo(raw.Raw); err != nil {
		return err
	}
	return nil
}
