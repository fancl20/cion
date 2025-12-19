package dataplane

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// Interface represents a router interface.
type Interface struct {
	Conn       net.PacketConn
	RemoteAddr net.Addr
}

// Router implements a SCION dataplane router.
type Router struct {
	// Interfaces maps the SCION Interface ID to the underlying connection and remote address.
	Interfaces map[uint16]Interface
	// Key is the secret key used for MAC verification (AES-CMAC usually, here HMAC-SHA256).
	Key []byte
}

// NewRouter creates a new Router.
func NewRouter(key []byte) *Router {
	return &Router{
		Interfaces: make(map[uint16]Interface),
		Key:        key,
	}
}

// AddInterface adds an interface to the router.
func (r *Router) AddInterface(id uint16, conn net.PacketConn, remote net.Addr) {
	r.Interfaces[id] = Interface{
		Conn:       conn,
		RemoteAddr: remote,
	}
}

// Run starts the router. It reads from all interfaces sequentially and forwards packets.
// This function blocks.
func (r *Router) Run() {
	buf := make([]byte, 65535) // Max payload size

	for {
		for id, iface := range r.Interfaces {
			// Set a short read deadline to poll interfaces sequentially
			iface.Conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))

			n, _, err := iface.Conn.ReadFrom(buf)
			if err != nil {
				// Check for timeout
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				// Log other errors but continue
				fmt.Printf("Error reading from interface %d: %v\n", id, err)
				continue
			}

			// Process packet (copy buffer to avoid race/overwrite in loop if parallelized later,
			// though strictly sequential here. Safe to use buf[:n] for now).
			// We clone it because we might modify it in place and send it out.
			packetData := make([]byte, n)
			copy(packetData, buf[:n])

			if err := r.processPacket(packetData, id); err != nil {
				fmt.Printf("Error processing packet on iface %d: %v\n", id, err)
			}
		}
	}
}

func (r *Router) processPacket(data []byte, recvID uint16) error {
	var s slayers.SCION
	// Decode SCION header
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return fmt.Errorf("failed to decode SCION header: %w", err)
	}

	// We only handle SCION path type for now
	if s.PathType != scion.PathType {
		return fmt.Errorf("unsupported path type: %v", s.PathType)
	}

	// Extract the path (using Raw for performance/direct access)
	rawPath, ok := s.Path.(*scion.Raw)
	if !ok {
		return fmt.Errorf("failed to cast path to scion.Raw")
	}

	// Get current Info and Hop fields
	info, err := rawPath.GetCurrentInfoField()
	if err != nil {
		return fmt.Errorf("failed to get info field: %w", err)
	}

	hop, err := rawPath.GetCurrentHopField()
	if err != nil {
		return fmt.Errorf("failed to get hop field: %w", err)
	}

	// Determine direction and roles
	var ingressID, egressID uint16
	if info.ConsDir {
		ingressID = hop.ConsIngress
		egressID = hop.ConsEgress
	} else {
		ingressID = hop.ConsEgress
		egressID = hop.ConsIngress
	}

	// Helper for MAC creation
	macFactory := func() hash.Hash {
		return hmac.New(sha256.New, r.Key)
	}

	// --- Ingress Processing ---
	if recvID == ingressID {
		// 1. Validate Expiry
		// Expiration = Timestamp + (1+ExpTime) * (24h/256)
		// Unit is approx 337.5 seconds
		expSeconds := (uint32(hop.ExpTime) + 1) * (24 * 60 * 60 / 256)
		expiry := time.Unix(int64(info.Timestamp)+int64(expSeconds), 0)
		if time.Now().After(expiry) {
			return fmt.Errorf("hop expired")
		}

		// 2. MAC Verification & Accumulator Update
		if !info.ConsDir {
			// Update Accumulator (SegID) first
			// Acc = Acc XOR MAC
			info.UpdateSegID(hop.Mac)

			// Verify MAC using the NEW Acc
			calcMAC := path.MAC(macFactory(), info, hop, nil)
			if !bytes.Equal(calcMAC[:], hop.Mac[:]) {
				return fmt.Errorf("MAC mismatch (Ingress !ConsDir)")
			}

			// Update InfoField in raw path
			if err := rawPath.SetInfoField(info, int(rawPath.PathMeta.CurrINF)); err != nil {
				return fmt.Errorf("failed to update info field: %w", err)
			}
		} else {
			// ConsDir: Just verify
			calcMAC := path.MAC(macFactory(), info, hop, nil)
			if !bytes.Equal(calcMAC[:], hop.Mac[:]) {
				return fmt.Errorf("MAC mismatch (Ingress ConsDir)")
			}
		}

		// --- Egress Processing Check ---
		// If the egress interface is also owned by this router, we perform egress processing immediately.
		// Otherwise, we simply forward to the next hop (internal router).
		// Since we only have 'Interfaces', we assume if ID is present, we own it.

		if _, ok := r.Interfaces[egressID]; ok {
			// We are also the Egress Router

			if info.ConsDir {
				// Verify MAC (again? Spec says Egress verifies)
				calcMAC := path.MAC(macFactory(), info, hop, nil)
				if !bytes.Equal(calcMAC[:], hop.Mac[:]) {
					return fmt.Errorf("MAC mismatch (Egress ConsDir)")
				}

				// Update Accumulator
				info.UpdateSegID(hop.Mac)
				if err := rawPath.SetInfoField(info, int(rawPath.PathMeta.CurrINF)); err != nil {
					return fmt.Errorf("failed to update info field: %w", err)
				}
			}
			// If !ConsDir, Egress just forwards (Case 3 in 4.2.2.2)

			// Increment Path Pointer
			// Egress router increments the path pointer to point to the next hop
			if err := rawPath.IncPath(); err != nil {
				return fmt.Errorf("failed to increment path: %w", err)
			}
		}

		// Serialize Path changes back to packet buffer
		// rawPath.Raw contains the bytes. We need to write them back to 'data'.
		// s.DecodeFromBytes used 'data' as backing slice for rawPath.Raw if possible?
		// scion.Raw implementation: s.Raw = data[:pathLen].
		// So modifications to rawPath.Raw ARE modifications to 'data' (slice of same array).
		// BUT: IncPath updates PathMeta.SerializeTo(s.Raw).
		// So 'data' should be updated automatically if s.Raw points to it.
		// Verify: scion.Raw.DecodeFromBytes sets s.Raw = data[:pathLen]. Yes.

		// Determine Output
		outIface, ok := r.Interfaces[egressID]
		if !ok {
			return fmt.Errorf("egress interface %d not found", egressID)
		}

		// Forward
		_, err = outIface.Conn.WriteTo(data, outIface.RemoteAddr)
		if err != nil {
			return fmt.Errorf("failed to write to interface %d: %w", egressID, err)
		}

		return nil

	} else {
		// Received on non-Ingress interface?
		// Could be a loop or misconfiguration.
		return fmt.Errorf("packet received on wrong interface: %d (expected ingress %d)", recvID, ingressID)
	}
}
