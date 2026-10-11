package measured

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"syscall"

	"github.com/fancl20/cion/pkg/modules/links"
)

// The link band: the ports a link's local address is drawn from. The band
// lies above the node's fixed ports, 30041 to 30044, and below the kernel's
// ephemeral range — Linux draws from 32768-60999 by default, macOS and
// Windows from the IANA dynamic range, 49152-65535 — so no bind of port 0,
// the node's own conns included, lands in it: a link's port stays the
// link's from its allocation through every generation's rebind and every
// restart. A Linux host whose ip_local_port_range reaches into the band
// keeps that only while ip_local_reserved_ports reserves the band.
const (
	LinkPortBase = 31000
	LinkPortSpan = 1000
)

// AllocateLinkAddr allocates a link's local underlay address on the given
// host: a port of the link band that no live entry among the given ones
// holds, drawn from a random offset, bound once to probe it, and released
// for the data plane generation to rebind. The release is safe, for nothing
// that binds port 0 draws from the band. Every generation rebinds the
// recorded address identically, which is what makes a swap invisible to the
// peer.
func AllocateLinkAddr(host netip.Addr, entries []*links.Link) (netip.AddrPort, error) {
	held := make(map[netip.AddrPort]bool, len(entries))
	for _, l := range entries {
		if l.Live() {
			held[l.Local] = true
		}
	}
	start := rand.IntN(LinkPortSpan)
	for i := range LinkPortSpan {
		addr := netip.AddrPortFrom(host, uint16(LinkPortBase+(start+i)%LinkPortSpan))
		if held[addr] {
			continue
		}
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("allocating a link address: %w", err)
		}
		bound := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if err := c.Close(); err != nil {
			return netip.AddrPort{}, err
		}
		return bound, nil
	}
	return netip.AddrPort{}, fmt.Errorf("allocating a link address: no port of %d-%d free on %v",
		LinkPortBase, LinkPortBase+LinkPortSpan-1, host)
}
