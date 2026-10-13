// Package underlay holds the facts of the UDP/IP network beneath SCION that the
// data plane shares with the node's sockets: the end-host port, the largest
// datagram, the underlay types, and the resolution of underlay addresses. A
// shared library: no loops of its own, no policy.
package underlay

import (
	"fmt"
	"net"
	"net/netip"
)

// BufferSize is the largest datagram the underlay carries, a jumbo frame: the
// data plane's packet buffers and the SCION sockets' reads are this size.
const BufferSize = 9000

// ResolveAddrPort resolves a "host:port" address. IPv4 addresses in the
// v4-mapped IPv6 form are normalized to plain IPv4.
func ResolveAddrPort(s string) (netip.AddrPort, error) {
	a, err := ResolveLocalAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := a.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid address: %q", s)
	}
	if ap.Addr().Is4In6() {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap, nil
}

// ResolveLocalAddr resolves a local address of the form "host:port". The host
// part may be empty, meaning any address. IPv4 addresses in the v4-mapped
// IPv6 form are normalized to plain IPv4.
func ResolveLocalAddr(s string) (*net.UDPAddr, error) {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	if a.IP != nil {
		if ip4 := a.IP.To4(); ip4 != nil {
			a.IP = ip4
		}
	}
	return a, nil
}
