// Package underlay holds the facts of the UDP/IP network beneath SCION that the
// data plane shares with the node's sockets: the end-host port, the largest
// datagram, the underlay types, the resolution of underlay addresses, and the
// socket source the node's sites bind through — the kernel's the default. A
// shared library: no loops of its own, no policy.
package underlay

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// BufferSize is the largest datagram the underlay carries, a jumbo frame: the
// data plane's packet buffers and the SCION sockets' reads are this size.
const BufferSize = 9000

// routeProbePort is the port RouteSource's socket connects to: routes name
// hosts alone, so any port asks the same question.
const routeProbePort = 9

// RouteSource returns the local address the kernel's routing table sends
// from toward dst: dst itself where one of the host's interfaces carries it,
// else the address of the interface the route leaves through — behind an
// address translation, the inside address and never the translated one. A
// connected UDP socket asks the table; no datagram leaves.
func RouteSource(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, routeProbePort)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// ResolveAddrPort resolves a "host:port" address whose host names an address.
// IPv4 addresses in the v4-mapped IPv6 form are normalized to plain IPv4.
func ResolveAddrPort(s string) (netip.AddrPort, error) {
	a, err := ResolveLocalAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := a.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid address: %q", s)
	}
	return ap, nil
}

// ResolveAddrPortDefault resolves an address as ResolveAddrPort does, a form
// without a port naming the given default port instead.
func ResolveAddrPortDefault(s string, defaultPort uint16) (netip.AddrPort, error) {
	if _, _, err := net.SplitHostPort(s); err != nil {
		s = net.JoinHostPort(s, strconv.Itoa(int(defaultPort)))
	}
	return ResolveAddrPort(s)
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
