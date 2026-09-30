package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"syscall"
)

// The SOCKS dialect (RFC 1928): method none
// is the one offer — tailnet reachability is the admission, hosts existing
// only through registration at the one seam; CONNECT and UDP ASSOCIATE are
// the two commands served, BIND refused; a datagram with FRAG set is
// refused; nothing relays UDP inside TCP; and a UDP ASSOCIATE reply names
// the exit's true tailnet address and the relay endpoint's port, a client
// never asked to guess its relay.
const (
	// Port is the registered SOCKS port the listener binds on the node's
	// own address — a code constant beside the flow bounds, so no argument
	// grows and every client knows it by convention.
	Port = 1080

	// version is SOCKS5's marker, the only version spoken.
	version byte = 0x05

	// methodNone is the no-authentication method, the one offered.
	methodNone byte = 0x00
	// methodNoAcceptable tells a client none of its methods served.
	methodNoAcceptable byte = 0xff

	// The commands: CONNECT and UDP ASSOCIATE are served, BIND refused.
	cmdConnect   byte = 0x01
	cmdBind      byte = 0x02
	cmdAssociate byte = 0x03

	// The address types on the wire.
	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04

	// The reply codes the service answers with.
	repSucceeded           byte = 0x00
	repGeneralFailure      byte = 0x01
	repHostUnreachable     byte = 0x04
	repConnectionRefused   byte = 0x05
	repCommandNotSupported byte = 0x07
)

// destination is one named destination, request or datagram: an address, or
// a domain the node resolves — the destination is the one selector every
// client can already express.
type destination struct {
	ip   netip.Addr
	name string
	port uint16
}

// dialAddr renders the destination a net.Dial call takes: a domain dials by
// name — the node's resolver answers — an address by itself.
func (d destination) dialAddr() string {
	host := d.name
	if host == "" {
		host = d.ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(d.port)))
}

// String renders the destination for logs.
func (d destination) String() string {
	return d.dialAddr()
}

// resolve turns the named destination into an address: an address-named one
// is itself, a domain-named one resolves through the node's resolver under
// the dial timeout's bound, IPv4 preferred — the stack the service
// terminates is IPv4, the outbound legs the node's own sockets.
func (d destination) resolve() (netip.AddrPort, error) {
	if d.name == "" {
		return netip.AddrPortFrom(d.ip, d.port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), egressDialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", d.name)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: %w", d.name, err)
	}
	for _, ip := range ips {
		if ip.Is4() {
			return netip.AddrPortFrom(ip, d.port), nil
		}
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: no address", d.name)
	}
	return netip.AddrPortFrom(ips[0], d.port), nil
}

// negotiate performs the method selection: method none is the one method
// the service offers, and a client offering none of it is refused on the
// spot.
func negotiate(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != version {
		return fmt.Errorf("the SOCKS version %d is not 5", hdr[0])
	}
	if hdr[1] == 0 {
		return errors.New("the client offered no method")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if slices.Contains(methods, methodNone) {
		_, err := conn.Write([]byte{version, methodNone})
		return err
	}
	_, err := conn.Write([]byte{version, methodNoAcceptable})
	if err != nil {
		return err
	}
	return errors.New("no acceptable method offered")
}

// readRequest reads the one request a client sends: VER CMD RSV ATYP
// DST.ADDR DST.PORT.
func readRequest(conn net.Conn) (cmd byte, dst destination, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version {
		err = fmt.Errorf("the request's version %d is not 5", hdr[0])
		return
	}
	if hdr[2] != 0 {
		err = errors.New("the request's reserved field is not zero")
		return
	}
	cmd = hdr[1]
	var addr []byte
	switch hdr[3] {
	case atypIPv4:
		addr = make([]byte, 4)
	case atypIPv6:
		addr = make([]byte, 16)
	case atypDomain:
		var len [1]byte
		if _, err = io.ReadFull(conn, len[:]); err != nil {
			return
		}
		addr = make([]byte, len[0])
	default:
		err = fmt.Errorf("the address type %d is not supported", hdr[3])
		return
	}
	if _, err = io.ReadFull(conn, addr); err != nil {
		return
	}
	var port [2]byte
	if _, err = io.ReadFull(conn, port[:]); err != nil {
		return
	}
	dst.port = binary.BigEndian.Uint16(port[:])
	if hdr[3] == atypDomain {
		if len(addr) == 0 {
			err = errors.New("the domain name is empty")
			return
		}
		dst.name = string(addr)
		return
	}
	if ip, ok := netip.AddrFromSlice(addr); ok {
		dst.ip = ip.Unmap()
		return
	}
	err = errors.New("the destination address is malformed")
	return
}

// reply builds one SOCKS reply around an IPv4 bound address — the form the
// tailnet is; a zero address is the bound-less reply of a refusal.
func reply(rep byte, addr netip.Addr, port uint16) []byte {
	b := make([]byte, 0, 10)
	b = append(b, version, rep, 0, atypIPv4)
	var ip [4]byte
	if addr.Is4() {
		ip = addr.As4()
	}
	b = append(b, ip[0], ip[1], ip[2], ip[3])
	b = append(b, byte(port>>8), byte(port))
	return b
}

// repOfDial maps an outbound leg's failure onto the reply that tells its
// cause: a refused destination says refused, an unresolvable or unreachable
// one says unreachable, and the rest the general failure.
func repOfDial(err error) byte {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return repHostUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnectionRefused
	case errors.Is(err, os.ErrDeadlineExceeded):
		return repHostUnreachable
	default:
		return repGeneralFailure
	}
}

// parseDatagram decodes one client datagram: RSV FRAG ATYP DST.ADDR
// DST.PORT DATA. A datagram with FRAG set is refused — whole datagrams or
// none — and a malformed one with it; neither has an error channel to be
// told on.
func parseDatagram(b []byte) (dst destination, payload []byte, ok bool) {
	if len(b) < 4 {
		return destination{}, nil, false
	}
	if b[0] != 0 || b[1] != 0 {
		return destination{}, nil, false
	}
	if b[2] != 0 {
		// Fragmented: refused.
		return destination{}, nil, false
	}
	addr := b[4:]
	var width int
	switch b[3] {
	case atypIPv4:
		width = 4
	case atypIPv6:
		width = 16
	case atypDomain:
		if len(addr) < 1 {
			return destination{}, nil, false
		}
		width = 1 + int(addr[0])
	default:
		return destination{}, nil, false
	}
	if len(addr) < width+2 {
		return destination{}, nil, false
	}
	port := binary.BigEndian.Uint16(addr[width:])
	addr = addr[:width]
	switch b[3] {
	case atypIPv4:
		ip, _ := netip.AddrFromSlice(addr)
		dst.ip = ip.Unmap()
	case atypIPv6:
		ip, _ := netip.AddrFromSlice(addr)
		dst.ip = ip.Unmap()
	default:
		dst.name = string(addr[1:])
	}
	dst.port = port
	return dst, b[4+width+2:], true
}

// appendDatagram builds one reply datagram around the payload: RSV FRAG(0)
// ATYP DST.ADDR DST.PORT, the destination the reply came from.
func appendDatagram(b []byte, from netip.AddrPort, payload []byte) []byte {
	b = append(b, 0, 0, 0)
	if from.Addr().Is4() {
		b = append(b, atypIPv4)
		ip := from.Addr().As4()
		b = append(b, ip[0], ip[1], ip[2], ip[3])
	} else {
		b = append(b, atypIPv6)
		ip := from.Addr().As16()
		for _, octet := range ip {
			b = append(b, octet)
		}
	}
	b = binary.BigEndian.AppendUint16(b, from.Port())
	return append(b, payload...)
}
