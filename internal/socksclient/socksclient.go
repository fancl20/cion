// Package socksclient is the minimal RFC 1928 client double the SOCKS
// service's suites exercise — the only SOCKS client written in-tree: standard
// clients are the compatibility surface, and nothing here grows past the
// dialect the service pins — method none, CONNECT, UDP ASSOCIATE, whole
// datagrams.
package socksclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// The dialect's constants, mirrored from RFC 1928 for the double's own
// speech.
const (
	version        byte = 0x05
	methodNone     byte = 0x00
	cmdConnect     byte = 0x01
	cmdAssociate   byte = 0x03
	atypIPv4       byte = 0x01
	atypDomain     byte = 0x03
	atypIPv6       byte = 0x04
	repSucceeded   byte = 0x00
	socksHeaderLen      = 10 // an IPv4 datagram's fixed head
)

// Refused is a service refusal: the reply code it answered with.
type Refused struct {
	Rep byte
}

func (e *Refused) Error() string {
	return fmt.Sprintf("the service answered reply %#x", e.Rep)
}

// Connect negotiates method none over conn and issues CONNECT for address,
// returning the spliced leg: bytes written cross at the destination, and
// the destination's bytes return.
func Connect(conn net.Conn, address string) (net.Conn, error) {
	if err := negotiate(conn); err != nil {
		return nil, err
	}
	if err := writeRequest(conn, cmdConnect, address); err != nil {
		return nil, err
	}
	if err := readReply(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// Relay is one association's client leg: the packet conn the client's
// datagrams ride beside the relay endpoint the reply named.
type Relay struct {
	// Conn is the client's own UDP socket.
	Conn net.PacketConn
	// Addr is the relay endpoint the ASSOCIATE reply carried — the exit's
	// true address and the relay's port.
	Addr netip.AddrPort
}

// Associate negotiates method none over conn and issues UDP ASSOCIATE,
// returning the relay endpoint the reply named beside the client's own
// datagram leg, pc.
func Associate(conn net.Conn, pc net.PacketConn) (*Relay, error) {
	if err := negotiate(conn); err != nil {
		return nil, err
	}
	if err := writeRequest(conn, cmdAssociate, "0.0.0.0:0"); err != nil {
		return nil, err
	}
	addr, port, err := readReplyAddress(conn)
	if err != nil {
		return nil, err
	}
	return &Relay{Conn: pc, Addr: netip.AddrPortFrom(addr, port)}, nil
}

// WriteTo sends payload to dst through the association, the SOCKS header
// naming the destination.
func (r *Relay) WriteTo(payload []byte, dst netip.AddrPort) error {
	_, err := r.Conn.WriteTo(EncodeDatagram(payload, dst), net.UDPAddrFromAddrPort(r.Addr))
	return err
}

// ReadFrom waits one reply: its payload and the source the header names.
func (r *Relay) ReadFrom(payload []byte) (int, netip.AddrPort, error) {
	var buf [1 << 16]byte
	n, _, err := r.Conn.ReadFrom(buf[:])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	got, from, err := DecodeDatagram(buf[:n])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return copy(payload, got), from, nil
}

// EncodeDatagram frames payload for dst the way the client leg sends it.
func EncodeDatagram(payload []byte, dst netip.AddrPort) []byte {
	b := make([]byte, 0, socksHeaderLen+len(payload))
	b = append(b, 0, 0, 0)
	if dst.Addr().Is4() {
		b = append(b, atypIPv4)
		ip := dst.Addr().As4()
		b = append(b, ip[0], ip[1], ip[2], ip[3])
	} else {
		b = append(b, atypIPv6)
		ip := dst.Addr().As16()
		b = append(b, ip[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, dst.Port())
	return append(b, payload...)
}

// DecodeDatagram parses one reply datagram: the payload and the source its
// header names.
func DecodeDatagram(b []byte) (payload []byte, from netip.AddrPort, err error) {
	if len(b) < 4 {
		return nil, netip.AddrPort{}, errors.New("a short datagram")
	}
	var width int
	switch b[3] {
	case atypIPv4:
		width = 4
	case atypIPv6:
		width = 16
	default:
		return nil, netip.AddrPort{}, fmt.Errorf("the datagram's address type %d", b[3])
	}
	if len(b) < 4+width+2 {
		return nil, netip.AddrPort{}, errors.New("a short datagram")
	}
	addr, _ := netip.AddrFromSlice(b[4 : 4+width])
	port := binary.BigEndian.Uint16(b[4+width : 4+width+2])
	return b[4+width+2:], netip.AddrPortFrom(addr.Unmap(), port), nil
}

// negotiate performs the method selection, offering none alone.
func negotiate(conn net.Conn) error {
	if _, err := conn.Write([]byte{version, 1, methodNone}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != version || reply[1] != methodNone {
		return fmt.Errorf("the method reply %x", reply)
	}
	return nil
}

// writeRequest issues one request for address, "host:port".
func writeRequest(conn net.Conn, cmd byte, address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}
	var b []byte
	b = append(b, version, cmd, 0)
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			b = append(b, atypIPv4)
			v4 := ip.As4()
			b = append(b, v4[:]...)
		} else {
			b = append(b, atypIPv6)
			v6 := ip.As16()
			b = append(b, v6[:]...)
		}
	} else {
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	_, err = conn.Write(b)
	return err
}

// readReply reads one reply, refusing every code but success.
func readReply(conn net.Conn) error {
	_, _, err := readReplyAddress(conn)
	return err
}

// readReplyAddress reads one reply's bound address and port.
func readReplyAddress(conn net.Conn) (netip.Addr, uint16, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return netip.Addr{}, 0, err
	}
	if hdr[0] != version {
		return netip.Addr{}, 0, fmt.Errorf("the reply's version %d", hdr[0])
	}
	var addr []byte
	switch hdr[3] {
	case atypIPv4:
		addr = make([]byte, 4)
	case atypIPv6:
		addr = make([]byte, 16)
	default:
		return netip.Addr{}, 0, fmt.Errorf("the reply's address type %d", hdr[3])
	}
	if _, err := io.ReadFull(conn, addr); err != nil {
		return netip.Addr{}, 0, err
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return netip.Addr{}, 0, err
	}
	ip, _ := netip.AddrFromSlice(addr)
	if hdr[1] != repSucceeded {
		return netip.Addr{}, 0, &Refused{Rep: hdr[1]}
	}
	return ip.Unmap(), binary.BigEndian.Uint16(port[:]), nil
}
