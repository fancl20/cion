package underlay

import (
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// UDPConn is a UDP socket with the operations the node's sites use: the
// datagram pair the control plane and the rendezvous exchange read and write
// beside the batch pair the data plane's connections run, the deadlines, the
// bound address, buffer sizing, and Close. ipv4.Message and ipv6.Message are
// aliases of one underlying type, so one message slice serves both address
// families.
type UDPConn interface {
	// ReadFromUDP reads the next datagram, returning it with the sender's
	// address.
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	// WriteToUDP sends one datagram to the given destination.
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	// ReadBatch reads datagrams into msgs until one lands or the wait
	// elapses, then fills whatever is immediately ready — the shape
	// MSG_WAITFORONE gives the kernel's own.
	ReadBatch(msgs []ipv4.Message) (int, error)
	// WriteBatch sends the msgs' datagrams, reporting how many left.
	WriteBatch(msgs []ipv4.Message) (int, error)
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	// LocalAddr returns the socket's bound address, a concrete port after
	// a bind that named none.
	LocalAddr() *net.UDPAddr
	// SetReadBuffer and SetWriteBuffer size the socket's buffers; best
	// effort, for not every backing socket honors them.
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	Close() error
}

// Sockets is the node's socket source: the seam the packages that bind
// underlay sockets construct through, so the whole node can boot on one
// network. The zero value is the kernel source — the sockets the sites
// opened before the seam — so a caller that names no network gets the
// kernel's own semantics.
type Sockets struct {
	// ListenUDP binds an unconnected UDP socket on listen. A valid
	// remoteHint names the family a wildcard listen host binds under —
	// the kernel implementation's own selection; an implementation that
	// owns its port space binds the address it is given.
	ListenUDP func(listen *net.UDPAddr, remoteHint netip.AddrPort) (UDPConn, error)
	// ListenTCP binds a TCP listener on the "host:port" address — the
	// founder's HTTPS bind.
	ListenTCP func(addr string) (net.Listener, error)
}

// Kernel is the kernel socket source: the sockets the sites opened before
// the seam.
var Kernel = Sockets{}

// NewUDP binds an unconnected UDP socket through the source, the kernel's
// where the source names none.
func (s Sockets) NewUDP(listen *net.UDPAddr, remoteHint netip.AddrPort) (UDPConn, error) {
	if s.ListenUDP != nil {
		return s.ListenUDP(listen, remoteHint)
	}
	return kernelUDP(listen, remoteHint)
}

// NewTCP binds a TCP listener through the source, the kernel's where the
// source names none.
func (s Sockets) NewTCP(addr string) (net.Listener, error) {
	if s.ListenTCP != nil {
		return s.ListenTCP(addr)
	}
	return net.Listen("tcp", addr)
}

// kernelConn is the kernel's UDP socket: a net.UDPConn beside the batch
// sockets its packet conns give.
type kernelConn struct {
	conn *net.UDPConn
	pc4  *ipv4.PacketConn
	pc6  *ipv6.PacketConn
}

// kernelUDP opens a kernel UDP socket bound to listen, unconnected. A valid
// remoteHint names the family the link's initial locator spells, so a
// wildcard listen host of the other family — the wildcard-bound link's
// recorded local address, whose port alone it names — binds that family's
// wildcard at the same port; without a hint the kernel's own "udp" bind
// answers, the wildcard of either family binding dual-stack IPv6.
func kernelUDP(
	listen *net.UDPAddr,
	remoteHint netip.AddrPort,
) (UDPConn, error) {

	network := "udp"
	if remoteHint.IsValid() {
		wildcard := net.IPv6zero
		if remoteHint.Addr().Is4() || remoteHint.Addr().Is4In6() {
			network = "udp4"
			wildcard = net.IPv4zero
		} else {
			network = "udp6"
		}
		if listen.IP.IsUnspecified() && (listen.IP.To4() != nil) != (wildcard.To4() != nil) {
			listen = &net.UDPAddr{IP: wildcard, Port: listen.Port}
		}
	}

	c, err := net.ListenUDP(network, listen)
	if err != nil {
		return nil, err
	}
	uc := &kernelConn{conn: c}
	if c.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		uc.pc4 = ipv4.NewPacketConn(c)
	} else {
		uc.pc6 = ipv6.NewPacketConn(c)
	}
	return uc, nil
}

func (c *kernelConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	return c.conn.ReadFromUDP(b)
}

func (c *kernelConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.conn.WriteToUDP(b, addr)
}

func (c *kernelConn) ReadBatch(msgs []ipv4.Message) (int, error) {
	if c.pc4 != nil {
		return c.pc4.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	}
	return c.pc6.ReadBatch(msgs, syscall.MSG_WAITFORONE)
}

func (c *kernelConn) WriteBatch(msgs []ipv4.Message) (int, error) {
	if c.pc4 != nil {
		return c.pc4.WriteBatch(msgs, 0)
	}
	return c.pc6.WriteBatch(msgs, 0)
}

func (c *kernelConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *kernelConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *kernelConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *kernelConn) LocalAddr() *net.UDPAddr {
	return c.conn.LocalAddr().(*net.UDPAddr)
}

func (c *kernelConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *kernelConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}

func (c *kernelConn) Close() error {
	return c.conn.Close()
}
