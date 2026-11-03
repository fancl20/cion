package egress

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// tcpFlow is one spliced TCP flow: the host's leg the netstack ended and the
// outbound leg from the node's own socket.
type tcpFlow struct {
	in, out net.Conn
	last    atomic.Int64
}

func (f *tcpFlow) close() {
	_ = f.in.Close()
	_ = f.out.Close()
}

// udpFlow is one mapped UDP flow: the host's leg the netstack ended and the
// node's own socket, connected to the destination, the reply mapping.
type udpFlow struct {
	in   *gonet.UDPConn
	out  *net.UDPConn
	last atomic.Int64
}

func (f *udpFlow) close() {
	_ = f.in.Close()
	_ = f.out.Close()
}

// forwardTCP serves one TCP flow a host opened that no listener holds. A
// flow toward the tailnet — the node's own address at a port no listener
// holds — or past the flow bound is refused with a reset. Any other dials
// its outbound leg first, from the node's own sockets under Run's context,
// so a destination that refuses or never answers reaches the host as a
// reset; a dialed flow alone completes the host's handshake and splices.
// gVisor runs each request in a goroutine of its own, which joins Run's
// wait group while Run serves.
func (a *App) forwardTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dst := netip.AddrPortFrom(addressToNetip(id.LocalAddress), id.LocalPort)
	if wireguard.Tailnet.Contains(dst.Addr()) {
		a.refuseTCP(req)
		return
	}
	ctx, ok := a.joinDial()
	if !ok {
		a.refuseTCP(req)
		return
	}
	defer a.wg.Done()
	out, err := a.dial(ctx, "tcp", a.internet(dst).String())
	if err != nil {
		a.settleDial(nil)
		slog.Debug("Egress dialing a TCP flow", "dst", dst, "err", err)
		a.refuseTCP(req)
		return
	}
	// A handshake started once the stop closed the netstack would escape
	// the close's abort and hold Run until its retries ran out, so a flow
	// dialed past the stop is refused.
	if !a.serving() {
		_ = out.Close()
		a.settleDial(nil)
		a.refuseTCP(req)
		return
	}
	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	req.Complete(false)
	if tcpErr != nil {
		_ = out.Close()
		a.settleDial(nil)
		a.cnt.droppedPackets.Add(1)
		return
	}
	flow := &tcpFlow{in: gonet.NewTCPConn(&wq, ep), out: out}
	flow.last.Store(time.Now().UnixNano())
	if !a.settleDial(flow) {
		flow.close()
		return
	}
	defer a.removeTCPFlow(flow)
	spliceConns(flow.in, flow.out, &flow.last)
}

// refuseTCP refuses a TCP flow with a reset, counting it.
func (a *App) refuseTCP(req *tcp.ForwarderRequest) {
	a.cnt.droppedPackets.Add(1)
	req.Complete(true)
}

// joinDial joins a TCP flow's goroutine to Run's wait group and holds the
// flow's place against the flow bound while it dials, returning Run's
// context; false once Run stopped or at the flow bound.
func (a *App) joinDial() (context.Context, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.stopped || a.atCapacityLocked() {
		return nil, false
	}
	a.dialing++
	a.wg.Add(1)
	return a.ctx, true
}

// settleDial ends a TCP flow's dialing: a dialed flow enters the table,
// false once Run stopped; a nil flow, failed, gives its place back alone.
func (a *App) settleDial(f *tcpFlow) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.dialing--
	if f == nil || a.stopped {
		return false
	}
	a.tcpFlows[f] = struct{}{}
	return true
}

// serving reports whether Run still serves.
func (a *App) serving() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return !a.stopped
}

// removeTCPFlow retires one TCP flow from the table and closes it.
func (a *App) removeTCPFlow(f *tcpFlow) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	delete(a.tcpFlows, f)
	f.close()
}

// forwardUDP maps one UDP flow a host opened that no endpoint holds to one
// socket of the node's own, connected to the destination so the
// destination's replies alone return: the socket is the reply mapping. A
// flow toward the tailnet — the node's own address at a port no endpoint
// holds — past the flow bound, or whose socket the system refuses is
// declined, counted, and answered by the netstack as an unreachable port.
// The forwarder runs on the delivering goroutine.
func (a *App) forwardUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	dst := netip.AddrPortFrom(addressToNetip(id.LocalAddress), id.LocalPort)
	if wireguard.Tailnet.Contains(dst.Addr()) {
		a.cnt.droppedPackets.Add(1)
		return false
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.stopped || a.atCapacityLocked() {
		a.cnt.droppedPackets.Add(1)
		return false
	}
	out, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(a.internet(dst)))
	if err != nil {
		a.cnt.droppedPackets.Add(1)
		slog.Debug("Egress binding a UDP flow's socket", "dst", dst, "err", err)
		return false
	}
	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		_ = out.Close()
		a.cnt.droppedPackets.Add(1)
		return false
	}
	flow := &udpFlow{in: gonet.NewUDPConn(&wq, ep), out: out}
	flow.last.Store(time.Now().UnixNano())
	a.udpFlows[flow] = struct{}{}
	a.wg.Go(func() { a.pumpUDP(flow) })
	return true
}

// pumpUDP relays one UDP flow both ways until a leg fails: the host's
// datagrams leave the node's socket, and the destination's replies return on
// the host's leg. The refusal a connected socket reads once the destination
// answered with an unreachable port leaves the mapping standing until it
// idles out.
func (a *App) pumpUDP(f *udpFlow) {
	defer a.removeUDPFlow(f)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer f.close()
		buf := make([]byte, 64<<10)
		for {
			n, err := f.in.Read(buf)
			if err != nil {
				return
			}
			f.last.Store(time.Now().UnixNano())
			if _, err := f.out.Write(buf[:n]); err != nil && !refused(err) {
				return
			}
		}
	})
	buf := make([]byte, 64<<10)
	for {
		n, err := f.out.Read(buf)
		if refused(err) {
			continue
		}
		if err != nil {
			break
		}
		f.last.Store(time.Now().UnixNano())
		if _, err := f.in.Write(buf[:n]); err != nil {
			break
		}
	}
	f.close()
	wg.Wait()
}

// refused reports whether err is the refusal a connected UDP socket reads
// once the destination answered a datagram with an unreachable port.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// removeUDPFlow retires one UDP flow from the table and closes it.
func (a *App) removeUDPFlow(f *udpFlow) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	delete(a.udpFlows, f)
	f.close()
}

// spliceConns copies both directions between the legs, propagating
// half-closes, and touches last on every byte moved.
func spliceConns(a, b net.Conn, last *atomic.Int64) {
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					_ = dst.Close()
					_ = src.Close()
					return
				}
			}
			if err != nil {
				// A finished direction half-closes the leg so the peer
				// sees the end of stream instead of a hang.
				if hc, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = hc.CloseWrite()
				} else {
					_ = dst.Close()
				}
				return
			}
		}
	}
	wg.Go(func() { copyOne(a, b) })
	wg.Go(func() { copyOne(b, a) })
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
