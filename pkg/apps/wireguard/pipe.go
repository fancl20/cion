package wireguard

import (
	"net"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// pipeDepth bounds the packets queued in each direction of a pipe; a full
// direction drops rather than blocks the writer — an overlay is allowed to
// lose, never to stall the process.
const pipeDepth = 256

// pipe is an in-process packet pipe: wireguard-go's device interface with a
// kernel TUN's two halves as channels. The router reads packets the device
// decrypted from outbound and queues packets to encrypt on inbound; nothing
// in the operating system ever holds overlay state (ADR-0005).
type pipe struct {
	name string
	mtu  int
	cnt  *counters
	// inbound queues plaintext packets for the device to read — packets the
	// router routed into this tunnel.
	inbound chan []byte
	// outbound carries packets the device decrypted — packets the router
	// takes away. Each packet is freshly allocated and owned by the reader.
	outbound chan []byte
	events   chan tun.Event
	closeOne sync.Once
	closed   chan struct{}
}

func newPipe(name string, mtu int, cnt *counters) *pipe {
	return &pipe{
		name:     name,
		mtu:      mtu,
		cnt:      cnt,
		inbound:  make(chan []byte, pipeDepth),
		outbound: make(chan []byte, pipeDepth),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
}

// File implements tun.Device; a pipe owns none.
func (p *pipe) File() *os.File { return nil }

// Read returns queued packets, written at offset, until the pipe closes.
func (p *pipe) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	select {
	case pkt := <-p.inbound:
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		for n = 1; n < len(bufs); n++ {
			select {
			case pkt := <-p.inbound:
				copy(bufs[n][offset:], pkt)
				sizes[n] = len(pkt)
			default:
				return n, nil
			}
		}
		return n, nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

// Write takes the device's decrypted packets from offset into the router's
// half.
func (p *pipe) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case p.outbound <- pkt:
		case <-p.closed:
			return 0, net.ErrClosed
		default:
			// The router lags; drop rather than stall the receive path.
			p.cnt.droppedPackets.Add(1)
		}
	}
	return len(bufs), nil
}

func (p *pipe) MTU() (int, error) { return p.mtu, nil }

func (p *pipe) Name() (string, error) { return p.name, nil }

func (p *pipe) Events() <-chan tun.Event { return p.events }

func (p *pipe) BatchSize() int { return 16 }

// Close stops both halves. Reads and writes thereafter report the pipe
// closed, which retires the device's routines.
func (p *pipe) Close() error {
	p.closeOne.Do(func() {
		close(p.closed)
		close(p.events)
	})
	return nil
}

// deliver queues a routed packet for the device to encrypt, dropping it when
// the pipe is full or closed.
func (p *pipe) deliver(pkt []byte) {
	select {
	case p.inbound <- pkt:
	case <-p.closed:
	default:
		p.cnt.droppedPackets.Add(1)
	}
}

// drain takes packets away from the device until the pipe closes; the router
// runs it once per device.
func (p *pipe) drain(fn func(pkt []byte)) {
	for {
		select {
		case pkt := <-p.outbound:
			fn(pkt)
		case <-p.closed:
			return
		}
	}
}
