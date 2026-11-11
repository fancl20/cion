package testnetwork

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
)

// flowHeader is the bytes a flow's datagram leads with: its sequence and
// its send time, in nanoseconds of the bubble's clock.
const flowHeader = 16

// flowRetry spaces a sender's asks for its lease's first path.
const flowRetry = time.Second

// Flow is a stream of datagrams one node sends another at a rate, over the
// path the sender's path library leases: the sender's conn rides the node's
// internal link and marks no control class, so its packets cross every
// transit as data. The receiver counts what arrives and reads each
// datagram's one-way delay on the clock both ends share.
type Flow struct {
	// stop ends the flow once, returning when both ends have.
	stop func()

	// mtx guards the window being counted: the datagrams offered and the
	// one-way delays of those received.
	mtx     sync.Mutex
	offered int
	delays  []time.Duration
}

// FlowWindow is what a flow carried over a window: the datagrams offered,
// and the one-way delays of those received, ascending.
type FlowWindow struct {
	Offered int
	Delays  []time.Duration
}

// Received returns how many of the window's datagrams arrived.
func (w FlowWindow) Received() int { return len(w.Delays) }

// DeliveredShare returns the share of the window's offered datagrams that
// arrived; zero for none offered. A datagram sent at a window's end and
// received in the next counts there, so a share may pass one.
func (w FlowWindow) DeliveredShare() float64 {
	if w.Offered == 0 {
		return 0
	}
	return float64(len(w.Delays)) / float64(w.Offered)
}

// Quantile returns the delay at the quantile q of those received, by
// nearest rank; zero for none received.
func (w FlowWindow) Quantile(q float64) time.Duration {
	if len(w.Delays) == 0 {
		return 0
	}
	return w.Delays[min(len(w.Delays)-1, int(q*float64(len(w.Delays))))]
}

// Add returns the window of both flows' datagrams: the offered summed, the
// delays merged.
func (w FlowWindow) Add(o FlowWindow) FlowWindow {
	delays := slices.Concat(w.Delays, o.Delays)
	slices.Sort(delays)
	return FlowWindow{Offered: w.Offered + o.Offered, Delays: delays}
}

// StartFlow starts a flow of rate bits per second of datagrams of size bytes
// from one node to the port of another, until Stop or the test ends. The
// sender awaits its lease's first path to the receiver, asking again each
// flowRetry, then offers a datagram at random times, a mean of size bytes
// at the rate apart — the arrivals of a Poisson process, so that flows
// never lock in step with each other or with a queue — and reads the
// lease's path for each: one with no path counts as offered and unsent.
func StartFlow(t *testing.T, from, to *Node, port uint16, rate int64, size int) *Flow {
	t.Helper()
	if size < flowHeader || rate <= 0 {
		t.Fatalf("a flow of %d-byte datagrams at %d bits per second", size, rate)
	}
	recv, err := to.App().Conn(port)
	if err != nil {
		t.Fatalf("binding the flow's receiver on %v port %d: %v", to.Host(), port, err)
	}
	send, err := from.App().Conn(0)
	if err != nil {
		_ = recv.Close()
		t.Fatalf("binding the flow's sender on %v: %v", from.Host(), err)
	}
	fl := &Flow{}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { fl.receive(recv) })
	wg.Go(func() {
		fl.send(ctx, send, from.App().Provider().Lease(to.App().IA()),
			&scion.Addr{IA: to.App().IA(), Addr: netip.AddrPortFrom(to.Host(), port)},
			time.Duration(int64(size)*8*int64(time.Second)/rate), size)
	})
	fl.stop = sync.OnceFunc(func() {
		cancel()
		_ = recv.Close()
		_ = send.Close()
		wg.Wait()
	})
	t.Cleanup(fl.stop)
	return fl
}

// Stop ends the flow, returning once its sender and receiver have; a
// window read after it counts what arrived before.
func (fl *Flow) Stop() { fl.stop() }

// send offers a datagram to the peer a mean of interval apart, over the
// lease's path, until ctx ends.
func (fl *Flow) send(ctx context.Context, c *scion.Conn, lease *scion.Lease, peer *scion.Addr,
	interval time.Duration, size int) {

	for {
		if _, err := lease.Await(ctx); err == nil {
			break
		}
		if !loops.Sleep(ctx, flowRetry) {
			return
		}
	}
	buf := make([]byte, size)
	for seq := uint64(0); ; seq++ {
		if !loops.Sleep(ctx, time.Duration(rand.ExpFloat64()*float64(interval))) {
			return
		}
		fl.mtx.Lock()
		fl.offered++
		fl.mtx.Unlock()
		leased, err := lease.Path()
		if err != nil {
			continue
		}
		binary.BigEndian.PutUint64(buf, seq)
		binary.BigEndian.PutUint64(buf[8:], uint64(time.Now().UnixNano()))
		to := *peer
		to.Path = leased.Path
		_, _ = c.WriteTo(buf, &to)
	}
}

// receive records the one-way delay of every datagram the conn reads, until
// it closes.
func (fl *Flow) receive(c *scion.Conn) {
	buf := make([]byte, flowHeader)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < flowHeader {
			continue
		}
		sent := time.Unix(0, int64(binary.BigEndian.Uint64(buf[8:])))
		fl.mtx.Lock()
		fl.delays = append(fl.delays, time.Since(sent))
		fl.mtx.Unlock()
	}
}

// Window returns what the flow carried since the window before, or since
// it started, and starts the next.
func (fl *Flow) Window() FlowWindow {
	fl.mtx.Lock()
	defer fl.mtx.Unlock()
	slices.Sort(fl.delays)
	w := FlowWindow{Offered: fl.offered, Delays: fl.delays}
	fl.offered, fl.delays = 0, nil
	return w
}
