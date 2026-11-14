package fabric

import (
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// line is a rate and a queue bounded by the wait it holds at that rate, as
// a modem's buffer holds a time's worth of its line. Packets leave it one
// after another, each holding the line for its size at the rate, in the
// order they reach it.
type line struct {
	f *Fabric
	// hosts are the hosts the line carries; they never change.
	hosts map[netip.Addr]bool

	// The fabric's mtx guards the rest: the rate in bits per second, the
	// longest wait a packet queues for, when the line falls free, and the
	// window being counted.
	rate  int64
	queue time.Duration
	free  tcpip.MonotonicTime
	win   LineWindow
}

// Uplink is the line its hosts send through to every other host.
type Uplink struct {
	line
}

// Downlink is the line its hosts receive through from every other host.
type Downlink struct {
	line
}

// LineWindow is what a line carried over a window: the packets and bytes it
// sent, the packets it dropped, and the total and the longest wait of the
// packets it sent.
type LineWindow struct {
	Sent, Dropped   int
	Bytes           int64
	Waited, MaxWait time.Duration
}

// MeanWait returns the mean wait of the packets the window sent; zero for
// none.
func (w LineWindow) MeanWait() time.Duration {
	if w.Sent == 0 {
		return 0
	}
	return w.Waited / time.Duration(w.Sent)
}

// DropShare returns the share of the window's packets the line dropped;
// zero for none offered.
func (w LineWindow) DropShare() float64 {
	if w.Sent+w.Dropped == 0 {
		return 0
	}
	return float64(w.Dropped) / float64(w.Sent+w.Dropped)
}

// Uplink draws an uplink carrying the hosts at rate bits per second, its
// queue holding a packet for at most queue: every packet one of the hosts
// sends to a host the uplink does not carry leaves through it, so a node's
// packets to its own host, and those between the members of a site the lab
// draws one uplink over, cross nothing. A host rides one uplink at most.
func (f *Fabric) Uplink(rate int64, queue time.Duration, hosts ...netip.Addr) *Uplink {
	f.t.Helper()
	u := &Uplink{f.newLine(rate, queue, hosts)}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, h := range hosts {
		if _, ok := f.uplinks[h]; ok {
			f.t.Fatalf("%v rides an uplink already", h)
		}
		f.uplinks[h] = u
	}
	return u
}

// Downlink draws a downlink carrying the hosts at rate bits per second, its
// queue holding a packet for at most queue: every packet one of the hosts
// receives from a host the downlink does not carry arrives through it, after
// the sender's uplink and the taps between them. A host rides one downlink
// at most.
func (f *Fabric) Downlink(rate int64, queue time.Duration, hosts ...netip.Addr) *Downlink {
	f.t.Helper()
	d := &Downlink{f.newLine(rate, queue, hosts)}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, h := range hosts {
		if _, ok := f.downlinks[h]; ok {
			f.t.Fatalf("%v rides a downlink already", h)
		}
		f.downlinks[h] = d
	}
	return d
}

// newLine returns a line carrying the hosts at rate bits per second, its
// queue holding a packet for at most queue.
func (f *Fabric) newLine(rate int64, queue time.Duration, hosts []netip.Addr) line {
	f.t.Helper()
	if rate <= 0 {
		f.t.Fatalf("a line's rate is %d bits per second, not above zero", rate)
	}
	l := line{f: f, hosts: make(map[netip.Addr]bool, len(hosts)), rate: rate, queue: queue}
	for _, h := range hosts {
		l.hosts[h] = true
	}
	return l
}

// SetRate changes the line's rate, in bits per second, for the packets that
// reach it after; the packets it queued keep their departures.
func (l *line) SetRate(rate int64) {
	l.f.t.Helper()
	if rate <= 0 {
		l.f.t.Fatalf("a line's rate is %d bits per second, not above zero", rate)
	}
	l.f.mtx.Lock()
	defer l.f.mtx.Unlock()
	l.rate = rate
}

// Window returns what the line carried since the window before, or since it
// was drawn, and starts the next.
func (l *line) Window() LineWindow {
	l.f.mtx.Lock()
	defer l.f.mtx.Unlock()
	w := l.win
	l.win = LineWindow{}
	return w
}

// depart takes a packet of size bytes onto the line at now: false when it
// would wait past the queue's bound, and otherwise how long the line holds
// it, its wait and its serialization. The caller holds the fabric's mtx.
func (l *line) depart(now tcpip.MonotonicTime, size int) (time.Duration, bool) {
	start := now
	if l.free.After(now) {
		start = l.free
	}
	wait := start.Sub(now)
	if wait > l.queue {
		l.win.Dropped++
		return 0, false
	}
	l.free = start.Add(serialization(size, l.rate))
	l.win.Sent++
	l.win.Bytes += int64(size)
	l.win.Waited += wait
	l.win.MaxWait = max(l.win.MaxWait, wait)
	return l.free.Sub(now), true
}

// serialization returns how long a packet of size bytes holds a line of
// rate bits per second.
func serialization(size int, rate int64) time.Duration {
	return time.Duration(int64(size) * 8 * int64(time.Second) / rate)
}
