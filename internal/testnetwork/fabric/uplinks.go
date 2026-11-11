package fabric

import (
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// Uplink is the line its hosts send through to every other host: a rate,
// and a queue bounded by the wait it holds at that rate, as a modem's buffer
// holds a time's worth of its line. Packets leave it one after another, each
// holding the line for its size at the rate, in the order they were sent.
type Uplink struct {
	f *Fabric
	// hosts are the hosts the uplink carries; they never change.
	hosts map[netip.Addr]bool

	// The fabric's mtx guards the rest: the rate in bits per second, the
	// longest wait a packet queues for, when the line falls free, and the
	// window being counted.
	rate  int64
	queue time.Duration
	free  tcpip.MonotonicTime
	win   UplinkWindow
}

// UplinkWindow is what an uplink carried over a window: the packets and
// bytes it sent, the packets it dropped, and the total and the longest wait
// of the packets it sent.
type UplinkWindow struct {
	Sent, Dropped   int
	Bytes           int64
	Waited, MaxWait time.Duration
}

// MeanWait returns the mean wait of the packets the window sent; zero for
// none.
func (w UplinkWindow) MeanWait() time.Duration {
	if w.Sent == 0 {
		return 0
	}
	return w.Waited / time.Duration(w.Sent)
}

// DropShare returns the share of the window's packets the uplink dropped;
// zero for none offered.
func (w UplinkWindow) DropShare() float64 {
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
	if rate <= 0 {
		f.t.Fatalf("an uplink's rate is %d bits per second, not above zero", rate)
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	u := &Uplink{f: f, hosts: make(map[netip.Addr]bool, len(hosts)), rate: rate, queue: queue}
	for _, h := range hosts {
		if _, ok := f.uplinks[h]; ok {
			f.t.Fatalf("%v rides an uplink already", h)
		}
		f.uplinks[h] = u
		u.hosts[h] = true
	}
	return u
}

// SetRate changes the uplink's rate, in bits per second, for the packets
// sent after it; the packets it queued keep their departures.
func (u *Uplink) SetRate(rate int64) {
	u.f.t.Helper()
	if rate <= 0 {
		u.f.t.Fatalf("an uplink's rate is %d bits per second, not above zero", rate)
	}
	u.f.mtx.Lock()
	defer u.f.mtx.Unlock()
	u.rate = rate
}

// Window returns what the uplink carried since the window before, or since
// it was drawn, and starts the next.
func (u *Uplink) Window() UplinkWindow {
	u.f.mtx.Lock()
	defer u.f.mtx.Unlock()
	w := u.win
	u.win = UplinkWindow{}
	return w
}

// depart takes a packet of size bytes onto the line at now: false when it
// would wait past the queue's bound, and otherwise how long the uplink holds
// it, its wait and its serialization. The caller holds the fabric's mtx.
func (u *Uplink) depart(now tcpip.MonotonicTime, size int) (time.Duration, bool) {
	start := now
	if u.free.After(now) {
		start = u.free
	}
	wait := start.Sub(now)
	if wait > u.queue {
		u.win.Dropped++
		return 0, false
	}
	u.free = start.Add(serialization(size, u.rate))
	u.win.Sent++
	u.win.Bytes += int64(size)
	u.win.Waited += wait
	u.win.MaxWait = max(u.win.MaxWait, wait)
	return u.free.Sub(now), true
}

// serialization returns how long a packet of size bytes holds a line of
// rate bits per second.
func serialization(size int, rate int64) time.Duration {
	return time.Duration(int64(size) * 8 * int64(time.Second) / rate)
}
