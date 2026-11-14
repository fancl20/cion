package scion

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.org/x/net/ipv4"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

var (
	ecnLocal = addr.MustIAFrom(20, 0xff0000000001)
	ecnPeer  = addr.MustIAFrom(20, 0xff0000000002)
)

// mbit is a megabit a second, in bits a second.
const mbit = 1_000_000.0

// offer offers the state writes to dst of size bytes at bps, one each
// size*8/bps from start until span ends, and returns how many it took.
func offer(e *ECN, dst addr.IA, start time.Time, span time.Duration, bps float64, size int) int {
	gap := time.Duration(float64(size*8) * float64(time.Second) / bps)
	taken := 0
	for at := start; at.Before(start.Add(span)); at = at.Add(gap) {
		if e.admit(dst, size, at) {
			taken++
		}
	}
	return taken
}

// withBase returns a fresh state whose destination was sent 1 Mbit in each
// of the two seconds from start, its base, and when they ended.
func withBase(start time.Time) (*ECN, time.Time) {
	e := NewECN()
	offer(e, ecnPeer, start, 2*time.Second, mbit, 1250)
	return e, start.Add(2 * time.Second)
}

// TestECNWritesAtOnceWithoutARate checks that a destination without a rate
// takes every write, however many arrive at once.
func TestECNWritesAtOnceWithoutARate(t *testing.T) {
	e := NewECN()
	now := time.Unix(1_700_000_000, 0)
	for i := range 1000 {
		if !e.admit(ecnPeer, 1500, now) {
			t.Fatalf("write %d at once dropped without a rate", i)
		}
	}
}

// TestECNCuts checks a marked answer's cut, for a destination sent 1 Mbit
// in each of its last seconds, its base: to 1 - average/2 of the lesser of
// the rate and the base, an unset rate from the base, never under the floor
// and never set from a base under it; an answer to a probe sent before the
// last cut or at it cuts nothing, nor does a clean one.
func TestECNCuts(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name   string
		bps    float64
		rate   float64
		alpha  float64
		marked bool
		// sent is when the probe was sent, against the last cut.
		sent time.Duration
		want float64
	}{
		{"unset, clean", mbit, 0, 1, false, time.Millisecond, 0},
		{"unset, marked", mbit, 0, 1, true, time.Millisecond, mbit / 2},
		{"unset, marked, a base under the floor", 40_000, 0, 1, true, time.Millisecond, 0},
		{"set under the base, marked", mbit, 800_000, 1, true, time.Millisecond, 400_000},
		{"set over the base, marked", mbit, 1.5 * mbit, 1, true, time.Millisecond, mbit / 2},
		{"set near the floor, marked", mbit, 100_000, 1, true, time.Millisecond, rateFloor},
		{"set, marked, probe sent before the last cut", mbit, 800_000, 1, true, -time.Millisecond, 800_000},
		{"set, marked, probe sent at the last cut", mbit, 800_000, 1, true, 0, 800_000},
		{"set, clean", mbit, 800_000, 1, false, time.Millisecond, 800_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewECN()
			offer(e, ecnPeer, start, 2*time.Second, tc.bps, 1250)
			now := start.Add(2 * time.Second)
			cut := now.Add(-time.Second)
			d := e.dests[ecnPeer]
			d.rate, d.alpha, d.cut, d.moved = tc.rate, tc.alpha, cut, cut
			e.answer(ecnPeer, tc.marked, cut.Add(tc.sent), now)
			if d.rate != tc.want {
				t.Errorf("rate %v, want %v", d.rate, tc.want)
			}
		})
	}
}

// TestECNStrayMarksCutLittle checks the average's start: it stands at zero
// through clean answers, the first marked one moves it by rateGain and sets
// the rate at 1 - rateGain/2 of the base, and each answer after it moves the
// average whether or not a rate is set.
func TestECNStrayMarksCutLittle(t *testing.T) {
	e, now := withBase(time.Unix(1_700_000_000, 0))
	for range 32 {
		e.answer(ecnPeer, false, now, now)
	}
	d := e.dests[ecnPeer]
	if d.alpha != 0 || d.rate != 0 {
		t.Fatalf("average %v, rate %v after clean answers, want zero and unset", d.alpha, d.rate)
	}
	now = now.Add(time.Millisecond)
	e.answer(ecnPeer, true, now, now)
	if want := (1 - rateGain/2) * mbit; d.rate != want || d.alpha != rateGain {
		t.Fatalf("rate %v, average %v after the first marked answer, want %v and %v",
			d.rate, d.alpha, want, rateGain)
	}
	e.answer(ecnPeer, false, now, now)
	if want := rateGain * (1 - rateGain); d.alpha != want {
		t.Errorf("average %v after a clean answer, want %v", d.alpha, want)
	}
}

// TestECNCutsDeepenWithTheAverage checks that the cuts deepen as the
// average share of marked answers grows: once a rate is set and clean
// answers bring the average low, each marked answer to a probe sent after
// the last cut moves it by rateGain toward one, and cuts to 1 - average/2 of
// the rate, less than the cut before left.
func TestECNCutsDeepenWithTheAverage(t *testing.T) {
	e, now := withBase(time.Unix(1_700_000_000, 0))
	e.answer(ecnPeer, true, now, now)
	alpha := rateGain
	for range 32 {
		e.answer(ecnPeer, false, now, now)
		alpha -= rateGain * alpha
	}
	d := e.dests[ecnPeer]
	rate, kept := (1-rateGain/2)*mbit, 1.0
	for i := range 5 {
		now = now.Add(time.Millisecond)
		e.answer(ecnPeer, true, now, now)
		alpha += rateGain * (1 - alpha)
		want := (1 - alpha/2) * rate
		if math.Abs(d.rate-want) > 1e-6*want {
			t.Fatalf("cut %d left %v, want %v", i, d.rate, want)
		}
		if keep := d.rate / rate; keep >= kept {
			t.Errorf("cut %d kept %v of the rate, want less than the %v the cut before kept", i, keep, kept)
		} else {
			kept = keep
		}
		rate = d.rate
	}
}

// TestECNClimbsToTwiceTheBase checks the climb: ticks closed after a marked
// answer raise nothing, and each tick closed after a clean one raises a set
// rate by rateClimb while the destination is offered its base, 1 Mbit/s,
// until the rate stands at twice the base, never past it.
func TestECNClimbsToTwiceTheBase(t *testing.T) {
	e, now := withBase(time.Unix(1_700_000_000, 0))
	e.answer(ecnPeer, true, now, now)
	d := e.dests[ecnPeer]
	first := (1 - rateGain/2) * mbit
	if d.rate != first {
		t.Fatalf("rate %v after a marked answer, want %v", d.rate, first)
	}
	offer(e, ecnPeer, now, time.Second, mbit, 1250)
	now = now.Add(time.Second)
	if d.rate != first {
		t.Fatalf("rate %v a second after a marked answer, want held at %v", d.rate, first)
	}
	e.answer(ecnPeer, false, now, now)
	offer(e, ecnPeer, now, time.Second, mbit, 1250)
	now = now.Add(time.Second)
	// The second's last write closed its ninth tick.
	if want := first * math.Pow(1+rateClimb, 9); math.Abs(d.rate-want) > 1e-6*want {
		t.Errorf("rate %v nine ticks after a clean answer, want %v", d.rate, want)
	}
	highest := 0.0
	for range 30 {
		offer(e, ecnPeer, now, time.Second, mbit, 1250)
		now = now.Add(time.Second)
		highest = max(highest, d.rate)
	}
	if d.rate != 2*mbit || highest > 2*mbit {
		t.Errorf("rate %v, at most %v, after 31s of clean answers, want twice the base, %v, and never past it",
			d.rate, highest, 2*mbit)
	}
}

// TestECNUnsetsUnmoved checks that a rate neither cut nor climbed for
// rateUnset holds until then, and unsets at the destination's next event,
// its average share of marked answers kept.
func TestECNUnsetsUnmoved(t *testing.T) {
	e, cut := withBase(time.Unix(1_700_000_000, 0))
	e.answer(ecnPeer, true, cut, cut)
	// A marked answer to a probe sent at the cut stops the climb without a
	// cut.
	e.answer(ecnPeer, false, cut, cut)
	e.answer(ecnPeer, true, cut, cut)
	d := e.dests[ecnPeer]
	rate, alpha := d.rate, d.alpha
	if rate == 0 {
		t.Fatal("no rate set after a marked answer")
	}
	offer(e, ecnPeer, cut, rateUnset-rateTick, mbit, 1250)
	if d.rate != rate {
		t.Fatalf("rate %v a tick short of %v after the cut, want held at %v", d.rate, rateUnset, rate)
	}
	e.admit(ecnPeer, 1250, cut.Add(rateUnset))
	if d.rate != 0 || d.alpha != alpha {
		t.Errorf("rate %v, average %v, %v after the cut, want unset, and %v", d.rate, d.alpha, rateUnset, alpha)
	}
}

// TestECNBaseForgetsOldSeconds checks that the base reaches back rateBase
// seconds and the second those seconds' windows began in: a destination sent
// 1 Mbit/s for two seconds, then 100 kbit/s for rateBase+1 seconds more, has
// a base of 100 kbit/s.
func TestECNBaseForgetsOldSeconds(t *testing.T) {
	e, now := withBase(time.Unix(1_700_000_000, 0))
	span := (rateBase+1)*time.Second + rateTick
	offer(e, ecnPeer, now, span, 100_000, 1250)
	if got := e.dests[ecnPeer].base(); got > 2*100_000 {
		t.Errorf("base %v bit/s %v after the megabit seconds, want the 100 kbit/s since", got, span)
	}
}

// TestECNDropsWritesPastTheHold checks the pacing at a set rate: writes run
// ahead of it until their turn lies rateHold ahead, the one whose turn lies
// past it is dropped, and the rate's time lets the next through.
func TestECNDropsWritesPastTheHold(t *testing.T) {
	e := NewECN()
	now := time.Unix(1_700_000_000, 0)
	d := e.dest(ecnPeer)
	d.rate, d.moved = mbit, now
	// 1250 bytes take 10ms at 1 Mbit/s.
	for i := range 11 {
		if !e.admit(ecnPeer, 1250, now) {
			t.Fatalf("write %d, its turn %v ahead, dropped", i, time.Duration(i)*10*time.Millisecond)
		}
	}
	if e.admit(ecnPeer, 1250, now) {
		t.Error("a write whose turn lies 110ms ahead taken, want dropped")
	}
	if e.admit(ecnPeer, 1250, now.Add(9500*time.Microsecond)) {
		t.Error("a write whose turn lies 100.5ms ahead taken, want dropped")
	}
	if !e.admit(ecnPeer, 1250, now.Add(10*time.Millisecond)) {
		t.Error("a write whose turn lies back within the hold 10ms on dropped")
	}
}

// fakeSocket is an underlay socket that keeps the datagrams written to it
// and reads none.
type fakeSocket struct {
	local  *net.UDPAddr
	mtx    sync.Mutex
	sent   [][]byte
	closed chan struct{}
	close  sync.Once
}

func (s *fakeSocket) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	<-s.closed
	return 0, nil, net.ErrClosed
}

func (s *fakeSocket) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.sent = append(s.sent, slices.Clone(b))
	return len(b), nil
}

func (s *fakeSocket) ReadBatch([]ipv4.Message) (int, error)  { return 0, errors.ErrUnsupported }
func (s *fakeSocket) WriteBatch([]ipv4.Message) (int, error) { return 0, errors.ErrUnsupported }
func (s *fakeSocket) SetDeadline(time.Time) error            { return nil }
func (s *fakeSocket) SetReadDeadline(time.Time) error        { return nil }
func (s *fakeSocket) SetWriteDeadline(time.Time) error       { return nil }
func (s *fakeSocket) LocalAddr() *net.UDPAddr                { return s.local }
func (s *fakeSocket) SetReadBuffer(int) error                { return nil }
func (s *fakeSocket) SetWriteBuffer(int) error               { return nil }

func (s *fakeSocket) Close() error {
	s.close.Do(func() { close(s.closed) })
	return nil
}

// packets returns the datagrams written to the socket.
func (s *fakeSocket) packets() [][]byte {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return slices.Clone(s.sent)
}

// fakeConn returns a conn sharing the ECN state, a control conn where
// control is set, over a fake socket that keeps what the conn writes.
func fakeConn(t *testing.T, e *ECN, control bool) (*Conn, *fakeSocket) {
	t.Helper()
	sock := &fakeSocket{
		local:  net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:40001")),
		closed: make(chan struct{}),
	}
	c, err := NewConn(ConnConfig{
		IA:           ecnLocal,
		Bind:         "127.0.0.1:0",
		InternalAddr: "127.0.0.1:30001",
		MACKey:       testMACKeyBytes,
		Links:        tableTopic(map[uint16]addr.IA{testIfID: ecnPeer}),
		Control:      control,
		ECN:          e,
		Sockets: underlay.Sockets{ListenUDP: func(*net.UDPAddr, netip.AddrPort) (underlay.UDPConn, error) {
			return sock, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, sock
}

// TestConnKeepsToTheRate checks the conns sharing the node's ECN state, on
// the bubble's clock: a conn's datagrams set the base, and the marked answer
// it hands the state, with the average at one, sets the rate at half of it; a
// burst then leaves while its turns lie within the hold and is dropped past
// it, every write reporting success; a control conn's datagrams and every
// SCMP message leave at once and count nothing; and a conn without the state
// paces nothing.
func TestConnKeepsToTheRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := NewECN()
		data, dataOut := fakeConn(t, e, false)
		control, controlOut := fakeConn(t, e, true)
		outside, outsideOut := fakeConn(t, nil, false)
		to := &Addr{IA: ecnPeer, Addr: netip.MustParseAddrPort("127.0.0.1:40000")}
		payload := make([]byte, 1000)
		write := func(c *Conn, n int) {
			t.Helper()
			for range n {
				if got, err := c.WriteTo(payload, to); err != nil || got != len(payload) {
					t.Fatalf("WriteTo() = %d, %v; want %d, nil", got, err, len(payload))
				}
			}
		}
		for range 200 {
			write(data, 1)
			time.Sleep(10 * time.Millisecond)
		}
		e.dests[ecnPeer].alpha = 1
		data.Answer(ecnPeer, true, time.Now())
		// The base is a hundred datagrams a second, and the rate half of it,
		// so each datagram's turn comes 20ms after the last's: six lie within
		// the hold.
		write(data, 20)
		if got := len(dataOut.packets()); got != 200+6 {
			t.Errorf("the data conn sent %d datagrams, want the 200 before the rate and 6 of the burst", got)
		}
		counted := e.dests[ecnPeer].tickBytes
		write(control, 20)
		if got := len(controlOut.packets()); got != 20 {
			t.Errorf("the control conn sent %d of its 20 datagrams", got)
		}
		if err := data.WriteEchoRequestTo(to, 1, nil); err != nil {
			t.Fatal(err)
		}
		if got := len(dataOut.packets()); got != 200+6+1 {
			t.Errorf("the data conn sent %d packets past the burst, want its echo request past the rate", got-200-6)
		}
		if got := e.dests[ecnPeer].tickBytes; got != counted {
			t.Errorf("the tick counts %d bytes past the control datagrams and the echo request, want its %d", got, counted)
		}
		write(outside, 20)
		outside.Answer(ecnPeer, true, time.Now())
		write(outside, 20)
		if got := len(outsideOut.packets()); got != 40 {
			t.Errorf("a conn without the state sent %d of its 40 datagrams", got)
		}
	})
}

// TestECNCountsArrivals checks the arrivals the state counts from a
// destination: those within hotSpan, marked and not, and none from before
// it; a destination that sent nothing counts none.
func TestECNCountsArrivals(t *testing.T) {
	e := NewECN()
	now := time.Unix(1_700_000_000, 0)
	for i := range 4 {
		e.arrived(ecnPeer, i%2 == 0, now)
	}
	later := now.Add(hotSpan - arrivalBucket)
	e.arrived(ecnPeer, true, later)
	if arrived, marked := e.Arrivals(ecnPeer, later); arrived != 5 || marked != 3 {
		t.Errorf("Arrivals() = %d, %d within the span, want 5, 3", arrived, marked)
	}
	if arrived, marked := e.Arrivals(ecnPeer, now.Add(hotSpan+arrivalBucket)); arrived != 1 || marked != 1 {
		t.Errorf("Arrivals() = %d, %d past the first arrivals' span, want 1, 1", arrived, marked)
	}
	if arrived, marked := e.Arrivals(ecnLocal, now); arrived != 0 || marked != 0 {
		t.Errorf("Arrivals() = %d, %d from a destination that sent nothing, want 0, 0", arrived, marked)
	}
}
