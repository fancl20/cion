package fabric

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// siteAddr is a host the uplink proofs draw beside the two plain ones.
var siteAddr = netip.MustParseAddr("127.0.1.18")

// The uplink proofs' line: a packet of wireSize bytes holds a line of
// proofRate for exactly a tenth of a second.
const (
	proofRate = 80_000
	wireSize  = 1000
	slot      = 100 * time.Millisecond
)

// payloadOf returns a payload that makes a UDP datagram of wireSize bytes on
// the wire, its IPv4 and UDP headers beside it, led by the label.
func payloadOf(label string) string {
	return label + strings.Repeat(".", wireSize-20-8-len(label))
}

// arrivals reads count datagrams within the wait and returns, by label, how
// long after start each arrived.
func arrivals(t *testing.T, c underlay.UDPConn, count int, start time.Time, wait time.Duration) map[string]time.Duration {
	t.Helper()
	out := make(map[string]time.Duration, count)
	for range count {
		got, _ := recv(t, c, wait)
		if got == "" {
			break
		}
		out[strings.TrimRight(got, ".")] = time.Since(start)
	}
	return out
}

// TestUplinkPacesAtItsRate checks the line: a burst leaves the uplink one
// packet after another, each holding the line for its size at the rate, in
// the order sent, and the window counts what it sent and how long each
// waited.
func TestUplinkPacesAtItsRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b := f.Node(insideAddr), f.Node(upstreamAddr)
		ca, _ := listen(t, a)
		cb, ab := listen(t, b)
		u := f.Uplink(proofRate, time.Second, insideAddr)

		start := time.Now()
		for k := range 5 {
			send(t, ca, ab, payloadOf(strconv.Itoa(k)))
		}
		for k := range 5 {
			got, _ := recv(t, cb, time.Second)
			if label := strings.TrimRight(got, "."); label != strconv.Itoa(k) {
				t.Fatalf("datagram %d arrived as %q", k, label)
			}
			if held, want := time.Since(start), time.Duration(k+1)*slot; held != want {
				t.Errorf("datagram %d arrived after %v, want exactly %v", k, held, want)
			}
		}
		want := UplinkWindow{Sent: 5, Bytes: 5 * wireSize, Waited: 10 * slot, MaxWait: 4 * slot}
		if got := u.Window(); got != want {
			t.Errorf("the window counted %+v, want %+v", got, want)
		}
		if got := u.Window(); got != (UplinkWindow{}) {
			t.Errorf("the next window counted %+v before any packet", got)
		}
	})
}

// TestUplinkDropsPastItsQueue checks the queue's bound: a packet whose wait
// would pass it is dropped and counted, and the line it would have held
// stays free for the packets after it.
func TestUplinkDropsPastItsQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b := f.Node(insideAddr), f.Node(upstreamAddr)
		ca, _ := listen(t, a)
		cb, ab := listen(t, b)
		u := f.Uplink(proofRate, 5*slot/2, insideAddr)

		start := time.Now()
		for k := range 6 {
			send(t, ca, ab, payloadOf(strconv.Itoa(k)))
		}
		got := arrivals(t, cb, 6, start, time.Second)
		want := map[string]time.Duration{"0": slot, "1": 2 * slot, "2": 3 * slot}
		if len(got) != len(want) {
			t.Fatalf("the burst arrived as %v, want %v", got, want)
		}
		for label, at := range want {
			if got[label] != at {
				t.Errorf("datagram %s arrived after %v, want exactly %v", label, got[label], at)
			}
		}
		if w := u.Window(); w.Sent != 3 || w.Dropped != 3 || w.DropShare() != 0.5 {
			t.Errorf("the window counted %+v, want 3 sent and 3 dropped", w)
		}

		// The line fell free once the queue drained: a packet sent then
		// holds it for its own size alone.
		time.Sleep(time.Second)
		start = time.Now()
		send(t, ca, ab, payloadOf("after"))
		if got := arrivals(t, cb, 1, start, time.Second); got["after"] != slot {
			t.Errorf("a datagram on the free line arrived as %v, want after exactly %v", got, slot)
		}
	})
}

// TestUplinkCarriesOnlyLeavingPackets checks what crosses an uplink: a
// node's packets to its own host and those between the hosts of one uplink
// pass at once, and those to any other host leave through the line.
func TestUplinkCarriesOnlyLeavingPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, site, b := f.Node(insideAddr), f.Node(siteAddr), f.Node(upstreamAddr)
		ca, _ := listen(t, a)
		ownConn, own := listen(t, a)
		siteConn, sa := listen(t, site)
		cb, ab := listen(t, b)
		u := f.Uplink(proofRate, time.Second, insideAddr, siteAddr)

		for _, c := range []struct {
			name string
			conn underlay.UDPConn
			to   netip.AddrPort
			want time.Duration
		}{
			{"to its own host", ownConn, own, 0},
			{"to the site's other host", siteConn, sa, 0},
			{"to a host past the uplink", cb, ab, slot},
		} {
			start := time.Now()
			send(t, ca, c.to, payloadOf("x"))
			if got := arrivals(t, c.conn, 1, start, time.Second); len(got) != 1 || got["x"] != c.want {
				t.Errorf("a datagram %s arrived as %v, want after exactly %v", c.name, got, c.want)
			}
		}
		if w := u.Window(); w.Sent != 1 {
			t.Errorf("the uplink sent %d packets, want the one to the host past it", w.Sent)
		}
	})
}

// TestUplinkRateChangesFromTheNextPacket checks a rate change: the packets
// queued keep their departures, and the next packet holds the line for its
// size at the new rate. A packet takes its departure when the forwarder
// carries it, so the change waits for the bubble to park.
func TestUplinkRateChangesFromTheNextPacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b := f.Node(insideAddr), f.Node(upstreamAddr)
		ca, _ := listen(t, a)
		cb, ab := listen(t, b)
		u := f.Uplink(proofRate, time.Second, insideAddr)

		start := time.Now()
		send(t, ca, ab, payloadOf("before"))
		synctest.Wait()
		u.SetRate(2 * proofRate)
		send(t, ca, ab, payloadOf("after"))
		got := arrivals(t, cb, 2, start, time.Second)
		if got["before"] != slot || got["after"] != slot+slot/2 {
			t.Errorf("the datagrams arrived as %v, want before after %v and after after %v",
				got, slot, slot+slot/2)
		}
	})
}

// TestUplinkHoldsTheTapsFromTheDeparture checks the taps behind an uplink:
// a packet's delay starts at its departure, and a jittered direction's burst
// arrives in the order sent.
func TestUplinkHoldsTheTapsFromTheDeparture(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b := f.Node(insideAddr), f.Node(upstreamAddr)
		ca, _ := listen(t, a)
		cb, ab := listen(t, b)
		const oneWay = 30 * time.Millisecond
		f.Delay(insideAddr, upstreamAddr, oneWay)
		f.Uplink(proofRate, 10*time.Second, insideAddr)

		start := time.Now()
		send(t, ca, ab, payloadOf("delayed"))
		if got := arrivals(t, cb, 1, start, time.Second); got["delayed"] != slot+oneWay {
			t.Fatalf("the datagram arrived as %v, want after exactly %v", got, slot+oneWay)
		}

		f.Jitter(insideAddr, upstreamAddr, 20*time.Millisecond)
		start = time.Now()
		for k := range 50 {
			send(t, ca, ab, payloadOf(strconv.Itoa(k)))
		}
		for k := range 50 {
			got, _ := recv(t, cb, 10*time.Second)
			if label := strings.TrimRight(got, "."); label != strconv.Itoa(k) {
				t.Fatalf("datagram %d of the burst arrived as %q", k, label)
			}
			if held, least := time.Since(start), time.Duration(k+1)*slot+oneWay; held < least {
				t.Errorf("datagram %d arrived after %v, before its departure and delay at %v", k, held, least)
			}
		}
	})
}
