package brake

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/ping"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The echo tests' neighbors: over interface 7, up; over 9, down.
var (
	neighbor7 = addr.MustIAFrom(1, 0xff0000000007)
	neighbor9 = addr.MustIAFrom(1, 0xff0000000009)
)

// fakeLink answers each echo after its round trip, or never while it loses
// them, and keeps the echoes sent.
type fakeLink struct {
	mu      sync.Mutex
	rtt     time.Duration
	losing  bool
	over    []sentOver
	replies chan ping.Reply
}

// sentOver is one echo a fakeLink sent.
type sentOver struct {
	Neighbor addr.IA
	Host     netip.Addr
	IfID     uint16
}

func newFakeLink(rtt time.Duration, losing bool) *fakeLink {
	return &fakeLink{rtt: rtt, losing: losing, replies: make(chan ping.Reply, 1024)}
}

func (f *fakeLink) SendOver(neighbor addr.IA, host netip.Addr, ifID, seq uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.over = append(f.over, sentOver{Neighbor: neighbor, Host: host, IfID: ifID})
	if !f.losing {
		time.AfterFunc(f.rtt, func() { f.replies <- ping.Reply{Seq: seq, At: time.Now()} })
	}
	return nil
}

func (f *fakeLink) Replies() <-chan ping.Reply { return f.replies }

func (f *fakeLink) ReadReplies(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// sent returns the echoes sent.
func (f *fakeLink) sent() []sentOver {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.over)
}

// fakeNeighbors resolves every neighbor's host over the one-hop path, or
// fails every resolution while failing, recording the paths each neighbor
// was resolved over.
type fakeNeighbors struct {
	mu      sync.Mutex
	failing bool
	calls   map[addr.IA][]*spath.Decoded
}

func (r *fakeNeighbors) resolve(_ context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = make(map[addr.IA][]*spath.Decoded)
	}
	r.calls[dst] = append(r.calls[dst], path)
	if r.failing {
		return netip.Addr{}, errors.New("no responder")
	}
	return netip.MustParseAddr("192.0.2.1"), nil
}

// count returns how many resolutions the neighbor drew.
func (r *fakeNeighbors) count(dst addr.IA) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls[dst])
}

// fail has every resolution fail from now on.
func (r *fakeNeighbors) fail() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failing = true
}

// linkSample is one echo's outcome handed the policy.
type linkSample struct {
	IfID   uint16
	Sample evidence.Sample
}

// testLinks returns a link state topic whose interface 7 is up to neighbor7
// and interface 9 down to neighbor9.
func testLinks() *bus.Topic[bus.LinkState] {
	b := bus.New()
	b.Links().Publish(bus.NewLinkState(
		bus.Link{Entry: links.Link{IfID: 7, NeighborIA: neighbor7}},
		bus.Link{Entry: links.Link{IfID: 9, NeighborIA: neighbor9}, Down: true},
	))
	return b.Links()
}

// echoing runs link echoes over the fakes in the bubble for the body, which
// calls for echoes and reads the outcomes handed the policy.
func echoing(t *testing.T, f *fakeLink, r *fakeNeighbors,
	body func(ask func(uint16), samples func() []linkSample)) {
	t.Helper()
	var mu sync.Mutex
	var got []linkSample
	e := newLinkEchoes(linkEchoesConfig{
		links:   testLinks(),
		echo:    f,
		resolve: r.resolve,
		sampled: func(ifID uint16, s evidence.Sample) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, linkSample{IfID: ifID, Sample: s})
		},
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.run(ctx)
	}()
	body(e.ask, func() []linkSample {
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	})
	cancel()
	<-done
}

// TestEchoesCrossTheLink checks an echo's course: the first call for a link
// resolves its neighbor's host over the one-hop path and sends nothing, and
// each call after sends an echo to that host over the link, whose round trip
// goes to the policy.
func TestEchoesCrossTheLink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := newFakeLink(20*ms, false), &fakeNeighbors{}
		echoing(t, f, r, func(ask func(uint16), samples func() []linkSample) {
			ask(7)
			synctest.Wait()
			if got := f.sent(); len(got) != 0 {
				t.Fatalf("echoes sent before the host resolved: %v", got)
			}
			if diff := cmp.Diff(map[addr.IA][]*spath.Decoded{neighbor7: {nil}}, r.calls); diff != "" {
				t.Errorf("resolutions (-want +got):\n%s", diff)
			}
			start := time.Now()
			ask(7)
			time.Sleep(time.Second)
			want := []linkSample{{IfID: 7, Sample: evidence.Sample{At: start, RTT: 20 * ms}}}
			if diff := cmp.Diff(want, samples()); diff != "" {
				t.Errorf("samples (-want +got):\n%s", diff)
			}
			addrs := cmp.Comparer(func(a, b netip.Addr) bool { return a == b })
			wantSent := []sentOver{{Neighbor: neighbor7, Host: netip.MustParseAddr("192.0.2.1"), IfID: 7}}
			if diff := cmp.Diff(wantSent, f.sent(), addrs); diff != "" {
				t.Errorf("echoes sent (-want +got):\n%s", diff)
			}
		})
	})
}

// TestEchoesCountLost checks that an echo unanswered within echoWait goes to
// the policy lost, and that staleLosses lost in a row have the neighbor's
// host resolved again, the echoes going on to the host they had while the
// resolution fails.
func TestEchoesCountLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := newFakeLink(0, true), &fakeNeighbors{}
		echoing(t, f, r, func(ask func(uint16), samples func() []linkSample) {
			ask(7)
			synctest.Wait()
			r.fail()
			start := time.Now()
			ask(7)
			time.Sleep(echoWait - time.Millisecond)
			if got := samples(); len(got) != 0 {
				t.Fatalf("samples within the echo's wait: %v", got)
			}
			time.Sleep(time.Millisecond)
			want := []linkSample{{IfID: 7, Sample: evidence.Sample{At: start, Lost: true}}}
			if diff := cmp.Diff(want, samples()); diff != "" {
				t.Errorf("samples (-want +got):\n%s", diff)
			}
			for range staleLosses - 2 {
				ask(7)
			}
			time.Sleep(2 * echoWait)
			if got := r.count(neighbor7); got != 1 {
				t.Fatalf("%d resolutions after %d echoes lost in a row, want 1", got, staleLosses-1)
			}
			ask(7)
			time.Sleep(2 * echoWait)
			if got := r.count(neighbor7); got != 2 {
				t.Fatalf("%d resolutions after %d echoes lost in a row, want 2", got, staleLosses)
			}
			ask(7)
			synctest.Wait()
			if got := len(f.sent()); got != staleLosses+1 {
				t.Errorf("%d echoes sent, want %d: the stale host kept while it fails to resolve",
					got, staleLosses+1)
			}
		})
	})
}

// TestEchoesSkipDownLinks checks that a call for a link whose verdict is
// down, or one no entry holds, resolves and sends nothing.
func TestEchoesSkipDownLinks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := newFakeLink(20*ms, false), &fakeNeighbors{}
		echoing(t, f, r, func(ask func(uint16), samples func() []linkSample) {
			for range 3 {
				ask(9)
				ask(11)
			}
			time.Sleep(2 * echoWait)
			if got := r.count(neighbor9); got != 0 {
				t.Errorf("%d resolutions for a down link, want none", got)
			}
			if got := f.sent(); len(got) != 0 {
				t.Errorf("echoes over down or unknown links: %v", got)
			}
		})
	})
}

// TestEchoesSendEachCall checks that every call the queue holds sends an
// echo, however many come within a second.
func TestEchoesSendEachCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := newFakeLink(20*ms, false), &fakeNeighbors{}
		echoing(t, f, r, func(ask func(uint16), samples func() []linkSample) {
			ask(7)
			synctest.Wait()
			for range asksQueued {
				ask(7)
			}
			synctest.Wait()
			if got := len(f.sent()); got != asksQueued {
				t.Errorf("%d echoes sent, want all %d called for", got, asksQueued)
			}
		})
	})
}

// TestBrakeEchoesWhatItCalls checks a brake's wiring: the echoes its policy
// calls for as a link writes go across the link, and their outcomes reach
// the policy.
func TestBrakeEchoesWhatItCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := newFakeLink(20*ms, false), &fakeNeighbors{}
		b := newBrake(linkEchoesConfig{links: testLinks(), echo: f, resolve: r.resolve})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = b.Run(ctx)
		}()
		b.Wrote(7, maxGrant, maxGrant*1000, false)
		synctest.Wait()
		if got := r.count(neighbor7); got != 1 {
			t.Fatalf("%d resolutions after the link's first echo called for, want 1", got)
		}
		time.Sleep(leastSpan)
		b.Wrote(7, maxGrant, maxGrant*1000, false)
		time.Sleep(time.Second)
		synctest.Wait()
		if got := len(f.sent()); got != 1 {
			t.Fatalf("%d echoes sent, want the one the second write called for", got)
		}
		b.mu.Lock()
		got := slices.Clone(b.links[7].samples)
		b.mu.Unlock()
		if len(got) != 1 || got[0].RTT != 20*ms {
			t.Errorf("the policy's samples = %v, want the echo's 20ms round trip", got)
		}
		cancel()
		<-done
	})
}
