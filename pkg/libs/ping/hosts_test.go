package ping

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"
)

var (
	dstA = addr.MustIAFrom(1, 0xff0000000010)
	dstB = addr.MustIAFrom(1, 0xff0000000011)
)

// fakeResolver answers each resolution with its host, over every path but
// the dead ones, recording the paths each destination was asked over.
type fakeResolver struct {
	mu    sync.Mutex
	host  netip.Addr
	dead  map[*spath.Decoded]bool
	calls map[addr.IA][]*spath.Decoded
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		host:  netip.MustParseAddr("192.0.2.1"),
		dead:  make(map[*spath.Decoded]bool),
		calls: make(map[addr.IA][]*spath.Decoded),
	}
}

func (r *fakeResolver) resolve(_ context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[dst] = append(r.calls[dst], path)
	if r.dead[path] {
		return netip.Addr{}, errors.New("no responder")
	}
	return r.host, nil
}

// asked returns the paths the destination was asked over.
func (r *fakeResolver) asked(dst addr.IA) []*spath.Decoded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[dst]
}

// set has every resolution over the path fail, or else answer the host.
func (r *fakeResolver) set(host netip.Addr, dead ...*spath.Decoded) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.host = host
	clear(r.dead)
	for _, p := range dead {
		r.dead[p] = true
	}
}

// resolving runs Hosts over the resolver in the bubble for the body, which
// adopts the resolutions that landed by land.
func resolving(t *testing.T, r *fakeResolver, body func(h *Hosts, land func() []Resolution)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		h := NewHosts(r.resolve, 5*time.Second)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.Resolve(ctx)
		}()
		body(h, func() []Resolution {
			synctest.Wait()
			var landed []Resolution
			for len(h.Landed()) > 0 {
				res := <-h.Landed()
				h.Adopt(res, time.Now())
				landed = append(landed, res)
			}
			return landed
		})
		cancel()
		<-done
	})
}

// addrs compares addresses by value.
var addrs = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })

// TestHostsResolvesOnceAtATime checks that a destination asked for twice
// before its resolution lands resolves once, and that its host holds once
// adopted.
func TestHostsResolvesOnceAtATime(t *testing.T) {
	r := newFakeResolver()
	resolving(t, r, func(h *Hosts, land func() []Resolution) {
		if _, ok := h.Host(dstA); ok {
			t.Fatal("a host held before any resolution")
		}
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		want := []Resolution{{Dst: dstA, Host: netip.MustParseAddr("192.0.2.1")}}
		if diff := cmp.Diff(want, land(), addrs); diff != "" {
			t.Errorf("landed (-want +got):\n%s", diff)
		}
		if got := len(r.asked(dstA)); got != 1 {
			t.Errorf("%d resolutions, want 1", got)
		}
		if host, ok := h.Host(dstA); !ok || host != netip.MustParseAddr("192.0.2.1") {
			t.Errorf("host = %v, %t, want 192.0.2.1", host, ok)
		}
	})
}

// TestHostsTriesPathsInTurn checks that a resolution tries its paths in
// turn until one answers, fails when none does, and fails over no path.
func TestHostsTriesPathsInTurn(t *testing.T) {
	r := newFakeResolver()
	a, b, c := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
	r.set(netip.MustParseAddr("192.0.2.1"), a, c)
	resolving(t, r, func(h *Hosts, land func() []Resolution) {
		h.Ask(dstA, []*spath.Decoded{a, b, c}, time.Now())
		h.Ask(dstB, []*spath.Decoded{a, c}, time.Now())
		landed := land()
		if len(landed) != 2 || landed[0].Err != nil || landed[1].Err == nil {
			t.Fatalf("landed %+v, want A resolved and B failed", landed)
		}
		if diff := cmp.Diff([]*spath.Decoded{a, b}, r.asked(dstA)); diff != "" {
			t.Errorf("A's paths asked (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]*spath.Decoded{a, c}, r.asked(dstB)); diff != "" {
			t.Errorf("B's paths asked (-want +got):\n%s", diff)
		}
		dstC := addr.MustIAFrom(1, 0xff0000000012)
		h.Ask(dstC, nil, time.Now())
		if landed := land(); len(landed) != 1 || !errors.Is(landed[0].Err, errNoPath) {
			t.Errorf("landed %+v over no path, want errNoPath", landed)
		}
	})
}

// TestHostsSpacesRetries checks that a failed resolution is asked for again
// only once its spacing elapsed.
func TestHostsSpacesRetries(t *testing.T) {
	r := newFakeResolver()
	r.set(netip.Addr{}, nil)
	resolving(t, r, func(h *Hosts, land func() []Resolution) {
		failed := time.Now()
		h.Ask(dstA, []*spath.Decoded{nil}, failed)
		land()
		if got, want := h.RetryAt(dstA), failed.Add(5*time.Second); !got.Equal(want) {
			t.Errorf("retry at %v, want %v", got, want)
		}
		time.Sleep(5*time.Second - time.Millisecond)
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		land()
		if got := len(r.asked(dstA)); got != 1 {
			t.Fatalf("%d resolutions within the spacing, want 1", got)
		}
		time.Sleep(time.Millisecond)
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		land()
		if got := len(r.asked(dstA)); got != 2 {
			t.Errorf("%d resolutions once the spacing elapsed, want 2", got)
		}
	})
}

// TestHostsKeepsTheHostAsked checks that a host stays while it is asked for
// again and that resolution fails, gives way to the host the next one
// names, and goes once forgotten.
func TestHostsKeepsTheHostAsked(t *testing.T) {
	r := newFakeResolver()
	resolving(t, r, func(h *Hosts, land func() []Resolution) {
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		land()
		r.set(netip.Addr{}, nil)
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		land()
		if host, ok := h.Host(dstA); !ok || host != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("host = %v, %t through a failed resolution, want 192.0.2.1 kept", host, ok)
		}
		time.Sleep(5 * time.Second)
		r.set(netip.MustParseAddr("192.0.2.2"))
		h.Ask(dstA, []*spath.Decoded{nil}, time.Now())
		land()
		if host, ok := h.Host(dstA); !ok || host != netip.MustParseAddr("192.0.2.2") {
			t.Fatalf("host = %v, %t, want the new 192.0.2.2", host, ok)
		}
		h.Forget(dstA)
		if host, ok := h.Host(dstA); ok {
			t.Errorf("host = %v once forgotten", host)
		}
	})
}

// TestHostsDropsAsksPastTheQueue checks that an ask past the queue's room is
// dropped, and can be asked again once the queue drains.
func TestHostsDropsAsksPastTheQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newFakeResolver()
		h := NewHosts(r.resolve, 5*time.Second)
		dsts := make([]addr.IA, hostsQueued+1)
		for i := range dsts {
			dsts[i] = addr.MustIAFrom(1, addr.AS(0xff0000000100+i))
			h.Ask(dsts[i], []*spath.Decoded{nil}, time.Now())
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.Resolve(ctx)
		}()
		for range hostsQueued {
			h.Adopt(<-h.Landed(), time.Now())
		}
		last := dsts[hostsQueued]
		if got := len(r.asked(last)); got != 0 {
			t.Fatalf("%d resolutions of the ask past the queue, want none", got)
		}
		h.Ask(last, []*spath.Decoded{nil}, time.Now())
		h.Adopt(<-h.Landed(), time.Now())
		if _, ok := h.Host(last); !ok {
			t.Error("the ask dropped past the queue resolved nothing once asked again")
		}
		cancel()
		<-done
	})
}
