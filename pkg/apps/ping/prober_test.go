package ping

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// fakeEcho answers each probe by its path's behavior: after its round trip,
// or never while the path loses or drops its next probes.
type fakeEcho struct {
	mu       sync.Mutex
	sent     map[*spath.Decoded][]time.Time
	rtt      map[*spath.Decoded]time.Duration
	losing   map[*spath.Decoded]bool
	dropping map[*spath.Decoded]int
	replies  chan Reply
}

func newFakeEcho() *fakeEcho {
	return &fakeEcho{
		sent:     make(map[*spath.Decoded][]time.Time),
		rtt:      make(map[*spath.Decoded]time.Duration),
		losing:   make(map[*spath.Decoded]bool),
		dropping: make(map[*spath.Decoded]int),
		replies:  make(chan Reply, 1024),
	}
}

func (e *fakeEcho) Send(_ addr.IA, _ netip.Addr, path *spath.Decoded, seq uint16) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sent[path] = append(e.sent[path], time.Now())
	if e.dropping[path] > 0 {
		e.dropping[path]--
		return nil
	}
	if !e.losing[path] {
		time.AfterFunc(e.rtt[path], func() { e.replies <- Reply{Seq: seq, At: time.Now()} })
	}
	return nil
}

func (e *fakeEcho) Replies() <-chan Reply   { return e.replies }
func (e *fakeEcho) Run(ctx context.Context) { <-ctx.Done() }

// sends returns how many probes the path drew.
func (e *fakeEcho) sends(path *spath.Decoded) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sent[path])
}

// lose has the path lose every probe from now on.
func (e *fakeEcho) lose(path *spath.Decoded) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.losing[path] = true
}

// recover has the path answer every probe from now on.
func (e *fakeEcho) recover(path *spath.Decoded) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.losing[path] = false
}

// drop has the path lose its next n probes.
func (e *fakeEcho) drop(path *spath.Decoded, n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dropping[path] = n
}

// fakeResolver resolves every destination over every path but the dead
// ones, or fails every resolution, recording the paths it was asked over.
type fakeResolver struct {
	mu    sync.Mutex
	fail  bool
	dead  map[*spath.Decoded]bool
	calls map[addr.IA][]*spath.Decoded
}

func (r *fakeResolver) resolve(_ context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = make(map[addr.IA][]*spath.Decoded)
	}
	r.calls[dst] = append(r.calls[dst], path)
	if r.fail || r.dead[path] {
		return netip.Addr{}, errors.New("no responder")
	}
	return netip.MustParseAddr("192.0.2.1"), nil
}

func (r *fakeResolver) count(dst addr.IA) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls[dst])
}

// kill has every resolution over the path fail from now on.
func (r *fakeResolver) kill(path *spath.Decoded) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dead == nil {
		r.dead = make(map[*spath.Decoded]bool)
	}
	r.dead[path] = true
}

var (
	dstA = addr.MustIAFrom(1, 0xff0000000010)
	dstB = addr.MustIAFrom(1, 0xff0000000011)
)

// prober runs a prober over a fresh bus in the bubble for the body.
func prober(t *testing.T, e *fakeEcho, r *fakeResolver, body func(b *bus.Bus)) {
	t.Helper()
	b := bus.New()
	p := NewProber(ProberConfig{
		Requests:      b.PathRequests(),
		Measurements:  b.PathMeasurements(),
		InterfaceDown: b.InterfaceDown(),
		Echo:          e,
		Resolve:       r.resolve,
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx)
	}()
	body(b)
	cancel()
	<-done
}

// request publishes the destination's entries.
func request(b *bus.Bus, dst addr.IA, entries ...bus.PathRequest) {
	b.PathRequests().Update(func(r bus.PathRequests) bus.PathRequests {
		return r.Requested("picks", dst, entries, time.Now().Add(-bus.RequestLapse))
	})
}

// entryOf returns a request for the path.
func entryOf(id bus.PathID, dst addr.IA, path *spath.Decoded, role bus.PathRole, picked time.Time,
	links ...segment.LinkID) bus.PathRequest {
	return bus.PathRequest{ID: id, Dst: dst, Path: path, Role: role, Picked: picked, Links: links}
}

// record returns the path's published record.
func record(b *bus.Bus, id bus.PathID) (bus.PathRecord, bool) {
	return b.PathMeasurements().Latest().Of(id)
}

// TestProberPacesByPick checks the cadences: a hot destination's path in use
// every heartbeat, its standby and its suspect once a minute, the standby's
// lost probe calling no burst; a warm one's path in use once a minute, its
// standby and its suspect never; a lapsed one's nothing, its record
// forgotten.
func TestProberPacesByPick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		hotUse, hotStandby, hotSuspect := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
		warmUse, warmStandby, warmSuspect := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
		lapsed := &spath.Decoded{}
		e.rtt[hotUse] = 10 * time.Millisecond
		e.lose(hotStandby)
		prober(t, e, r, func(b *bus.Bus) {
			now, warm := time.Now(), time.Now().Add(-2*time.Minute)
			request(b, dstA,
				entryOf("hot-use", dstA, hotUse, bus.PathInUse, now),
				entryOf("hot-standby", dstA, hotStandby, bus.PathStandby, now),
				entryOf("hot-suspect", dstA, hotSuspect, bus.PathSuspect, now))
			request(b, dstB,
				entryOf("warm-use", dstB, warmUse, bus.PathInUse, warm),
				entryOf("warm-standby", dstB, warmStandby, bus.PathStandby, warm),
				entryOf("warm-suspect", dstB, warmSuspect, bus.PathSuspect, warm))
			request(b, addr.MustIAFrom(1, 0xff0000000012),
				entryOf("lapsed", addr.MustIAFrom(1, 0xff0000000012), lapsed, bus.PathInUse,
					now.Add(-bus.RequestLapse-time.Second)))
			time.Sleep(59 * time.Second)
			synctest.Wait()
			for _, tc := range []struct {
				name string
				path *spath.Decoded
				want int
			}{{"hot in use", hotUse, 12}, {"hot standby", hotStandby, 1}, {"hot suspect", hotSuspect, 1},
				{"warm in use", warmUse, 1}, {"warm standby", warmStandby, 0}, {"warm suspect", warmSuspect, 0},
				{"lapsed", lapsed, 0}} {
				if got := e.sends(tc.path); got != tc.want {
					t.Errorf("%s drew %d probes in 59s, want %d", tc.name, got, tc.want)
				}
			}
			rec, ok := record(b, "hot-use")
			if !ok || len(rec.Samples) != 12 || rec.Samples[0].RTT != 10*time.Millisecond ||
				rec.LastAnswer.IsZero() {
				t.Errorf("the hot path's record = %+v, %v, want its twelve answered probes", rec, ok)
			}
			if _, ok := record(b, "lapsed"); ok {
				t.Error("the lapsed path has a record")
			}
			if got := r.count(dstA); got != 1 {
				t.Errorf("dstA resolved %d times, want once for all its paths", got)
			}

			// Warm from 1m, the hot path draws a probe a minute, past the
			// samples a record keeps, until its lapse at 10m.
			time.Sleep(bus.RequestLapse - time.Second - 59*time.Second)
			synctest.Wait()
			if rec, _ := record(b, "hot-use"); len(rec.Samples) != bus.PathSamples {
				t.Errorf("the hot path's record holds %d samples, want the last %d", len(rec.Samples), bus.PathSamples)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if n := len(maps.Collect(b.PathMeasurements().Latest().All())); n != 0 {
				t.Errorf("records past every lapse = %d, want none", n)
			}
			sent := e.sends(hotUse)
			time.Sleep(time.Minute)
			synctest.Wait()
			if got := e.sends(hotUse); got != sent {
				t.Errorf("the lapsed hot path drew %d probes past its lapse, want none", got-sent)
			}
		})
	})
}

// TestProberBurstsOnLoss checks that a lost heartbeat calls a burst, that a
// burst lost whole counts in the record, that the destination's host is
// resolved again after it, and that the first answer after it restarts the
// samples and clears the lost bursts.
func TestProberBurstsOnLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			request(b, dstA, entryOf("use", dstA, path, bus.PathInUse, time.Now()))
			time.Sleep(7 * time.Second) // heartbeats at 0s and 5s, answered
			synctest.Wait()
			e.lose(path)
			time.Sleep(3500 * time.Millisecond) // the heartbeat at 10s, awaiting its answer
			synctest.Wait()
			if got := e.sends(path); got != 3 {
				t.Fatalf("probes before the burst = %d, want the three heartbeats", got)
			}
			time.Sleep(2500 * time.Millisecond) // lost at 11s; the burst from 11s settles by 12.8s
			synctest.Wait()
			if got := e.sends(path); got != 3+BurstProbes {
				t.Errorf("probes = %d, want the heartbeats and a burst of %d", got, BurstProbes)
			}
			rec, _ := record(b, "use")
			if rec.LostBursts != 1 || rec.LastLoss.IsZero() || len(rec.Samples) != 3+BurstProbes {
				t.Errorf("record = %+v, want every probe and one burst lost", rec)
			}
			e.recover(path)
			time.Sleep(3 * time.Second) // the heartbeat at 15s resolves again and answers
			synctest.Wait()
			if got := r.count(dstA); got != 2 {
				t.Errorf("resolutions = %d, want another after the lost burst", got)
			}
			rec, _ = record(b, "use")
			if rec.LostBursts != 0 || len(rec.Samples) != 1 || rec.Samples[0].Lost {
				t.Errorf("record = %+v, want the answer alone", rec)
			}
		})
	})
}

// TestProberBurstsOnSignal checks that a signal on a link a requested path
// crosses calls a burst for that path alone, and that a later state still
// holding the same signal calls none.
func TestProberBurstsOnSignal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		crossing, other := &spath.Decoded{}, &spath.Decoded{}
		link := segment.LinkID{IA: addr.MustIAFrom(1, 0xff0000000020), IfID: 4}
		signal := func(b *bus.Bus, link segment.LinkID) {
			b.InterfaceDown().Update(func(s bus.InterfaceDownState) bus.InterfaceDownState {
				return s.Signaled(link, time.Now())
			})
		}
		prober(t, e, r, func(b *bus.Bus) {
			now := time.Now()
			request(b, dstA,
				entryOf("crossing", dstA, crossing, bus.PathInUse, now, link),
				entryOf("other", dstA, other, bus.PathStandby, now))
			time.Sleep(2 * time.Second)
			synctest.Wait()
			signal(b, link)
			time.Sleep(2 * time.Second)
			synctest.Wait()
			if got := e.sends(crossing); got != 1+BurstProbes {
				t.Errorf("the crossing path drew %d probes, want its heartbeat and a burst", got)
			}
			if got := e.sends(other); got != 1 {
				t.Errorf("the other path drew %d probes, want its routine one alone", got)
			}
			signal(b, segment.LinkID{IA: link.IA, IfID: 5})
			time.Sleep(2 * time.Second) // the heartbeat at 5s
			synctest.Wait()
			if got := e.sends(crossing); got != 1+BurstProbes+1 {
				t.Errorf("the crossing path drew %d probes, want another heartbeat alone", got)
			}
		})
	})
}

// TestProberBurstAnswered checks that a burst one of whose probes answers
// counts no lost burst and keeps the destination's host.
func TestProberBurstAnswered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			request(b, dstA, entryOf("use", dstA, path, bus.PathInUse, time.Now()))
			time.Sleep(time.Second)
			synctest.Wait()
			e.drop(path, 2)
			time.Sleep(7 * time.Second) // the heartbeat at 5s lost; the burst from 6s, its first lost
			synctest.Wait()
			if got := e.sends(path); got != 2+BurstProbes {
				t.Fatalf("probes = %d, want two heartbeats and a burst", got)
			}
			if rec, _ := record(b, "use"); rec.LostBursts != 0 {
				t.Errorf("record = %+v, want no lost burst", rec)
			}
			if got := r.count(dstA); got != 1 {
				t.Errorf("resolutions = %d, want the first alone", got)
			}
		})
	})
}

// TestProberHalfOpen checks that a half-open path draws nothing until its
// due time, a burst then, and that an answer clears its lost bursts.
func TestProberHalfOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			entry := entryOf("ejected", dstA, path, bus.PathHalfOpen, time.Now())
			entry.Due = time.Now().Add(10 * time.Second)
			request(b, dstA, entry)
			time.Sleep(9 * time.Second)
			synctest.Wait()
			if got := e.sends(path); got != 0 {
				t.Fatalf("probes before the due time = %d, want none", got)
			}
			time.Sleep(3 * time.Second)
			synctest.Wait()
			if got := e.sends(path); got != BurstProbes {
				t.Errorf("probes = %d, want one burst", got)
			}
			if rec, _ := record(b, "ejected"); rec.LostBursts != 0 || rec.LastAnswer.IsZero() {
				t.Errorf("record = %+v, want an answer", rec)
			}
		})
	})
}

// TestProberBudget checks the node-wide budget: a full bucket's twenty
// probes at once, the rest as it refills.
func TestProberBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		var paths []*spath.Decoded
		var entries []bus.PathRequest
		for i := range 50 {
			p := &spath.Decoded{}
			paths = append(paths, p)
			entries = append(entries, entryOf(bus.PathID(rune('A'+i)), dstA, p, bus.PathInUse, time.Now()))
		}
		total := func() int {
			n := 0
			for _, p := range paths {
				n += e.sends(p)
			}
			return n
		}
		prober(t, e, r, func(b *bus.Bus) {
			request(b, dstA, entries...)
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			if got := total(); got != Budget {
				t.Errorf("probes at once = %d, want the bucket's %d", got, Budget)
			}
			time.Sleep(1500 * time.Millisecond)
			synctest.Wait()
			if got := total(); got != len(paths) {
				t.Errorf("probes after 1.5s = %d, want every path's first", got)
			}
		})
	})
}

// TestProberBudgetOrder checks the order a spent budget serves the probes
// due in as it refills, a probe each twentieth of a second: a burst first,
// then a heartbeat, then a once-a-minute probe.
func TestProberBudgetOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		link := segment.LinkID{IA: addr.MustIAFrom(1, 0xff0000000020), IfID: 4}
		now := time.Now()
		var spend []bus.PathRequest
		for i := range Budget {
			spend = append(spend, entryOf(bus.PathID(rune('A'+i)), dstA, &spath.Decoded{}, bus.PathInUse, now))
		}
		burst, heartbeat, slow := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			request(b, dstA, spend...)
			synctest.Wait()
			request(b, dstA, append(spend,
				entryOf("burst", dstA, burst, bus.PathInUse, now, link),
				entryOf("heartbeat", dstA, heartbeat, bus.PathInUse, now),
				entryOf("slow", dstA, slow, bus.PathStandby, now))...)
			synctest.Wait()
			b.InterfaceDown().Update(func(s bus.InterfaceDownState) bus.InterfaceDownState {
				return s.Signaled(link, now)
			})
			for _, want := range [][3]int{{1, 0, 0}, {1, 1, 0}, {1, 1, 1}} {
				time.Sleep(time.Second / Budget)
				synctest.Wait()
				if got := [3]int{e.sends(burst), e.sends(heartbeat), e.sends(slow)}; got != want {
					t.Fatalf("probes of the burst, the heartbeat, and the slow path = %v, want %v", got, want)
				}
			}
		})
	})
}

// TestProberResolveRetry checks that a failed resolution is retried after
// its spacing, the destination's path unprobed meanwhile.
func TestProberResolveRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{fail: true}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			request(b, dstA, entryOf("use", dstA, path, bus.PathInUse, time.Now()))
			time.Sleep(12 * time.Second)
			synctest.Wait()
			if got := r.count(dstA); got != 3 {
				t.Errorf("resolutions in 12s = %d, want those at 0s, 5s, and 10s", got)
			}
			if got := e.sends(path); got != 0 {
				t.Errorf("probes = %d, want none without a host", got)
			}
		})
	})
}

// TestProberResolvesOverAnsweringPaths checks the order the resolution
// after a lost burst tries the destination's paths in until one answers:
// those that lost no burst first, the latest answer first among them.
func TestProberResolvesOverAnsweringPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		inUse, standby, suspect := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
		e.rtt[standby], e.rtt[suspect] = 10*time.Millisecond, 200*time.Millisecond
		prober(t, e, r, func(b *bus.Bus) {
			now := time.Now()
			request(b, dstA,
				entryOf("use", dstA, inUse, bus.PathInUse, now),
				entryOf("standby", dstA, standby, bus.PathStandby, now),
				entryOf("suspect", dstA, suspect, bus.PathSuspect, now))
			time.Sleep(time.Second)
			synctest.Wait()
			e.lose(inUse)
			r.kill(inUse)
			r.kill(suspect)
			time.Sleep(9500 * time.Millisecond) // the heartbeat at 5s lost; its burst lost by 7.8s; resolved at 10s
			synctest.Wait()
			r.mu.Lock()
			calls := slices.Clone(r.calls[dstA])
			r.mu.Unlock()
			if len(calls) != 3 || calls[1] != suspect || calls[2] != standby {
				t.Errorf("resolutions = %d, want the first, then over the suspect and the standby", len(calls))
			}
			if got := e.sends(inUse); got != 2+BurstProbes+1 {
				t.Errorf("probes of the path in use = %d, want two heartbeats, a burst, and the one at 10s", got)
			}
		})
	})
}

// TestProberVerifiesSuspects checks that a suspect path that answers draws
// its routine probe alone, and that one whose probe is lost draws a burst,
// which counts once lost whole.
func TestProberVerifiesSuspects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		answering, losing := &spath.Decoded{}, &spath.Decoded{}
		e.lose(losing)
		prober(t, e, r, func(b *bus.Bus) {
			now := time.Now()
			request(b, dstA,
				entryOf("answering", dstA, answering, bus.PathSuspect, now),
				entryOf("losing", dstA, losing, bus.PathSuspect, now))
			time.Sleep(3 * time.Second) // the probes at 0s; the loss at 1s; its burst lost by 2.8s
			synctest.Wait()
			if got := e.sends(answering); got != 1 {
				t.Errorf("the answering suspect drew %d probes, want one", got)
			}
			if got := e.sends(losing); got != 1+BurstProbes {
				t.Errorf("the losing suspect drew %d probes, want one and a burst", got)
			}
			if rec, _ := record(b, "losing"); rec.LostBursts != 1 {
				t.Errorf("the losing suspect's record = %+v, want one burst lost", rec)
			}
		})
	})
}

// TestProberSkipsConfirmed checks that a caller's confirmation stands in for
// a routine probe: the path's next probe is due a heartbeat after it.
func TestProberSkipsConfirmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			picked := time.Now()
			confirmed := func() bus.PathRequest {
				entry := entryOf("use", dstA, path, bus.PathInUse, picked)
				entry.Confirmed = time.Now()
				return entry
			}
			request(b, dstA, confirmed())
			time.Sleep(4 * time.Second)
			synctest.Wait()
			request(b, dstA, confirmed())
			time.Sleep(4500 * time.Millisecond) // the heartbeat a confirmation at 4s put off to 9s
			synctest.Wait()
			if got := e.sends(path); got != 0 {
				t.Fatalf("probes = %d, want none while callers confirm the path", got)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if got := e.sends(path); got != 1 {
				t.Errorf("probes = %d, want the heartbeat at 9s", got)
			}
		})
	})
}

// TestProberBurstsOnDoubt checks that a caller's doubt newer than the path's
// last answer calls a burst once, however often the requests repeat it, and
// that one older than its last answer calls none.
func TestProberBurstsOnDoubt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		path := &spath.Decoded{}
		prober(t, e, r, func(b *bus.Bus) {
			picked := time.Now()
			doubted := func(at time.Time) bus.PathRequest {
				entry := entryOf("standby", dstA, path, bus.PathStandby, picked)
				entry.Doubted = at
				return entry
			}
			request(b, dstA, entryOf("standby", dstA, path, bus.PathStandby, picked))
			time.Sleep(time.Second) // the first probe at 0s answered
			synctest.Wait()
			request(b, dstA, doubted(time.Now().Add(-2*time.Second)))
			time.Sleep(time.Second)
			synctest.Wait()
			if got := e.sends(path); got != 1 {
				t.Fatalf("probes = %d, want the first alone for a doubt older than its answer", got)
			}
			// The doubt's burst is lost whole, so its answer stays older than
			// the doubt the requests repeat.
			e.lose(path)
			doubt := time.Now()
			request(b, dstA, doubted(doubt))
			time.Sleep(2 * time.Second)
			synctest.Wait()
			request(b, dstA, doubted(doubt))
			time.Sleep(2 * time.Second)
			synctest.Wait()
			if got := e.sends(path); got != 1+BurstProbes {
				t.Errorf("probes = %d, want the first and one burst for the doubt", got)
			}
		})
	})
}

// TestProberProbesPricedRoutes checks a priced route's pacing: probed every
// RouteProbe while hot, first at once, its lost probe calling a burst, its
// role kept over the standby another requester names it, and never once its
// destination is warm.
func TestProberProbesPricedRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, r := newFakeEcho(), &fakeResolver{}
		priced, lossy, warm := &spath.Decoded{}, &spath.Decoded{}, &spath.Decoded{}
		e.drop(lossy, 1)
		prober(t, e, r, func(b *bus.Bus) {
			now := time.Now()
			b.PathRequests().Update(func(rs bus.PathRequests) bus.PathRequests {
				return rs.Replaced("selection", map[addr.IA][]bus.PathRequest{
					dstA: {
						entryOf("priced", dstA, priced, bus.PathPriced, now),
						entryOf("lossy", dstA, lossy, bus.PathPriced, now),
					},
					dstB: {entryOf("warm", dstB, warm, bus.PathPriced, now.Add(-2*time.Minute))},
				})
			})
			request(b, dstA, entryOf("priced", dstA, priced, bus.PathStandby, now))
			time.Sleep(RouteProbe + time.Second)
			synctest.Wait()
			for _, tc := range []struct {
				name string
				path *spath.Decoded
				want int
			}{{"priced", priced, 2}, {"lossy", lossy, 2 + BurstProbes}, {"warm", warm, 0}} {
				if got := e.sends(tc.path); got != tc.want {
					t.Errorf("the %s route drew %d probes in %v, want %d", tc.name, got, RouteProbe+time.Second, tc.want)
				}
			}
		})
	})
}
