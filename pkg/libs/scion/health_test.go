package scion

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// measuredFixture is the rank fixture's leaf with the measurements and
// requests topics, and its two routes to the destination: direct to the
// core, 40ms declared, and through the middle, 10ms; both then down the core's
// segment, 5ms.
type measuredFixture struct {
	rankFixture
	p              *PathProvider
	direct, viaMid Candidate
}

func newMeasuredFixture(t *testing.T, midAge time.Duration) measuredFixture {
	t.Helper()
	f := measuredFixture{rankFixture: newRankFixture(t, midAge)}
	f.p = f.provider(t, f.upDirect, f.upMid)
	f.p.InterfaceDown = new(bus.Topic[bus.InterfaceDownState])
	f.p.Measurements = new(bus.Topic[bus.PathMeasurements])
	f.p.Requests = new(bus.Topic[bus.PathRequests])
	candidates, err := f.p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range candidates {
		switch c.Segments[0].PCB {
		case f.upDirect:
			f.direct = c
		case f.upMid:
			f.viaMid = c
		}
	}
	return f
}

// measure publishes the records, by the candidates they measure.
func (f measuredFixture) measure(records map[*Candidate]bus.PathRecord) {
	m := make(map[bus.PathID]bus.PathRecord, len(records))
	for c, r := range records {
		r.Links = c.Crossed
		m[c.ID] = r
	}
	f.p.Measurements.Publish(bus.NewPathMeasurements(m))
}

// signalAt records a signal on the link, arrived at the given time.
func (f measuredFixture) signalAt(link segment.LinkID, at time.Time) {
	f.p.InterfaceDown.Update(func(s bus.InterfaceDownState) bus.InterfaceDownState {
		return s.Signaled(link, at)
	})
}

// answered returns a record whose probes, each answered at at, took the
// round trips.
func answered(at time.Time, rtts ...time.Duration) bus.PathRecord {
	r := bus.PathRecord{LastAnswer: at}
	for _, rtt := range rtts {
		r.Samples = append(r.Samples, bus.PathSample{At: at, RTT: rtt})
	}
	return r
}

// ejectedAt returns a record that answered a minute before now and lost two
// bursts since.
func ejectedAt(now time.Time) bus.PathRecord {
	r := answered(now.Add(-time.Minute), 10*time.Millisecond)
	r.LastLoss, r.LostBursts = now, 2
	return r
}

// failedThrough returns a measured path of its own crossing the link alone,
// for a record that fails it.
func (f measuredFixture) failedThrough(link segment.LinkID) *Candidate {
	failed := f.viaMid
	failed.ID = bus.PathID("through " + link.IA.String())
	failed.Crossed = []segment.LinkID{link}
	return &failed
}

// TestCandidateIdentity checks the pairs a candidate's packets cross: a
// meeting's, travel order, without the core-ward interface at its turn; a
// containing branch's, without the destination's core-ward interface its
// links still name; and one route's ID through two refreshes of its segment.
func TestCandidateIdentity(t *testing.T) {
	f := newMeasuredFixture(t, time.Minute)
	link := func(ia addr.IA, ifID uint16) segment.LinkID { return segment.LinkID{IA: ia, IfID: ifID} }
	want := []segment.LinkID{link(iaLeaf, 24), link(iaMid, 23), link(iaMid, 22), link(iaCore, 21),
		link(iaCore, 31), link(iaDest, 32)}
	if diff := cmp.Diff(want, f.viaMid.Crossed); diff != "" {
		t.Errorf("the meeting's crossed pairs (-want +got):\n%s", diff)
	}
	if f.viaMid.ID != bus.PathIDOf(want) {
		t.Errorf("ID = %q, want its crossed pairs'", f.viaMid.ID)
	}

	branch, err := f.p.local(iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]segment.LinkID{link(iaLeaf, 24), link(iaMid, 23)}, branch.Crossed); diff != "" {
		t.Errorf("the containing branch's crossed pairs (-want +got):\n%s", diff)
	}
	if !slices.Contains(branch.Links, link(iaMid, 22)) {
		t.Errorf("the branch's links %v lack the destination's core-ward interface", branch.Links)
	}

	refreshed := f.provider(t, signedLine(t, time.Now().Add(time.Second),
		linkHop{ia: iaCore, eg: 21, latency: 5 * time.Millisecond},
		linkHop{ia: iaMid, in: 22, eg: 23, latency: 5 * time.Millisecond},
		linkHop{ia: iaLeaf, in: 24}))
	again, err := refreshed.Choose(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != f.viaMid.ID {
		t.Errorf("a refreshed segment's ID = %q, want %q", again.ID, f.viaMid.ID)
	}
}

// TestHealth checks the health and cost a candidate carries by its record,
// its callers' reports, the signals, its staleness, and the links its failed
// paths share.
func TestHealth(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		name   string
		midAge time.Duration
		setup  func(f measuredFixture, now time.Time)
		health Health
		cost   time.Duration
	}{{
		name:   "unmeasured",
		midAge: time.Minute,
		setup:  func(measuredFixture, time.Time) {},
		health: HealthUnknown,
		cost:   30 * ms, // twice the declared 15ms
	}, {
		name:   "answered lately",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			r := answered(now.Add(-time.Minute), 10*ms, 12*ms, 30*ms)
			r.Samples = append(r.Samples, bus.PathSample{At: now, Lost: true})
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: r})
		},
		health: HealthHealthy,
		cost:   16 * ms, // the median 12ms over a delivery of three in four
	}, {
		name:   "answered before the trust window",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-4*time.Minute), 20*ms)})
		},
		health: HealthUnknown,
		cost:   20 * ms,
	}, {
		name:   "a burst lost whole",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			r := answered(now.Add(-time.Minute), 10*ms)
			r.LostBursts = 1
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: r})
		},
		health: HealthEjected,
		cost:   10 * ms,
	}, {
		name:   "nearly every probe lost",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			r := answered(now, 10*ms)
			for range 19 {
				r.Samples = append(r.Samples, bus.PathSample{At: now, Lost: true})
			}
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: r})
		},
		health: HealthEjected,
		cost:   100 * ms, // its loss counted to nine in ten
	}, {
		name:   "a lost probe alone",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{
				&f.viaMid: {Samples: []bus.PathSample{{At: now, Lost: true}}, LastLoss: now},
			})
		},
		health: HealthUnknown,
		cost:   30 * ms,
	}, {
		name:   "a signal newer than the last answer",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-5*time.Second), 10*ms)})
			f.signalAt(segment.LinkID{IA: iaMid, IfID: 22}, now.Add(-time.Second))
		},
		health: HealthSuspect,
		cost:   10 * ms,
	}, {
		name:   "a signal older than the last answer",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-time.Second), 10*ms)})
			f.signalAt(segment.LinkID{IA: iaMid, IfID: 22}, now.Add(-5*time.Second))
		},
		health: HealthHealthy,
		cost:   10 * ms,
	}, {
		name:   "a signal standing since the last answer",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-2*time.Minute), 10*ms)})
			f.signalAt(segment.LinkID{IA: iaMid, IfID: 22}, now.Add(-time.Minute))
		},
		health: HealthSuspect,
		cost:   10 * ms,
	}, {
		name:   "a signal past its lapse",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.signalAt(segment.LinkID{IA: iaMid, IfID: 22}, now.Add(-bus.RequestLapse))
		},
		health: HealthUnknown,
		cost:   30 * ms,
	}, {
		name:   "stale and unanswered",
		midAge: StaleAfter + time.Minute,
		setup:  func(measuredFixture, time.Time) {},
		health: HealthSuspect,
		cost:   30 * ms,
	}, {
		name:   "stale but answered",
		midAge: StaleAfter + time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-time.Minute), 10*ms)})
		},
		health: HealthHealthy,
		cost:   10 * ms,
	}, {
		name:   "a link its failed paths share",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			// A measured path crossing the middle's link failed while the
			// direct route answers.
			f.measure(map[*Candidate]bus.PathRecord{
				f.failedThrough(segment.LinkID{IA: iaMid, IfID: 23}): ejectedAt(now),
				&f.direct: answered(now.Add(-time.Second), 50*ms),
			})
		},
		health: HealthSuspect,
		cost:   30 * ms,
	}, {
		name:   "a link failed paths share while nothing answers",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{
				f.failedThrough(segment.LinkID{IA: iaMid, IfID: 23}): ejectedAt(now),
			})
		},
		health: HealthUnknown,
		cost:   30 * ms,
	}, {
		name:   "a link an answering path crosses too",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			// The failed path crosses the core's link toward the
			// destination, which the answering direct route crosses too.
			f.measure(map[*Candidate]bus.PathRecord{
				f.failedThrough(segment.LinkID{IA: iaCore, IfID: 31}): ejectedAt(now),
				&f.direct: answered(now.Add(-time.Second), 50*ms),
			})
		},
		health: HealthUnknown,
		cost:   30 * ms,
	}, {
		name:   "a caller's delivery",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.p.record(f.viaMid.ID, true, now.Add(-time.Minute))
		},
		health: HealthHealthy,
		cost:   30 * ms,
	}, {
		name:   "a caller's delivery since a lost burst",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: ejectedAt(now.Add(-10 * time.Second))})
			f.p.record(f.viaMid.ID, true, now.Add(-5*time.Second))
		},
		health: HealthHealthy,
		cost:   10 * ms,
	}, {
		name:   "a caller's loss since the last answer",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-time.Minute), 10*ms)})
			f.p.record(f.viaMid.ID, false, now.Add(-30*time.Second))
		},
		health: HealthSuspect,
		cost:   10 * ms,
	}, {
		name:   "callers' losses within the trust window",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-2*time.Minute), 10*ms)})
			for _, ago := range []time.Duration{90, 60, 30} {
				f.p.record(f.viaMid.ID, false, now.Add(-ago*time.Second))
			}
		},
		health: HealthEjected,
		cost:   10 * ms,
	}, {
		name:   "two callers' losses within the trust window",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-2*time.Minute), 10*ms)})
			for _, ago := range []time.Duration{60, 30} {
				f.p.record(f.viaMid.ID, false, now.Add(-ago*time.Second))
			}
		},
		health: HealthSuspect,
		cost:   10 * ms,
	}, {
		name:   "callers' losses before the last answer",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			for _, ago := range []time.Duration{90, 80, 70} {
				f.p.record(f.viaMid.ID, false, now.Add(-ago*time.Second))
			}
			f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-time.Minute), 10*ms)})
		},
		health: HealthHealthy,
		cost:   10 * ms,
	}, {
		name:   "callers' losses past the trust window",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			for _, ago := range []time.Duration{240, 200, 30} {
				f.p.record(f.viaMid.ID, false, now.Add(-ago*time.Second))
			}
		},
		health: HealthSuspect,
		cost:   30 * ms,
	}, {
		name:   "a caller's loss past the request lapse",
		midAge: time.Minute,
		setup: func(f measuredFixture, now time.Time) {
			f.p.record(f.viaMid.ID, false, now.Add(-bus.RequestLapse))
		},
		health: HealthUnknown,
		cost:   30 * ms,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMeasuredFixture(t, tc.midAge)
			tc.setup(f, time.Now())
			candidates, err := f.p.Enumerate(context.Background(), iaDest)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(candidates, func(c Candidate) bool { return c.ID == f.viaMid.ID })
			c := candidates[i]
			if c.Health != tc.health {
				t.Errorf("health = %d, want %d", c.Health, tc.health)
			}
			if c.Cost == nil || *c.Cost != tc.cost {
				t.Errorf("cost = %v, want %v", c.Cost, tc.cost)
			}
		})
	}
}

// TestEjectedRetry checks when an ejected candidate is due its half-open
// probe: its backoff after its last loss, and never for one not ejected.
func TestEjectedRetry(t *testing.T) {
	f := newMeasuredFixture(t, time.Minute)
	now := time.Now()
	f.measure(map[*Candidate]bus.PathRecord{
		&f.viaMid: ejectedAt(now),
		&f.direct: answered(now, 10*time.Millisecond),
	})
	candidates, err := f.p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range candidates {
		var want time.Time
		if c.ID == f.viaMid.ID {
			want = now.Add(backoff(2))
		}
		if !c.Retry.Equal(want) {
			t.Errorf("%s retries at %v, want %v", c.ID, c.Retry, want)
		}
	}
}

// TestBackoff checks the half-open backoff: ten seconds after the first lost
// burst, doubling with each, at most a minute.
func TestBackoff(t *testing.T) {
	for lost, want := range map[int]time.Duration{
		0: 10 * time.Second, 1: 10 * time.Second, 2: 20 * time.Second, 3: 40 * time.Second,
		4: time.Minute, 9: time.Minute,
	} {
		if got := backoff(lost); got != want {
			t.Errorf("backoff(%d) = %v, want %v", lost, got, want)
		}
	}
}

// TestPicksFollowHealth checks the picks' order: a deliverable path before a
// suspect one before an ejected one, a suspect one no signal names since its
// last answer before a signaled one; within a tier, a cost beyond the band,
// an unmeasured path's prior standing in, else the prior order.
func TestPicksFollowHealth(t *testing.T) {
	ms := time.Millisecond
	viaMidLink := func(measuredFixture) segment.LinkID { return segment.LinkID{IA: iaMid, IfID: 23} }
	for _, tc := range []struct {
		name    string
		records func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord
		// signal, when set, names the link signaled as the pick runs.
		signal func(f measuredFixture) segment.LinkID
		// stale has the route through the middle read stale.
		stale  bool
		direct bool
	}{{
		name:    "the prior order unmeasured",
		records: func(measuredFixture, time.Time) map[*Candidate]bus.PathRecord { return nil },
	}, {
		name: "an ejected prior best",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{&f.viaMid: ejectedAt(now)}
		},
		direct: true,
	}, {
		name: "a signaled prior best",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{&f.viaMid: answered(now.Add(-5*time.Second), 5*ms)}
		},
		signal: viaMidLink,
		direct: true,
	}, {
		name: "an ejected path below a signaled one",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{&f.viaMid: ejectedAt(now)}
		},
		signal: func(f measuredFixture) segment.LinkID { return f.direct.Crossed[1] },
		direct: true,
	}, {
		name: "a stale path above a cheaper signaled one",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{&f.direct: answered(now.Add(-5*time.Second), 5*ms)}
		},
		signal: func(f measuredFixture) segment.LinkID { return f.direct.Crossed[1] },
		stale:  true,
	}, {
		name: "a measured cost beyond the band",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{
				&f.direct: answered(now, 10*ms),
				&f.viaMid: answered(now, 20*ms),
			}
		},
		direct: true,
	}, {
		name: "measured costs within the band's floor",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{
				&f.direct: answered(now, 1*ms),
				&f.viaMid: answered(now, 2500*time.Microsecond),
			}
		},
	}, {
		name: "measured costs within the band's share",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{
				&f.direct: answered(now, 100*ms),
				&f.viaMid: answered(now, 110*ms),
			}
		},
	}, {
		name: "an unmeasured prior beyond a measured cost",
		records: func(f measuredFixture, now time.Time) map[*Candidate]bus.PathRecord {
			return map[*Candidate]bus.PathRecord{&f.direct: answered(now, 40*ms)}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			midAge := time.Minute
			if tc.stale {
				midAge = StaleAfter + time.Minute
			}
			f := newMeasuredFixture(t, midAge)
			now := time.Now()
			f.measure(tc.records(f, now))
			if tc.signal != nil {
				f.signalAt(tc.signal(f), now)
			}
			pick, err := f.p.Choose(context.Background(), iaDest)
			if err != nil {
				t.Fatal(err)
			}
			want := f.viaMid.ID
			if tc.direct {
				want = f.direct.ID
			}
			if pick.ID != want {
				t.Errorf("Choose picked %q, want %q", pick.ID, want)
			}
		})
	}

	t.Run("LocalPath's containing branches", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		mid, err := f.p.local(iaCore)
		if err != nil {
			t.Fatal(err)
		}
		r := answered(time.Now(), 5*ms)
		r.LostBursts = 1
		f.measure(map[*Candidate]bus.PathRecord{mid: r})
		pick, err := f.p.local(iaCore)
		if err != nil {
			t.Fatal(err)
		}
		if pick.ID == mid.ID || pick.Segments[0].PCB != f.upDirect {
			t.Errorf("LocalPath picked %q, want the direct branch over the ejected %q", pick.ID, mid.ID)
		}
	})
}

// TestPickRequests checks the entries a pick updates for its destination:
// the pick in use; the best other path sharing no link with it, standby; a
// suspect path whose prior order beats the pick's, suspect; an ejected path
// whose prior order beats the pick's, half-open at its backoff; all stamped
// with the pick's time; and the lapse of another destination's.
func TestPickRequests(t *testing.T) {
	// requests returns the provider's entries by path, failing on a path
	// two entries name.
	requests := func(t *testing.T, p *PathProvider) map[bus.PathID]bus.PathRequest {
		t.Helper()
		out := make(map[bus.PathID]bus.PathRequest)
		for r := range p.Requests.Latest().All() {
			if _, ok := out[r.ID]; ok {
				t.Errorf("two entries name %q", r.ID)
			}
			out[r.ID] = r
		}
		return out
	}

	t.Run("in use and standby", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		lapsed := time.Now().Add(-bus.RequestLapse - time.Second)
		f.p.Requests.Update(func(r bus.PathRequests) bus.PathRequests {
			return r.Requested(picksRequester, iaMid, []bus.PathRequest{{ID: "old", Dst: iaMid, Picked: lapsed}}, lapsed)
		})
		before := time.Now()
		if _, err := f.p.Choose(context.Background(), iaDest); err != nil {
			t.Fatal(err)
		}
		got := requests(t, f.p)
		if len(got) != 2 {
			t.Fatalf("requests = %v, want the pick and its standby alone", got)
		}
		inUse, standby := got[f.viaMid.ID], got[f.direct.ID]
		if inUse.Role != bus.PathInUse || standby.Role != bus.PathStandby {
			t.Errorf("roles = %d, %d, want in use and standby", inUse.Role, standby.Role)
		}
		if inUse.Dst != iaDest || inUse.Path == nil || !slices.Equal(inUse.Links, f.viaMid.Crossed) {
			t.Errorf("the in-use entry = %+v, want the pick's destination, path, and crossed pairs", inUse)
		}
		if inUse.Picked.Before(before) || !standby.Picked.Equal(inUse.Picked) {
			t.Errorf("picked at %v and %v, want the pick's time", inUse.Picked, standby.Picked)
		}
	})

	t.Run("half-open", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		lastLoss := time.Now().Add(-5 * time.Second)
		f.measure(map[*Candidate]bus.PathRecord{&f.viaMid: ejectedAt(lastLoss)})
		pick, err := f.p.Choose(context.Background(), iaDest)
		if err != nil {
			t.Fatal(err)
		}
		got := requests(t, f.p)
		if len(got) != 2 || pick.ID != f.direct.ID || got[f.direct.ID].Role != bus.PathInUse {
			t.Fatalf("requests = %v, want the direct route in use and the ejected one alone", got)
		}
		halfOpen := got[f.viaMid.ID]
		if halfOpen.Role != bus.PathHalfOpen || !halfOpen.Due.Equal(lastLoss.Add(20*time.Second)) {
			t.Errorf("the ejected entry = role %d due %v, want half-open 20s after its last loss",
				halfOpen.Role, halfOpen.Due)
		}
	})

	t.Run("an ejected path the pick outranks", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		f.measure(map[*Candidate]bus.PathRecord{&f.direct: ejectedAt(time.Now())})
		pick, err := f.p.Choose(context.Background(), iaDest)
		if err != nil {
			t.Fatal(err)
		}
		if got := requests(t, f.p); len(got) != 1 || pick.ID != f.viaMid.ID || got[pick.ID].Role != bus.PathInUse {
			t.Errorf("requests = %v, want the pick in use alone", got)
		}
	})

	t.Run("a suspect path whose prior order beats the pick's", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		// A second branch through the middle, over a link to the core of its
		// own. A failed path through the leaf's link to the middle makes
		// both branches through it suspect while the direct route answers.
		f.p = f.provider(t, f.upDirect, f.upMid, signedLine(t, time.Now(),
			linkHop{ia: iaCore, eg: 26, latency: 6 * time.Millisecond},
			linkHop{ia: iaMid, in: 25, eg: 23, latency: 5 * time.Millisecond},
			linkHop{ia: iaLeaf, in: 24}))
		f.p.Measurements = new(bus.Topic[bus.PathMeasurements])
		f.p.Requests = new(bus.Topic[bus.PathRequests])
		now := time.Now()
		f.measure(map[*Candidate]bus.PathRecord{
			f.failedThrough(segment.LinkID{IA: iaLeaf, IfID: 24}): ejectedAt(now),
			&f.direct: answered(now, 50*time.Millisecond),
		})
		pick, err := f.p.Choose(context.Background(), iaDest)
		if err != nil {
			t.Fatal(err)
		}
		got := requests(t, f.p)
		if len(got) != 3 || pick.ID != f.direct.ID || got[f.viaMid.ID].Role != bus.PathStandby {
			t.Fatalf("requests = %v, want the direct route, the middle branch standby, and a suspect", got)
		}
		for id, r := range got {
			if id != pick.ID && id != f.viaMid.ID && r.Role != bus.PathSuspect {
				t.Errorf("the second middle branch's entry %q = role %d, want suspect", id, r.Role)
			}
		}
	})

	t.Run("a suspect path the pick outranks", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		// The second branch through the middle is suspect by a failed path
		// through its own link to the core, and the first branch answers.
		f.p = f.provider(t, f.upDirect, f.upMid, signedLine(t, time.Now(),
			linkHop{ia: iaCore, eg: 26, latency: 6 * time.Millisecond},
			linkHop{ia: iaMid, in: 25, eg: 23, latency: 5 * time.Millisecond},
			linkHop{ia: iaLeaf, in: 24}))
		f.p.Measurements = new(bus.Topic[bus.PathMeasurements])
		f.p.Requests = new(bus.Topic[bus.PathRequests])
		now := time.Now()
		f.measure(map[*Candidate]bus.PathRecord{
			f.failedThrough(segment.LinkID{IA: iaCore, IfID: 26}): ejectedAt(now),
			&f.viaMid: answered(now, 20*time.Millisecond),
		})
		pick, err := f.p.Choose(context.Background(), iaDest)
		if err != nil {
			t.Fatal(err)
		}
		got := requests(t, f.p)
		if len(got) != 2 || pick.ID != f.viaMid.ID || got[f.direct.ID].Role != bus.PathStandby {
			t.Errorf("requests = %v, want the first middle branch in use and the direct route standby alone", got)
		}
	})

	t.Run("LocalPath's disjoint standby", func(t *testing.T) {
		f := newMeasuredFixture(t, time.Minute)
		// A second branch through the middle, over a link to the core of its
		// own, ranks between the pick and the direct branch, and shares the
		// leaf's link to the middle with the pick.
		p := f.provider(t, f.upDirect, f.upMid, signedLine(t, time.Now(),
			linkHop{ia: iaCore, eg: 26, latency: 6 * time.Millisecond},
			linkHop{ia: iaMid, in: 25, eg: 23, latency: 5 * time.Millisecond},
			linkHop{ia: iaLeaf, in: 24}))
		p.Requests = new(bus.Topic[bus.PathRequests])
		pick, err := p.local(iaCore)
		if err != nil {
			t.Fatal(err)
		}
		got := requests(t, p)
		if len(got) != 2 || got[pick.ID].Role != bus.PathInUse {
			t.Fatalf("requests = %v, want the pick and a standby", got)
		}
		for id, r := range got {
			if id != pick.ID && (r.Role != bus.PathStandby || slices.ContainsFunc(r.Links,
				func(l segment.LinkID) bool { return slices.Contains(pick.Crossed, l) })) {
				t.Errorf("the other entry %q = %+v, want a standby sharing no link with the pick", id, r)
			}
		}
	})
}
