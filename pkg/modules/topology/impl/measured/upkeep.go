package measured

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The link upkeep's timing: each link's locator is kept on the source the
// link observes its peer at, and a punched link whose verdict stays down is
// punched again in place.
const (
	// UpkeepGrace is how long a change to a link holds before the upkeep
	// acts on it: one BFD detection time. A verdict down that long is no
	// outage the link rides out, an observation away from the locator that
	// long is no stray arrival, and the request that just landed the entry
	// has passed the peer's admission rate by then.
	UpkeepGrace = 3 * time.Second
	// FollowRetry is the first pause after a confirm one entry's mismatch
	// sends; later pauses double up to FollowRetryMax.
	FollowRetry = 5 * time.Second
	// FollowRetryMax caps the pause between one entry's confirms.
	FollowRetryMax = time.Minute
	// RepunchRetry is the first wait after a link's failed re-punch; later
	// waits double it.
	RepunchRetry = 5 * time.Second
	// RepunchAttempts bounds the re-punches of one down period: a peer that
	// stays unreachable leaves the link to the selection's retirement.
	RepunchAttempts = 3
)

// runUpkeep keeps each link on its peer's current mapping: it follows each
// link's flow, and punches a punched link again once its verdict stays down.
// It wakes on each link state event and each event of the node's own state,
// when an entry's action ends, and when the next retry or grace it waits on
// is due, never on a cadence of its own.
// Each entry's action runs off the loop, one at a time; the loop returns
// once every action has.
func (z *Provider) runUpkeep(ctx context.Context) {
	u := &upkeep{
		z:         z,
		confirms:  loops.Attempts[uint16]{Backoff: loops.Backoff{Base: FollowRetry, Max: FollowRetryMax}},
		repunches: newRepunchState(),
		busy:      make(map[uint16]bool),
		done:      make(chan uint16),
	}
	defer u.wg.Wait()
	events := z.linkState.Subscribe(ctx)
	selfEvents := z.self.Subscribe(ctx)
	wake := time.NewTimer(0)
	wake.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case state, ok := <-events:
			if !ok {
				return
			}
			u.links = state
		case self, ok := <-selfEvents:
			if !ok {
				return
			}
			u.self = self
		case <-wake.C:
		case ifID := <-u.done:
			delete(u.busy, ifID)
		}
		if next := u.pass(ctx, time.Now()); next.IsZero() {
			wake.Stop()
		} else {
			wake.Reset(time.Until(next))
		}
	}
}

// upkeep is the link upkeep's memory.
type upkeep struct {
	z *Provider
	// links and self are the latest events of the link state and the
	// node's own state.
	links bus.LinkState
	self  bus.SelfState
	// mismatched holds since when each established entry's link has
	// observed its peer away from its locator; confirms paces their
	// confirms; repunches remembers the punched links whose verdict is
	// down.
	mismatched map[uint16]time.Time
	confirms   loops.Attempts[uint16]
	repunches  *repunchState
	// busy holds the entries whose action runs; done receives each entry
	// whose action ended.
	busy map[uint16]bool
	done chan uint16
	wg   sync.WaitGroup
}

// pass starts the actions due at now and returns when the next one waits to
// be due, the zero time when none does.
func (u *upkeep) pass(ctx context.Context, now time.Time) time.Time {
	entries, err := u.z.env.Store.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return time.Time{}
	}
	return earliest(u.follow(ctx, entries, now), u.repunch(ctx, entries, now))
}

// follow keeps each live entry's locator on its link's own flow, the source
// the link observes its peer at. An established entry observed elsewhere for
// UpkeepGrace sends a confirm, its retries backing off from FollowRetry up to
// FollowRetryMax, whose answer — the authenticated reply, arriving over that
// link — records the observation. A candidate, which no chain confirms yet,
// takes the observation once its BFD session answers there: the
// return-routability the rendezvous exchange already holds candidates to. It
// returns when the next confirm waits to be due.
func (u *upkeep) follow(ctx context.Context, entries []*links.Link, now time.Time) time.Time {
	var next time.Time
	mismatched := make(map[uint16]time.Time, len(u.mismatched))
	for _, l := range entries {
		if !l.Live() || l.NeighborIA.IsZero() || !l.Remote.IsValid() {
			continue
		}
		observed := u.links.Observed(l.IfID)
		if !observed.IsValid() || observed == l.Remote {
			continue
		}
		switch l.State {
		case links.StateEstablished:
			since, ok := u.mismatched[l.IfID]
			if !ok {
				since = now
			}
			mismatched[l.IfID] = since
			if u.busy[l.IfID] {
				continue
			}
			if graced := since.Add(UpkeepGrace); now.Before(graced) {
				next = earliest(next, graced)
				continue
			}
			if !u.confirms.Due(l.IfID, now) {
				at, _ := u.confirms.Next(l.IfID)
				next = earliest(next, at)
				continue
			}
			u.confirms.Tried(l.IfID, now)
			slog.Info("Following a link's flow", "neighbor", l.NeighborIA,
				"remote", l.Remote, "observed", observed, "interface", l.IfID)
			entry := *l
			u.start(ctx, l.IfID, func(ctx context.Context) { u.z.confirmEntry(ctx, &entry) })
		case links.StateCandidate:
			if !u.links.Up(l.IfID) {
				continue
			}
			l.Remote = observed
			if err := u.z.env.Store.Update(ctx, l); err != nil {
				slog.Error("Following a candidate's flow", "neighbor", l.NeighborIA, "err", err)
				continue
			}
			slog.Info("A candidate followed its link's flow", "neighbor", l.NeighborIA,
				"remote", l.Remote, "interface", l.IfID)
		}
	}
	u.mismatched = mismatched
	u.confirms.Retain(func(ifID uint16) bool {
		_, ok := mismatched[ifID]
		return ok
	})
	return next
}

// repunch keeps punched links on their peers' current mappings. A NAT that
// remaps one end of a punched link leaves it down for good while the far
// end's NAT filters by address: that NAT drops what the new mapping sends,
// so no flow arrives to follow. It starts a re-punch of each punched link
// due at now and returns when the next one waits to be due. A node whose own
// published rendezvous address answers holds no punched link: its peers'
// flows reach it, and following keeps its links.
func (u *upkeep) repunch(ctx context.Context, entries []*links.Link, now time.Time) time.Time {
	if !u.self.RendezvousUnanswered {
		return time.Time{}
	}
	undialable := make(map[addr.IA]bool)
	for _, e := range u.z.directory.Entries() {
		if e.Reach.RendezvousUnanswered {
			undialable[e.IA] = true
		}
	}
	due, next := u.repunches.due(u.z.env.IA, entries, u.links.Up, undialable, now)
	for _, l := range due {
		if u.busy[l.IfID] {
			continue
		}
		u.repunches.attempts.Tried(l.IfID, now)
		entry := *l
		u.start(ctx, l.IfID, func(ctx context.Context) { u.z.repunch(ctx, u.z.puncher, &entry) })
	}
	return next
}

// start runs one entry's action off the loop; the entry starts no other
// until it ends. The action works on its own copy of the entry, for the pass
// that started it reads on.
func (u *upkeep) start(ctx context.Context, ifID uint16, act func(context.Context)) {
	u.busy[ifID] = true
	u.wg.Go(func() {
		act(ctx)
		select {
		case u.done <- ifID:
		case <-ctx.Done():
		}
	})
}

// earliest returns the earlier of two times, the zero time standing for
// none.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// repunchState is the upkeep's memory of the punched links whose verdict is
// down, by interface ID: since when each has been down, and its re-punches'
// backoff.
type repunchState struct {
	downSince map[uint16]time.Time
	attempts  loops.Attempts[uint16]
}

// newRepunchState returns the memory of an upkeep that has seen no down
// link.
func newRepunchState() *repunchState {
	return &repunchState{attempts: loops.Attempts[uint16]{
		Backoff: loops.Backoff{Base: RepunchRetry},
		Limit:   RepunchAttempts,
	}}
}

// due returns the punched links due for a re-punch at now and when the next
// one waits to be due, the zero time when none does, and advances the
// memory; the caller records each re-punch it starts. A punched link is an
// established, serving entry whose peer reports its published rendezvous
// address unanswered. Of its two ends, the one with the lower ISD-AS punches
// it again and the other's handler takes its own down entry, so the two
// never punch toward each other at once. A link is due once its verdict has
// stayed down for UpkeepGrace, then again on the backoff from RepunchRetry,
// until the down period has taken RepunchAttempts. A link whose verdict came
// back, as linkUp reports it, is forgotten.
func (st *repunchState) due(
	mine addr.IA, entries []*links.Link, linkUp func(ifID uint16) bool, undialable map[addr.IA]bool,
	now time.Time,
) (due []*links.Link, next time.Time) {

	down := make(map[uint16]time.Time, len(st.downSince))
	for _, l := range entries {
		if linkUp(l.IfID) || l.State != links.StateEstablished ||
			!l.Serving() || !undialable[l.NeighborIA] || mine >= l.NeighborIA {
			continue
		}
		since, ok := st.downSince[l.IfID]
		if !ok {
			since = now
		}
		down[l.IfID] = since
		if graced := since.Add(UpkeepGrace); now.Before(graced) {
			next = earliest(next, graced)
			continue
		}
		if !st.attempts.Due(l.IfID, now) {
			if at, ok := st.attempts.Next(l.IfID); ok {
				next = earliest(next, at)
			}
			continue
		}
		due = append(due, l)
	}
	st.downSince = down
	st.attempts.Retain(func(ifID uint16) bool {
		_, ok := down[ifID]
		return ok
	})
	return due, next
}
