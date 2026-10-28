// Package bus is a node's event bus: a component publishes events about the
// state it owns, and the components that depend on that state subscribe.
// Every event carries the full state it describes, so a topic remembers its
// last event: a subscriber that starts late starts from the state as it
// stands, and a subscriber slower than the publisher skips to the latest
// event, the ones it missed carrying nothing the latest does not; a
// component that reads the state on demand reads the last event. A bus
// belongs to one node — the node's assembly builds it and hands it to the
// components it wires — and runs no loop of its own; no subscriber's code
// runs under a publisher's lock.
//
// Every topic is declared here: the bus's accessor names the topic's event,
// its publisher, and its readers.
package bus

import (
	"context"
	"sync"
)

// Bus is one node's topics.
type Bus struct {
	links     Topic[LinkState]
	ifDown    Topic[InterfaceDownState]
	latencies Topic[LinkLatencies]
	self      Topic[SelfState]
	directory Topic[Directory]
}

// New returns a bus nothing has been published on.
func New() *Bus {
	return &Bus{}
}

// Links returns the node's link state topic. The node's assembly publishes
// on it whenever the neighbor table, a link's verdict, or a link's
// observation changes; the beaconer, the path provider, the conns, and the
// topology provider read it.
func (b *Bus) Links() *Topic[LinkState] {
	return &b.links
}

// InterfaceDown returns the node's interface-down topic. The node's conns
// update it with each SCMP External Interface Down signal they recognize;
// the path provider and the WireGuard application read it.
func (b *Bus) InterfaceDown() *Topic[InterfaceDownState] {
	return &b.ifDown
}

// Latencies returns the node's link latency topic. The topology provider's
// selection publishes on it once per window; the beaconer reads it.
func (b *Bus) Latencies() *Topic[LinkLatencies] {
	return &b.latencies
}

// Self returns the topic of the node's own state. The topology provider
// publishes on it whenever the host the node's publications carry or the
// node's rendezvous answer changes; the node directory, the link upkeep, the
// WireGuard application, and the wildcard-bound conns read it.
func (b *Bus) Self() *Topic[SelfState] {
	return &b.self
}

// Directory returns the node directory topic. The topology provider
// publishes each directory fetch on it; the topology provider's own loops
// and the portal read it.
func (b *Bus) Directory() *Topic[Directory] {
	return &b.directory
}

// Topic carries one kind of event and remembers the last one published. Its
// zero value is a topic nothing has been published on.
type Topic[T any] struct {
	mtx  sync.Mutex
	last T
	held bool
	subs map[chan T]struct{}
}

// Publish makes e the topic's last event and delivers it to every
// subscriber, replacing an event the subscriber has not taken yet. It never
// blocks, and e is never mutated after.
func (t *Topic[T]) Publish(e T) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.publishLocked(e)
}

// Update publishes, as Publish does, the event f makes of the topic's last
// one, the zero event before the first: no other publish comes between the
// read and the publish, so each of a topic's publishers adds to the state
// the others left. f runs under the topic's lock: it must not block, and
// builds a new event rather than mutate the last.
func (t *Topic[T]) Update(f func(T) T) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.publishLocked(f(t.last))
}

// publishLocked makes e the last event and delivers it; the caller holds
// the topic's lock.
func (t *Topic[T]) publishLocked(e T) {
	t.last, t.held = e, true
	for s := range t.subs {
		// The publishers alone send, under the lock, so the slot the
		// receive empties stays empty for the send.
		select {
		case <-s:
		default:
		}
		s <- e
	}
}

// Subscribe returns a channel of the topic's events: its last event at once
// when it holds one, then each event published after, a subscriber slower
// than the publisher receiving the latest. The channel closes once ctx ends.
func (t *Topic[T]) Subscribe(ctx context.Context) <-chan T {
	s := make(chan T, 1)
	t.mtx.Lock()
	if t.subs == nil {
		t.subs = make(map[chan T]struct{})
	}
	t.subs[s] = struct{}{}
	if t.held {
		s <- t.last
	}
	t.mtx.Unlock()
	context.AfterFunc(ctx, func() {
		t.mtx.Lock()
		defer t.mtx.Unlock()
		delete(t.subs, s)
		select {
		case <-s:
		default:
		}
		close(s)
	})
	return s
}

// Latest returns the topic's last event, the zero event before the first.
// A nil topic's is the zero event: the read of a component wired with no
// bus.
func (t *Topic[T]) Latest() T {
	if t == nil {
		var zero T
		return zero
	}
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.last
}
