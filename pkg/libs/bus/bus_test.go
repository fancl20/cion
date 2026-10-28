package bus

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
)

// TestTopicSubscribe checks a subscription: nothing arrives before the first
// publish; a subscriber that has not taken an event receives the latest in
// its place; a late subscriber receives the last event at once; and the
// channel closes, its untaken event dropped, once the context ends.
func TestTopicSubscribe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var topic Topic[int]
		ctx, cancel := context.WithCancel(t.Context())
		early := topic.Subscribe(ctx)
		if e, ok := taken(early); ok {
			t.Fatalf("a subscriber of an unpublished topic received %d", e)
		}
		topic.Publish(1)
		topic.Publish(2)
		if e, ok := taken(early); !ok || e != 2 {
			t.Errorf("after two publishes the subscriber received %d (%t), want the latest, 2", e, ok)
		}
		if e, ok := taken(early); ok {
			t.Errorf("the subscriber received %d past the latest", e)
		}

		late := topic.Subscribe(t.Context())
		if e, ok := taken(late); !ok || e != 2 {
			t.Errorf("a late subscriber received %d (%t), want the last event, 2", e, ok)
		}

		topic.Publish(3)
		cancel()
		synctest.Wait()
		if e, ok := <-early; ok {
			t.Errorf("a subscription received %d after its context ended, want it closed", e)
		}
		topic.Publish(4)
		if e, ok := taken(late); !ok || e != 4 {
			t.Errorf("a live subscriber received %d (%t), want the latest, 4", e, ok)
		}
	})
}

// TestTopicLatest checks the read on demand: the zero event before the first
// publish, the last event after, and the zero event from a nil topic.
func TestTopicLatest(t *testing.T) {
	var topic Topic[int]
	if e := topic.Latest(); e != 0 {
		t.Errorf("an unpublished topic's latest = %d, want 0", e)
	}
	topic.Publish(1)
	topic.Publish(2)
	if e := topic.Latest(); e != 2 {
		t.Errorf("latest = %d, want the last event, 2", e)
	}
	var none *Topic[int]
	if e := none.Latest(); e != 0 {
		t.Errorf("a nil topic's latest = %d, want 0", e)
	}
}

// TestTopicUpdate checks the update: it builds on the last event, the zero
// event before the first publish, delivers what it builds as a publish
// does, and many publishers' updates each add to the state the others left.
func TestTopicUpdate(t *testing.T) {
	var topic Topic[int]
	sub := topic.Subscribe(t.Context())
	topic.Update(func(e int) int { return e + 1 })
	if e, ok := taken(sub); !ok || e != 1 {
		t.Errorf("the first update delivered %d (%t), want 1 built on the zero event", e, ok)
	}
	topic.Publish(10)
	topic.Update(func(e int) int { return e + 1 })
	if e := topic.Latest(); e != 11 {
		t.Errorf("an update after a publish left %d, want 11", e)
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { topic.Update(func(e int) int { return e + 1 }) })
	}
	wg.Wait()
	if e := topic.Latest(); e != 111 {
		t.Errorf("100 concurrent updates left %d, want 111", e)
	}
}

// taken receives the subscription's pending event, if one is pending.
func taken(s <-chan int) (int, bool) {
	select {
	case e, ok := <-s:
		return e, ok
	default:
		return 0, false
	}
}
