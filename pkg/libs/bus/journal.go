package bus

import (
	"context"
	"sync"
)

// JournalKept is how many entries a journal keeps: how far its reader may
// fall behind before entries go unread, more than every lease of a node
// with 64 destinations moving four times between two reads.
const JournalKept = 256

// Journal keeps entries in the order they were appended, numbered from
// zero, the last JournalKept of them. Where a topic's event carries the
// state as it stands, a journal's entry carries one change: a reader reads
// every entry in order from the number it reached, and learns how many went
// unread. Its zero value holds none.
type Journal[T any] struct {
	mtx sync.Mutex
	// next is the number the next entry takes.
	next uint64
	// kept holds the last entries, the one numbered n at n modulo
	// JournalKept.
	kept []T
	// appended carries next to the subscribers after each append.
	appended Topic[uint64]
}

// Append adds e as the journal's next entry, dropping the oldest past
// JournalKept, and wakes the subscribers. It never blocks, and e is never
// mutated after.
func (j *Journal[T]) Append(e T) {
	j.mtx.Lock()
	defer j.mtx.Unlock()
	if len(j.kept) < JournalKept {
		j.kept = append(j.kept, e)
	} else {
		j.kept[j.next%JournalKept] = e
	}
	j.next++
	j.appended.Publish(j.next)
}

// Next returns the number the next entry takes: a read from it returns the
// entries appended after.
func (j *Journal[T]) Next() uint64 {
	j.mtx.Lock()
	defer j.mtx.Unlock()
	return j.next
}

// Since returns the entries kept from the one numbered n on, beside how
// many entries from n on are no longer kept: the reader's next read starts
// at n plus both counts.
func (j *Journal[T]) Since(n uint64) (entries []T, dropped uint64) {
	j.mtx.Lock()
	defer j.mtx.Unlock()
	if first := j.next - uint64(len(j.kept)); n < first {
		n, dropped = first, first-n
	}
	for ; n < j.next; n++ {
		entries = append(entries, j.kept[n%JournalKept])
	}
	return entries, dropped
}

// Subscribe returns a channel of the number the next entry takes: at once
// when the journal holds an entry, then after each append, a subscriber
// slower than the appends receiving the latest. The channel closes once ctx
// ends.
func (j *Journal[T]) Subscribe(ctx context.Context) <-chan uint64 {
	return j.appended.Subscribe(ctx)
}
