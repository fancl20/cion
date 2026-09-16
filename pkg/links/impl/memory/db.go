// Package memory implements the neighbor table database in memory, for
// tests and embeddings that prefer no state directory.
package memory

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
)

// DB is the in-memory neighbor table: one mutex over a slice, interface IDs
// allocated from a monotonic counter.
type DB struct {
	mtx      sync.Mutex
	entries  []*links.Link
	nextIfID uint16
	now      func() time.Time
}

// New returns an empty table.
func New() *DB {
	return &DB{nextIfID: 1, now: time.Now}
}

// Now sets the table's clock.
func (d *DB) Now(now func() time.Time) { d.now = now }

// Insert stores a new entry: an entry carrying no interface ID is allocated
// one, and one carrying an ID takes it, refused when the ID is held.
func (d *DB) Insert(ctx context.Context, l *links.Link) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	now := d.now()
	held := func(id uint16) bool {
		for _, e := range d.entries {
			if e.IfID == id && (e.Live() || now.Sub(e.Retired) < links.IfIDHoldback) {
				return true
			}
		}
		return false
	}
	if l.IfID != 0 {
		if held(l.IfID) {
			return fmt.Errorf("interface ID %d is held", l.IfID)
		}
	} else {
		for {
			id := d.nextIfID
			d.nextIfID++
			if d.nextIfID == 0 {
				d.nextIfID = 1
			}
			if !held(id) {
				l.IfID = id
				break
			}
		}
	}
	l.Created = now
	l.Updated = now
	copied := *l
	d.entries = append(d.entries, &copied)
	return nil
}

// Update replaces the stored entry with the same interface ID.
func (d *DB) Update(ctx context.Context, l *links.Link) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	for i, e := range d.entries {
		if e.IfID == l.IfID {
			copied := *l
			copied.Updated = d.now()
			d.entries[i] = &copied
			return nil
		}
	}
	return fmt.Errorf("no stored link with interface ID %d", l.IfID)
}

// All returns every stored entry, freshly copied: callers own the entries
// they hold.
func (d *DB) All(ctx context.Context) ([]*links.Link, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make([]*links.Link, len(d.entries))
	for i, l := range d.entries {
		copied := *l
		out[i] = &copied
	}
	return out, nil
}

// ByRemote returns the live entry whose remote or rendezvous address matches.
func (d *DB) ByRemote(ctx context.Context, remote netip.AddrPort) (*links.Link, error) {
	entries, err := d.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range entries {
		if !l.Live() {
			continue
		}
		if (l.Remote.IsValid() && l.Remote == remote) ||
			(l.Rendezvous.IsValid() && l.Rendezvous == remote) {
			return l, nil
		}
	}
	return nil, nil
}

// ByNeighbor returns the live entry of the neighbor.
func (d *DB) ByNeighbor(ctx context.Context, ia addr.IA) (*links.Link, error) {
	entries, err := d.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range entries {
		if l.Live() && l.NeighborIA.Equal(ia) {
			return l, nil
		}
	}
	return nil, nil
}

// Close is a no-op.
func (d *DB) Close() error { return nil }
