package bbolt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/dbtest"
)

// testableDB adapts the bbolt implementation to the contract test harness.
type testableDB struct {
	links.DB
	t    *testing.T
	path string
}

func (d *testableDB) Prepare(t *testing.T, ctx context.Context) {
	d.t = t
	if d.DB != nil {
		d.DB.Close() //nolint:errcheck
		if err := os.Remove(d.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	db, err := New(d.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.DB = db
}

func (d *testableDB) Reopen(t *testing.T, ctx context.Context) {
	if err := d.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := New(d.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.DB = db
}

func TestDB(t *testing.T) {
	db := &testableDB{path: filepath.Join(t.TempDir(), "links.db")}
	dbtest.Run(t, db)
}

// TestAllocateHoldsRetired checks the interface ID holdback: with the counter
// rewound onto it, the allocator hands out the ID of an entry retired beyond
// the holdback but never that of a live or recently retired entry.
func TestAllocateHoldsRetired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "links.db")
	db, err := New(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	ctx := context.Background()

	live := &links.Link{NeighborIA: ia(1), State: links.StateEstablished}
	recent := &links.Link{NeighborIA: ia(2), State: links.StateCandidate}
	old := &links.Link{NeighborIA: ia(3), State: links.StateCandidate}
	for _, l := range []*links.Link{live, recent, old} {
		if err := db.Insert(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	recent.State = links.StateRetired
	recent.Retired = now
	old.State = links.StateRetired
	old.Retired = now.Add(-links.IfIDHoldback - time.Minute)
	for _, l := range []*links.Link{recent, old} {
		if err := db.Update(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	// Rewind the persisted counter onto the oldest held ID so every
	// allocation walks past all three.
	b := db.(*bboltDB)
	if err := b.db.Batch(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(metaBucket)).
			Put([]byte(nextIfIDKey), beUint16(old.IfID))
	}); err != nil {
		t.Fatal(err)
	}
	allocated := make(map[uint16]bool)
	for range 4 {
		fresh := &links.Link{NeighborIA: ia(4), State: links.StateEstablished}
		if err := db.Insert(ctx, fresh); err != nil {
			t.Fatal(err)
		}
		allocated[fresh.IfID] = true
	}
	if allocated[live.IfID] || allocated[recent.IfID] {
		t.Errorf("allocated a held interface ID: live=%d recent=%d got=%v",
			live.IfID, recent.IfID, allocated)
	}
	if !allocated[old.IfID] {
		t.Errorf("the ID retired beyond the holdback (%d) was never reallocated: %v",
			old.IfID, allocated)
	}
}

func ia(n uint64) addr.IA {
	return addr.MustIAFrom(20, addr.AS(0xfd0000000000+n))
}
