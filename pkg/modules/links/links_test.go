package links_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/dbtest"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
)

// notifyingDB adapts a memory store wrapped by Notifying to the contract
// harness.
type notifyingDB struct {
	links.DB
}

func (d *notifyingDB) Prepare(*testing.T, context.Context) {
	d.DB = links.Notifying(memory.New(), func() {})
}

func (d *notifyingDB) Reopen(t *testing.T, _ context.Context) {
	t.Skip("an in-memory table does not persist")
}

// TestNotifyingContract checks that a store wrapped by Notifying keeps the
// contract the bare store keeps.
func TestNotifyingContract(t *testing.T) {
	dbtest.Run(t, &notifyingDB{})
}

// TestNotifyingSignalsWrites checks the signal: once for each successful
// insert and update, and never for a refused write or a read.
func TestNotifyingSignalsWrites(t *testing.T) {
	ctx := context.Background()
	signals := 0
	db := links.Notifying(memory.New(), func() { signals++ })
	ia := addr.MustIAFrom(20, 0xfd0000000001)
	l := &links.Link{
		NeighborIA: ia,
		Local:      netip.MustParseAddrPort("127.0.0.1:31001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:31002"),
		State:      links.StateCandidate,
	}
	if err := db.Insert(ctx, l); err != nil {
		t.Fatal(err)
	}
	if signals != 1 {
		t.Errorf("signals after an insert = %d, want 1", signals)
	}
	l.State = links.StateEstablished
	if err := db.Update(ctx, l); err != nil {
		t.Fatal(err)
	}
	if signals != 2 {
		t.Errorf("signals after an update = %d, want 2", signals)
	}

	twin := &links.Link{
		NeighborIA: ia,
		Local:      netip.MustParseAddrPort("127.0.0.1:31003"),
		State:      links.StateCandidate,
	}
	if err := db.Insert(ctx, twin); !errors.Is(err, links.ErrDuplicateNeighbor) {
		t.Fatalf("a second live entry of %s inserted with %v, want ErrDuplicateNeighbor", ia, err)
	}
	stranger := &links.Link{IfID: 999, State: links.StateCandidate}
	if err := db.Update(ctx, stranger); err == nil {
		t.Fatal("updating an unstored interface ID succeeded")
	}
	if _, err := db.All(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ByNeighbor(ctx, ia); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ByRemote(ctx, l.Remote); err != nil {
		t.Fatal(err)
	}
	if signals != 2 {
		t.Errorf("signals after refused writes and reads = %d, want the 2 of the writes", signals)
	}
}
