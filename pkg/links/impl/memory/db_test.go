package memory

import (
	"context"
	"testing"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/dbtest"
)

// testableDB adapts the in-memory implementation to the contract test
// harness.
type testableDB struct {
	*DB
}

func (d *testableDB) Prepare(t *testing.T, ctx context.Context) {
	d.DB = New()
}

func (d *testableDB) Reopen(t *testing.T, ctx context.Context) {
	// An in-memory table has nothing to reopen into; a fresh one stands in,
	// and the persistence test's expectations do not apply.
	t.Skip("an in-memory table does not persist")
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &testableDB{})
}

var _ links.DB = (*DB)(nil)
