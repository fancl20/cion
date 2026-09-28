package bbolt_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/dbtest"
)

type testDB struct {
	trustdb.DB
}

func (db *testDB) Prepare(t *testing.T, ctx context.Context) {
	_ = os.Remove(filepath.Join(t.TempDir(), "test.db"))
	b, err := bbolt.New(filepath.Join(t.TempDir(), "test.db"), nil)
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	db.DB = b
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &testDB{}, dbtest.Config{})
}
