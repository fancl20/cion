package bbolt_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/pathdb/impl/dbtest"
)

type testDB struct {
	pathdb.DB
	path string
}

func (db *testDB) Prepare(t *testing.T, ctx context.Context) {
	db.path = ""
	db.open(t)
}

func (db *testDB) Reopen(t *testing.T, ctx context.Context) {
	if err := db.Close(); err != nil {
		t.Fatalf("closing database: %v", err)
	}
	db.open(t)
}

func (db *testDB) open(t *testing.T) {
	t.Helper()
	if db.path == "" {
		db.path = filepath.Join(t.TempDir(), "path.db")
	}
	b, err := bbolt.New(db.path, nil)
	if err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	db.DB = b
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &testDB{})
}
