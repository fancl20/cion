package bbolt_test

import (
	"context"
	"testing"

	filedb "github.com/fancl20/cion/internal/dbtest"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/pathdb/impl/dbtest"
)

// testDB adapts the bbolt implementation to the contract test harness over
// the shared file-backed lifecycle.
type testDB struct {
	pathdb.DB
	file *filedb.FileDB[pathdb.DB]
}

func (db *testDB) Prepare(t *testing.T, ctx context.Context) {
	db.file.Prepare(t)
	db.DB = db.file.DB()
}

func (db *testDB) Reopen(t *testing.T, ctx context.Context) {
	db.file.Reopen(t)
	db.DB = db.file.DB()
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &testDB{
		file: filedb.NewFileDB(func(path string) (pathdb.DB, error) {
			return bbolt.New(path, nil)
		}),
	})
}
