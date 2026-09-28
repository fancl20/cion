package bbolt_test

import (
	"context"
	"testing"

	filedb "github.com/fancl20/cion/internal/dbtest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/dbtest"
)

// testDB adapts the bbolt implementation to the contract test harness over
// the shared file-backed lifecycle.
type testDB struct {
	trustdb.DB
	file *filedb.FileDB[trustdb.DB]
}

func (db *testDB) Prepare(t *testing.T, ctx context.Context) {
	db.file.Prepare(t)
	db.DB = db.file.DB()
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &testDB{
		file: filedb.NewFileDB(func(path string) (trustdb.DB, error) {
			return bbolt.New(path, nil)
		}),
	}, dbtest.Config{})
}
