// Package dbtest holds the database contract suites' file-backed adapter:
// the one Prepare and Reopen shape every bbolt store the suites drive
// shares, whatever module's store it opens.
package dbtest

import (
	"io"
	"path/filepath"
	"testing"
)

// FileDB opens a store at a path of the current round's choosing and holds
// the open store for the suite's adapter to embed. Prepare resets to a
// fresh file in a fresh temporary directory — a previous round's store
// closed, its directory the round's own to reap — and Reopen closes and
// reopens the same file: the persistence the contract suites assert of a
// file-backed store.
type FileDB[T io.Closer] struct {
	// open opens the store at the path; the suite's subject.
	open func(path string) (T, error)
	path string
	db   T
}

// NewFileDB builds the adapter over the store's constructor.
func NewFileDB[T io.Closer](open func(path string) (T, error)) *FileDB[T] {
	return &FileDB[T]{open: open}
}

// Prepare resets to a fresh database file.
func (f *FileDB[T]) Prepare(t *testing.T) {
	t.Helper()
	if any(f.db) != nil {
		if err := f.db.Close(); err != nil {
			t.Fatalf("closing the previous round's database: %v", err)
		}
	}
	f.path = filepath.Join(t.TempDir(), "test.db")
	f.reopen(t)
}

// Reopen closes and reopens the same database file.
func (f *FileDB[T]) Reopen(t *testing.T) {
	t.Helper()
	if any(f.db) != nil {
		if err := f.db.Close(); err != nil {
			t.Fatalf("closing the database for reopen: %v", err)
		}
	}
	f.reopen(t)
}

func (f *FileDB[T]) reopen(t *testing.T) {
	t.Helper()
	db, err := f.open(f.path)
	if err != nil {
		t.Fatalf("opening the test database: %v", err)
	}
	f.db = db
}

// DB returns the open store.
func (f *FileDB[T]) DB() T { return f.db }
