// Package statefile writes and opens the files a node keeps in its state
// directory: the small files written whole, and the bbolt databases opened
// with their buckets in place. A shared library: no loops of its own, no
// policy.
//
// A reader of a file written whole sees the old content or the new one, and a
// crash leaves one of the two. Every such file has a single writer — a loop,
// the boot, or the holder of a mutex — for the writes to one path share one
// temporary name; bbolt serializes a database's writers itself.
package statefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

// Write replaces the file at path with data, mode 0600: it writes the data to
// <path>.tmp, syncs it, renames it over the path, and syncs the directory. A
// missing parent directory is created with mode 0700 and synced into its own
// parent. A failed write removes the temporary file, and the path keeps its
// old content unless the rename has already replaced it. Writes to one path
// must not overlap.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := mkdirAll(dir); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// Remove removes the file at path and syncs its directory, so the removal
// survives a crash. A missing file is not an error.
func Remove(path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// LoadOrCreate returns the value the file at path holds, as decode reads it;
// a decode error names the path. When the file is missing, create returns a
// fresh value and its bytes, and Write persists the bytes before the value
// returns.
func LoadOrCreate[T any](
	path string,
	decode func([]byte) (T, error),
	create func() (T, []byte, error),
) (T, error) {

	var zero T
	raw, err := os.ReadFile(path)
	if err == nil {
		v, err := decode(raw)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", path, err)
		}
		return v, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return zero, err
	}
	v, data, err := create()
	if err != nil {
		return zero, err
	}
	if err := Write(path, data); err != nil {
		return zero, err
	}
	return v, nil
}

// OpenBolt opens the bbolt database at path with opts, creating the file with
// mode 0600 when missing (its directory must exist), and creates the named
// buckets it lacks. A failed bucket setup closes the database again,
// releasing its file lock.
func OpenBolt(path string, opts *bbolt.Options, buckets ...string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// writeSynced writes data to the file at path, created with mode 0600 or
// truncated, and syncs it. A failure after the open removes the file.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// mkdirAll creates the directory and every missing parent with mode 0700,
// syncing each directory it creates into its own parent. A directory another
// writer creates first counts as created.
func mkdirAll(dir string) error {
	_, err := os.Stat(dir)
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return err
	}
	if err := mkdirAll(parent); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return syncDir(parent)
}

// syncDir syncs the directory, so the entries created, renamed, or removed in
// it survive a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}
