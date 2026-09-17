// Package bbolt is the application directory's bbolt store, following the
// trust DB's pattern: a small file, one bucket, values marshaled beside
// their keys.
package bbolt

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// entriesBucket holds one directory entry per publishing ISD-AS.
var entriesBucket = []byte("entries")

type directoryDB struct {
	db *bbolt.DB
}

// New opens the directory store at path, creating it when missing.
func New(path string, opts *bbolt.Options) (wireguard.DirectoryStore, error) {
	db, err := bbolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(entriesBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &directoryDB{db: db}, nil
}

type wireEntry struct {
	PublicKey string `json:"publicKey"`
	Overlay   string `json:"overlay"`
}

// Publish records the entry, keyed by its ISD-AS: a publisher's later entry
// replaces its earlier one.
func (b *directoryDB) Publish(ctx context.Context, entry wireguard.Entry) error {
	if entry.IA.IsZero() {
		return errors.New("entry has no ISD-AS")
	}
	return b.db.Update(func(tx *bbolt.Tx) error {
		raw, err := json.Marshal(wireEntry{
			PublicKey: entry.PublicKey.String(),
			Overlay:   entry.Overlay.String(),
		})
		if err != nil {
			return err
		}
		return tx.Bucket(entriesBucket).Put([]byte(entry.IA.String()), raw)
	})
}

// List returns every published entry. Stored entries shaped by proposal 0006
// carry their retired port and underlay fields beside these; the JSON decode
// ignores what the struct no longer names.
func (b *directoryDB) List(ctx context.Context) ([]wireguard.Entry, error) {
	var entries []wireguard.Entry
	err := b.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(entriesBucket).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var wire wireEntry
			if err := json.Unmarshal(v, &wire); err != nil {
				return fmt.Errorf("decoding the entry for %s: %w", k, err)
			}
			ia, err := parseIA(string(k))
			if err != nil {
				return err
			}
			key, err := wireguard.ParsePublicKey(wire.PublicKey)
			if err != nil {
				return fmt.Errorf("decoding the entry for %s: %w", k, err)
			}
			overlay, err := parsePrefix(wire.Overlay)
			if err != nil {
				return fmt.Errorf("decoding the entry for %s: %w", k, err)
			}
			entries = append(entries, wireguard.Entry{
				IA:        ia,
				PublicKey: key,
				Overlay:   overlay,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (b *directoryDB) Close() error { return b.db.Close() }

func parseIA(s string) (addr.IA, error) {
	ia, err := addr.ParseIA(s)
	if err != nil {
		return addr.IA(0), fmt.Errorf("parsing the ISD-AS %q: %w", s, err)
	}
	return ia, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parsing the subnet %q: %w", s, err)
	}
	return prefix, nil
}
