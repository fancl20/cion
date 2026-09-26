// Package bbolt is the application directory's bbolt store, following the
// trust DB's pattern: a small file, values marshaled beside their keys —
// node entries keyed by ISD-AS, host entries by public key.
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

// entriesBucket holds one directory entry per publishing ISD-AS; hostsBucket
// holds one registry entry per registered host key.
var (
	entriesBucket = []byte("entries")
	hostsBucket   = []byte("hosts")
)

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
		for _, bucket := range [][]byte{entriesBucket, hostsBucket} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &directoryDB{db: db}, nil
}

type wireEntry struct {
	PublicKey    string `json:"publicKey"`
	Overlay      string `json:"overlay"`
	HostEndpoint string `json:"hostEndpoint,omitempty"`
}

// wireHostEntry is one host's registry entry beside its key.
type wireHostEntry struct {
	Addr string `json:"addr"`
	IA   string `json:"ia"`
	Note string `json:"note,omitempty"`
}

// Publish records the entry, keyed by its ISD-AS: a publisher's later entry
// replaces its earlier one.
func (b *directoryDB) Publish(ctx context.Context, entry wireguard.Entry) error {
	if entry.IA.IsZero() {
		return errors.New("entry has no ISD-AS")
	}
	endpoint := ""
	if entry.HostEndpoint.IsValid() {
		endpoint = entry.HostEndpoint.String()
	}
	return b.db.Update(func(tx *bbolt.Tx) error {
		raw, err := json.Marshal(wireEntry{
			PublicKey:    entry.PublicKey.String(),
			Overlay:      entry.Overlay.String(),
			HostEndpoint: endpoint,
		})
		if err != nil {
			return err
		}
		return tx.Bucket(entriesBucket).Put([]byte(entry.IA.String()), raw)
	})
}

// PublishHost records the host entry, keyed by its public key: the same key
// re-registering meets the same record, and a re-registration replaces it
// wholesale.
func (b *directoryDB) PublishHost(ctx context.Context, entry wireguard.HostEntry) error {
	if entry.PublicKey == (wireguard.PublicKey{}) {
		return errors.New("host entry has no public key")
	}
	return b.db.Update(func(tx *bbolt.Tx) error {
		raw, err := json.Marshal(wireHostEntry{
			Addr: entry.Addr.String(),
			IA:   entry.IA.String(),
			Note: entry.Note,
		})
		if err != nil {
			return err
		}
		return tx.Bucket(hostsBucket).Put([]byte(entry.PublicKey.String()), raw)
	})
}

// List returns every published entry, nodes and hosts together. Stored
// entries shaped by proposal 0006 carry their retired port and underlay
// fields beside these; the JSON decode ignores what the struct no longer
// names.
func (b *directoryDB) List(ctx context.Context) (wireguard.Directory, error) {
	var directory wireguard.Directory
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
			entry := wireguard.Entry{
				IA:        ia,
				PublicKey: key,
				Overlay:   overlay,
			}
			if wire.HostEndpoint != "" {
				endpoint, err := netip.ParseAddrPort(wire.HostEndpoint)
				if err != nil {
					return fmt.Errorf("decoding the entry for %s: %w", k, err)
				}
				entry.HostEndpoint = endpoint
			}
			directory.Nodes = append(directory.Nodes, entry)
		}
		hosts := tx.Bucket(hostsBucket).Cursor()
		for k, v := hosts.First(); k != nil; k, v = hosts.Next() {
			var wire wireHostEntry
			if err := json.Unmarshal(v, &wire); err != nil {
				return fmt.Errorf("decoding the host entry for %s: %w", k, err)
			}
			key, err := wireguard.ParsePublicKey(string(k))
			if err != nil {
				return fmt.Errorf("decoding the host key %s: %w", k, err)
			}
			entry := wireguard.HostEntry{PublicKey: key}
			if entry.Addr, err = netip.ParseAddr(wire.Addr); err != nil {
				return fmt.Errorf("decoding the host entry for %s: %w", k, err)
			}
			if entry.IA, err = parseIA(wire.IA); err != nil {
				return err
			}
			entry.Note = wire.Note
			directory.Hosts = append(directory.Hosts, entry)
		}
		return nil
	})
	if err != nil {
		return wireguard.Directory{}, err
	}
	return directory, nil
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
