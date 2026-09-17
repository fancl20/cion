// Package bbolt implements the neighbor table database on top of bbolt,
// following the path DB's implementation (pkg/pathdb/impl/bbolt).
package bbolt

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/pkg/links"
)

const (
	linksBucket = "links"
	metaBucket  = "meta"
	// nextIfIDKey holds the persisted monotonic interface ID counter.
	nextIfIDKey = "next_ifid"
)

// storedLink is the JSON-encoded value of an entry; the addresses ride as
// strings, the zero value encoding an unset address.
type storedLink struct {
	NeighborIA  uint64 `json:"neighbor_ia,omitempty"`
	IfID        uint16 `json:"ifid"`
	RemoteIfID  uint16 `json:"remote_ifid,omitempty"`
	Local       string `json:"local,omitempty"`
	Remote      string `json:"remote,omitempty"`
	Rendezvous  string `json:"rendezvous,omitempty"`
	State       int32  `json:"state"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
	RetiredUnix int64  `json:"retired,omitempty"`
}

func marshalStored(l *links.Link) ([]byte, error) {
	s := storedLink{
		NeighborIA:  uint64(l.NeighborIA),
		IfID:        l.IfID,
		RemoteIfID:  l.RemoteIfID,
		Local:       addrStored(l.Local),
		Remote:      addrStored(l.Remote),
		Rendezvous:  addrStored(l.Rendezvous),
		State:       int32(l.State),
		Created:     l.Created.Unix(),
		Updated:     l.Updated.Unix(),
		RetiredUnix: l.Retired.Unix(),
	}
	if l.Retired.IsZero() {
		s.RetiredUnix = 0
	}
	return json.Marshal(s)
}

// addrStored encodes an address for the wire, the zero address as "".
func addrStored(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func unmarshalStored(raw []byte, key uint16) (*links.Link, error) {
	var s storedLink
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("decoding link %d: %w", key, err)
	}
	l := &links.Link{
		NeighborIA: addr.IA(s.NeighborIA),
		IfID:       key,
		RemoteIfID: s.RemoteIfID,
		State:      links.State(s.State),
		Created:    time.Unix(s.Created, 0),
		Updated:    time.Unix(s.Updated, 0),
	}
	for _, a := range []struct {
		raw   string
		dst   *netip.AddrPort
		field string
	}{
		{s.Local, &l.Local, "local"},
		{s.Remote, &l.Remote, "remote"},
		{s.Rendezvous, &l.Rendezvous, "rendezvous"},
	} {
		if a.raw == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(a.raw)
		if err != nil {
			return nil, fmt.Errorf("decoding link %d %s address %q: %w",
				key, a.field, a.raw, err)
		}
		*a.dst = ap
	}
	if s.RetiredUnix != 0 {
		l.Retired = time.Unix(s.RetiredUnix, 0)
	}
	return l, nil
}

type bboltDB struct {
	db *bbolt.DB
}

// New opens the link database at path, creating it if needed.
func New(path string, opts *bbolt.Options) (links.DB, error) {
	db, err := bbolt.Open(path, 0600, opts)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{linksBucket, metaBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	return &bboltDB{db: db}, nil
}

// Insert stores a new entry: an entry carrying no interface ID is allocated
// one monotonically from the persisted counter — IDs of live entries and of
// entries retired within the holdback are skipped — and one carrying an ID
// takes it, refused when the ID is held.
func (b *bboltDB) Insert(ctx context.Context, l *links.Link) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		linksB := tx.Bucket([]byte(linksBucket))
		metaB := tx.Bucket([]byte(metaBucket))
		held, err := heldIfIDs(linksB, time.Now())
		if err != nil {
			return err
		}
		id := l.IfID
		if id == 0 {
			var next uint16
			id, next, err = allocateIfID(linksB, metaB, held)
			if err != nil {
				return err
			}
			if err := metaB.Put([]byte(nextIfIDKey), beUint16(next)); err != nil {
				return err
			}
		} else if held[id] {
			return fmt.Errorf("interface ID %d is held", id)
		}
		now := time.Now()
		l.IfID = id
		l.Created = now
		l.Updated = now
		value, err := marshalStored(l)
		if err != nil {
			return err
		}
		return linksB.Put(beUint16(id), value)
	})
}

// Update replaces the stored entry with the same interface ID, stamping
// Updated.
func (b *bboltDB) Update(ctx context.Context, l *links.Link) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		linksB := tx.Bucket([]byte(linksBucket))
		key := beUint16(l.IfID)
		if linksB.Get(key) == nil {
			return fmt.Errorf("no stored link with interface ID %d", l.IfID)
		}
		l.Updated = time.Now()
		value, err := marshalStored(l)
		if err != nil {
			return err
		}
		return linksB.Put(key, value)
	})
}

// All returns every stored entry, retired ones included.
func (b *bboltDB) All(ctx context.Context) ([]*links.Link, error) {
	var out []*links.Link
	err := b.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(linksBucket)).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			l, err := unmarshalStored(v, beUint16Decode(k))
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ByRemote returns the live entry whose remote or rendezvous address matches.
func (b *bboltDB) ByRemote(ctx context.Context, remote netip.AddrPort) (*links.Link, error) {
	entries, err := b.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range entries {
		if !l.Live() {
			continue
		}
		if (l.Remote.IsValid() && l.Remote == remote) ||
			(l.Rendezvous.IsValid() && l.Rendezvous == remote) {
			return l, nil
		}
	}
	return nil, nil
}

// ByNeighbor returns the live entry of the neighbor.
func (b *bboltDB) ByNeighbor(ctx context.Context, ia addr.IA) (*links.Link, error) {
	entries, err := b.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range entries {
		if l.Live() && l.NeighborIA.Equal(ia) {
			return l, nil
		}
	}
	return nil, nil
}

func (b *bboltDB) Close() error {
	return b.db.Close()
}

// heldIfIDs returns the IDs no new entry may take — those of live entries
// and of entries retired within the holdback — purging the entries whose
// holdback passed, no segment being able to name them any longer.
func heldIfIDs(linksB *bbolt.Bucket, now time.Time) (map[uint16]bool, error) {
	held := make(map[uint16]bool)
	c := linksB.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		l, err := unmarshalStored(v, beUint16Decode(k))
		if err != nil {
			return nil, err
		}
		if l.Live() || now.Sub(l.Retired) < links.IfIDHoldback {
			held[l.IfID] = true
		} else if err := linksB.Delete(k); err != nil {
			return nil, err
		}
	}
	return held, nil
}

// allocateIfID picks the next free interface ID and the counter value to
// persist: the counter advances monotonically, skipping the held IDs.
func allocateIfID(linksB, metaB *bbolt.Bucket, held map[uint16]bool) (id, next uint16, err error) {
	next = 1
	if raw := metaB.Get([]byte(nextIfIDKey)); raw != nil {
		next = beUint16Decode(raw)
	}
	for try := 0; try <= 1<<16; try++ {
		cand := next
		next++
		if next == 0 { // wrapped past the maximum
			next = 1
		}
		if !held[cand] {
			return cand, next, nil
		}
	}
	return 0, 0, errors.New("no free interface ID")
}

func beUint16(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}

func beUint16Decode(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
