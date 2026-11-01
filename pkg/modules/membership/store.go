package membership

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/pkg/libs/statefile"
)

// bucket is the store database's one bucket: a membership's AS and CA
// certificates, DER concatenated, keyed by its ISD-AS in eight big-endian
// bytes.
var bucket = []byte("memberships")

// Store keeps one membership per ISD-AS: the newest its method accepted, by
// the AS certificate's issuance, never swept. It reads from memory and, when
// it has a database, writes through to it. It is safe for concurrent use.
type Store struct {
	db *bbolt.DB

	mtx  sync.RWMutex
	held map[addr.IA][]*x509.Certificate
}

// NewStore returns an empty store kept in memory alone.
func NewStore() *Store {
	return &Store{held: make(map[addr.IA][]*x509.Certificate)}
}

// OpenStore opens the store's database at path, creating it when missing,
// and loads the memberships it holds.
func OpenStore(path string, opts *bbolt.Options) (*Store, error) {
	db, err := statefile.OpenBolt(path, opts, string(bucket))
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, held: make(map[addr.IA][]*x509.Certificate)}
	if err := db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, v []byte) error {
			chain, err := x509.ParseCertificates(bytes.Clone(v))
			if err != nil {
				return fmt.Errorf("parsing the membership of %s: %w",
					addr.IA(binary.BigEndian.Uint64(k)), err)
			}
			s.held[addr.IA(binary.BigEndian.Uint64(k))] = chain
			return nil
		})
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the store's database, if it has one.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Get returns ia's membership, nil when the store holds none.
func (s *Store) Get(ia addr.IA) []*x509.Certificate {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.held[ia]
}

// Put keeps chain as its ISD-AS's membership unless the store holds one
// issued no earlier, and reports whether it did.
func (s *Store) Put(chain []*x509.Certificate) (bool, error) {
	if len(chain) != 2 {
		return false, fmt.Errorf("a membership is two certificates, got %d", len(chain))
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return false, fmt.Errorf("reading the membership's ISD-AS: %w", err)
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if held, ok := s.held[ia]; ok && !chain[0].NotBefore.After(held[0].NotBefore) {
		return false, nil
	}
	if s.db != nil {
		key := binary.BigEndian.AppendUint64(nil, uint64(ia))
		value := append(bytes.Clone(chain[0].Raw), chain[1].Raw...)
		if err := s.db.Update(func(tx *bbolt.Tx) error {
			return tx.Bucket(bucket).Put(key, value)
		}); err != nil {
			return false, fmt.Errorf("storing the membership of %s: %w", ia, err)
		}
	}
	s.held[ia] = chain
	return true, nil
}

// All returns every membership the store holds, in ISD-AS order.
func (s *Store) All() [][]*x509.Certificate {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	ias := slices.SortedFunc(maps.Keys(s.held), func(a, b addr.IA) int {
		return cmp.Compare(uint64(a), uint64(b))
	})
	all := make([][]*x509.Certificate, 0, len(ias))
	for _, ia := range ias {
		all = append(all, s.held[ia])
	}
	return all
}
