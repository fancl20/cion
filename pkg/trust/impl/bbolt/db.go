package bbolt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/fancl20/cion/pkg/trust"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"go.etcd.io/bbolt"
)

type bboltDB struct {
	db *bbolt.DB
}

func New(path string, opts *bbolt.Options) (trust.DB, error) {
	db, err := bbolt.Open(path, 0600, opts)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, s := range []string{"chains", "trcs"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(s)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &bboltDB{
		db: db,
	}, nil
}

// Chains looks up all chains that match the query.
func (b *bboltDB) Chains(ctx context.Context, query trust.ChainQuery) ([][]*x509.Certificate, error) {
	var chains [][]*x509.Certificate
	if err := b.db.View(func(tx *bbolt.Tx) error {
		var ia []byte
		if !query.IA.IsZero() {
			ia = []byte(query.IA.String())
		}
		b := tx.Bucket([]byte("chains"))
		c := b.Cursor()

		for k, _ := c.Seek(ia); k != nil && bytes.HasPrefix(k, ia); k, _ = c.Next() {
			c := b.Bucket(k).Cursor()

			for k, v := c.Seek(query.SubjectKeyID); k != nil && bytes.HasPrefix(k, query.SubjectKeyID); k, v = c.Next() {
				chain, err := x509.ParseCertificates(slices.Clone(v))
				if err != nil {
					return err
				}
				if (query.Validity.NotBefore.IsZero() || !chain[0].NotBefore.After(query.Validity.NotBefore)) &&
					(query.Validity.NotAfter.IsZero() || !chain[0].NotAfter.Before(query.Validity.NotAfter)) {
					chains = append(chains, chain)
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return chains, nil
}

// InsertChain inserts the given chain.
func (b *bboltDB) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	if len(chain) != 2 {
		return false, fmt.Errorf("invalid chain length, expected 2 actual %d", len(chain))
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return false, fmt.Errorf("invalid AS cert, invalid ISD-AS")
	}

	var existed bool
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.Bucket([]byte("chains")).CreateBucketIfNotExists([]byte(ia.String()))
		if err != nil {
			return err
		}
		key := slices.Concat(chain[0].SubjectKeyId, chainID(chain))
		if b.Get(key) != nil {
			existed = true
			return nil
		}
		return b.Put(key, slices.Concat(chain[0].Raw, chain[1].Raw))
	}); err != nil {
		return false, err
	}

	return !existed, nil
}

// SignedTRC looks up the TRC identified by the id.
func (b *bboltDB) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	if id.Base.IsLatest() != id.Serial.IsLatest() {
		return cppki.SignedTRC{}, fmt.Errorf("unsupported TRC ID for query: %s", id)
	}

	var trc cppki.SignedTRC
	err := b.db.View(func(tx *bbolt.Tx) (err error) {
		b := tx.Bucket([]byte("trcs")).Bucket([]byte(id.ISD.String()))
		if b == nil {
			return nil
		}
		var key [16]byte
		binary.BigEndian.PutUint64(key[:8], uint64(id.Base))
		binary.BigEndian.PutUint64(key[8:], uint64(id.Serial))

		var raw []byte
		if id.Base.IsLatest() {
			_, raw = b.Cursor().Last()
		} else {
			raw = b.Get(key[:])
		}

		if raw == nil {
			return nil
		}
		trc, err = cppki.DecodeSignedTRC(raw)
		return err
	})

	return trc, err
}

// InsertTRC inserts the given TRC. Returns true if the TRC was not yet in
// the DB.
func (b *bboltDB) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	var existed bool
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.Bucket([]byte("trcs")).CreateBucketIfNotExists([]byte(trc.TRC.ID.ISD.String()))
		if err != nil {
			return err
		}

		var key [16]byte
		binary.BigEndian.PutUint64(key[:8], uint64(trc.TRC.ID.Base))
		binary.BigEndian.PutUint64(key[8:], uint64(trc.TRC.ID.Serial))
		if v := b.Get(key[:]); v != nil {
			if existing, err := cppki.DecodeSignedTRC(v); err != nil {
				return err
			} else if !bytes.Equal(trc.TRC.Raw, existing.TRC.Raw) {
				return fmt.Errorf("insert conflicted TRC")
			}
			existed = true
			return nil
		}
		return b.Put(key[:], trc.Raw)
	}); err != nil {
		return false, err
	}

	return !existed, nil
}
func (b *bboltDB) Close() error {
	return b.db.Close()
}

func chainID(chain []*x509.Certificate) []byte {
	h := sha256.New()
	h.Write(chain[0].Raw)
	h.Write(chain[1].Raw)
	return h.Sum(nil)
}
