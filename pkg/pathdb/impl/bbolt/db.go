// Package bbolt implements the path segment database on top of bbolt,
// following the trust DB's implementation (pkg/trust/impl/bbolt).
package bbolt

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	cppb "github.com/scionproto/scion/pkg/proto/control_plane"

	"github.com/fancl20/cion/pkg/pathdb"
)

const bucketName = "segments"

// value prefix carrying the segment type before the marshaled message.
type storedSegment struct {
	Type pathdb.SegmentType
	PB   *cppb.PathSegment
}

func marshalStored(s *storedSegment) ([]byte, error) {
	raw, err := proto.Marshal(s.PB)
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(s.Type)}, raw...), nil
}

func unmarshalStored(raw []byte) (*storedSegment, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("empty value")
	}
	pb := &cppb.PathSegment{}
	if err := proto.Unmarshal(raw[1:], pb); err != nil {
		return nil, err
	}
	return &storedSegment{Type: pathdb.SegmentType(raw[0]), PB: pb}, nil
}

type bboltDB struct {
	db *bbolt.DB
}

// New opens the path database at path, creating it if needed.
func New(path string, opts *bbolt.Options) (pathdb.DB, error) {
	db, err := bbolt.Open(path, 0600, opts)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &bboltDB{db: db}, nil
}

// Insert inserts the segment, replacing the stored segment with the same
// identity: originating core, segment ID, and creation timestamp.
func (b *bboltDB) Insert(ctx context.Context, seg *pathdb.Segment) (bool, error) {
	key, err := marshalKey(seg.Key())
	if err != nil {
		return false, err
	}
	value, err := marshalStored(&storedSegment{Type: seg.Type, PB: seg.PCB.PB})
	if err != nil {
		return false, err
	}
	var existed bool
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket.Get(key) != nil {
			existed = true
		}
		return bucket.Put(key, value)
	}); err != nil {
		return false, err
	}
	return !existed, nil
}

// Get returns the segments matching the query whose hops have not expired.
func (b *bboltDB) Get(ctx context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	var prefix []byte
	if !q.SrcIA.IsZero() {
		p, err := iaPrefix(q.SrcIA)
		if err != nil {
			return nil, err
		}
		prefix = p
	}
	var segs []*pathdb.Segment
	now := time.Now()
	if err := b.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(bucketName)).Cursor()
		for k, v := c.Seek(prefix); k != nil && matchPrefix(k, prefix); k, v = c.Next() {
			stored, err := unmarshalStored(v)
			if err != nil {
				return err
			}
			seg, err := pathdb.NewSegment(stored.Type, stored.PB)
			if err != nil {
				return err
			}
			if q.Type != pathdb.SegmentTypeUnspecified && seg.Type != q.Type {
				continue
			}
			if !q.DstIA.IsZero() && !seg.LastIA().Equal(q.DstIA) {
				continue
			}
			if !seg.Expiration().After(now) {
				continue
			}
			segs = append(segs, seg)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return segs, nil
}

// DeleteExpired evicts the segments expired before the given time.
func (b *bboltDB) DeleteExpired(ctx context.Context, t time.Time) (int, error) {
	var keys [][]byte
	if err := b.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(bucketName)).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			stored, err := unmarshalStored(v)
			if err != nil {
				return err
			}
			seg, err := pathdb.NewSegment(stored.Type, stored.PB)
			if err != nil {
				return err
			}
			if !seg.Expiration().After(t) {
				keys = append(keys, slices.Clone(k))
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		for _, k := range keys {
			if err := tx.Bucket([]byte(bucketName)).Delete(k); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return len(keys), nil
}

func (b *bboltDB) Close() error {
	return b.db.Close()
}

// marshalKey encodes the segment identity: originating IA, segment ID,
// creation timestamp.
func marshalKey(k pathdb.Key) ([]byte, error) {
	if k.Origin.AS() == 0 && k.Origin.ISD() == 0 {
		return nil, fmt.Errorf("segment identity needs an origin IA")
	}
	key := make([]byte, 0, 20)
	key = binary.BigEndian.AppendUint64(key, uint64(k.Origin))
	key = binary.BigEndian.AppendUint32(key, uint32(k.ID))
	key = binary.BigEndian.AppendUint64(key, uint64(k.Timestamp.Unix()))
	return key, nil
}

// iaPrefix returns the key prefix selecting one originating IA.
func iaPrefix(ia addr.IA) ([]byte, error) {
	return binary.BigEndian.AppendUint64(nil, uint64(ia)), nil
}

// matchPrefix reports whether k falls in the prefix range; a nil prefix
// matches everything.
func matchPrefix(k, prefix []byte) bool {
	return len(prefix) == 0 || bytes.HasPrefix(k, prefix)
}
