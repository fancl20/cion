// Package pathdb stores registered path segments (control plane draft,
// Section 4): up, down, and core segments terminated by this node or
// registered with it. It follows the trust DB pattern: a pure interface, a
// bbolt implementation, and shared contract tests in impl/dbtest.
package pathdb

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"

	"github.com/fancl20/cion/pkg/segment"
)

// SegmentType mirrors the draft's segment types: the role a stored segment
// plays for the node whose database it lives in.
type SegmentType int32

const (
	// SegmentTypeUnspecified matches the draft's unspecified type.
	SegmentTypeUnspecified SegmentType = 0
	// SegmentTypeUp is a segment from a core to this node, kept locally as
	// this node's route to the core (Section 4.1.2).
	SegmentTypeUp SegmentType = 1
	// SegmentTypeDown is a segment from a core to a non-core, registered
	// with the originating core (Sections 4.1.3 and 4.3).
	SegmentTypeDown SegmentType = 2
	// SegmentTypeCore is a segment between cores (Section 4.2).
	SegmentTypeCore SegmentType = 3
)

// Segment is a registered path segment: a terminated PCB and its type.
type Segment struct {
	// Type is the segment's role for this node.
	Type SegmentType
	// PCB is the terminated segment.
	PCB *segment.PCB
}

// NewSegment parses the wire message into a typed segment.
func NewSegment(t SegmentType, pb *cppb.PathSegment) (*Segment, error) {
	pcb, err := segment.ParsePCB(pb)
	if err != nil {
		return nil, err
	}
	return &Segment{Type: t, PCB: pcb}, nil
}

// Key identifies a segment by origin, segment ID, and creation timestamp;
// a newly registered segment replaces the stored segment with the same
// identity (ADR-0004).
type Key struct {
	// Origin is the ISD-AS of the first AS entry.
	Origin addr.IA
	// ID is the segment identifier.
	ID uint16
	// Timestamp is the creation timestamp.
	Timestamp time.Time
}

// Key returns the segment's identity.
func (s *Segment) Key() Key {
	return Key{Origin: s.PCB.FirstIA(), ID: s.PCB.ID(), Timestamp: s.PCB.Timestamp()}
}

// FirstIA returns the ISD-AS of the first entry: the core the segment
// originates from.
func (s *Segment) FirstIA() addr.IA { return s.PCB.FirstIA() }

// LastIA returns the ISD-AS of the last entry: the segment's far end.
func (s *Segment) LastIA() addr.IA { return s.PCB.LastIA() }

// Expiration returns the earliest hop expiration of the segment.
func (s *Segment) Expiration() time.Time { return s.PCB.Expiration() }

// Query selects stored segments.
type Query struct {
	// Type selects the segment type; SegmentTypeUnspecified selects any.
	Type SegmentType
	// SrcIA matches the first AS entry; a zero IA matches any.
	SrcIA addr.IA
	// DstIA matches the last AS entry; a zero IA matches any.
	DstIA addr.IA
}

// DB is the database of registered path segments.
type DB interface {
	// Insert inserts the segment, replacing the stored segment with the same
	// identity. It reports whether the segment was newly inserted.
	Insert(ctx context.Context, seg *Segment) (bool, error)
	// Get returns the unexpired segments matching the query.
	Get(ctx context.Context, q Query) ([]*Segment, error)
	// DeleteExpired evicts the segments whose expiration passed before the
	// given time, and reports how many were evicted.
	DeleteExpired(ctx context.Context, t time.Time) (int, error)

	Close() error
}
