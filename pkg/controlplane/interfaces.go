package controlplane

import "context"

// SCIONAddress represents a SCION address (ISD-AS).
type SCIONAddress string

// Beacon represents a Path Segment Construction Beacon (PCB).
type Beacon struct {
	// Info and HopFields would go here
	SegmentID []byte
}

// PathSegment represents a registered path segment.
type PathSegment struct {
	ID         []byte
	Interfaces []uint64
}

// Path represents an end-to-end path.
type Path struct {
	Segments []PathSegment
}

// Beaconing defines the interface for path exploration and propagation.
type Beaconing interface {
	// Propagate sends a beacon to neighbors.
	Propagate(ctx context.Context, beacon Beacon) error

	// Register registers a path segment with the control service.
	Register(ctx context.Context, segment PathSegment) error
}

// PathLookup defines the interface for resolving paths.
type PathLookup interface {
	// GetPaths returns a list of paths from source to destination.
	GetPaths(ctx context.Context, src, dst SCIONAddress) ([]Path, error)
}
