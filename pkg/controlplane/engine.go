package controlplane

import (
	"context"
	"fmt"
)

// Engine implements the control plane logic.
type Engine struct {
	discovery    *Discovery
	localAddress SCIONAddress
}

// NewEngine creates a new control plane engine.
func NewEngine(discovery *Discovery, localAddr SCIONAddress) *Engine {
	return &Engine{
		discovery:    discovery,
		localAddress: localAddr,
	}
}

// GetPaths returns paths to the destination. For now, only direct links.
func (e *Engine) GetPaths(ctx context.Context, src, dst SCIONAddress) ([]Path, error) {
	// Check if dst is a neighbor
	neighbor, ok := e.discovery.GetNeighbor(dst)
	if !ok {
		return nil, fmt.Errorf("no path found to %s (only direct links supported)", dst)
	}

	// Construct a direct path.
	// In a full implementation, this would involve retrieving valid path segments.
	// For this simplified control plane, we construct a synthetic segment representing the direct link.
	segment := PathSegment{
		ID:         []byte(neighbor.Address), // Use the overlay address as the ID for now
		Interfaces: []uint64{1},              // Dummy interface ID
	}

	return []Path{{Segments: []PathSegment{segment}}}, nil
}
