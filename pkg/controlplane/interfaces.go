package controlplane

import (
	"context"
	"crypto/x509"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

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

// TrustStore defines the interface for retrieving trust material.
type TrustStore interface {
	// GetTRC retrieves a specific TRC.
	GetTRC(ctx context.Context, isd int, version int) (cppki.TRC, error)

	// GetCertificate retrieves a specific certificate.
	GetCertificate(ctx context.Context, isd int, as int) (*x509.Certificate, error)

	// GetLatestTRC retrieves the latest TRC for an ISD.
	GetLatestTRC(ctx context.Context, isd int) (cppki.TRC, error)
}

// ControlPlane defines the main control plane interface.
type ControlPlane interface {
	PathLookup
	TrustStore
	// GetLocalAddress returns the local ISD-AS address.
	GetLocalAddress() SCIONAddress
	// SetActiveDirectPath stores an active direct path for a given destination.
	SetActiveDirectPath(destination SCIONAddress, path Path)
}

const (
	// SegmentCreationServiceBeaconProcedure is the HTTP path for the Beacon RPC.
	SegmentCreationServiceBeaconProcedure = "/proto.control_plane.v1.SegmentCreationService/Beacon"
	// SegmentLookupServiceSegmentsProcedure is the HTTP path for the Segments RPC.
	SegmentLookupServiceSegmentsProcedure = "/proto.control_plane.v1.SegmentLookupService/Segments"
	// SegmentRegistrationServiceSegmentsRegistrationProcedure is the HTTP path for the SegmentsRegistration RPC.
	SegmentRegistrationServiceSegmentsRegistrationProcedure = "/proto.control_plane.v1.SegmentRegistrationService/SegmentsRegistration"
	// TrustMaterialServiceChainsProcedure is the HTTP path for the Chains RPC.
	TrustMaterialServiceChainsProcedure = "/proto.control_plane.v1.TrustMaterialService/Chains"
	// TrustMaterialServiceTRCProcedure is the HTTP path for the TRC RPC.
	TrustMaterialServiceTRCProcedure = "/proto.control_plane.v1.TrustMaterialService/TRC"
)
