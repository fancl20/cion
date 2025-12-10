package pki

import "context"

// TRC represents a Trust Root Configuration.
type TRC struct {
	ISD     int
	Version int
	// Content would go here
}

// Certificate represents a SCION certificate.
type Certificate struct {
	ISD int
	AS  int
	// Content would go here
}

// Verifier defines the interface for cryptographic verification.
type Verifier interface {
	// Verify checks the signature of data against a certificate or TRC.
	Verify(ctx context.Context, data []byte, signature []byte, certID string) error
}

// TrustStore defines the interface for retrieving trust material.
type TrustStore interface {
	// GetTRC retrieves a specific TRC.
	GetTRC(ctx context.Context, isd int, version int) (TRC, error)

	// GetCertificate retrieves a specific certificate.
	GetCertificate(ctx context.Context, isd int, as int) (Certificate, error)

	// GetLatestTRC retrieves the latest TRC for an ISD.
	GetLatestTRC(ctx context.Context, isd int) (TRC, error)
}
