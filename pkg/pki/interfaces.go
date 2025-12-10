package pki

import (
	"context"
	"crypto/x509"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Verifier defines the interface for cryptographic verification.
type Verifier interface {
	// Verify checks the signature of data against a certificate or TRC.
	Verify(ctx context.Context, data []byte, signature []byte, certID string) error
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
