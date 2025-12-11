package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// VotingRole represents the voting authority of an AS in the SCION PKI.
type VotingRole int

const (
	// VotingRoleRoot indicates root authority (can sign CA certificates and vote on TRCs).
	VotingRoleRoot VotingRole = iota
	// VotingRoleSensitive indicates sensitive voting authority (higher trust level).
	VotingRoleSensitive
	// VotingRoleRegular indicates regular voting authority.
	VotingRoleRegular
)

// Certificates manages the certificates and private keys owned by a single AS.
// Private keys are kept internal for security and never exposed outside the interface.
// An AS typically has one voting certificate (root, sensitive, or regular) depending on its authority.
type Certificates struct {
	// certificate and private key for voting (one of root, sensitive, or regular)
	votingCert *x509.Certificate
	votingKey  crypto.PrivateKey

	// TODO: support for CA and AS certificates in future
}

// NewCertificates creates an empty certificate manager.
func NewCertificates() *Certificates {
	return &Certificates{}
}

// Create generates a new voting certificate and private key for the given AS.
// The votingRole determines the type of certificate (root, sensitive, or regular).
// This method replaces any existing certificate and key.
func (c *Certificates) Create(ia addr.IA, commonName string, votingRole VotingRole, validity cppki.Validity) error {
	var cert *x509.Certificate
	var privKey crypto.PrivateKey
	var err error

	switch votingRole {
	case VotingRoleRoot:
		cert, privKey, err = generateRootCert(ia, commonName, validity)
	case VotingRoleSensitive:
		cert, privKey, err = generateVotingCert(ia, commonName, cppki.OIDExtKeyUsageSensitive, validity)
	case VotingRoleRegular:
		cert, privKey, err = generateVotingCert(ia, commonName, cppki.OIDExtKeyUsageRegular, validity)
	default:
		return fmt.Errorf("invalid voting role: %v", votingRole)
	}
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	c.votingCert = cert
	c.votingKey = privKey
	return nil
}

// Load is a placeholder for loading certificates from persistent storage.
// Not implemented in this PoC.
func (c *Certificates) Load() error {
	return fmt.Errorf("Load not implemented")
}

// Vote signs a TRC with the AS's private key and returns the updated SignedTRC.
// This implements the voting use case where an AS adds its signature to a TRC proposal.
func (c *Certificates) Vote(signedTRC cppki.SignedTRC) (cppki.SignedTRC, error) {
	// TODO: implement actual signing using c.votingKey
	// For PoC, return the input unchanged
	return signedTRC, fmt.Errorf("Vote not implemented yet")
}

// Join adds the AS's voting certificate to a TRC and returns the updated TRC.
// This is used when an AS wants to join an ISD and needs its certificate included in the TRC.
// The returned TRC is unsigned and would need to be voted on by existing members.
// Note: In the current PoC, only the AS's single voting certificate is added.
// A future enhancement could allow adding root and multiple voting certificates
// when joining a base TRC that lacks them.
func (c *Certificates) Join(trc cppki.TRC) (cppki.TRC, error) {
	if c.votingCert == nil {
		return cppki.TRC{}, fmt.Errorf("no voting certificate available")
	}

	// Check if certificate is already in TRC to avoid duplicates
	for _, cert := range trc.Certificates {
		if cert.Equal(c.votingCert) {
			// Certificate already present, return unchanged
			return trc, nil
		}
	}

	// Append certificate to Certificates slice
	trc.Certificates = append(trc.Certificates, c.votingCert)

	// Re-encode TRC to update Raw field
	raw, err := trc.Encode()
	if err != nil {
		return cppki.TRC{}, fmt.Errorf("failed to encode TRC after adding certificate: %w", err)
	}
	trc.Raw = raw

	return trc, nil
}

// Certificate returns the AS's voting certificate, if any.
func (c *Certificates) Certificate() *x509.Certificate {
	return c.votingCert
}

// HasCertificate returns true if the AS has a voting certificate.
func (c *Certificates) HasCertificate() bool {
	return c.votingCert != nil
}

// generateRootCert creates a SCION-compliant root certificate for a given IA.
// The certificate is self-signed, includes the SCION-specific OIDs for IA and root usage,
// and uses ECDSA P-256 with SHA256 signature algorithm as required by SCION.
func generateRootCert(ia addr.IA, commonName string, validity cppki.Validity) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate ECDSA P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	pubKey := privKey.Public()

	// Subject key identifier
	subjectKeyID, err := cppki.SubjectKeyID(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute subject key identifier: %w", err)
	}

	// Serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Subject and Issuer Name with SCION IA OID in ExtraNames
	subject := pkix.Name{
		CommonName: commonName,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: ia.String()},
		},
	}
	// Self-signed, issuer same as subject
	issuer := subject

	tpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             validity.NotBefore,
		NotAfter:              validity.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign, // Root CA only needs CertSign, not DigitalSignature
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // Root can issue CA certificates (path length 1)
		MaxPathLenZero:        false,
		Version:               3, // SCION CertVersion constant is 3
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKey:             pubKey,
		SubjectKeyId:          subjectKeyID,
		// SCION-specific extended key usage for root certificates
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{cppki.OIDExtKeyUsageRoot},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, privKey, nil
}

// generateVotingCert creates a SCION-compliant self-signed voting certificate for a given IA.
// The certificate is self-signed, includes the SCION-specific OIDs for IA and voting usage,
// and uses ECDSA P-256 with SHA256 signature algorithm as required by SCION.
// votingOID must be either cppki.OIDExtKeyUsageSensitive or cppki.OIDExtKeyUsageRegular.
func generateVotingCert(ia addr.IA, commonName string, votingOID asn1.ObjectIdentifier, validity cppki.Validity) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate ECDSA P-256 key pair for the voting certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	pubKey := privKey.Public()

	// Serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Subject Name with SCION IA OID in ExtraNames
	subject := pkix.Name{
		CommonName: commonName,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: ia.String()},
		},
	}
	// Self-signed, issuer same as subject
	issuer := subject

	// Subject key identifier
	subjectKeyID, err := cppki.SubjectKeyID(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute subject key identifier: %w", err)
	}

	tpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             validity.NotBefore,
		NotAfter:              validity.NotAfter,
		KeyUsage:              0, // Voting certificates must not have CertSign or DigitalSignature
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: false,
		IsCA:                  false,
		Version:               3, // SCION CertVersion constant is 3
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKey:             pubKey,
		SubjectKeyId:          subjectKeyID,
		// SCION-specific extended key usage for voting certificates
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{votingOID},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, privKey, nil
}
