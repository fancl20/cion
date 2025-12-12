package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// CertType represents the type of certificate in the SCION PKI.
type CertType int

const (
	CertTypeUnknown CertType = iota
	// CertTypeRegular indicates a regular voting certificate.
	CertTypeRegular
	// CertTypeSensitive indicates a sensitive voting certificate.
	CertTypeSensitive
	// CertTypeRoot indicates a root certificate (can sign CA certificates).
	CertTypeRoot
	// CertTypeAS indicates an AS certificate (used for TLS).
	CertTypeAS
)

// ASType represents the role of an AS in the SCION ISD.
type ASType int

const (
	// ASTypeCore indicates a Core AS (holds Root, Sensitive, and Regular voting rights).
	// Matches spec "Core AS" governing the ISD.
	ASTypeCore ASType = iota
	// ASTypeAuthoritative indicates an Authoritative AS (holds Regular voting rights).
	// In this simplified model, Authoritative ASes are ASes that participate in regular voting.
	ASTypeAuthoritative
	// ASTypeNormal indicates a regular AS (no voting rights).
	ASTypeNormal
)

// Certificates manages the certificates and private keys owned by a single AS.
// Private keys are kept internal for security and never exposed outside the interface.
type Certificates struct {
	// certificate and private key by type
	certs map[CertType]*x509.Certificate
	keys  map[CertType]crypto.PrivateKey

	// TODO: support for CA and AS certificates in future
}

// NewCertificates creates an empty certificate manager.
func NewCertificates() *Certificates {
	return &Certificates{
		certs: make(map[CertType]*x509.Certificate),
		keys:  make(map[CertType]crypto.PrivateKey),
	}
}

// Create generates the necessary certificates and private keys for the given AS based on its type.
// This method replaces any existing certificates and keys.
func (c *Certificates) Create(ia addr.IA, asType ASType, validity cppki.Validity) error {
	switch asType {
	case ASTypeCore:
		// Core AS gets Root, Sensitive, and Regular certificates
		if err := c.generateCert(ia, CertTypeRoot, validity); err != nil {
			return err
		}
		if err := c.generateCert(ia, CertTypeSensitive, validity); err != nil {
			return err
		}
		if err := c.generateCert(ia, CertTypeRegular, validity); err != nil {
			return err
		}
		// Generate AS cert signed by the Root we just generated
		if err := c.generateASCert(ia, validity); err != nil {
			return err
		}
	case ASTypeAuthoritative:
		// Authoritative AS gets Regular voting certificate
		if err := c.generateCert(ia, CertTypeRegular, validity); err != nil {
			return err
		}
		// For now, self-signed AS cert as we don't have a CA service in PoC
		if err := c.generateASCertSelfSigned(ia, validity); err != nil {
			return err
		}
	case ASTypeNormal:
		// Normal AS gets no TRC-level certificates (will get AS cert in future)
		// For now, self-signed AS cert
		if err := c.generateASCertSelfSigned(ia, validity); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid AS type: %v", asType)
	}
	return nil
}

func (c *Certificates) generateCert(ia addr.IA, certType CertType, validity cppki.Validity) error {
	var cert *x509.Certificate
	var privKey crypto.PrivateKey
	var err error
	var commonName string

	switch certType {
	case CertTypeRoot:
		commonName = fmt.Sprintf("ISD%d-AS%s Root", ia.ISD(), ia.AS())
		cert, privKey, err = generateRootCert(ia, commonName, validity)
	case CertTypeSensitive:
		commonName = fmt.Sprintf("ISD%d-AS%s Sensitive Voting", ia.ISD(), ia.AS())
		cert, privKey, err = generateVotingCert(ia, commonName, cppki.OIDExtKeyUsageSensitive, validity)
	case CertTypeRegular:
		commonName = fmt.Sprintf("ISD%d-AS%s Regular Voting", ia.ISD(), ia.AS())
		cert, privKey, err = generateVotingCert(ia, commonName, cppki.OIDExtKeyUsageRegular, validity)
	default:
		return fmt.Errorf("invalid cert type: %v", certType)
	}

	if err != nil {
		return fmt.Errorf("failed to generate certificate for %v: %w", certType, err)
	}

	c.certs[certType] = cert
	c.keys[certType] = privKey
	return nil
}

// generateASCert generates an AS certificate signed by the local Root key (must exist).
func (c *Certificates) generateASCert(ia addr.IA, validity cppki.Validity) error {
	rootKey, ok := c.keys[CertTypeRoot]
	if !ok {
		return fmt.Errorf("cannot generate AS cert: missing root key")
	}
	rootCert, ok := c.certs[CertTypeRoot]
	if !ok {
		return fmt.Errorf("cannot generate AS cert: missing root cert")
	}

	commonName := fmt.Sprintf("ISD%d-AS%s AS Certificate", ia.ISD(), ia.AS())
	cert, privKey, err := generateASCert(ia, commonName, validity, rootCert, rootKey)
	if err != nil {
		return err
	}

	c.certs[CertTypeAS] = cert
	c.keys[CertTypeAS] = privKey
	return nil
}

// generateASCertSelfSigned generates a self-signed AS certificate (for non-Core AS PoC).
func (c *Certificates) generateASCertSelfSigned(ia addr.IA, validity cppki.Validity) error {
	commonName := fmt.Sprintf("ISD%d-AS%s AS Certificate (Self-Signed)", ia.ISD(), ia.AS())

	// Pass nil parent/key to trigger self-signing logic in helper
	cert, privKey, err := generateASCert(ia, commonName, validity, nil, nil)
	if err != nil {
		return err
	}

	c.certs[CertTypeAS] = cert
	c.keys[CertTypeAS] = privKey
	return nil
}

// GetTLSCertificate returns the AS certificate and private key as a tls.Certificate.
// This is used for configuring the control plane's QUIC/TLS server.
func (c *Certificates) GetTLSCertificate() (*tls.Certificate, error) {
	cert, ok := c.certs[CertTypeAS]
	if !ok {
		return nil, fmt.Errorf("AS certificate not found")
	}
	key, ok := c.keys[CertTypeAS]
	if !ok {
		return nil, fmt.Errorf("AS private key not found")
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	return tlsCert, nil
}

// Load is a placeholder for loading certificates from persistent storage.
// Not implemented in this PoC.
func (c *Certificates) Load() error {
	return fmt.Errorf("load not implemented")
}

// Vote signs a TRC with the AS's private key and returns the updated SignedTRC.
// This implements the voting use case where an AS adds its signature to a TRC proposal.
func (c *Certificates) Vote(signedTRC cppki.SignedTRC) (cppki.SignedTRC, error) {
	// TODO: implement actual signing using the appropriate key from c.keys
	// For PoC, return the input unchanged
	return signedTRC, fmt.Errorf("vote not implemented yet")
}

// Join adds the AS's voting certificate to a TRC and returns the updated TRC.
// This is used when an AS wants to join an ISD and needs its certificate included in the TRC.
// The returned TRC is unsigned and would need to be voted on by existing members.
func (c *Certificates) Join(trc cppki.TRC) (cppki.TRC, error) {
	if len(c.certs) == 0 {
		return cppki.TRC{}, fmt.Errorf("no voting certificate available")
	}

	// Iterate in deterministic order: Root -> Sensitive -> Regular
	types := []CertType{CertTypeRoot, CertTypeSensitive, CertTypeRegular}
	for _, t := range types {
		myCert, ok := c.certs[t]
		if !ok {
			continue
		}

		// Check if certificate is already in TRC to avoid duplicates
		found := false
		for _, cert := range trc.Certificates {
			if cert.Equal(myCert) {
				found = true
				break
			}
		}
		if !found {
			trc.Certificates = append(trc.Certificates, myCert)
		}
	}

	// Re-encode TRC to update Raw field
	raw, err := trc.Encode()
	if err != nil {
		return cppki.TRC{}, fmt.Errorf("failed to encode TRC after adding certificate: %w", err)
	}
	trc.Raw = raw

	return trc, nil
}

// HasCertificate returns true if the AS has a certificate of the specified type.
func (c *Certificates) HasCertificate(t CertType) bool {
	_, ok := c.certs[t]
	return ok
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
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
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

// generateASCert creates a SCION-compliant AS certificate.
// If issuer is nil, it creates a self-signed certificate (for PoC or Root creation).
func generateASCert(ia addr.IA, commonName string, validity cppki.Validity, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate ECDSA P-256 key pair for the AS certificate
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

	// Subject key identifier
	subjectKeyID, err := cppki.SubjectKeyID(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute subject key identifier: %w", err)
	}

	tpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             validity.NotBefore,
		NotAfter:              validity.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		Version:               3,
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKey:             pubKey,
		SubjectKeyId:          subjectKeyID,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	var parent *x509.Certificate
	var signerKey crypto.PrivateKey

	if issuer != nil {
		parent = issuer
		signerKey = issuerKey
	} else {
		// Self-signed
		parent = &tpl
		signerKey = privKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tpl, parent, pubKey, signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AS certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated AS certificate: %w", err)
	}

	return cert, privKey, nil
}
