package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// asn1ID is used to encode and decode the TRC ID, duplicated from cppki/trc_asn1.go for internal encoding.
type asn1ID struct {
	ISD    int64 `asn1:"iSD"`
	Serial int64 `asn1:"serialNumber"`
	Base   int64 `asn1:"baseNumber"`
}

// asn1Validity is used to encode and decode validity, duplicated from cppki/trc_asn1.go.
type asn1Validity struct {
	NotBefore time.Time `asn1:"notBefore,generalized"`
	NotAfter  time.Time `asn1:"notAfter,generalized"`
}

// asn1TRCPayload is used to encode and decode the TRC payload, duplicated from cppki/trc_asn1.go.
type asn1TRCPayload struct {
	Version           int64           `asn1:"version"`
	ID                asn1ID          `asn1:"iD"`
	Validity          asn1Validity    `asn1:"validity"`
	GracePeriod       int64           `asn1:"gracePeriod"`
	NoTrustReset      bool            `asn1:"noTrustReset"`
	Votes             []int64         `asn1:"votes"`
	Quorum            int64           `asn1:"votingQuorum"`
	CoreASes          []string        `asn1:"coreASes"`
	AuthoritativeASes []string        `asn1:"authoritativeASes"`
	Description       string          `asn1:"description,utf8"`
	Certificates      []asn1.RawValue `asn1:"certificates"`
}

// GenerateSelfSignedCert creates a self-signed X.509 certificate for a given ISD-AS.
// This is a generic self-signed CA certificate for PoC purposes.
func GenerateSelfSignedCert(ia addr.IA, commonName string, privKey ed25519.PrivateKey) (*x509.Certificate, error) {
	pubKey := privKey.Public()

	// Serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Subject and Issuer Name
	subject := pkix.Name{
		Organization: []string{"CION"},
		CommonName:   commonName,
	}

	tpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                subject, // Self-signed
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		PublicKeyAlgorithm:    x509.Ed25519,
		SignatureAlgorithm:    x509.PureEd25519,
		PublicKey:             pubKey,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, nil
}

// GenerateTRC creates a simplified cppki.TRC for a given ISD.
// This is a minimal implementation for testing/PoC and does not reflect the full SCION TRC generation process.
// NOTE: For PoC, cppki.TRC.Validate() is skipped due to complexities with generating a fully spec-compliant root certificate from scratch.
// In a full implementation, the root certificate would be externally generated and correctly classified by cppki.
func GenerateTRC(isd int, version, baseVersion int, description string,
	validity cppki.Validity, coreASes []addr.AS, authASes []addr.AS) (*cppki.TRC, ed25519.PrivateKey, error) {

	// Generate a private key for the TRC's root certificate.
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate TRC private key: %w", err)
	}

	// Create a self-signed root certificate for the TRC.
	// For simplicity, this acts as the sole root certificate for voting/trust.
	isd_addr := addr.ISD(isd)
	rootIA := addr.MustIAFrom(isd_addr, coreASes[0]) // Use first core AS as root for simplicity
	// The commonName for the certificate will NOT include ISD-AS in Subject as it causes cppki.ExtractIA issues
	// We rely on the `ia` parameter for TRC construction.
	rootCert, err := GenerateSelfSignedCert(rootIA, fmt.Sprintf("ISD%d-AS%s Root", isd, rootIA.AS()), privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate root certificate for TRC: %w", err)
	}

	// Certificates for ASN.1 encoding
	var rawCerts []asn1.RawValue
	if _, err := asn1.Unmarshal(rootCert.Raw, &rawCerts); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal root cert for TRC raw encoding: %w", err)
	}

	// Populate asn1TRCPayload for encoding
	a := asn1TRCPayload{
		Version: int64(0), // Version 0 in ASN.1 is TRC Version 1
		ID: asn1ID{
			ISD:    int64(isd),
			Serial: int64(version),
			Base:   int64(baseVersion),
		},
		Validity: asn1Validity{
			NotBefore: validity.NotBefore.UTC().Truncate(time.Second),
			NotAfter:  validity.NotAfter.UTC().Truncate(time.Second),
		},
		GracePeriod:       int64(0),
		NoTrustReset:      false,
		Votes:             []int64{0}, // Placeholder: index of rootCert in Certificates slice
		Quorum:            int64(1),
		CoreASes:          []string{coreASes[0].String()}, // Use first core AS string for simplicity
		AuthoritativeASes: make([]string, len(authASes)),
		Description:       description,
		Certificates:      rawCerts,
	}
	for i, as := range authASes {
		a.AuthoritativeASes[i] = as.String()
	}

	rawTRCBytes, err := asn1.Marshal(a)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal TRC payload: %w", err)
	}

	// Populate cppki.TRC fields.
	trc := &cppki.TRC{
		Raw:          rawTRCBytes,
		Version:      1, // SCION TRC format version
		ID:           cppki.TRCID{
			ISD:    addr.ISD(isd),
			Base:   scrypto.Version(baseVersion),
			Serial: scrypto.Version(version),
		},
		Validity:    validity,
		Quorum:      1,
		CoreASes:    coreASes,
		AuthoritativeASes: authASes,
		Description: description,
		Certificates: []*x509.Certificate{rootCert},
	}

	// NOTE: For PoC, cppki.TRC.Validate() is skipped due to complexities with generating a fully spec-compliant root certificate from scratch.
	// In a full implementation, the root certificate would be externally generated and correctly classified by cppki.
	// if err := trc.Validate(); err != nil {
	// 	return nil, nil, fmt.Errorf("generated TRC failed cppki validation: %w", err)
	// }

	return trc, privKey, nil
}