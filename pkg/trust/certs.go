package trust

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Recommended validity periods of the trust material (proposal 0003; PKI
// draft, Section 2.1.6). There is no automated renewal yet: an expired node
// re-runs enrollment, and a new base TRC means redeploying.
const (
	TRCValidity     = 365 * 24 * time.Hour
	VotingValidity  = 365 * 24 * time.Hour
	RootValidity    = 365 * 24 * time.Hour
	CAValidity      = 11 * 24 * time.Hour
	ASValidity      = 3 * 24 * time.Hour
	signingBackdate = -1 * time.Minute
)

// serialNumber returns a random certificate serial number.
func serialNumber() (*big.Int, error) {
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(serial), nil
}

// subject builds the distinguished name carrying the ISD-AS. The IA is both
// the common name and a dedicated RDN (OID 1.3.6.1.4.1.55324.1.2.1) so cppki
// can extract it; ExtraNames is what gets marshaled.
func subject(ia addr.IA, cn string) pkix.Name {
	name := ia.String()
	if cn == "" {
		cn = name
	}
	return pkix.Name{
		CommonName: cn,
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: cppki.OIDNameIA, Value: name}},
	}
}

// createCertificate signs template with parent, or self-signs it when
// parent is the template itself.
func createCertificate(
	template, parent *x509.Certificate,
	subjectPub, issuerKey any,
) (*x509.Certificate, error) {

	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectPub, issuerKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// createVotingCert creates the self-signed voting certificate for key. The
// sensitive flag selects the id-kp-sensitive over the id-kp-regular extended
// key usage. Voting certificates carry id-kp-timeStamping alongside their
// voting usage, like the reference tooling; voting keys sign TRC updates,
// never certificates or messages, so the key usage extension stays empty.
func createVotingCert(
	ia addr.IA,
	key crypto.Signer,
	sensitive bool,
	now time.Time,
) (*x509.Certificate, error) {

	usage := cppki.OIDExtKeyUsageRegular
	cn := "regular voting"
	if sensitive {
		usage = cppki.OIDExtKeyUsageSensitive
		cn = "sensitive voting"
	}
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Version:            cppki.CertVersion,
		SerialNumber:       serial,
		Subject:            subject(ia, cn),
		NotBefore:          now.UTC(),
		NotAfter:           now.UTC().Add(VotingValidity),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{usage},
		SubjectKeyId:       skid,
	}
	cert, err := createCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	if _, err := cppki.ValidateCert(cert); err != nil {
		return nil, fmt.Errorf("generated %s certificate: %w", cn, err)
	}
	return cert, nil
}

// createRootCert creates the self-signed CP root certificate for key. The
// root certificate carries id-kp-root, never votes, and signs CP CA
// certificates.
func createRootCert(ia addr.IA, key crypto.Signer, now time.Time) (*x509.Certificate, error) {
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Version:            cppki.CertVersion,
		SerialNumber:       serial,
		Subject:            subject(ia, "cp root"),
		NotBefore:          now.UTC(),
		NotAfter:           now.UTC().Add(RootValidity),
		KeyUsage:           x509.KeyUsageCertSign,
		// id-kp-timeStamping keeps the certificate usable in standard chain
		// verification, which walks the extended key usages of every
		// certificate in the chain.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{cppki.OIDExtKeyUsageRoot},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}
	cert, err := createCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	if t, err := cppki.ValidateCert(cert); err != nil || t != cppki.Root {
		return nil, fmt.Errorf("generated cp root certificate: %w", err)
	}
	return cert, nil
}

// createCACert creates the CP CA certificate for caKey, signed by the CP
// root key. It is never placed in the TRC (PKI draft, Sections 2.1.5.2 and
// 3.1.2.2.11); the resulting chain is [AS certificate, CP CA certificate]
// anchored in the TRC's root certificate.
func createCACert(
	ia addr.IA,
	caKey crypto.Signer,
	rootCert *x509.Certificate,
	rootKey crypto.Signer,
	now time.Time,
) (*x509.Certificate, error) {

	skid, err := cppki.SubjectKeyID(caKey.Public())
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Version:               cppki.CertVersion,
		SerialNumber:          serial,
		Subject:               subject(ia, "cp ca"),
		NotBefore:             now.UTC(),
		NotAfter:              now.UTC().Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}
	cert, err := createCertificate(tmpl, rootCert, caKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	if t, err := cppki.ValidateCert(cert); err != nil || t != cppki.CA {
		return nil, fmt.Errorf("generated cp ca certificate: %w", err)
	}
	return cert, nil
}
