package trust

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/proto"
)

// BuildRenewalRequest builds the CMS-signed chain renewal request for the
// CSR. The wrapper is signed by the CSR's subject key itself — proof of
// possession (PKI draft, Section 4.3) — because a fresh node has no
// certificate chain yet. CMS identifies signers by certificate, so the
// wrapper carries a self-signed certificate minted on the spot for the
// subject key; it is never trusted or used beyond binding the signature to
// the CSR.
func BuildRenewalRequest(csr *x509.CertificateRequest, key crypto.Signer) ([]byte, error) {
	wrapper, err := enrollmentWrapperCert(key, time.Now())
	if err != nil {
		return nil, fmt.Errorf("minting wrapper certificate: %w", err)
	}
	body, err := proto.Marshal(&cppb.ChainRenewalRequestBody{Csr: csr.Raw})
	if err != nil {
		return nil, err
	}
	return SignCMS(body, []*x509.Certificate{wrapper}, key)
}

// ParseRenewalResponse extracts the certificate chain from the CMS-signed
// renewal response, checking that the response is signed by the CP CA
// certificate it carries.
func ParseRenewalResponse(der []byte) ([]*x509.Certificate, error) {
	signed, err := ParseCMS(der)
	if err != nil {
		return nil, err
	}
	var body cppb.ChainRenewalResponseBody
	if err := proto.Unmarshal(signed.Payload, &body); err != nil {
		return nil, serrors.Wrap("parsing renewal response body", err)
	}
	if body.Chain == nil {
		return nil, serrors.New("renewal response carries no chain")
	}
	asCert, err := x509.ParseCertificate(body.Chain.AsCert)
	if err != nil {
		return nil, serrors.Wrap("parsing AS certificate", err)
	}
	caCert, err := x509.ParseCertificate(body.Chain.CaCert)
	if err != nil {
		return nil, serrors.Wrap("parsing CA certificate", err)
	}
	if !signed.SignedBy(caCert.PublicKey) {
		return nil, serrors.New("renewal response is not signed by its CA certificate")
	}
	return []*x509.Certificate{asCert, caCert}, nil
}

// enrollmentWrapperCert mints the ephemeral self-signed certificate riding
// in the renewal request's CMS wrapper.
func enrollmentWrapperCert(key crypto.Signer, now time.Time) (*x509.Certificate, error) {
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		SerialNumber:       big.NewInt(0).SetBytes(serial),
		Subject:            pkix.Name{CommonName: "cion chain renewal"},
		NotBefore:          now.Add(-time.Hour).UTC(),
		NotAfter:           now.Add(time.Hour).UTC(),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SubjectKeyId:       skid,
	}
	return createCertificate(tmpl, tmpl, key.Public(), key)
}
