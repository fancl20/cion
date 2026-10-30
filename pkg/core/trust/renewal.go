package trust

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/proto"
)

// BuildRenewalRequest builds the CMS-signed chain renewal request for the
// CSR. A node that holds a valid chain signs with its AS key under the chain
// and carries it: the requester's current chain is the authority a renewal
// rests on (PKI draft, Section 4.3), and the CSR certifies the same key. A
// node without one — a first issuance — signs with the CSR's subject key
// itself, proof of possession: CMS identifies signers by certificate, so the
// wrapper carries a self-signed certificate minted on the spot for the
// subject key; it is never trusted or used beyond binding the signature to
// the CSR.
func BuildRenewalRequest(
	csr *x509.CertificateRequest,
	key crypto.Signer,
	chain []*x509.Certificate,
) ([]byte, error) {

	raw, err := proto.Marshal(&cppb.ChainRenewalRequestBody{Csr: csr.Raw})
	if err != nil {
		return nil, err
	}
	if chain != nil {
		return SignCMS(raw, chain, key)
	}
	wrapper, err := enrollmentWrapperCert(key, time.Now())
	if err != nil {
		return nil, fmt.Errorf("minting wrapper certificate: %w", err)
	}
	return SignCMS(raw, []*x509.Certificate{wrapper}, key)
}

// RequestChain returns the chain a renewal request carries, its AS
// certificate first: the request's one signer, beside the CA certificate
// that issued it. A request carrying one certificate — a first issuance's
// wrapper — carries no chain, and a nil chain answers it; any other shape
// is refused.
func RequestChain(signed *CMSSigned) ([]*x509.Certificate, error) {
	if len(signed.Certificates) == 1 {
		return nil, nil
	}
	if len(signed.Certificates) != 2 {
		return nil, serrors.New("the request carries neither a chain nor a wrapper",
			"certificates", len(signed.Certificates))
	}
	chain := slices.Clone(signed.Certificates)
	if ct, err := cppki.ValidateCert(chain[0]); err == nil && ct == cppki.CA {
		chain[0], chain[1] = chain[1], chain[0]
	}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, serrors.Wrap("the request's certificates form no chain", err)
	}
	if len(signed.SignerCerts) != 1 || !signed.SignerCerts[0].Equal(chain[0]) {
		return nil, serrors.New("the request is not signed by its chain's AS certificate alone")
	}
	return chain, nil
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
