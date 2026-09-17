package trust

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Issuer issues AS certificate chains with the founding core's CP CA key.
// The chains are two-certificate chains [AS certificate, CP CA certificate]
// verified against the root pool extracted from the TRC (PKI draft,
// Section 4.2.2; enforced by cppki.ValidateChain).
type Issuer struct {
	// IA is the core's ISD-AS.
	IA addr.IA
	// RootKey signs CP CA certificates; its certificate is in the TRC.
	RootKey crypto.Signer
	// CAKey signs AS certificates; its certificate is never in the TRC.
	CAKey crypto.Signer
	// TRC is the base TRC anchoring the issued chains.
	TRC cppki.SignedTRC

	mtx    sync.Mutex
	caCert *x509.Certificate
}

// NewIssuer returns an issuer anchored in the given TRC. The allowlist is
// handled by the caller, so issuance here is only about correct certificates.
func NewIssuer(ia addr.IA, keys CoreKeys, trc cppki.SignedTRC) (*Issuer, error) {
	rootCert, err := rootCertificate(trc)
	if err != nil {
		return nil, err
	}
	i := &Issuer{IA: ia, RootKey: keys.Root, CAKey: keys.CA, TRC: trc}
	caCert, err := createCACert(ia, keys.CA, rootCert, keys.Root, i.signingTime())
	if err != nil {
		return nil, err
	}
	i.caCert = caCert
	return i, nil
}

// signingTime is the base time for certificate validity: backdated to
// tolerate clock skew between nodes and truncated to whole seconds so
// certificates and their containers line up exactly.
func (i *Issuer) signingTime() time.Time {
	return time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
}

// IssueChain creates a certificate chain for the subject of the CSR. The CSR
// must be self-signed (proof of possession of the subject key, PKI draft,
// Section 4.3) and its subject ISD-AS must be in the same ISD as the issuer.
func (i *Issuer) IssueChain(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, serrors.Wrap("CSR is not self-signed", err)
	}
	ia, err := cppki.ExtractIA(csr.Subject)
	if err != nil {
		return nil, serrors.Wrap("extracting subject ISD-AS from CSR", err)
	}
	if ia.ISD() != i.IA.ISD() {
		return nil, serrors.New("CSR ISD does not match core ISD",
			"csr_isd", ia.ISD(), "core_isd", i.IA.ISD())
	}
	if err := validateISD(ia); err != nil {
		return nil, err
	}
	caCert, err := i.ensureCACert()
	if err != nil {
		return nil, err
	}
	policy := cppki.CAPolicy{
		Validity:    ASValidity,
		Certificate: caCert,
		Signer:      i.CAKey,
		CurrentTime: i.signingTime(),
	}
	chain, err := policy.CreateChain(csr)
	if err != nil {
		return nil, serrors.Wrap("creating chain", err)
	}
	// Verify at signing time, not wall-clock time: the CA certificate is
	// valid from the (possibly backdated) signing time.
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC:         []*cppki.TRC{&i.TRC.TRC},
		CurrentTime: time.Now(),
	}); err != nil {
		return nil, serrors.Wrap("generated chain does not verify against TRC", err)
	}
	return chain, nil
}

// ensureCACert returns a CP CA certificate whose validity covers a full AS
// certificate validity. The CA certificate is reissued from the root key —
// which is anchored in the TRC and valid for a year — whenever the current
// one gets too close to its end. Without renewal workflows this keeps
// enrollment working for the lifetime of the base TRC; nodes simply see a
// new CA certificate in each chain they obtain.
func (i *Issuer) ensureCACert() (*x509.Certificate, error) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	minExpiration := time.Now().Add(ASValidity)
	if i.caCert != nil && i.caCert.NotAfter.After(minExpiration) {
		return i.caCert, nil
	}
	rootCert, err := rootCertificate(i.TRC)
	if err != nil {
		return nil, err
	}
	caCert, err := createCACert(i.IA, i.CAKey, rootCert, i.RootKey, i.signingTime())
	if err != nil {
		return nil, err
	}
	i.caCert = caCert
	return caCert, nil
}

// CACert returns the currently active CP CA certificate.
func (i *Issuer) CACert() (*x509.Certificate, error) {
	return i.ensureCACert()
}

// SignResponse wraps msg in a CMS SignedData signed with the CP CA
// certificate, as the chain renewal response requires.
func (i *Issuer) SignResponse(msg []byte) ([]byte, error) {
	caCert, err := i.ensureCACert()
	if err != nil {
		return nil, err
	}
	return SignCMS(msg, []*x509.Certificate{caCert}, i.CAKey)
}

// rootCertificate extracts the CP root certificate from the TRC, which must
// contain exactly one.
func rootCertificate(trc cppki.SignedTRC) (*x509.Certificate, error) {
	roots, err := trc.TRC.RootCerts()
	if err != nil {
		return nil, err
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("TRC must contain exactly one CP root certificate, has %d",
			len(roots))
	}
	return roots[0], nil
}
