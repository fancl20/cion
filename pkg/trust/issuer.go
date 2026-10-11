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
	caCert, err := createCACert(ia, keys.CA, rootCert, keys.Root, signingTime())
	if err != nil {
		return nil, err
	}
	i.caCert = caCert
	return i, nil
}

// signingTime is the base time for certificate validity: backdated to
// tolerate clock skew between nodes and truncated to whole seconds so
// certificates and their containers line up exactly.
func signingTime() time.Time {
	return time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
}

// IssueChain creates a certificate chain for the subject of the CSR from the
// issuer's current CA material.
func (i *Issuer) IssueChain(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	ca, err := i.CA()
	if err != nil {
		return nil, err
	}
	return ca.IssueChain(csr)
}

// CA is one snapshot of an issuer's CA material: the CA certificate, the
// key signing with it, and the TRC anchoring them, read as one set. A
// renewal issues its chain and signs its response from one snapshot, for
// the client requires the response signed by the chain's CA certificate.
type CA struct {
	ia   addr.IA
	cert *x509.Certificate
	key  crypto.Signer
	trc  cppki.SignedTRC
}

// CA snapshots the issuer's current CA material under the mutex — the
// rotation's rekey swaps all three as a set.
func (i *Issuer) CA() (*CA, error) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	caCert, err := i.ensureCACertLocked()
	if err != nil {
		return nil, err
	}
	return &CA{ia: i.IA, cert: caCert, key: i.CAKey, trc: i.TRC}, nil
}

// IssueChain creates a certificate chain for the subject of the CSR. The CSR
// must be self-signed (proof of possession of the subject key, PKI draft,
// Section 4.3) and its subject ISD-AS must be in the same ISD as the issuer.
func (c *CA) IssueChain(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, serrors.Wrap("CSR is not self-signed", err)
	}
	ia, err := cppki.ExtractIA(csr.Subject)
	if err != nil {
		return nil, serrors.Wrap("extracting subject ISD-AS from CSR", err)
	}
	if ia.ISD() != c.ia.ISD() {
		return nil, serrors.New("CSR ISD does not match core ISD",
			"csr_isd", ia.ISD(), "core_isd", c.ia.ISD())
	}
	if err := validateISD(ia); err != nil {
		return nil, err
	}
	policy := cppki.CAPolicy{
		Validity:    ASValidity,
		Certificate: c.cert,
		Signer:      c.key,
		CurrentTime: signingTime(),
	}
	chain, err := policy.CreateChain(csr)
	if err != nil {
		return nil, serrors.Wrap("creating chain", err)
	}
	// Verify at signing time, not wall-clock time: the CA certificate is
	// valid from the (possibly backdated) signing time.
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC:         []*cppki.TRC{&c.trc.TRC},
		CurrentTime: time.Now(),
	}); err != nil {
		return nil, serrors.Wrap("generated chain does not verify against TRC", err)
	}
	return chain, nil
}

// SignResponse wraps msg in a CMS SignedData signed with the snapshot's CA
// certificate, as the chain renewal response requires.
func (c *CA) SignResponse(msg []byte) ([]byte, error) {
	return SignCMS(msg, []*x509.Certificate{c.cert}, c.key)
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
	return i.ensureCACertLocked()
}

// ensureCACertLocked is ensureCACert under a held mutex.
func (i *Issuer) ensureCACertLocked() (*x509.Certificate, error) {
	minExpiration := time.Now().Add(ASValidity)
	if i.caCert.NotAfter.After(minExpiration) {
		return i.caCert, nil
	}
	rootCert, err := rootCertificate(i.TRC)
	if err != nil {
		return nil, err
	}
	caCert, err := createCACert(i.IA, i.CAKey, rootCert, i.RootKey, signingTime())
	if err != nil {
		return nil, err
	}
	i.caCert = caCert
	return caCert, nil
}

// Rekey rekeys the issuer under the successor a rotation pinned: the staged
// root and CA keys taking the place of the ones it held, the CA certificate
// minted afresh under the successor's root certificate, the chains issuing
// under it from the pin on. The successor is already verified and pinned; the
// live key files catch up when the staged keys are promoted.
func (i *Issuer) Rekey(keys CoreKeys, trc cppki.SignedTRC) error {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	rootCert, err := rootCertificate(trc)
	if err != nil {
		return err
	}
	caCert, err := createCACert(i.IA, keys.CA, rootCert, keys.Root, signingTime())
	if err != nil {
		return err
	}
	i.RootKey, i.CAKey, i.TRC, i.caCert = keys.Root, keys.CA, trc, caCert
	return nil
}

// CACert returns the currently active CP CA certificate.
func (i *Issuer) CACert() (*x509.Certificate, error) {
	return i.ensureCACert()
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
