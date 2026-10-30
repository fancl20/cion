package trust

import (
	"crypto"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// ErrUnanchored reports an issuer whose root certificate no TRC it holds
// carries: it issues nothing until its root lands.
var ErrUnanchored = errors.New("the issuer's root certificate is in no TRC it holds")

// Issuer issues AS certificate chains with a core's CP CA key, under the
// core's own root certificate among the TRC's roots. The chains are
// two-certificate chains [AS certificate, CP CA certificate] verified
// against the root pool extracted from the TRC (PKI draft, Section 4.2.2;
// enforced by cppki.ValidateChain). An issuer whose TRC carries no root of
// its own is unanchored: it issues nothing until Anchor hands it a TRC that
// does.
type Issuer struct {
	// IA is the core's ISD-AS.
	IA addr.IA

	// mtx guards the CA material, which an anchoring or a rekey swaps as a
	// set.
	mtx sync.Mutex
	// keys sign the CA certificates and the AS certificates.
	keys IssuerKeys
	// trc anchors the issued chains, and root is the issuer's own root
	// certificate in it; both are zero while the issuer is unanchored.
	trc    cppki.SignedTRC
	root   *x509.Certificate
	caCert *x509.Certificate
}

// NewIssuer returns an issuer of the keys, anchored in the TRC when the TRC
// carries the root certificate the root key covers, and unanchored
// otherwise. The allowlist is handled by the caller, so issuance here is
// only about correct certificates.
func NewIssuer(ia addr.IA, keys IssuerKeys, trc cppki.SignedTRC) (*Issuer, error) {
	i := &Issuer{IA: ia, keys: keys}
	root, err := ownRoot(trc, keys.Root)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return i, nil
	}
	if err := i.anchorLocked(keys, trc, root); err != nil {
		return nil, err
	}
	return i, nil
}

// signingTime is the base time for certificate validity: backdated to
// tolerate clock skew between nodes and truncated to whole seconds so
// certificates and their containers line up exactly.
func signingTime() time.Time {
	return time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
}

// Anchor anchors the issuer in the TRC, which must carry the root
// certificate the issuer's root key covers, and mints the CA certificate
// under it: the chains issue under that root from here on.
func (i *Issuer) Anchor(trc cppki.SignedTRC) error {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	root, err := ownRoot(trc, i.keys.Root)
	if err != nil {
		return err
	}
	if root == nil {
		return serrors.New("the TRC carries no root certificate of the issuer",
			"trc", trc.TRC.ID)
	}
	return i.anchorLocked(i.keys, trc, root)
}

// Anchored reports whether the issuer holds a TRC carrying its root, and so
// issues.
func (i *Issuer) Anchored() bool {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	return i.root != nil
}

// anchorLocked takes the keys, the TRC, and the root certificate in it as
// the issuer's set, the CA certificate minted afresh under the root.
func (i *Issuer) anchorLocked(keys IssuerKeys, trc cppki.SignedTRC, root *x509.Certificate) error {
	caCert, err := createCACert(i.IA, keys.CA, root, keys.Root, signingTime())
	if err != nil {
		return err
	}
	i.keys, i.trc, i.root, i.caCert = keys, trc, root, caCert
	return nil
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

// CA snapshots the issuer's current CA material under the mutex — an
// anchoring or a rekey swaps all three as a set. An unanchored issuer
// answers ErrUnanchored.
func (i *Issuer) CA() (*CA, error) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	if i.root == nil {
		return nil, ErrUnanchored
	}
	caCert, err := i.ensureCACertLocked()
	if err != nil {
		return nil, err
	}
	return &CA{ia: i.IA, cert: caCert, key: i.keys.CA, trc: i.trc}, nil
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
// whose certificate is anchored in the TRC and valid for a year — whenever
// the current one gets too close to its end, so nodes simply see a new CA
// certificate in each chain they obtain.
func (i *Issuer) ensureCACert() (*x509.Certificate, error) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	return i.ensureCACertLocked()
}

// ensureCACertLocked is ensureCACert under a held mutex, on an anchored
// issuer.
func (i *Issuer) ensureCACertLocked() (*x509.Certificate, error) {
	minExpiration := time.Now().Add(ASValidity)
	if i.caCert.NotAfter.After(minExpiration) {
		return i.caCert, nil
	}
	caCert, err := createCACert(i.IA, i.keys.CA, i.root, i.keys.Root, signingTime())
	if err != nil {
		return nil, err
	}
	i.caCert = caCert
	return caCert, nil
}

// Rekey rekeys the issuer under the successor a roll pinned: the staged root
// and CA keys taking the place of the ones it held, the CA certificate
// minted afresh under the successor's root certificate the staged root key
// covers, the chains issuing under it from the pin on. The successor is
// already verified and pinned; the live key files catch up when the staged
// keys are promoted.
func (i *Issuer) Rekey(keys IssuerKeys, trc cppki.SignedTRC) error {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	root, err := ownRoot(trc, keys.Root)
	if err != nil {
		return err
	}
	if root == nil {
		return serrors.New("the successor carries no root certificate of the staged root key",
			"trc", trc.TRC.ID)
	}
	return i.anchorLocked(keys, trc, root)
}

// ownRoot returns the root certificate among the TRC's that the root key
// covers, nil when the TRC — the zero one included — carries none.
func ownRoot(trc cppki.SignedTRC, key crypto.Signer) (*x509.Certificate, error) {
	if trc.IsZero() {
		return nil, nil
	}
	roots, err := trc.TRC.RootCerts()
	if err != nil {
		return nil, err
	}
	for _, root := range roots {
		if KeyMatchesCert(key, root) {
			return root, nil
		}
	}
	return nil, nil
}
