package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Genesis creates the ISD's base TRC for the founding core and persists it
// in the trust DB, listing the given fellow cores of the same ISD beside it
// — without voting certificates, the founder alone forming the quorum.
// Genesis is idempotent: if the base TRC is already in the DB, it is
// returned unchanged and never silently replaced.
//
// The base TRC follows the PKI draft's genesis rules: the ID is
// ISDx-B1-S1, gracePeriod is zero, votes is empty, and votingQuorum is 1 —
// valid only because the single core holds one sensitive and one regular
// voting certificate. The TRC is CMS-signed by both voting keys, as cppki's
// base-TRC verification requires a signature for every voting certificate.
func Genesis(
	ctx context.Context, db trustdb.DB, ia addr.IA, keys CoreKeys, cores ...addr.IA,
) (cppki.SignedTRC, error) {

	if err := validateISD(ia); err != nil {
		return cppki.SignedTRC{}, err
	}
	coreASes := make([]addr.AS, 0, len(cores)+1)
	coreASes = append(coreASes, ia.AS())
	for _, core := range cores {
		if core.ISD() != ia.ISD() {
			return cppki.SignedTRC{}, fmt.Errorf(
				"fellow core %v outside the founding core's ISD %d", core, ia.ISD())
		}
		coreASes = append(coreASes, core.AS())
	}
	id := cppki.TRCID{ISD: ia.ISD(), Base: 1, Serial: 1}
	if existing, err := db.SignedTRC(ctx, id); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("checking for existing TRC: %w", err)
	} else if !existing.IsZero() {
		return existing, nil
	}

	// Whole seconds: the TRC's validity is truncated to seconds on the wire,
	// and every certificate must cover it from the very first second.
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	sensitive, err := createVotingCert(ia, keys.Sensitive, true, now)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	regular, err := createVotingCert(ia, keys.Regular, false, now)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	root, err := createRootCert(ia, keys.Root, now)
	if err != nil {
		return cppki.SignedTRC{}, err
	}

	trc := cppki.TRC{
		Version:  1,
		ID:       id,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now.Add(TRCValidity)},
		// Base-TRC rules: no grace period, no votes; the single core alone
		// forms the quorum of one.
		Quorum:            1,
		CoreASes:          coreASes,
		AuthoritativeASes: []addr.AS{ia.AS()},
		Description:       fmt.Sprintf("CION genesis TRC for ISD %d", ia.ISD()),
		// Nothing but voting and CP root certificates may appear in the TRC
		// (PKI draft, Section 3.2.11); cppki rejects CA
		// certificates here.
		Certificates: []*x509.Certificate{sensitive, regular, root},
	}
	signed, err := signTRC(trc, keys)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if _, err := db.InsertTRC(ctx, signed); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("inserting TRC: %w", err)
	}
	return signed, nil
}

// signTRC CMS-signs the TRC payload with both voting keys and verifies the
// result with cppki, including the check that every voting certificate has
// signed.
func signTRC(trc cppki.TRC, keys CoreKeys) (cppki.SignedTRC, error) {
	// Order matters for verification error messages only; both voting
	// certificates must sign.
	sensitive, err := signerCert(trc, cppki.Sensitive)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	regular, err := signerCert(trc, cppki.Regular)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	signed, err := signTRCPayload(trc,
		[]*x509.Certificate{sensitive, regular},
		[]crypto.Signer{keys.Sensitive, keys.Regular})
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if err := signed.Verify(nil); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("verifying generated TRC: %w", err)
	}
	return signed, nil
}

// signerCert returns the voting certificate of the given type in the TRC.
func signerCert(trc cppki.TRC, ct cppki.CertType) (*x509.Certificate, error) {
	for _, cert := range trc.Certificates {
		if classified, err := cppki.ValidateCert(cert); err == nil && classified == ct {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("the TRC holds no %s voting certificate", ct)
}
