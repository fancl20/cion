package trust

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Genesis creates the ISD's base TRC for the founding core and persists it in
// the trust DB. Genesis is idempotent: if the base TRC is already in the DB,
// it is returned unchanged and never silently replaced.
//
// The base TRC follows the PKI draft's genesis rules: the ID is
// ISDx-B1-S1, gracePeriod is zero, votes is empty, and votingQuorum is 1 —
// valid only because the single core holds one sensitive and one regular
// voting certificate. The TRC is CMS-signed by both voting keys, as cppki's
// base-TRC verification requires a signature for every voting certificate.
func Genesis(ctx context.Context, db DB, ia addr.IA, keys CoreKeys) (cppki.SignedTRC, error) {
	if err := validateISD(ia); err != nil {
		return cppki.SignedTRC{}, err
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
		CoreASes:          []addr.AS{ia.AS()},
		AuthoritativeASes: []addr.AS{ia.AS()},
		Description:       fmt.Sprintf("CION genesis TRC for ISD %d", ia.ISD()),
		// Nothing but voting and CP root certificates may appear in the TRC
		// (PKI draft, Sections 2.1.5.2 and 3.1.2.2.11); cppki rejects CA
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
	payload, err := trc.Encode()
	if err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("encoding TRC: %w", err)
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(payload)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	// Order matters for verification error messages only; both voting
	// certificates must sign.
	if err := sd.AddSignerInfo([]*x509.Certificate{signerCert(trc, cppki.Sensitive)},
		keys.Sensitive); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("signing with sensitive voting key: %w", err)
	}
	if err := sd.AddSignerInfo([]*x509.Certificate{signerCert(trc, cppki.Regular)},
		keys.Regular); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("signing with regular voting key: %w", err)
	}
	raw, err := sd.ContentInfoDER()
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	signed, err := cppki.DecodeSignedTRC(raw)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if err := signed.Verify(nil); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("verifying generated TRC: %w", err)
	}
	return signed, nil
}

// signerCert returns the voting certificate of the given type in the TRC.
func signerCert(trc cppki.TRC, ct cppki.CertType) *x509.Certificate {
	for _, cert := range trc.Certificates {
		if classified, err := cppki.ValidateCert(cert); err == nil && classified == ct {
			return cert
		}
	}
	return nil
}
