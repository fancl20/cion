package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// RollTimeout bounds one roll attempt: a wedged submission must not stall the
// watch rolling behind it.
const RollTimeout = 10 * time.Second

// AssembleRotation builds the successor TRC that rolls the staged
// certificates: each staged certificate replaces the predecessor's
// same-named counterpart of its class, everything else carried unchanged —
// the quorum, both AS lists, and noTrustReset as they were, for a roll
// changes keys, never membership. The votes field carries the predecessor's
// index of the sensitive voting certificate (PKI draft, Section 3.5.5), the
// validity is the window every certificate the successor carries still
// covers, and the grace period is the AS certificate validity: the window a
// chain issued under replaced material keeps verifying, the draft's Section
// 3.2.4 update grace.
func AssembleRotation(
	pred cppki.SignedTRC,
	fresh []*x509.Certificate,
) (cppki.TRC, error) {

	if len(fresh) == 0 {
		return cppki.TRC{}, serrors.New("the rotation stages no certificate")
	}
	sensitiveIdx := -1
	for i, cert := range pred.TRC.Certificates {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == cppki.Sensitive {
			sensitiveIdx = i
			break
		}
	}
	if sensitiveIdx < 0 {
		return cppki.TRC{}, serrors.New("the predecessor holds no sensitive voting certificate",
			"trc", pred.TRC.ID)
	}
	certs := slices.Clone(pred.TRC.Certificates)
	replaced := make([]bool, len(fresh))
	for fi, cert := range fresh {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			return cppki.TRC{}, serrors.Wrap("classifying the staged certificate", err,
				"subject", cert.Subject)
		}
		for pi, counterpart := range pred.TRC.Certificates {
			if certs[pi] != counterpart {
				continue // already replaced by an earlier staged certificate
			}
			pct, err := cppki.ValidateCert(counterpart)
			if err != nil || pct != ct || !sameSubject(cert.Subject, counterpart.Subject) {
				continue
			}
			if bytes.Equal(cert.Raw, counterpart.Raw) {
				return cppki.TRC{}, serrors.New("the staged certificate is the predecessor's own",
					"subject", cert.Subject)
			}
			certs[pi] = cert
			replaced[fi] = true
			break
		}
		if !replaced[fi] {
			return cppki.TRC{}, serrors.New("the predecessor holds no counterpart of the staged certificate",
				"subject", cert.Subject)
		}
	}
	// The window every carried certificate still covers: the latest start to
	// the earliest end.
	validity := cppki.Validity{
		NotBefore: certs[0].NotBefore,
		NotAfter:  certs[0].NotAfter,
	}
	for _, cert := range certs[1:] {
		if cert.NotBefore.After(validity.NotBefore) {
			validity.NotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(validity.NotAfter) {
			validity.NotAfter = cert.NotAfter
		}
	}
	return cppki.TRC{
		Version:  1,
		ID:       cppki.TRCID{ISD: pred.TRC.ID.ISD, Base: pred.TRC.ID.Base, Serial: pred.TRC.ID.Serial + 1},
		Validity: validity,
		// The grace window a chain issued under the replaced material keeps
		// verifying: exactly the AS certificate validity, so a chain issued
		// before the cast has expired by the time the window closes.
		GracePeriod:       ASValidity,
		NoTrustReset:      pred.TRC.NoTrustReset,
		Votes:             []int{sensitiveIdx},
		Quorum:            pred.TRC.Quorum,
		CoreASes:          slices.Clone(pred.TRC.CoreASes),
		AuthoritativeASes: slices.Clone(pred.TRC.AuthoritativeASes),
		Description:       fmt.Sprintf("CION rotation of %d certificates in ISD %d", len(fresh), pred.TRC.ID.ISD),
		Certificates:      certs,
	}, nil
}

// SignRotation signs the assembled successor with each staged certificate's
// key — the proof of possession cppki requires of every certificate that
// supersedes a same-named one, extended to the root.
func SignRotation(
	trc cppki.TRC,
	keys []crypto.Signer,
	certs []*x509.Certificate,
) (cppki.SignedTRC, error) {

	return signTRCPayload(trc, certs, keys)
}

// RotateCoreKeys rolls the founder's whole trust material — the sensitive and
// regular voting certificates and the root certificate, the CA key beside
// them — inside the cast it signs itself: fresh keys minted in memory, the
// successor assembled on the given predecessor, each fresh certificate
// signing it, the persisted sensitive key casting the vote. The completed
// artifact verifies against the predecessor before anything pins; the pin
// persists the staged set as a set and answers with it, so the caller rekeys
// the issuer and the decision's signer under the fresh material.
func RotateCoreKeys(
	ctx context.Context,
	db trustdb.DB,
	stateDir string,
	ia addr.IA,
	pred cppki.SignedTRC,
) (CoreKeys, cppki.SignedTRC, error) {

	persisted, err := LoadOrCreateCoreKeys(stateDir)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	// The vote is cast by the persisted sensitive key — an index into the
	// predecessor's certificates — so a key the predecessor's certificate does
	// not cover cannot cast the roll at all.
	predSensitive, err := SignerCert(pred.TRC, cppki.Sensitive)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	if !KeyMatchesCert(persisted.Sensitive, predSensitive) {
		return CoreKeys{}, cppki.SignedTRC{}, serrors.New(
			"the persisted sensitive key is not the one the predecessor names; "+
				"the roll has no vote to cast", "predecessor", pred.TRC.ID)
	}
	fresh, certs, err := stageCoreKeys(ia, pred)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	trc, err := AssembleRotation(pred, certs)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	if _, err := trc.ValidateUpdate(&pred.TRC); err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, serrors.Wrap(
			"classifying the successor against the predecessor", err,
			"predecessor", pred.TRC.ID)
	}
	partial, err := SignRotation(trc,
		[]crypto.Signer{fresh.Sensitive, fresh.Regular, fresh.Root}, certs)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	completed, err := CoSign(partial, persisted.Sensitive, predSensitive)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	if err := completed.Verify(&pred.TRC); err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, serrors.Wrap(
			"verifying the completed rotation", err, "id", completed.TRC.ID)
	}
	if _, err := db.InsertTRC(ctx, completed); err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, fmt.Errorf("pinning the completed rotation: %w", err)
	}
	if err := PersistCoreKeys(stateDir, fresh); err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	return fresh, completed, nil
}

// RollVotingKey rolls the authoritative core's regular voting certificate
// through the submission channel its join used: it resolves the founder's
// newest TRC — the drafts' numbers-less ask, verified against the pinned
// chain and pinned — stages a fresh key with its self-signed certificate,
// assembles the successor replacing the certificate the newest names for the
// core, signs the proof of possession, and submits the partially signed
// artifact to the founder's voting application, whose decision casts the
// sensitive vote. The completed artifact verifies against the resolved
// predecessor before anything pins; the pin persists the staged pair beside
// the key.
func RollVotingKey(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	caster TRCCaster,
	ia addr.IA,
	stateDir string,
) error {

	freshTRC, err := remote.TRC(ctx, newestTRCID(ia.ISD()))
	if err != nil {
		return serrors.Wrap("fetching the founder's newest TRC", err, "isd_as", ia)
	}
	newest, err := verifyAndPinTRC(ctx, db, remote, freshTRC)
	if err != nil {
		return err
	}
	named := CertsOf(newest.TRC, ia)
	if len(named) == 0 {
		return serrors.New("the newest TRC names no certificate of the core", "trc", newest.TRC.ID)
	}
	key, cert, err := stageVotingPair(ia)
	if err != nil {
		return err
	}
	trc, err := AssembleRotation(newest, []*x509.Certificate{cert})
	if err != nil {
		return err
	}
	if _, err := trc.ValidateUpdate(&newest.TRC); err != nil {
		return serrors.Wrap("classifying the successor against the founder's newest TRC",
			err, "predecessor", newest.TRC.ID)
	}
	partial, err := SignUpdate(trc, key, cert)
	if err != nil {
		return err
	}
	// The submitted artifact is checked short of the founder's vote: the
	// successor classifies, and the possession signature verifies over the
	// payload. The completion's verification demands both signatures.
	if err := verifySignedBy(partial, cert); err != nil {
		return serrors.Wrap("verifying the proof of possession", err)
	}
	completed, err := caster.SubmitTRC(ctx, partial)
	if err != nil {
		return err
	}
	if err := completed.Verify(&newest.TRC); err != nil {
		return serrors.Wrap("verifying the completed rotation", err, "id", completed.TRC.ID)
	}
	if _, err := db.InsertTRC(ctx, completed); err != nil {
		return fmt.Errorf("pinning the completed rotation: %w", err)
	}
	return PersistVotingPair(stateDir, key, cert)
}

// CertsOf returns the certificates in the TRC naming the ISD-AS: the material
// the holder of the ISD-AS rolls — the founder's three, an authoritative
// core's one.
func CertsOf(trc cppki.TRC, ia addr.IA) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, cert := range trc.Certificates {
		if certIA, err := cppki.ExtractIA(cert.Subject); err == nil && certIA.Equal(ia) {
			certs = append(certs, cert)
		}
	}
	return certs
}

// KeyMatchesCert reports whether the certificate covers the key's public
// half.
func KeyMatchesCert(key crypto.Signer, cert *x509.Certificate) bool {
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(skid, cert.SubjectKeyId)
}

// stageCoreKeys mints the founder's fresh material — the whole set as a set,
// for the issuer's keys rotate beside the anchored ones — with the
// certificates over the fresh keys naming the ISD-AS exactly as the
// predecessors' constructions do.
func stageCoreKeys(ia addr.IA, pred cppki.SignedTRC) (CoreKeys, []*x509.Certificate, error) {
	keys, err := generateCoreKeys()
	if err != nil {
		return CoreKeys{}, nil, err
	}
	// Whole seconds and the signing backdate, the genesis certificates' own
	// shape, so the fresh certificates cover the successor's validity from
	// its first second.
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	sensitive, err := createVotingCert(ia, keys.Sensitive, true, now)
	if err != nil {
		return CoreKeys{}, nil, err
	}
	regular, err := createVotingCert(ia, keys.Regular, false, now)
	if err != nil {
		return CoreKeys{}, nil, err
	}
	root, err := createRootCert(ia, keys.Root, now)
	if err != nil {
		return CoreKeys{}, nil, err
	}
	return keys, []*x509.Certificate{sensitive, regular, root}, nil
}

// stageVotingPair mints the authoritative core's fresh voting pair, the
// construction its join used.
func stageVotingPair(ia addr.IA) (crypto.Signer, *x509.Certificate, error) {
	key, err := generateKey()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	cert, err := createVotingCert(ia, key, false, now)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// sameSubject reports whether the distinguished names are equal, cppki's own
// reading of a certificate's name.
func sameSubject(a, b pkix.Name) bool {
	return reflect.DeepEqual(a.ToRDNSequence(), b.ToRDNSequence())
}

// persistVotingCertPath names the persisted voting certificate inside the
// state directory, for the pair's persist.
func votingCertPath(stateDir string) string {
	return filepath.Join(keyDir(stateDir), RegularVotingCertFile)
}
