package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
// changes keys, never membership. The votes field carries the voter's index
// in the predecessor: a sensitive voting certificate makes a sensitive
// update (PKI draft, Section 3.5.5), and the regular one the roll replaces
// makes a regular update (Section 3.5.4). The validity is the window every
// certificate the successor carries still covers, and the grace period is
// the AS certificate validity: the window a chain issued under replaced
// material keeps verifying, the draft's Section 3.2.4 update grace.
func AssembleRotation(
	pred cppki.SignedTRC,
	voter *x509.Certificate,
	fresh []*x509.Certificate,
) (cppki.TRC, error) {

	if len(fresh) == 0 {
		return cppki.TRC{}, serrors.New("the rotation stages no certificate")
	}
	vote := slices.IndexFunc(pred.TRC.Certificates, voter.Equal)
	if vote < 0 {
		return cppki.TRC{}, serrors.New("the predecessor does not carry the voter",
			"trc", pred.TRC.ID, "voter", voter.Subject)
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
		Votes:             []int{vote},
		Quorum:            pred.TRC.Quorum,
		CoreASes:          slices.Clone(pred.TRC.CoreASes),
		AuthoritativeASes: slices.Clone(pred.TRC.AuthoritativeASes),
		Description:       fmt.Sprintf("CION rotation of %d certificates in ISD %d", len(fresh), pred.TRC.ID.ISD),
		Certificates:      certs,
	}, nil
}

// SignRotation signs the assembled successor with each key under its
// certificate: the staged keys' proof of possession cppki requires of every
// certificate that supersedes a same-named one, extended to the root, and
// on a regular update the vote of the key the roll replaces.
func SignRotation(
	trc cppki.TRC,
	keys []crypto.Signer,
	certs []*x509.Certificate,
) (cppki.SignedTRC, error) {

	return signTRCPayload(trc, certs, keys)
}

// RotateCoreKeys rolls the founder's whole trust material — the sensitive and
// regular voting certificates and the root certificate, the CA key beside
// them — inside the cast it signs itself: the fresh keys staged on disk, or
// the ones an earlier attempt staged, certified afresh; the successor
// assembled on the given predecessor, each fresh certificate signing it, the
// live sensitive key casting the vote. The completed artifact verifies
// against the predecessor before it pins. The roll ends at the pin and
// answers with the staged keys and the successor, so the caller moves the
// decision's signer and the issuer onto them before it promotes the staged
// file.
func RotateCoreKeys(
	ctx context.Context,
	db trustdb.DB,
	stateDir string,
	ia addr.IA,
	pred cppki.SignedTRC,
) (CoreKeys, cppki.SignedTRC, error) {

	live, err := LoadOrCreateCoreKeys(stateDir)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	// The vote is cast by the live sensitive key — an index into the
	// predecessor's certificates — so a key the predecessor's certificate does
	// not cover cannot cast the roll at all.
	predSensitive, err := SignerCert(pred.TRC, cppki.Sensitive)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	if !KeyMatchesCert(live.Sensitive, predSensitive) {
		return CoreKeys{}, cppki.SignedTRC{}, serrors.New(
			"the live sensitive key is not the one the predecessor names; "+
				"the roll has no vote to cast", "predecessor", pred.TRC.ID)
	}
	fresh, certs, err := stageCoreKeys(stateDir, ia)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	trc, err := AssembleRotation(pred, predSensitive, certs)
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
	completed, err := CoSign(partial, live.Sensitive, predSensitive)
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
	return fresh, completed, nil
}

// RollVotingKey rolls the authoritative core's regular voting certificate
// through the submission channel its join used: it resolves the founder's
// newest TRC — the drafts' numbers-less ask, verified against the pinned
// chain and pinned — and promotes the staged pair if the newest names it,
// for then an earlier attempt landed though its answer was lost, and the roll
// is complete without a submission. Otherwise it stages a fresh key with its
// self-signed certificate, or reuses the pair an earlier attempt staged, and
// assembles the successor replacing the certificate the newest names for the
// core. While the live key covers that certificate, the successor is a
// regular update the live key votes on beside the fresh key's proof of
// possession, and the founder pins it as submitted. Once it no longer does,
// the live key has no vote to cast: the successor is a sensitive update the
// fresh key alone signs, completed by the founder's vote on its admission
// policy's allow. What the founder answers verifies against the resolved
// predecessor before it pins here, and must name the staged pair, which the
// pin then promotes.
func RollVotingKey(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	caster TRCCaster,
	ia addr.IA,
	stateDir string,
) error {

	newest, err := pullNewestTRC(ctx, db, remote, ia.ISD())
	if err != nil {
		return err
	}
	promoted, err := PromoteStaged(stateDir, ia, newest.TRC)
	if err != nil {
		return err
	}
	if promoted {
		return nil
	}
	named := CertsOf(newest.TRC, ia)
	if len(named) == 0 {
		return serrors.New("the newest TRC names no certificate of the core", "trc", newest.TRC.ID)
	}
	held := named[0]
	current, err := LoadOrCreateVotingKey(stateDir)
	if err != nil {
		return err
	}
	key, cert, err := stageVotingPair(stateDir, ia)
	if err != nil {
		return err
	}
	var (
		voter   *x509.Certificate
		signers []crypto.Signer
		certs   []*x509.Certificate
	)
	if KeyMatchesCert(current, held) {
		// The replaced certificate's key votes beside the fresh key's proof
		// of possession: a regular update.
		voter = held
		signers = []crypto.Signer{key, current}
		certs = []*x509.Certificate{cert, held}
	} else {
		// The live key covers no certificate of the newest TRC, so the
		// founder's sensitive certificate is the voter: a sensitive update
		// the fresh key alone signs.
		voter, err = SignerCert(newest.TRC, cppki.Sensitive)
		if err != nil {
			return err
		}
		signers = []crypto.Signer{key}
		certs = []*x509.Certificate{cert}
	}
	trc, err := AssembleRotation(newest, voter, []*x509.Certificate{cert})
	if err != nil {
		return err
	}
	if _, err := trc.ValidateUpdate(&newest.TRC); err != nil {
		return serrors.Wrap("classifying the successor against the founder's newest TRC",
			err, "predecessor", newest.TRC.ID)
	}
	partial, err := SignRotation(trc, signers, certs)
	if err != nil {
		return err
	}
	// The submitted artifact is checked before it leaves: the successor
	// classifies, and the possession signature verifies over the payload.
	// The answer's verification demands every signature its update requires.
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
	promoted, err = PromoteStaged(stateDir, ia, completed.TRC)
	if err != nil {
		return err
	}
	if !promoted {
		return serrors.New("the completed rotation does not name the staged pair",
			"id", completed.TRC.ID)
	}
	return nil
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

// stageCoreKeys returns the founder's fresh material — the whole set as a
// set, for the issuer's keys rotate beside the anchored ones — with the
// certificates over the fresh keys naming the ISD-AS exactly as the
// predecessors' constructions do. The keys are the staged ones; the
// certificates are minted afresh on every attempt.
func stageCoreKeys(stateDir string, ia addr.IA) (CoreKeys, []*x509.Certificate, error) {
	keys, err := stagedCoreKeys(stateDir)
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

// stagedCoreKeys returns the founder's staged keys: the set an earlier
// attempt staged, or four fresh keys staged in one write.
func stagedCoreKeys(stateDir string) (CoreKeys, error) {
	var keys CoreKeys
	files := []struct {
		name string
		key  *crypto.Signer
	}{
		{SensitiveKeyFile, &keys.Sensitive},
		{RegularKeyFile, &keys.Regular},
		{RootKeyFile, &keys.Root},
		{CAKeyFile, &keys.CA},
	}
	blocks, err := readStaged(stateDir)
	if err != nil {
		return CoreKeys{}, err
	}
	if blocks != nil {
		for _, file := range files {
			if *file.key, err = stagedKey(blocks, file.name); err != nil {
				return CoreKeys{}, err
			}
		}
		return keys, nil
	}
	for _, file := range files {
		key, err := generateKey()
		if err != nil {
			return CoreKeys{}, err
		}
		block, err := keyBlock(key)
		if err != nil {
			return CoreKeys{}, err
		}
		*file.key = key
		blocks = append(blocks, staged(file.name, block))
	}
	if err := writeStaged(stateDir, blocks...); err != nil {
		return CoreKeys{}, err
	}
	return keys, nil
}

// stageVotingPair returns the authoritative core's fresh voting pair, the
// construction its join used: the pair an earlier attempt staged, or a fresh
// one staged in one write.
func stageVotingPair(stateDir string, ia addr.IA) (crypto.Signer, *x509.Certificate, error) {
	blocks, err := readStaged(stateDir)
	if err != nil {
		return nil, nil, err
	}
	if blocks != nil {
		key, err := stagedKey(blocks, RegularKeyFile)
		if err != nil {
			return nil, nil, err
		}
		cert, err := stagedCert(blocks, RegularVotingCertFile)
		if err != nil {
			return nil, nil, err
		}
		return key, cert, nil
	}
	key, err := generateKey()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	cert, err := createVotingCert(ia, key, false, now)
	if err != nil {
		return nil, nil, err
	}
	block, err := keyBlock(key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeStaged(stateDir, staged(RegularKeyFile, block),
		staged(RegularVotingCertFile, certBlock(cert))); err != nil {

		return nil, nil, err
	}
	return key, cert, nil
}

// sameSubject reports whether the distinguished names are equal, cppki's own
// reading of a certificate's name.
func sameSubject(a, b pkix.Name) bool {
	return reflect.DeepEqual(a.ToRDNSequence(), b.ToRDNSequence())
}
