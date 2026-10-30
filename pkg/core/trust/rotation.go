package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
// counterpart of its class naming its ISD-AS, a holder keeping one
// certificate of each class, everything else carried unchanged —
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
			if err != nil || pct != ct || !sameHolder(cert, counterpart) {
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
	return cppki.TRC{
		Version:  1,
		ID:       successorID(pred.TRC.ID),
		Validity: coveredValidity(certs),
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
	partial, err := SignRotation(trc,
		[]crypto.Signer{fresh.Sensitive, fresh.Regular, fresh.Root}, certs)
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	completed, err := castSuccessor(ctx, db, pred, partial,
		func(_ context.Context, partial cppki.SignedTRC) (cppki.SignedTRC, error) {
			return CoSign(partial, live.Sensitive, predSensitive)
		})
	if err != nil {
		return CoreKeys{}, cppki.SignedTRC{}, err
	}
	return fresh, completed, nil
}

// RollCoreMaterial rolls the authoritative core's material through the
// submission channel its join used: its regular voting certificate and its
// root certificate together, the CA key beside them, as the founder's roll
// does. It resolves the founder's newest TRC — the drafts' numbers-less ask,
// verified against the pinned chain and pinned — and promotes the staged
// material if the newest names it, for then an earlier attempt landed though
// its answer was lost: the roll is complete without a submission once the
// issuer takes the promoted keys. Otherwise it stages fresh keys with their
// self-signed certificates, or reuses the set an earlier attempt staged, and
// assembles the successor replacing the certificates the newest names for
// the core. While the live keys cover those certificates, the successor is a
// regular update: the live voting key votes, the live root key signs for the
// root it replaces (PKI draft, Section 3.5.4), and both fresh keys prove
// possession, so the founder pins it as submitted. Once either no longer
// does, the live keys have nothing to sign: the successor is a sensitive
// update the fresh keys alone sign, completed by the founder's vote on its
// admission policy's allow. What the founder answers verifies against the
// resolved predecessor before it pins here; the issuer then rekeys onto the
// staged keys, and the pin promotes them.
func RollCoreMaterial(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	caster TRCCaster,
	ia addr.IA,
	stateDir string,
	issuer *Issuer,
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
		keys, err := LoadOrCreateIssuerKeys(stateDir)
		if err != nil {
			return err
		}
		return issuer.Rekey(keys, newest)
	}
	heldVoting, heldRoot := heldCert(newest.TRC, ia, cppki.Regular), heldCert(newest.TRC, ia, cppki.Root)
	if heldVoting == nil || heldRoot == nil {
		return serrors.New("the newest TRC names no voting and root certificate of the core",
			"trc", newest.TRC.ID)
	}
	liveVoting, err := LoadOrCreateVotingKey(stateDir)
	if err != nil {
		return err
	}
	liveIssuer, err := LoadOrCreateIssuerKeys(stateDir)
	if err != nil {
		return err
	}
	fresh, err := stageCoreMaterial(stateDir, ia)
	if err != nil {
		return err
	}
	var (
		voter   *x509.Certificate
		signers []KeyCert
	)
	if KeyMatchesCert(liveVoting, heldVoting) && KeyMatchesCert(liveIssuer.Root, heldRoot) {
		// The replaced certificates' keys sign beside the fresh keys' proofs
		// of possession, the voting key's signature its vote: a regular
		// update.
		voter = heldVoting
		signers = []KeyCert{fresh.voting, {Key: liveVoting, Cert: heldVoting},
			fresh.root, {Key: liveIssuer.Root, Cert: heldRoot}}
	} else {
		// A live key no longer covers its certificate in the newest TRC, so
		// the founder's sensitive certificate is the voter: a sensitive
		// update the fresh keys alone sign.
		voter, err = SignerCert(newest.TRC, cppki.Sensitive)
		if err != nil {
			return err
		}
		signers = []KeyCert{fresh.voting, fresh.root}
	}
	trc, err := AssembleRotation(newest, voter, []*x509.Certificate{fresh.voting.Cert, fresh.root.Cert})
	if err != nil {
		return err
	}
	partial, err := SignUpdate(trc, signers...)
	if err != nil {
		return err
	}
	completed, err := castSuccessor(ctx, db, newest, partial, caster.SubmitTRC)
	if err != nil {
		return err
	}
	// The issuer issues under the fresh root from the pin on; a promotion
	// that fails here completes at the next pass.
	if err := issuer.Rekey(IssuerKeys{Root: fresh.root.Key, CA: fresh.ca}, completed); err != nil {
		return err
	}
	promoted, err = PromoteStaged(stateDir, ia, completed.TRC)
	if err != nil {
		return err
	}
	if !promoted {
		return serrors.New("the completed rotation does not name the staged material",
			"id", completed.TRC.ID)
	}
	return nil
}

// heldCert returns the certificate of the class the TRC names for the
// ISD-AS, nil when it names none.
func heldCert(trc cppki.TRC, ia addr.IA, class cppki.CertType) *x509.Certificate {
	for _, cert := range CertsOf(trc, ia) {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == class {
			return cert
		}
	}
	return nil
}

// CertsOf returns the certificates in the TRC naming the ISD-AS: the material
// the holder of the ISD-AS rolls — the founder's three, an authoritative
// core's two.
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

// coreMaterial is an authoritative core's fresh material: the voting and
// root keys with their self-signed certificates, and the CA key.
type coreMaterial struct {
	voting, root KeyCert
	ca           crypto.Signer
}

// stageCoreMaterial returns the authoritative core's fresh material, the
// construction its join used: the set an earlier attempt staged, or a fresh
// one staged in one write.
func stageCoreMaterial(stateDir string, ia addr.IA) (coreMaterial, error) {
	blocks, err := readStaged(stateDir)
	if err != nil {
		return coreMaterial{}, err
	}
	if blocks != nil {
		return readStagedCoreMaterial(blocks)
	}
	var m coreMaterial
	for _, key := range []*crypto.Signer{&m.voting.Key, &m.root.Key, &m.ca} {
		if *key, err = generateKey(); err != nil {
			return coreMaterial{}, err
		}
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	if m.voting.Cert, err = createVotingCert(ia, m.voting.Key, false, now); err != nil {
		return coreMaterial{}, err
	}
	if m.root.Cert, err = createRootCert(ia, m.root.Key, now); err != nil {
		return coreMaterial{}, err
	}
	var keyBlocks []*pem.Block
	for _, key := range []crypto.Signer{m.voting.Key, m.root.Key, m.ca} {
		block, err := keyBlock(key)
		if err != nil {
			return coreMaterial{}, err
		}
		keyBlocks = append(keyBlocks, block)
	}
	if err := writeStaged(stateDir,
		staged(RegularKeyFile, keyBlocks[0]),
		staged(RegularVotingCertFile, certBlock(m.voting.Cert)),
		staged(RootKeyFile, keyBlocks[1]),
		staged(RootCertFile, certBlock(m.root.Cert)),
		staged(CAKeyFile, keyBlocks[2])); err != nil {

		return coreMaterial{}, err
	}
	return m, nil
}

// readStagedCoreMaterial reads the authoritative core's material an earlier
// attempt staged.
func readStagedCoreMaterial(blocks []*pem.Block) (coreMaterial, error) {
	var m coreMaterial
	var err error
	if m.voting.Key, err = stagedKey(blocks, RegularKeyFile); err != nil {
		return coreMaterial{}, err
	}
	if m.voting.Cert, err = stagedCert(blocks, RegularVotingCertFile); err != nil {
		return coreMaterial{}, err
	}
	if m.root.Key, err = stagedKey(blocks, RootKeyFile); err != nil {
		return coreMaterial{}, err
	}
	if m.root.Cert, err = stagedCert(blocks, RootCertFile); err != nil {
		return coreMaterial{}, err
	}
	if m.ca, err = stagedKey(blocks, CAKeyFile); err != nil {
		return coreMaterial{}, err
	}
	return m, nil
}

// sameHolder reports whether the certificates name the same ISD-AS.
func sameHolder(a, b *x509.Certificate) bool {
	aIA, aErr := cppki.ExtractIA(a.Subject)
	bIA, bErr := cppki.ExtractIA(b.Subject)
	return aErr == nil && bErr == nil && aIA.Equal(bIA)
}
