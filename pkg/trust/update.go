package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// ErrNoVotingApp reports a core that hosts no voting application: nothing
// answers the submission, so the joining core cannot obtain voting power
// through the founder. A terminal condition — the node stops itself on it,
// for the network keeps serving everything else without the application.
var ErrNoVotingApp = errors.New("the core hosts no voting application")

// TRCCaster submits a TRC update to the core's voting application: the
// channel a core seeking voting power presents its partially signed
// successor on, for the control plane behind the application to decide on.
type TRCCaster interface {
	// SubmitTRC hands the partially signed successor — the submitter's proof
	// of possession over its new voting certificate — to the core's
	// decision. It returns the completed TRC: the successor carrying the
	// founder's sensitive vote beside the submitted signature, or, when the
	// newest TRC already names the submitter, that TRC as pinned. The
	// implementation reports ErrNoVotingApp when nothing answers.
	SubmitTRC(ctx context.Context, trc cppki.SignedTRC) (cppki.SignedTRC, error)
}

// AssembleOnboarding builds the successor TRC that onboards an admitted
// joiner as an authoritative core: the serial incremented on the same base,
// the joiner's AS appended to the core and authoritative AS lists, its regular
// voting certificate appended to the certificate set, and the quorum,
// noTrustReset, and grace period untouched — a sensitive update, as cppki's
// classification reads it. The votes field carries the predecessor's index of
// the founder's sensitive voting certificate (PKI draft, Section 3.5.5), and
// the validity is the window every certificate the successor carries still
// covers — the joiner's fresh certificate never rules that window; the
// founder's carried ones do.
func AssembleOnboarding(
	pred cppki.SignedTRC,
	joiner addr.IA,
	votingCert *x509.Certificate,
) (cppki.TRC, error) {

	if err := validateISD(joiner); err != nil {
		return cppki.TRC{}, err
	}
	if joiner.ISD() != pred.TRC.ID.ISD {
		return cppki.TRC{}, serrors.New("joiner outside the TRC's ISD",
			"joiner", joiner, "isd", pred.TRC.ID.ISD)
	}
	if ct, err := cppki.ValidateCert(votingCert); err != nil || ct != cppki.Regular {
		return cppki.TRC{}, serrors.New("the presented certificate is not a regular voting certificate")
	}
	if certIA, err := cppki.ExtractIA(votingCert.Subject); err != nil || !certIA.Equal(joiner) {
		return cppki.TRC{}, serrors.New("the presented certificate names another ISD-AS",
			"certificate", votingCert.Subject, "joiner", joiner)
	}
	for _, as := range pred.TRC.CoreASes {
		if as == joiner.AS() {
			return cppki.TRC{}, serrors.New("the joiner is already a core of the TRC",
				"joiner", joiner, "trc", pred.TRC.ID)
		}
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
	// The window every carried certificate still covers: the latest start
	// to the earliest end.
	validity := cppki.Validity{
		NotBefore: pred.TRC.Certificates[0].NotBefore,
		NotAfter:  pred.TRC.Certificates[0].NotAfter,
	}
	for _, cert := range pred.TRC.Certificates[1:] {
		if cert.NotBefore.After(validity.NotBefore) {
			validity.NotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(validity.NotAfter) {
			validity.NotAfter = cert.NotAfter
		}
	}
	if votingCert.NotBefore.After(validity.NotBefore) {
		validity.NotBefore = votingCert.NotBefore
	}
	if votingCert.NotAfter.Before(validity.NotAfter) {
		validity.NotAfter = votingCert.NotAfter
	}
	return cppki.TRC{
		Version:  1,
		ID:       cppki.TRCID{ISD: pred.TRC.ID.ISD, Base: pred.TRC.ID.Base, Serial: pred.TRC.ID.Serial + 1},
		Validity: validity,
		// A sensitive update changes what a regular update may not; the
		// quorum and noTrustReset stay as they were, and the first updates
		// only add material, so no grace period.
		NoTrustReset:      pred.TRC.NoTrustReset,
		Votes:             []int{sensitiveIdx},
		Quorum:            pred.TRC.Quorum,
		CoreASes:          append(append([]addr.AS{}, pred.TRC.CoreASes...), joiner.AS()),
		AuthoritativeASes: append(append([]addr.AS{}, pred.TRC.AuthoritativeASes...), joiner.AS()),
		Description:       fmt.Sprintf("CION onboarding of %s", joiner),
		Certificates:      append(append([]*x509.Certificate{}, pred.TRC.Certificates...), votingCert),
	}, nil
}

// SignUpdate signs the assembled successor with the joining core's regular
// voting key — the proof of possession the draft requires of every new voter
// (PKI draft, Section 3.5.6). The artifact carries exactly the one
// signature; the founder's sensitive vote is what completes it.
func SignUpdate(
	trc cppki.TRC,
	key crypto.Signer,
	cert *x509.Certificate,
) (cppki.SignedTRC, error) {

	return signTRCPayload(trc, []*x509.Certificate{cert}, []crypto.Signer{key})
}

// CoSign adds the signer info the given key makes over the signed TRC,
// beside the signatures the artifact carries already. The founder's control
// plane completes a submitted successor with it — the sensitive certificate
// of its newest pinned TRC signing beside the submitter's proof of
// possession.
func CoSign(
	signed cppki.SignedTRC,
	key crypto.Signer,
	cert *x509.Certificate,
) (cppki.SignedTRC, error) {

	ci, err := protocol.ParseContentInfo(signed.Raw)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("parsing the signed TRC", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("parsing the signed TRC", err)
	}
	if err := sd.AddSignerInfo([]*x509.Certificate{cert}, key); err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("adding the signature", err)
	}
	raw, err := sd.ContentInfoDER()
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(raw)
}

// JoinCore obtains voting power for the authoritative core by sensitive TRC
// update: it resolves the founder's newest TRC — the drafts' numbers-less
// ask, verified against the pinned chain and pinned — assembles the
// successor onboarding itself, signs the proof of possession, and submits
// the partially signed artifact to the founder's voting application, whose
// control plane casts the sensitive vote and pins the completion. A core the
// newest TRC already names casts nothing: the resolved TRC pins, and the
// dance ends.
func JoinCore(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	caster TRCCaster,
	ia addr.IA,
	key crypto.Signer,
	cert *x509.Certificate,
) error {

	fresh, err := remote.TRC(ctx, newestTRCID(ia.ISD()))
	if err != nil {
		return serrors.Wrap("fetching the founder's newest TRC", err, "isd_as", ia)
	}
	newest, err := verifyAndPinTRC(ctx, db, remote, fresh)
	if err != nil {
		return err
	}
	if CoreNamed(newest.TRC, ia) {
		// The join already landed, whether here or before a restart: the
		// newest names the core and nothing is cast.
		return nil
	}
	trc, err := AssembleOnboarding(newest, ia, cert)
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
		return serrors.Wrap("verifying the completed TRC", err, "id", completed.TRC.ID)
	}
	if _, err := db.InsertTRC(ctx, completed); err != nil {
		return fmt.Errorf("pinning the completed TRC: %w", err)
	}
	return nil
}

// CoreNamed reports whether the TRC's core list names the ISD-AS.
func CoreNamed(trc cppki.TRC, ia addr.IA) bool {
	for _, as := range trc.CoreASes {
		if as == ia.AS() && trc.ID.ISD == ia.ISD() {
			return true
		}
	}
	return false
}

// SignerCert returns the voting certificate of the given type in the TRC's
// certificate set.
func SignerCert(trc cppki.TRC, ct cppki.CertType) (*x509.Certificate, error) {
	return signerCert(trc, ct)
}

// verifySignedBy checks that one of the signer infos is the certificate's
// and verifies over the payload.
func verifySignedBy(signed cppki.SignedTRC, cert *x509.Certificate) error {
	for _, si := range signed.SignerInfos {
		if found, err := si.FindCertificate([]*x509.Certificate{cert}); err == nil && found != nil {
			return verifySignerInfo(si, cert, signed.TRC.Raw)
		}
	}
	return serrors.New("the TRC carries no signature by the certificate")
}

// newestTRCID returns the numbers-less TRC ID asking an ISD's newest TRC —
// the active-discovery form the drafts' request carries (PKI draft,
// Section 4.1.2).
func newestTRCID(isd addr.ISD) cppki.TRCID {
	return cppki.TRCID{ISD: isd, Base: scrypto.LatestVer, Serial: scrypto.LatestVer}
}

// predecessorID returns the ID of the TRC one serial before id's.
func predecessorID(id cppki.TRCID) cppki.TRCID {
	return cppki.TRCID{ISD: id.ISD, Base: id.Base, Serial: id.Serial - 1}
}

// signTRCPayload CMS-signs the TRC payload with the given keys, embedding the
// matching certificates, and decodes the result.
func signTRCPayload(
	trc cppki.TRC,
	certs []*x509.Certificate,
	keys []crypto.Signer,
) (cppki.SignedTRC, error) {

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
	for i, key := range keys {
		if err := sd.AddSignerInfo([]*x509.Certificate{certs[i]}, key); err != nil {
			return cppki.SignedTRC{}, fmt.Errorf("signing TRC: %w", err)
		}
	}
	raw, err := sd.ContentInfoDER()
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(raw)
}
