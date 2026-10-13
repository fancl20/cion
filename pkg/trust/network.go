package trust

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Remote resolves trust material over the network, typically from the core's
// control endpoint.
type Remote interface {
	// TRC fetches the signed TRC with the given ID.
	TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error)
	// Chains fetches the chains matching the query.
	Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error)
	// RenewChain requests a certificate chain for the CSR, proving possession
	// of the subject key with the given signer. It returns the chain carried
	// by the verified renewal response.
	RenewChain(ctx context.Context, csr *x509.CertificateRequest,
		key crypto.Signer) ([]*x509.Certificate, error)
}

// NetworkProvider is a DB-first trust.Provider: lookups go to the local
// database and fall back to a Remote on a miss, caching the result. The
// founding core runs without a Remote — its DB holds every chain it issued —
// and a nil Remote resolves to "not found", never a panic.
type NetworkProvider struct {
	// DB is the local trust database.
	DB trustdb.DB
	// Remote resolves missing trust material over the network. Nil means the
	// provider is local-only.
	Remote Remote
}

var _ Provider = (*NetworkProvider)(nil)
var _ DBProvider = (*NetworkProvider)(nil)

// LocalTRC looks up the TRC in the local database only.
func (p *NetworkProvider) LocalTRC(id cppki.TRCID) (cppki.SignedTRC, error) {
	return p.DB.SignedTRC(context.Background(), id)
}

// LocalChains looks up chains in the local database only.
func (p *NetworkProvider) LocalChains(
	ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {

	return p.DB.Chains(ctx, q)
}

// GetSignedTRC returns the TRC with the given ID, fetching and validating it
// from the Remote if it is not in the DB. A base TRC is verified with its
// own voting certificates; an update is verified against its pinned
// predecessor — fetched first when it is missing, so a node holding only the
// base can chain its way to any successor. The numbers-less ID asks the
// ISD's newest TRC.
func (p *NetworkProvider) GetSignedTRC(
	ctx context.Context,
	id cppki.TRCID,
	opts ...Option,
) (cppki.SignedTRC, error) {

	return fetchTRC(ctx, p.DB, p.Remote, id)
}

// GetChains returns the chains matching the query that verify against the
// anchor pool — the newest pinned TRC's roots, the predecessor's beside them
// while the newest is within its grace period: the database's when any of
// them verifies, else the Remote's, which are cached. A stored chain whose
// root no pooled TRC carries is passed over.
func (p *NetworkProvider) GetChains(
	ctx context.Context,
	q trustdb.ChainQuery,
	opts ...Option,
) ([][]*x509.Certificate, error) {

	stored, err := p.DB.Chains(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 && p.Remote == nil {
		return nil, nil
	}
	pool, err := anchorPool(ctx, p.DB, p.Remote, q.IA.ISD())
	if err != nil {
		return nil, serrors.Wrap("fetching TRCs to verify chains", err)
	}
	if verified, _ := verifiedChains(stored, pool); len(verified) != 0 {
		return verified, nil
	}
	if p.Remote == nil {
		return nil, nil
	}
	fetched, err := p.Remote.Chains(ctx, q)
	if err != nil {
		return nil, serrors.Wrap("fetching chains from remote", err)
	}
	verified, failures := verifiedChains(fetched, pool)
	for _, err := range failures {
		slog.Warn("Dropping fetched chain that does not verify against TRC", "err", err)
	}
	for _, chain := range verified {
		if _, err := p.DB.InsertChain(ctx, chain); err != nil {
			return nil, fmt.Errorf("caching fetched chain: %w", err)
		}
	}
	return verified, nil
}

// verifiedChains returns the chains that verify against the pool, beside
// the failures of the ones that do not.
func verifiedChains(
	chains [][]*x509.Certificate, pool []*cppki.TRC,
) ([][]*x509.Certificate, []error) {

	var verified [][]*x509.Certificate
	var failures []error
	for _, chain := range chains {
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: pool}); err != nil {
			failures = append(failures, err)
			continue
		}
		verified = append(verified, chain)
	}
	return verified, failures
}

// NotifyTRC ensures the TRC with the given ID is known locally.
func (p *NetworkProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...Option) error {
	_, err := p.GetSignedTRC(ctx, id, opts...)
	return err
}

// RenewChain requests a fresh chain for the node's key from the core and
// stores it, whatever chains the DB holds: the enrollment loop calls it when
// the node holds no valid chain, when the chain nears its expiry, and when
// the chain no longer anchors in the newest pinned TRC.
func RenewChain(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	ia addr.IA,
	key crypto.Signer,
) ([]*x509.Certificate, error) {

	if err := validateISD(ia); err != nil {
		return nil, err
	}
	csr, err := CreateCSR(ia, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	chain, err := remote.RenewChain(ctx, csr, key)
	if err != nil {
		return nil, serrors.Wrap("requesting chain", err)
	}
	if len(chain) != 2 {
		return nil, serrors.New("chain must contain two certificates", "len", len(chain))
	}
	if certIA, err := cppki.ExtractIA(chain[0].Subject); err != nil || !certIA.Equal(ia) {
		return nil, serrors.New("issued chain is for another ISD-AS", "expected", ia)
	}
	// The newest TRC is pulled before the issued chain verifies, so a chain
	// under a fresh root verifies against the successor and not the
	// predecessor the node still holds; the pool carries the predecessor
	// beside it while the successor's grace window runs.
	if _, err := pullNewestTRC(ctx, db, remote, ia.ISD()); err != nil {
		return nil, err
	}
	pool, err := anchorPool(ctx, db, remote, ia.ISD())
	if err != nil {
		return nil, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: pool}); err != nil {
		return nil, serrors.Wrap("issued chain does not verify against TRC", err)
	}
	if _, err := db.InsertChain(ctx, chain); err != nil {
		return nil, fmt.Errorf("storing chain: %w", err)
	}
	return chain, nil
}

// anchorPool resolves the active TRCs that anchor chain verification, as
// activePool reads them: the ISD's newest and, inside its grace period, its
// predecessor, each from the DB or the Remote.
func anchorPool(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	isd addr.ISD,
) ([]*cppki.TRC, error) {

	newest, err := fetchTRC(ctx, db, remote, NewestTRCID(isd))
	if err != nil {
		return nil, err
	}
	return activePool(newest, func(id cppki.TRCID) (cppki.SignedTRC, error) {
		return fetchTRC(ctx, db, remote, id)
	})
}

// activePool returns the active TRCs the draft's Section 3.4 builds the
// trust anchor pool from: the newest, and its predecessor beside it while the
// newest is within its grace period, the window in which a chain issued under
// the replaced material keeps verifying. No TRC before the predecessor is
// active: a successor landing inside its predecessor's window resets the
// window (Section 3.2.4). lookup resolves the predecessor; one it does not
// find leaves the newest alone.
func activePool(
	newest cppki.SignedTRC,
	lookup func(cppki.TRCID) (cppki.SignedTRC, error),
) ([]*cppki.TRC, error) {

	pool := []*cppki.TRC{&newest.TRC}
	if newest.TRC.ID.IsBase() || !newest.TRC.InGracePeriod(time.Now()) {
		return pool, nil
	}
	pred, err := lookup(predecessorID(newest.TRC.ID))
	if err != nil {
		return nil, err
	}
	if pred.IsZero() {
		return pool, nil
	}
	return append(pool, &pred.TRC), nil
}

// fetchTRC returns the TRC with the given ID — the newest of the ISD when the
// ID is numbers-less — from the DB or the Remote, verifying what it fetches
// and caching it in the DB; with a nil Remote, a DB miss is the zero TRC.
func fetchTRC(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	id cppki.TRCID,
) (cppki.SignedTRC, error) {

	if trc, err := db.SignedTRC(ctx, id); err != nil {
		return cppki.SignedTRC{}, err
	} else if !trc.IsZero() {
		return trc, nil
	}
	if remote == nil {
		return cppki.SignedTRC{}, nil
	}
	if id.Base.IsLatest() {
		return pullNewestTRC(ctx, db, remote, id.ISD)
	}
	trc, err := remote.TRC(ctx, id)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching TRC from remote", err, "id", id)
	}
	if trc.TRC.ID != id {
		return cppki.SignedTRC{}, serrors.New("fetched TRC has unexpected ID",
			"expected", id, "actual", trc.TRC.ID)
	}
	return verifyAndPinTRC(ctx, db, remote, trc)
}

// pullNewestTRC asks the Remote for the ISD's newest TRC — the drafts'
// numbers-less request — whatever the DB holds, and pins it once it
// verifies, fetching the predecessors it stands on.
func pullNewestTRC(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	isd addr.ISD,
) (cppki.SignedTRC, error) {

	trc, err := remote.TRC(ctx, NewestTRCID(isd))
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching the newest TRC", err, "isd", isd)
	}
	if trc.TRC.ID.ISD != isd {
		return cppki.SignedTRC{}, serrors.New("fetched TRC is for another ISD",
			"expected", isd, "actual", trc.TRC.ID.ISD)
	}
	return verifyAndPinTRC(ctx, db, remote, trc)
}

// verifyAndPinTRC verifies the TRC — a base TRC with its own voting
// certificates, an update against the resolved predecessor — and pins it in
// the DB. The posture is fail-closed: a TRC no pinned predecessor vouches
// for never enters the database.
func verifyAndPinTRC(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	if trc.TRC.ID.IsBase() {
		if err := trc.Verify(nil); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("verifying fetched TRC", err, "id", trc.TRC.ID)
		}
	} else {
		pred, err := fetchTRC(ctx, db, remote, predecessorID(trc.TRC.ID))
		if err != nil {
			return cppki.SignedTRC{}, err
		}
		if err := trc.Verify(&pred.TRC); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("verifying fetched TRC against its predecessor",
				err, "id", trc.TRC.ID, "predecessor", pred.TRC.ID)
		}
	}
	if _, err := db.InsertTRC(ctx, trc); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("caching fetched TRC: %w", err)
	}
	return trc, nil
}

// CreateCSR creates a self-signed certificate signing request for the node's
// key; the self-signature is the proof of possession of the subject key.
func CreateCSR(ia addr.IA, key crypto.Signer) (*x509.CertificateRequest, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: subject(ia, "")}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}
